#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, LruPerCpuHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    BEGroup, BEKey, GroupInfo, NAT4Key, ZonInfo, BE, EP4, EP6, INET, MAX_BACKENDS, MAX_CONNTRACKS,
    MAX_GROUPS,
};

/// Keeps runtime config data.
#[map]
static ZLB_INFO: Array<ZonInfo> = Array::with_max_entries(1, 0);

/// Maintains the metadata about backend groups and interfaces. It is used only by userspace
/// application but loaded by the first program - hence the X.
/// This map is pinned to the default bpffs and it should persist after user space exists.
#[map]
static ZLBX_GMETA: HashMap<u64, GroupInfo> = HashMap::<u64, GroupInfo>::pinned(MAX_GROUPS, 0);

/// Maintains the backend endpoints for both IPv4 and IPv6 groups.
/// Both user space processes and xdp programs access this map but only the application
/// can update it. This map is pinned to the default bpffs.
#[map]
static ZLB_BACKENDS: HashMap<BEKey, BE> = HashMap::<BEKey, BE>::pinned(MAX_BACKENDS, 0);

/// Contains the IPv4 load balancing endpoints or groups. The program will search each
/// IPv4 ingress packet against this map and on match will forward to packet to an
/// backend from the pool allocated to the group.
#[map]
static ZLB_LB4: HashMap<EP4, BEGroup> = HashMap::<EP4, BEGroup>::pinned(MAX_GROUPS, 0);

/// Same as ZLB_LB4 but for IPv6 packets.
#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::pinned(MAX_GROUPS, 0);

/// Used for IPV4 connection tracking and NAT between backend and source endpoint.
/// This map will be updated upon forwarding the packet to backend and searched
/// upon returning the backend reply.
/// TBD: pin this map so the NAT table isn't lost when the program is reattached.
/// TODO: add timestamp in order to delete after some time
#[map]
static mut ZLB_CONNTRACK4: LruPerCpuHashMap<NAT4Key, INET> =
    LruPerCpuHashMap::<NAT4Key, INET>::pinned(MAX_CONNTRACKS, 0);

// TODO: add ipv6 connection tracking

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn zon_lb(ctx: XdpContext) -> u32 {
    match try_zon_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_zon_lb(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => ipv4_lb(&ctx),
        EtherType::Ipv6 => ipv6_lb(&ctx),
        _ => return Ok(xdp_action::XDP_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

fn ipv4_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let proto = unsafe { (*ipv4hdr).proto };
    let (if_index, rx_queue) = unsafe { ((*ctx.ctx).ingress_ifindex, (*ctx.ctx).rx_queue_index) };
    let (src_port, dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { ((*udphdr).source, (*udphdr).dest) }
        }
        _ => (0, 0),
    };

    // TODO: add prefilter based on port and proto for both ingress and egress

    let ep4 = EP4 {
        address: unsafe { (*ipv4hdr).dst_addr },
        port: dst_port,
        proto: proto as u16,
    };

    // Temp
    unsafe {
        let e = &ep4 as *const _ as *const u8;
        let a: &[u8] = core::slice::from_raw_parts(e, 8);
        info!(
            ctx,
            "raw ep4: 0x{:x},0x{:x},0x{:x},0x{:x},0x{:x},0x{:x},0x{:x},0x{:x}",
            a[0],
            a[1],
            a[2],
            a[3],
            a[4],
            a[5],
            a[6],
            a[7],
        );
    }

    info!(
        ctx,
        "[i:{}, rx:{}] [p:{}] {:i}:{} -> {:i}:{}",
        if_index,
        rx_queue,
        proto as u8,
        src_addr,
        src_port.to_be(),
        dst_addr,
        dst_port.to_be()
    );

    let group = match unsafe { ZLB_LB4.get(&ep4) } {
        None => {
            let nat4 = NAT4Key {
                ip_be_src: src_addr,
                ip_lb_dst: dst_addr,
                port_be_src: src_port,
                port_lb_dst: dst_port,
                proto: proto as u8,
                ..Default::default()
            };
            match unsafe { ZLB_CONNTRACK4.get(&nat4) } {
                Some(ip_src) => unsafe {
                    info!(ctx, "[egress] match nat, ip src: {:i}", ip_src.v4);

                    (*ipv4hdr.cast_mut()).dst_addr = ip_src.v4;
                    (*ipv4hdr.cast_mut()).src_addr = nat4.ip_lb_dst;
                    match proto {
                        IpProto::Tcp => {
                            let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                            (*tcphdr.cast_mut()).source = nat4.port_lb_dst;
                            // the destination port remains the same
                            // TODO: update tcp and ip csums
                            // TBD: monitor RST flag to remove the conntrack entry
                        }
                        IpProto::Udp => {
                            let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                            (*udphdr.cast_mut()).source = nat4.port_lb_dst;
                            // TODO: update udp and ip csums
                            // TBD: always delete entry ?
                        }
                        _ => {
                            // TODO: update ip csum
                            // TODO: always delete contrack entry
                        }
                    };
                    return Ok(xdp_action::XDP_PASS);
                },
                None => return Ok(xdp_action::XDP_PASS),
            }
        }
        Some(group) => group,
    };

    info!(ctx, "[ingress] Group {} match", group.gid);

    if group.becount == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    // TBD: always update contrack entry if exists or use TCP/UDP

    let mut _nat4 = NAT4Key {
        ip_be_src: src_addr,
        ip_lb_dst: dst_addr,
        port_be_src: src_port,
        port_lb_dst: dst_port,
        proto: proto as u8,
        ..Default::default()
    };

    // TODO: build hash and choose a backend index and fetch it
    // TODO: build the conntrack key and create/update entry
    // TODO: update packet with backend as dest and lb as source

    Ok(xdp_action::XDP_PASS)
}

fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let _proto = unsafe { (*ipv6hdr).next_hdr };

    info!(ctx, "received a ipv6 packet");

    Ok(xdp_action::XDP_PASS)
}
