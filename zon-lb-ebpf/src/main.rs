#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use core::mem;
use ebpf_rshelpers::{csum_fold_32_to_16, csum_update_u32};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    BEGroup, BEKey, GroupInfo, NAT4Key, ZonInfo, BE, EP4, EP6, MAX_BACKENDS, MAX_CONNTRACKS,
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

type LHM4 = LruHashMap<NAT4Key, u32>;
/// Used for IPV4 connection tracking and NAT between backend and source endpoint.
/// This map will be updated upon forwarding the packet to backend and searched
/// upon returning the backend reply.
/// TBD: pin this map so the NAT table isn't lost when the program is reattached.
/// TODO: add timestamp in order to delete after some time
#[map]
static mut ZLB_CONNTRACK4: LHM4 = LHM4::pinned(MAX_CONNTRACKS, 0);
// TODO: check flag BPF_F_NO_COMMON_LRU

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
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
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
        address: dst_addr,
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
        src_addr.to_be(),
        src_port.to_be(),
        dst_addr.to_be(),
        dst_port.to_be()
    );

    // TODO: Check conntrack first for non-connection oriented, eg. icmp.
    // Alternatively add another key element to differentiate between connections
    // for e.g. the request.
    // Also we can ignore all non-connection protocols like icmp.

    if let Some(group) = unsafe { ZLB_LB4.get(&ep4) } {
        info!(ctx, "[in] gid: {} match", group.gid);

        if group.becount == 0 {
            info!(ctx, "[in] gid: {}, no backends", group.gid);
            return Ok(xdp_action::XDP_PASS);
        }

        let key = BEKey {
            gid: group.gid,
            index: ((((src_addr >> 16) ^ src_addr) as u16) ^ src_port) % group.becount,
        };

        let be = match unsafe { ZLB_BACKENDS.get(&key) } {
            Some(be) => be,
            None => {
                info!(ctx, "[in] gid: {}, no BE at: {}", group.gid, key.index);
                return Ok(xdp_action::XDP_PASS);
            }
        };

        info!(
            ctx,
            "[ctrk] fw be: {:i}:{}",
            be.address.v4.to_be(),
            be.port.to_be()
        );

        // TODO: goto conntrack search if backend == source or replace it with lb and return ?

        // NOTE: the LB will use the source port since there can be multiple
        // connection to the same backend and it needs to track all of them.

        let nat4 = NAT4Key {
            ip_be_src: be.address.v4,
            ip_lb_dst: dst_addr,
            port_be_src: be.port,
            port_lb_dst: src_port, // use the source port of the endpoint
            proto: proto as u32,
        };

        // NOTE: Always use 64-bits values for faster data transfer and
        // fewer instructions during initialization

        // TBD: always update contrack entry if exists ?
        // TBD: use lock or atomic update ?
        // TBD: use BPF_F_LOCK ?
        match unsafe { ZLB_CONNTRACK4.insert(&nat4, &src_addr, 0) } {
            Ok(()) => info!(ctx, "[ctrk] {:i} added", src_addr.to_be()),
            Err(ret) => error!(ctx, "[ctrk] {:i} not added, err: {}", src_addr.to_be(), ret),
        };

        let mut csum = unsafe { !(*ipv4hdr).check } as u32;
        info!(ctx, "initial csum: 0x{:x}", csum);
        unsafe {
            (*ipv4hdr.cast_mut()).src_addr = dst_addr;
            (*ipv4hdr.cast_mut()).dst_addr = be.address.v4;

            csum = csum_update_u32(dst_addr, be.address.v4, csum);
            csum = csum_update_u32(src_addr, dst_addr, csum);
        }

        match proto {
            IpProto::Tcp => unsafe {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                // the source port remains the same
                // (*tcphdr.cast_mut()).source = src_port;
                (*tcphdr.cast_mut()).dest = be.port;

                // TODO: update tcp and ip csums
                // TBD: monitor RST flag to remove the conntrack entry
            },
            IpProto::Udp => unsafe {
                let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
                // the source port remains the same
                // (*tcphdr.cast_mut()).source = src_port;
                (*udphdr.cast_mut()).dest = be.port;

                // TODO: update udp and ip csums
                // TBD: always delete entry ?
            },
            _ => {
                // TODO: update ip csum
                // TODO: always delete contrack entry
            }
        };

        unsafe {
            (*ipv4hdr.cast_mut()).check = !csum_fold_32_to_16(csum);
        };

        info!(ctx, "final csum: 0x{:x}", csum);
        return Ok(xdp_action::XDP_PASS);
    } else {
        info!(ctx, "No LB4 entry");
    }

    let nat4 = NAT4Key {
        ip_be_src: src_addr,
        ip_lb_dst: dst_addr,
        port_be_src: src_port,
        port_lb_dst: dst_port,
        proto: proto as u32,
    };

    let ip_src = match unsafe { ZLB_CONNTRACK4.get(&nat4) } {
        Some(src) => *src,
        None => {
            info!(ctx, "No conntrack entry");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    info!(ctx, "[out] match nat, ip src: {:i}", ip_src.to_be());

    let mut csum = unsafe { !(*ipv4hdr).check as u32 };
    unsafe {
        (*ipv4hdr.cast_mut()).dst_addr = ip_src;
        (*ipv4hdr.cast_mut()).src_addr = dst_addr;

        csum = csum_update_u32(src_addr, dst_addr, csum);
        csum = csum_update_u32(dst_addr, ip_src, csum);
    };

    match proto {
        IpProto::Tcp => unsafe {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            // the destination port remains the same
            (*tcphdr.cast_mut()).source = dst_port;

            // TODO: update tcp and ip csums
            // TBD: monitor RST flag to remove the conntrack entry
        },
        IpProto::Udp => unsafe {
            let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            // the destination port remains the same
            (*udphdr.cast_mut()).source = dst_port;

            // TODO: update udp and ip csums
            // TBD: always delete entry ?
        },
        _ => {
            // TODO: update ip csum
            // TODO: always delete contrack entry
        }
    };

    unsafe {
        (*ipv4hdr.cast_mut()).check = !csum_fold_32_to_16(csum);
    };

    Ok(xdp_action::XDP_PASS)
}

fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let _proto = unsafe { (*ipv6hdr).next_hdr };

    info!(ctx, "received a ipv6 packet");

    Ok(xdp_action::XDP_PASS)
}
