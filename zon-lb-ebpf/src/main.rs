#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action::{self, XDP_PASS, XDP_TX},
    macros::{map, xdp},
    maps::{Array, HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{error, info};
use core::mem;
use ebpf_rshelpers::{csum_fold_32_to_16, csum_update_u16, csum_update_u32};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    BEGroup, BEKey, EPFlags, GroupInfo, NAT4Key, NAT4Value, ZonInfo, BE, EP4, EP6, MAX_BACKENDS,
    MAX_CONNTRACKS, MAX_GROUPS,
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

type LHM4 = LruHashMap<NAT4Key, NAT4Value>;
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
    // TODO: support vlan tags
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };
    let check = !unsafe { (*ipv4hdr).check } as u32;
    let (if_index, rx_queue) = unsafe { ((*ctx.ctx).ingress_ifindex, (*ctx.ctx).rx_queue_index) };

    // NOTE: compute the l4 header start based on ipv4hdr.IHL
    let l4hdr_offset = (unsafe { (*ipv4hdr).ihl() as usize } << 2);
    info!(ctx, "ipv4 hdr size {}", l4hdr_offset);
    let l4hdr_offset = l4hdr_offset + EthHdr::LEN;

    let (src_port, dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*udphdr).source, (*udphdr).dest) }
        }
        _ => (0, 0),
    };

    // TODO: add prefilter based on port and proto for both ingress and egress

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

    let nat4 = NAT4Key {
        ip_be_src: src_addr,
        ip_lb_dst: dst_addr,
        port_be_src: src_port,
        port_lb_dst: dst_port,
        proto: proto as u32,
    };

    if let Some(&nat) = unsafe { ZLB_CONNTRACK4.get(&nat4) } {
        info!(
            ctx,
            "[out] nat, src: {:i}, lb_port: {}",
            nat.ip_src.to_be(),
            (nat.port_lb as u16).to_be()
        );

        // Unlikely
        if nat.ip_src == src_addr && src_port == dst_port {
            error!(
                ctx,
                "[out] drop same src {:i}:{}",
                nat.ip_src.to_be(),
                src_port.to_be()
            );
            return Ok(xdp_action::XDP_DROP);
        }

        // NOTE: optimization: since the destination IP (LB)
        // 'remains' in the csum we can recompute it as if
        // only the source IP changes.
        unsafe {
            let hdr = ipv4hdr.cast_mut();
            (*hdr).dst_addr = nat.ip_src;
            (*hdr).src_addr = dst_addr;

            // NOTE: optimization: skip csum computation if the addresses
            // don't actually change.
            if src_addr != nat.ip_src {
                //csum = csum_update_u32(src_addr, dst_addr, csum);
                //csum = csum_update_u32(dst_addr, nat.ip_src, csum);
                let csum = csum_update_u32(src_addr, nat.ip_src, check);
                (*hdr).check = !csum_fold_32_to_16(csum);
            }
        }

        // NOTE: in order to compute the L4 csum must use bpf_loop
        // as the verifier doesn't allow loops. Without loop support
        // can't iterate over the entire packet as the number of iterations
        // are limited; e.g. for _ 0..100 {..}
        // Recomputing the L4 csum seems to be necessary only if the packet
        // is forwarded between local interfaces.

        match proto {
            IpProto::Tcp => unsafe {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?.cast_mut();
                // NOTE: the destination port remains the same

                (*tcphdr).source = nat.port_lb as u16;

                // NOTE: Update the csum from TCP header. This csum
                // is computed from the TCP pseudo header (e.g. addresses
                // from IP header) + TCP header (checksum is 0) + the
                // text (payload data).

                let mut tcs = !(*tcphdr).check as u32;

                // The source ip is part of the TCP pseudo header
                if src_addr != nat.ip_src {
                    tcs = csum_update_u32(src_addr, nat.ip_src, tcs);
                }
                // The destination port is part of the TCP header
                tcs = csum_update_u32(src_port as u32, nat.port_lb, tcs);
                (*tcphdr).check = !csum_fold_32_to_16(tcs);

                // TBD: monitor RST flag to remove the conntrack entry
            },
            IpProto::Udp => unsafe {
                let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?.cast_mut();

                // NOTE: the destination port remains the same

                (*udphdr).source = nat.port_lb as u16;

                // NOTE: Update the csum from header. This csum
                // is computed from the pseudo header (e.g. addresses
                // from IP header) + header (checksum is 0) + the
                // text (payload data).

                let mut ucs = !(*udphdr).check as u32;

                // The source ip is part of the pseudo header
                if src_addr != nat.ip_src {
                    ucs = csum_update_u32(src_addr, nat.ip_src, ucs);
                }
                // The destination port is part of the header
                ucs = csum_update_u32(src_port as u32, nat.port_lb, ucs);
                (*udphdr).check = !csum_fold_32_to_16(ucs);

                // TBD: always delete entry ?
            },
            _ => {
                // TODO: always delete contrack entry
            }
        };

        let ret = if nat.flags.contains(EPFlags::XDP_REDIRECT) {
            let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
            let ret = unsafe {
                *macs = nat.mac_addresses;
                aya_bpf::helpers::bpf_redirect(nat.ifindex, 0) as xdp_action::Type
            };
            info!(
                ctx,
                "[out] redirect to {:i}:{} via {}, ret={}",
                nat.ip_src.to_be(),
                dst_port.to_be(),
                nat.ifindex,
                ret,
            );
            ret
        } else if nat.flags.contains(EPFlags::XDP_TX) {
            info!(
                ctx,
                "[out] tx to {:i}:{}",
                nat.ip_src.to_be(),
                dst_port.to_be(),
            );
            XDP_TX
        } else {
            info!(
                ctx,
                "[out] pass to {:i}:{}",
                nat.ip_src.to_be(),
                dst_port.to_be(),
            );
            XDP_PASS
        };

        return Ok(ret);
    } else {
        info!(ctx, "No conntrack entry");
    }

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

    let group = match unsafe { ZLB_LB4.get(&ep4) } {
        Some(group) => *group,
        None => {
            info!(ctx, "No LB4 entry");
            return Ok(xdp_action::XDP_PASS);
        }
    };

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

    // For non-connection protocols like ICMP is ok to forward the call here and not insert
    // it in the conntrack. This works because the be is picked based on a computed hash.
    if dst_port == 0 && be.address.v4 == src_addr {}

    // NOTE: Don't insert entry if no connection tracking is enabled for this backend.
    // For e.g. if the backend can reply directly to the source endpoint.
    if !be.flags.contains(EPFlags::NO_CONNTRACK) {
        // NOTE: the LB will use the source port since there can be multiple
        // connection to the same backend and it needs to track all of them.
        let nat4key = NAT4Key {
            ip_be_src: be.address.v4,
            ip_lb_dst: dst_addr,
            port_be_src: be.port,
            port_lb_dst: src_port, // use the source port of the endpoint
            proto: proto as u32,
        };
        let mac_addresses = if be.flags.contains(EPFlags::XDP_REDIRECT) {
            let macs = ptr_at::<[u64; 2]>(&ctx, 0)?;
            let macs = unsafe { macs.as_ref() }.ok_or(())?;
            let macs = [
                (macs[1] & 0xffff_ffff) << 16 | macs[0] >> 48 | macs[0] << 48,
                macs[0] >> 16,
            ];
            unsafe { *(macs.as_ptr() as *const [u32; 3]) }
        } else {
            [0; 3]
        };
        let nat4value = NAT4Value {
            ip_src: src_addr,
            port_lb: dst_port as u32,
            ifindex: if_index,
            mac_addresses,
            flags: be.flags,
        };

        // NOTE: Always use 64-bits values for faster data transfer and
        // fewer instructions during initialization

        // TBD: always update contrack entry if exists ?
        // TBD: use lock or atomic update ?
        // TBD: use BPF_F_LOCK ?
        match unsafe { ZLB_CONNTRACK4.insert(&nat4key, &nat4value, 0) } {
            Ok(()) => info!(ctx, "[ctrk] {:i} added", src_addr.to_be()),
            Err(ret) => error!(ctx, "[ctrk] {:i} not added, err: {}", src_addr.to_be(), ret),
        };
    }

    // NOTE: optimization: compute the IP csum as if only
    // the source address changes.
    unsafe {
        let hdr = ipv4hdr.cast_mut();
        (*hdr).src_addr = dst_addr;
        (*hdr).dst_addr = be.address.v4;

        if src_addr != be.address.v4 {
            //csum = csum_update_u32(dst_addr, be.address.v4, csum);
            //csum = csum_update_u32(src_addr, dst_addr, csum);
            let csum = csum_update_u32(src_addr, be.address.v4, check);
            (*hdr).check = !csum_fold_32_to_16(csum);
        }
    }

    match proto {
        IpProto::Tcp => unsafe {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?.cast_mut();

            // NOTE: the source port remains the same

            (*tcphdr).dest = be.port;

            // NOTE: Update the csum from TCP header. This csum
            // is computed from the TCP pseudo header (e.g. addresses
            // from IP header) + TCP header (checksum is 0) + the
            // text (payload data).

            let mut tcs = !(*tcphdr).check as u32;

            // The source ip is part of the TCP pseudo header
            if src_addr != be.address.v4 {
                tcs = csum_update_u32(src_addr, be.address.v4, tcs);
            }
            // The destination port is part of the TCP header
            tcs = csum_update_u16(dst_port, be.port, tcs);
            (*tcphdr).check = !csum_fold_32_to_16(tcs);

            // TBD: monitor RST flag to remove the conntrack entry
        },
        IpProto::Udp => unsafe {
            let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?.cast_mut();

            // NOTE: the source port remains the same

            (*udphdr).dest = be.port;

            // NOTE: Update the csum from UDP header. This csum
            // is computed from the UDPP pseudo header (e.g. addresses
            // from IP header) + UDPP header (checksum is 0) + the
            // text (payload data).

            let mut ucs = !(*udphdr).check as u32;

            // The source ip is part of the pseudo header
            if src_addr != be.address.v4 {
                ucs = csum_update_u32(src_addr, be.address.v4, ucs);
            }
            // The destination port is part of the header
            ucs = csum_update_u16(dst_port, be.port, ucs);
            (*udphdr).check = !csum_fold_32_to_16(ucs);

            // TBD: always delete entry ?
        },
        _ => {
            // TODO: update ip csum
            // TODO: always delete contrack entry
        }
    };

    // TODO: check if bpf_redirect_peer() is usable for veth

    // Send back the packet to the same interface
    if be.flags.contains(EPFlags::XDP_TX) {
        info!(ctx, "in => xdp_tx");
        return Ok(xdp_action::XDP_TX);
    }

    info!(ctx, "in => xdp_pass");
    Ok(xdp_action::XDP_PASS)
}

fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let _proto = unsafe { (*ipv6hdr).next_hdr };

    info!(ctx, "received a ipv6 packet");

    Ok(xdp_action::XDP_PASS)
}
