use crate::{ptr_at, stats_inc, BpfFibLookUp, Features, ZLB_BACKENDS};
use aya_ebpf::{
    bindings::{bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_F_NO_COMMON_LRU},
    helpers::bpf_fib_lookup,
    macros::map,
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, Level};
use core::mem;
use ebpf_rshelpers::{csum_add_u32, csum_fold_32_to_16};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    stats, BEGroup, BEKey, EPFlags, Inet6U, NAT6Key, NAT6Value, EP6, MAX_CONNTRACKS, MAX_GROUPS,
};

/// Same as ZLB_LB4 but for IPv6 packets.
#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::pinned(MAX_GROUPS, 0);

type LHM6 = LruHashMap<NAT6Key, NAT6Value>;
/// Used for IPv6 connection tracking and NAT between backend and source endpoint.
/// This map will be updated upon forwarding the packet to backend and searched
/// upon returning the backend reply.
/// NOTE: BPF_F_NO_COMMON_LRU will increase the performance but in the user space
/// the conntrack listing will be affected as there are different LRU lists per CPU.
/// TODO: The key can change an replaced by ipv6 src, dst and flow label.
#[map]
static mut ZLB_CONNTRACK6: LHM6 = LHM6::pinned(MAX_CONNTRACKS, BPF_F_NO_COMMON_LRU);

#[inline(always)]
fn inet6_hash32(addr: &Inet6U) -> u32 {
    let addr = unsafe { &addr.addr32 };
    let csum = csum_add_u32(addr[0], 0);
    let csum = csum_add_u32(addr[1], csum);
    let csum = csum_add_u32(addr[2], csum);
    csum_add_u32(addr[3], csum)
}

#[inline(always)]
fn inet6_hash16(addr: &Inet6U) -> u16 {
    csum_fold_32_to_16(inet6_hash32(addr))
}

pub fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { Inet6U::from(&(*ipv6hdr).src_addr.in6_u.u6_addr32) };
    let dst_addr = unsafe { Inet6U::from(&(*ipv6hdr).dst_addr.in6_u.u6_addr32) };
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // TODO: consider the VLAN offset
    // NOTE: IPv6 header isn't fixed and the L4 header offset can
    // be computed iterating over the extension headers until we
    // reach a non-extension next_hdr value. For now we assume
    // there are no extensions or fragments.
    let l4hdr_offset = Ipv6Hdr::LEN + EthHdr::LEN;

    // TODO: For IPv6 there can be only 6 linked header types: Hop-by-Hop Options,
    // Fragment, Destination Options, Routing, Authentication and Encapsulating
    // Security Payload. I makes sense to make make 6 calls until reaching a
    // next header we can handle.
    let (src_port, dst_port) = match next_hdr {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*udphdr).source, (*udphdr).dest) }
        }
        // TODO: handle extention headers or at least fragments as they may contain
        // actual valid tcp or udp packets.
        // NOTE: unlike with IPv4, routers never fragment a packet.
        // NOTE: unlike IPv4, fragmentation in IPv6 is performed only by source
        // nodes, not by routers along a packet's delivery path. Must handle ipv6
        // fragments in case the source decides to fragment the packet due to MTU.
        // NOTE: IPv6 requires that every link in the Internet have an MTU of 1280
        // octets or greater. This is known as the IPv6 minimum link MTU.
        // On any link that cannot convey a 1280-octet packet in one piece,
        // link-specific fragmentation and reassembly must be provided at a layer
        // below IPv6.
        // See: https://www.rfc-editor.org/rfc/rfc8200.html#page-25
        // TODO: handle No Next Header => pass
        _ => (0, 0),
    };

    let feat = Features::new();
    if feat.log_enabled(Level::Info) {
        let (if_index, rx_queue) =
            unsafe { ((*ctx.ctx).ingress_ifindex, (*ctx.ctx).rx_queue_index) };
        info!(
            ctx,
            "[i:{}, rx:{}] [p:{}] [{:i}]:{} -> *[{:i}]:{}",
            if_index,
            rx_queue,
            next_hdr as u8,
            unsafe { src_addr.addr8 },
            src_port.to_be(),
            unsafe { dst_addr.addr8 },
            dst_port.to_be()
        );
    }

    let ep6 = EP6 {
        address: dst_addr,
        port: dst_port,
        proto: next_hdr as u16,
    };

    let group = match unsafe { ZLB_LB6.get(&ep6) } {
        Some(group) => *group,
        None => {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "No LB6 entry");
            }
            // *** This is the exit point for non-LB packets ***
            // These packets are not counted as they are not destined
            // to any backend group. By counting them would mean that
            // XDP_PASS would by far the outlier and would prevent
            // knowing which packets were actually modified.
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // Update the total processed packets when they are destined
    // to a known backend group.
    stats_inc(stats::PACKETS);

    if feat.log_enabled(Level::Info) {
        info!(ctx, "[in] gid: {} match", group.gid);
    }

    if group.becount == 0 {
        if feat.log_enabled(Level::Info) {
            info!(ctx, "[in] gid: {}, no backends", group.gid);
        }

        stats_inc(stats::XDP_PASS);
        stats_inc(stats::LB_ERROR_NO_BE);

        return Ok(xdp_action::XDP_PASS);
    }

    let key = BEKey {
        gid: group.gid,
        index: (inet6_hash16(&src_addr) ^ src_port) % group.becount,
    };

    let be = match unsafe { ZLB_BACKENDS.get(&key) } {
        Some(be) => be,
        None => {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "[in] gid: {}, no BE at: {}", group.gid, key.index);
            }

            stats_inc(stats::XDP_PASS);
            stats_inc(stats::LB_ERROR_BAD_BE);

            return Ok(xdp_action::XDP_PASS);
        }
    };

    let be_addr = Inet6U::from(&be.address);

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[ctrk] fw be: [{:i}]:{}",
            unsafe { be_addr.addr8 },
            be.port.to_be()
        );
    }

    let redirect = be.flags.contains(EPFlags::XDP_REDIRECT);
    let lb_addr = if redirect && be.flags.contains(EPFlags::XDP_TX) && be.src_ip[0] != 0 {
        // TODO: check the arp table and update or insert
        // smac/dmac and derived ip src and redirect ifindex
        &be.src_ip
    } else {
        unsafe { &dst_addr.addr32 }
    };

    // NOTE: Don't insert entry if no connection tracking is enabled for this backend.
    // For e.g. if the backend can reply directly to the source endpoint.
    // if !be.flags.contains(EPFlags::NO_CONNTRACK) {
    // NOTE: the LB will use the source port since there can be multiple
    // connection to the same backend and it needs to track all of them.
    // BUG: can't copy ipv6 addresses as [u32; 4] directly because aya
    // generates code that the verifier rejects.
    let nat6key = NAT6Key {
        //ip_be_src: [be.address[0], be.address[1], be.address[2], be.address[3]],
        ip_be_src: be_addr,
        ip_lb_dst: Inet6U::from(lb_addr),
        port_be_src: be.port as u32,
        port_lb_dst: src_port as u32, // use the source port of the endpoint
        next_hdr: next_hdr as u32,
    };

    // NOTE: Always use 64-bits values for faster data transfer and
    // fewer instructions during initialization
    let mac_addresses = if redirect {
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

    let if_index = unsafe { (*ctx.ctx).ingress_ifindex };

    // Update the nat entry only if the source details changes.
    // This will boost performance and less error prone on tests like iperf.
    let do_insert = if let Some(nat) = unsafe { ZLB_CONNTRACK6.get(&nat6key) } {
        nat.ifindex != if_index || nat.ip_src != src_addr || nat.mac_addresses != mac_addresses
    } else {
        true
    };

    if do_insert {
        let nat6value = NAT6Value {
            ip_src: src_addr,
            port_lb: dst_port as u32,
            ifindex: if_index,
            mac_addresses,
            flags: be.flags,
            lb_ip: dst_addr, // save the original LB IP
        };

        // TBD: use lock or atomic update ?
        // TBD: use BPF_F_LOCK ?
        match unsafe { ZLB_CONNTRACK6.insert(&nat6key, &nat6value, 0) } {
            Ok(()) => {
                if feat.log_enabled(Level::Info) {
                    info!(
                        ctx,
                        "[ctrk] [{:i}]:{} added",
                        unsafe { src_addr.addr8 },
                        src_port,
                    )
                }
            }
            Err(ret) => {
                if feat.log_enabled(Level::Error) {
                    error!(
                        ctx,
                        "[ctrk] [{:i}]:{} not added, err: {}",
                        unsafe { src_addr.addr8 },
                        src_port,
                        ret
                    )
                }
                stats_inc(stats::CT_ERROR_UPDATE);
            }
        };
    }

    // TODO: compute TCP or UDP csum

    // TODO: reduce hop limit by one on xmit and redirect
    // The IPv6 header does not have a csum field that needs to be
    // recalculated everytime the hop limit is decreased as it happens
    // when the TTL from IPv4 header is reduced by one.

    // NOTE: In the absence of an csum in IP header the IPv6 protocol relies
    // on Link and Transport layer for assuring packet integrity. That's
    // why UDP for IPv6 must have a valid csum and for IPv4 is not required.

    if !redirect {
        // Send back the packet to the same interface
        if be.flags.contains(EPFlags::XDP_TX) {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "in => xdp_tx");
            }

            stats_inc(stats::XDP_TX);

            return Ok(xdp_action::XDP_TX);
        }

        if feat.log_enabled(Level::Info) {
            info!(ctx, "in => xdp_pass");
        }

        stats_inc(stats::XDP_PASS);

        return Ok(xdp_action::XDP_PASS);
    }

    return redirect_ipv6(ctx, feat, ipv6hdr, Inet6U::from(lb_addr), be_addr);
}

fn redirect_ipv6(
    ctx: &XdpContext,
    feat: Features,
    ipv6hdr: *const Ipv6Hdr,
    src_ip: Inet6U,
    dst_ip: Inet6U,
) -> Result<u32, ()> {
    let fib_param = BpfFibLookUp::new_inet6(
        unsafe { (*ipv6hdr).payload_len.to_be() },
        unsafe { (*ctx.ctx).ingress_ifindex },
        unsafe { (*ipv6hdr).priority() as u32 },
        &src_ip,
        &dst_ip,
    );
    let p_fib_param = &fib_param as *const BpfFibLookUp as *mut bpf_fib_lookup_param_t;
    let rc = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            p_fib_param,
            mem::size_of::<BpfFibLookUp>() as i32,
            0,
        )
    };

    stats_inc(stats::FIB_LOOKUPS);

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[redirect] output, lkp_ret: {}, fw if: {}, src: {:i}, \
            gw: {:i}, dmac: {:mac}, smac: {:mac}",
            rc,
            fib_param.ifindex,
            unsafe { Inet6U::from(&fib_param.src).addr8 },
            unsafe { Inet6U::from(&fib_param.dst).addr8 },
            fib_param.dest_mac(),
            fib_param.src_mac(),
        );
    }

    stats_inc(stats::XDP_PASS);
    Ok(xdp_action::XDP_PASS)
}
