use crate::{ptr_at, redirect_txport, stats_inc, BpfFibLookUp, Features, ZLB_BACKENDS};
use aya_ebpf::{
    bindings::{self, bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_F_NO_COMMON_LRU},
    helpers::{bpf_fib_lookup, bpf_ktime_get_ns},
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
    icmp::IcmpHdr,
    ip::{in6_addr, IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    stats, ArpEntry, BEGroup, BEKey, EPFlags, Inet6U, NAT6Key, NAT6Value, EP6, MAX_ARP_ENTRIES,
    MAX_CONNTRACKS, MAX_GROUPS,
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

type HMARP6 = LruHashMap<[u32; 4usize], ArpEntry>;
/// ARP table for caching destination ip to smac/dmac and derived source ip.
/// The derived source ip is the address used as source when redirecting the
/// the packet.
#[map]
static mut ZLB_ARP6: HMARP6 = HMARP6::pinned(MAX_ARP_ENTRIES, 0);

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
    let (src_port, dst_port, check) = match next_hdr {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest, (*tcphdr).check) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*udphdr).source, (*udphdr).dest, (*udphdr).check) }
        }
        IpProto::Ipv6Icmp => {
            let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4hdr_offset)?;
            unsafe { (0, 0, (*icmphdr).checksum) }
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
        _ => (0, 0, 0),
    };

    let feat = Features::new();
    if feat.log_enabled(Level::Info) {
        unsafe {
            // NOTE: Looks like the log macro occupies a lot of stack
            // TBD: maybe remove this log ?
            info!(
                ctx,
                "[i:{}, rx:{}] [p:{}] [{:i}]:{} -> *[{:i}]:{}, flow: {:x}",
                (*ctx.ctx).ingress_ifindex,
                (*ctx.ctx).rx_queue_index,
                (*ipv6hdr).next_hdr as u32,
                src_addr.addr8,
                src_port.to_be(),
                // BUG: depending on current stack usage changing to dst_addr.addr8
                // will generate code that overflows the bpf program 512B stack
                dst_addr.addr8,
                dst_port.to_be(),
                {
                    let flow = &(*ipv6hdr).flow_label;
                    u32::from_be_bytes([0, flow[0], flow[1], flow[2]])
                }
            );
        }
    }

    // === reply ===

    // NOTE: looks like the 512bye stack can be exhausted pretty rapidly
    // for 1pv6 lb due to larger structs. One way to avoid the verifier error
    // `combined stack size of 2 calls is 544. Too large` is to:
    // * use temp variables during map searches: e.g. ZLB_CONNTRACK6.get(&NAT6Key {..
    // * use variables inside scopes { .. } so the vars are releases from stack
    // * use per cpu array maps
    // * try remove some log prints

    let nat6 = NAT6Key {
        ip_lb_dst: Inet6U::from(dst_addr),
        ip_be_src: Inet6U::from(src_addr),
        port_be_src: src_port as u32,
        port_lb_dst: dst_port as u32,
        next_hdr: next_hdr as u32,
    };
    if let Some(&nat) = unsafe { ZLB_CONNTRACK6.get(&nat6) } {
        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        if feat.log_enabled(Level::Info) {
            info!(
                ctx,
                "[out] nat, src: {:i}, lb_port: {}",
                unsafe { nat.ip_src.addr8 },
                (nat.port_lb as u16).to_be()
            );
        }

        // Unlikely
        if nat.ip_src == src_addr && src_port == dst_port {
            if feat.log_enabled(Level::Error) {
                error!(
                    ctx,
                    "[out] drop same src {:i}:{}",
                    unsafe { nat.ip_src.addr8 },
                    src_port.to_be()
                );
            }
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }

        return Ok(xdp_action::XDP_PASS);
    }

    // === request ===

    let group = match unsafe {
        ZLB_LB6.get(&EP6 {
            address: dst_addr,
            port: dst_port,
            proto: next_hdr as u16,
        })
    } {
        Some(group) => group,
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

    let be = {
        let index = (inet6_hash16(&src_addr) ^ src_port) % group.becount;
        match unsafe {
            ZLB_BACKENDS.get(&BEKey {
                gid: group.gid,
                index,
            })
        } {
            Some(be) => be,
            None => {
                if feat.log_enabled(Level::Error) {
                    error!(ctx, "[in] gid: {}, no BE at: {}", group.gid, index);
                }

                stats_inc(stats::XDP_PASS);
                stats_inc(stats::LB_ERROR_BAD_BE);

                return Ok(xdp_action::XDP_PASS);
            }
        }
    };

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
    // TBD: BUG: can't copy ipv6 addresses as [u32; 4] directly because aya
    // generates code that the verifier rejects. Maybe the address is not
    // aligned to 8B (see comment from Inet6U) ?
    // NOTE: don't care if 2 ipv6 addresses (16B) are copied because they
    // required to created the key to query the connection tracking map.
    // TBD: NOTE: can't use the same key as above because the verifier will
    // complain about stack size above 512.
    let nat6key = NAT6Key {
        ip_lb_dst: Inet6U::from(lb_addr),
        ip_be_src: Inet6U::from(&be.address),
        port_be_src: be.port as u32,
        port_lb_dst: src_port as u32, // use the source port of the endpoint
        next_hdr: next_hdr as u32,
    };

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[ctrk] fw be: [{:i}]:{}",
            unsafe { nat6key.ip_be_src.addr8 },
            be.port.to_be()
        );
    }

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
        // TODO: use a inet 32-bit hash instead of
        // the 3 comparations or 32B/32B total matching bytes ?
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

    // TODO: reduce hop limit by one on xmit and redirect
    // The IPv6 header does not have a csum field that needs to be
    // recalculated everytime the hop limit is decreased as it happens
    // when the TTL from IPv4 header is reduced by one.

    // TODO: compute TCP or UDP csum
    // TODO: compute ICMPv6 checksum

    let check = unsafe {
        //let to = ptr_at::<[u64; 4usize]>(&ctx, EthHdr::LEN + 8)?.cast_mut();
        let to = (&mut ((*ipv6hdr.cast_mut()).src_addr)) as *mut in6_addr;
        let to = to as *mut [u32; 8usize];
        let from = &nat6key.ip_lb_dst as *const Inet6U as *const [u32; 8usize];
        let mut csum = check as u32;

        // NOTE: optimization: use parallel scan over 8 x 32-bit values:
        // * cache friendly
        // * compute csum and copy address using the same 32-bit to/from values
        // * compute csum and copy `only` if the values at the same index are
        // different; for 16B IPv6 with many zeros this will reduce the csum
        // and copy to minimum.
        // NOTE: looks like loop unroll requires some stack allocation.
        for i in 0..8 {
            if (*to)[i] != (*from)[i] {
                csum = csum_add_u32((*to)[i], csum);
                csum = csum_add_u32(!(*from)[i], csum);
                (*to)[i] = (*from)[i];
            }
        }
        csum
    };

    match next_hdr {
        IpProto::Ipv6Icmp => {
            // NOTE: ICMPv6 header has the same fields as ICMP for IPv4.
            let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4hdr_offset)?.cast_mut();
            unsafe { (*icmphdr).checksum = csum_fold_32_to_16(check) };
        }
        _ => {
            // NOTE: In the absence of an csum in IP header the IPv6 protocol relies
            // on Link and Transport layer for assuring packet integrity. That's
            // why UDP for IPv6 must have a valid csum and for IPv4 is not required.
        }
    }

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

    return redirect_ipv6(ctx, feat, ipv6hdr);
}

fn redirect_ipv6(ctx: &XdpContext, feat: Features, ipv6hdr: *const Ipv6Hdr) -> Result<u32, ()> {
    let dst_ip = unsafe { &(*ipv6hdr).dst_addr.in6_u.u6_addr32 };

    if let Some(&entry) = unsafe { ZLB_ARP6.get(dst_ip) } {
        // NOTE: check expiry before using this entry
        let now = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32;

        if now - entry.expiry < 600 {
            let eth = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();

            // NOTE: look like aya can't convert the '*eth = entry.macs' into
            // a 3 load instructions block that doesn't panic the bpf verifier
            // with 'invalid access to packet'. The same statement when modifying
            // stack data passes the verifier check.
            unsafe {
                (*eth)[0] = entry.macs[0];
                (*eth)[1] = entry.macs[1];
                (*eth)[2] = entry.macs[2];
            };

            let action = redirect_txport(ctx, &feat, entry.ifindex);

            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[redirect] [arp-cache] oif: {} action => {}", entry.ifindex, action
                );
            }

            return Ok(action);
        }
    }

    let fib_param = BpfFibLookUp::new_inet6(
        unsafe { (*ipv6hdr).payload_len.to_be() },
        unsafe { (*ctx.ctx).ingress_ifindex },
        unsafe { (*ipv6hdr).priority() as u32 },
        unsafe { &(*ipv6hdr).src_addr.in6_u.u6_addr32 },
        dst_ip,
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

    if rc == bindings::BPF_FIB_LKUP_RET_SUCCESS as i64 {
        let action = unsafe {
            let eth = ptr_at::<EthHdr>(&ctx, 0)?;
            fib_param.fill_ethdr_macs(eth.cast_mut());
            redirect_txport(ctx, &feat, fib_param.ifindex)
        };

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[redirect] action => {}", action);
        }

        update_arp6(ctx, &feat, fib_param);

        return Ok(action);
    }

    // All other result codes represent a fib loopup fail,
    // even though the packet is eventually XDP_PASS-ed
    stats_inc(stats::FIB_LOOKUP_FAILS);

    if rc == bindings::BPF_FIB_LKUP_RET_BLACKHOLE as i64
        || rc == bindings::BPF_FIB_LKUP_RET_UNREACHABLE as i64
        || rc == bindings::BPF_FIB_LKUP_RET_PROHIBIT as i64
    {
        if feat.log_enabled(Level::Error) {
            error!(ctx, "[redirect] can't fw, fib rc: {}", rc);
        }

        stats_inc(stats::XDP_DROP);
        return Ok(xdp_action::XDP_DROP);
    }

    if feat.log_enabled(Level::Error) && rc < 0 {
        error!(ctx, "[redirect] invalid arg, fib rc: {}", rc);
    }
    if feat.log_enabled(Level::Info) && rc >= 0 {
        // let it pass to the stack to handle it
        info!(ctx, "[redirect] packet not fwd, fib rc: {}", rc);
    }

    stats_inc(stats::XDP_PASS);
    Ok(xdp_action::XDP_PASS)
}

fn update_arp6(ctx: &XdpContext, feat: &Features, fib_param: BpfFibLookUp) {
    let arp = ArpEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src, // not used for now
        // TODO: make the expiry time a runvar
        expiry: unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32,
    };

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_ARP6.insert(&fib_param.dst, &arp, 0) } {
        Ok(()) => {
            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[arp6] insert {:i} -> if:{}, smac: {:mac}, dmac: {:mac}, src: {:i}",
                    unsafe { Inet6U::from(&fib_param.dst).addr8 },
                    fib_param.ifindex,
                    fib_param.src_mac(),
                    fib_param.dest_mac(),
                    unsafe { Inet6U::from(&fib_param.src).addr8 },
                )
            }
        }
        Err(e) => {
            if feat.log_enabled(Level::Error) {
                error!(ctx, "[arp6] fail to insert entry, err:{}", e)
            }
            stats_inc(stats::ARP_ERROR_UPDATE);
        }
    };
}
