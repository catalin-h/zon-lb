use crate::{
    is_unicast_mac, ptr_at, redirect_txport, stats_inc, BpfFibLookUp, Features, L2Context,
    L4Context, ZLB_BACKENDS,
};
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
use ebpf_rshelpers::{csum_add_u32, csum_fold_32_to_16, csum_update_u32};
use network_types::{
    eth::EthHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv6Hdr},
};
use zon_lb_common::{
    stats, ArpEntry, BEGroup, BEKey, EPFlags, FibEntry, Inet6U, NAT6Key, NAT6Value, EP6,
    MAX_ARP_ENTRIES, MAX_CONNTRACKS, MAX_GROUPS,
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

type LHMARP6 = LruHashMap<[u32; 4usize], FibEntry>;
/// Fib used to cache the dest ipv6 to smac/dmac and derived source ip mapping.
/// The derived source ip is the address used as source when redirecting the
/// the packet.
#[map]
static mut ZLB_ARP6: LHMARP6 = LHMARP6::pinned(MAX_ARP_ENTRIES, 0);

type NeighborEntry = ArpEntry;
type LHMND = LruHashMap<[u32; 4usize], NeighborEntry>;
/// The Neighbor table is used to answer to VLAN neighbor discovery requests
/// mostly. For non VLAN traffic the system can handle and update the FIB
/// for LB interested IPs.
#[map]
static mut ZLB_ND: LHMND = LHMND::pinned(MAX_ARP_ENTRIES, 0);

#[inline(always)]
fn inet6_hash32(addr: &[u32; 4usize]) -> u32 {
    let csum = csum_add_u32(addr[0], 0);
    let csum = csum_add_u32(addr[1], csum);
    let csum = csum_add_u32(addr[2], csum);
    csum_add_u32(addr[3], csum)
}

#[inline(always)]
fn inet6_hash16(addr: &[u32; 4usize]) -> u16 {
    csum_fold_32_to_16(inet6_hash32(addr))
}

fn compute_checksum(mut csum: u32, from: &mut [u32; 4usize], to: &[u32; 4usize]) -> u32 {
    // NOTE: optimization: use parallel scan over 4 x 32-bit values:
    // * cache friendly
    // * compute csum and copy address using the same 32-bit to/from values
    // * compute csum and copy `only` if the values at the same index are
    // different; for 16B IPv6 with many zeros this will reduce the csum
    // and copy to minimum.
    // NOTE: looks like loop unroll requires some stack allocation.
    for i in 0..4 {
        if to[i] != from[i] {
            csum = csum_update_u32(from[i], to[i], csum);
            from[i] = to[i];
        }
    }

    csum
}

#[inline(always)]
fn update_ipv6hdr(hdr: &mut Ipv6Hdr, check: u32, src: &Inet6U, dst: &Inet6U) -> u32 {
    // NOTE: optimization: cache friendly parallel scan over 8 x 32-bit values.
    // NOTE: looks like loop unroll requires some stack allocation.
    // NOTE: Don't use this statement to get the mutable reference from ptr as it
    // is going to create a temp value:
    // let hdr = &mut unsafe { *ipv6hdr.cast_mut() };
    // To correctly get the mutable ref place the &mut inside the unsafe {}:
    // let hdr = unsafe { &mut (*ipv6hdr.cast_mut()) };
    let csum = unsafe { compute_checksum(check, &mut hdr.src_addr.in6_u.u6_addr32, &src.addr32) };
    unsafe { compute_checksum(csum, &mut hdr.dst_addr.in6_u.u6_addr32, &dst.addr32) }
}

/// Compute and update the L4 inet checksum while also updating the IPv6 header
/// src/dst addresses and L4 src/dst ports.
///
/// BUG: can't use #[inline(never)] for now because of the bpf_linker
/// NOTE: Support only inet protocols that rely on inet checksum
fn update_inet_csum(
    ctx: &XdpContext,
    ipv6hdr: &mut Ipv6Hdr,
    l4ctx: &L4Context,
    src: &Inet6U,
    dst: &Inet6U,
    port_combo: u32,
) -> Result<(), ()> {
    if l4ctx.check_off == 0 {
        return Ok(());
    }

    let check = ptr_at::<u16>(ctx, l4ctx.check_pkt_off())?.cast_mut();
    let mut csum = unsafe { !(*check) } as u32;

    csum = update_ipv6hdr(ipv6hdr, csum, src, dst);

    // TODO: reduce hop limit by one on xmit and redirect
    // The IPv6 header does not have a csum field that needs to be
    // recalculated every time the hop limit is decreased as it happens
    // when the TTL from IPv4 header is reduced by one.

    // NOTE: to update the ports on TCP and UDP just exploit the fact that
    // both headers start with [src_port:u16][dst_port:u16] and/ just set
    // a single u32 combo value as the begining of the L4 header:
    // port_combo = dst_port << 16 | src_port;
    // NOTE: the destination port remains the same.
    if port_combo != 0 {
        if let Ok(ptr) = ptr_at::<u32>(ctx, l4ctx.offset) {
            csum = csum_update_u32(l4ctx.dst_port << 16 | l4ctx.src_port, port_combo, csum);
            unsafe { *(ptr.cast_mut()) = port_combo };
        }
    }

    // NOTE: In the absence of an csum in IP header the IPv6 protocol relies
    // on Link and Transport layer for assuring packet integrity. That's
    // why UDP for IPv6 must have a valid csum and for IPv4 is not required.

    unsafe { *check = !csum_fold_32_to_16(csum) };

    Ok(())
}

// NOTE: Log some details inside functions in order to avoid
// program rejection from bpf verifier due to stack overflow.
// The AYA logger seems to require a lot of stack variables
// and this prevents other program stack allocations.
// NOTE: Use attribute inline(never) to contain allocations
// inside the function.
#[inline(never)]
fn log_nat6(ctx: &XdpContext, nat: &NAT6Value, feat: &Features) {
    if !feat.log_enabled(Level::Info) {
        return;
    }

    info!(
        ctx,
        "[out] nat, src:{:i}, lb_port: {}",
        unsafe { nat.ip_src.addr8 },
        (nat.port_lb as u16).to_be()
    );
}

// NOTE: It is important to pass args by ref and not as
// pointers in order to contain the aya log stack allocations
// inside the function. For eg. passing the Ipv6Hdr as pointer
// will prevent the function from containing aya allocations.
#[inline(never)]
fn log_ipv6_packet(ctx: &XdpContext, feat: &Features, ipv6hdr: &Ipv6Hdr) {
    if !feat.log_enabled(Level::Info) {
        return;
    }

    // NOTE: Looks like the log macro occupies a lot of stack
    // TBD: maybe remove this log ?
    info!(
        ctx,
        "[i:{}, rx:{}] [p:{}] {:i} -> {:i}, flow: {:x}",
        unsafe { (*ctx.ctx).ingress_ifindex },
        unsafe { (*ctx.ctx).rx_queue_index },
        ipv6hdr.next_hdr as u32,
        unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
        // BUG: depending on current stack usage changing to dst_addr.addr8
        // will generate code that overflows the bpf program 512B stack
        unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 },
        {
            let flow = ipv6hdr.flow_label;
            u32::from_be_bytes([0, flow[0], flow[1], flow[2]])
        }
    );
}

pub mod icmpv6 {
    pub const ECHO_REQUEST: u8 = 128_u8;
    pub const ECHO_REPLY: u8 = 129_u8;
    pub const ND_SOLICIT: u8 = 135_u8;
    pub const ND_ADVERT: u8 = 136_u8;
}

/// The source/target link-layer address option
/// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type      |    Length     |    Link-Layer Address ...
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[repr(C)]
#[derive(Clone, Copy)]
struct Icmpv6LLAddrOption {
    /// It is set to 1 for NDS and 2 for NDA
    otype: u8,
    /// Set to 1 both NDS and NDA representing the number of 8 bytes
    /// in this option including the option type and length.
    len: u8,
    /// On NDS it is set to the source mac address and on NDR to the
    /// requested target mac address.
    mac: [u8; 6],
}

impl Icmpv6LLAddrOption {
    fn as_array(&self) -> &[u32; 2] {
        unsafe { &*(self as *const Icmpv6LLAddrOption as *const [u32; 2]) }
    }
}

/// The neighbor discovery header for handling icmpv6 types:
/// - 135 neighbor solicitation request (NDS)
/// - 136 neighbor advertisement reply (NDA)
#[repr(C)]
pub struct Icmpv6NdHdr {
    type_: u8,
    code: u8,
    check: u16,
    /// Used only for NDA
    flags: u32,
    /// Both NDS and NDA set this field to the target IPv6 address
    tgt_addr: Inet6U,
    /// It is set to 1 for NDS and 2 for NDA
    option_type: u8,
    /// Set to 1 both NDS and NDA representing the number of 8 bytes
    /// in this option including the option type and length.
    len: u8,
    /// On NDS it is set to the source mac address and on NDR to the
    /// requested target mac address.
    mac: [u8; 6],
}

/// Update the neighbour entry for source IPv6 address
/// BUG: the bpf_linker need this inline(always) in order to avoid link errors
/// or to increase the stack size over 512.
#[inline(always)]
fn update_neighbors_cache(
    ctx: &XdpContext,
    ip: &[u32; 4usize],
    vlan_id: u32,
    mac: &[u8; 6],
    eth: &EthHdr,
) {
    // NOTE: This won't work in promiscuous mode
    let if_mac = if is_unicast_mac(&eth.dst_addr) {
        eth.dst_addr
    } else {
        match unsafe { ZLB_ND.get(&ip) } {
            None => [0_u8; 6],
            Some(entry) => entry.if_mac,
        }
    };

    // Set the expiry to 2 min but it can be used as last resort
    let expiry = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32 + 120;
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let ndentry = NeighborEntry {
        ifindex,
        mac: *mac,
        if_mac,
        expiry,
        vlan_id,
    };

    // BUG: looks like using Result objects confuses the bpf_linker
    // if it is used in a match statement after later.
    let rc = match unsafe { ZLB_ND.insert(&ip, &ndentry, 0) } {
        Ok(()) => 0,
        Err(e) => e,
    };

    let feat = Features::new();
    if !feat.log_enabled(Level::Info) {
        return;
    }

    match rc {
        0 => info!(
            ctx,
            "[nd] added if: {} [{:i}] => {:mac} ",
            ifindex,
            unsafe { Inet6U::from(ip).addr8 },
            *mac,
        ),
        _ => {
            if feat.log_enabled(Level::Error) {
                error!(
                    ctx,
                    "[nd] not added if:{} [{:i}] => {:mac}, err={}",
                    ifindex,
                    unsafe { Inet6U::from(ip).addr8 },
                    *mac,
                    rc
                )
            }
        }
    }
}

fn neighbor_solicit(ctx: &XdpContext, l2ctx: L2Context, l4ctx: L4Context) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth = unsafe { &mut *eth.cast_mut() };
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &mut *ipv6hdr.cast_mut() };
    let ndhdr = ptr_at::<Icmpv6NdHdr>(&ctx, l4ctx.offset)?;
    let ndhdr = unsafe { &mut *ndhdr.cast_mut() };
    let feat = Features::new();

    if !is_unicast_mac(&ndhdr.mac) || ndhdr.option_type == 0 || ndhdr.option_type > 2 {
        return Ok(xdp_action::XDP_PASS);
    }

    if feat.log_enabled(Level::Info) {
        let opt = if ndhdr.option_type == 1 {
            "sol-req"
        } else {
            "adver-reply"
        };
        info!(
            ctx,
            "[nd] {} if:{} src:[{:i}]/{:mac}/vlan={} for target [{:i}]",
            opt,
            ifindex,
            unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
            eth.src_addr,
            (l2ctx.vlan_id() as u16).to_be(),
            unsafe { ndhdr.tgt_addr.addr8 }
        );
    }

    // If this is a ND advertisement
    if ndhdr.option_type == 2 {
        update_neighbors_cache(
            ctx,
            unsafe { &ndhdr.tgt_addr.addr32 },
            l2ctx.vlan_id(),
            &ndhdr.mac,
            eth,
        );

        return Ok(xdp_action::XDP_PASS);
    }

    // If this is a ND request
    update_neighbors_cache(
        ctx,
        unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 },
        l2ctx.vlan_id(),
        &ndhdr.mac,
        eth,
    );

    Ok(xdp_action::XDP_PASS)
}

pub fn ipv6_lb(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &mut *ipv6hdr.cast_mut() };
    let src_addr = unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 };
    let dst_addr = unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 };

    // NOTE: IPv6 header isn't fixed and the L4 header offset can
    // be computed iterating over the extension headers until we
    // reach a non-extension next_hdr value. For now we assume
    // there are no extensions or fragments.
    // TODO: For IPv6 there can be only 6 linked header types: Hop-by-Hop Options,
    // Fragment, Destination Options, Routing, Authentication and Encapsulating
    // Security Payload. I makes sense to make make 6 calls until reaching a
    // next header we can handle.
    let l4ctx = L4Context::new_with_offset(ctx, Ipv6Hdr::LEN + l2ctx.ethlen, ipv6hdr.next_hdr)?;

    let icmp_type = if ipv6hdr.next_hdr == IpProto::Ipv6Icmp {
        let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4ctx.offset)?;
        let icmp_type = unsafe { (*icmphdr).type_ };
        match icmp_type {
            icmpv6::ND_ADVERT | icmpv6::ND_SOLICIT => return neighbor_solicit(ctx, l2ctx, l4ctx),
            icmpv6::ECHO_REPLY | icmpv6::ECHO_REQUEST => { /* Handle bellow */ }
            _ => return Ok(xdp_action::XDP_PASS),
        }
        icmp_type
    } else {
        0_u8
    };

    let feat = Features::new();
    log_ipv6_packet(ctx, &feat, ipv6hdr);

    // === reply ===

    // NOTE: looks like the 512bye stack can be exhausted pretty rapidly
    // for 1pv6 lb due to larger structs. One way to avoid the verifier error
    // `combined stack size of 2 calls is 544. Too large` is to:
    // * use temp variables during map searches: e.g. ZLB_CONNTRACK6.get(&NAT6Key {..
    // * use variables inside scopes { .. } so the vars are releases from stack
    // * use per cpu array maps
    // * try remove some log prints

    if let Some(&nat) = unsafe {
        ZLB_CONNTRACK6.get(&NAT6Key {
            ip_lb_dst: Inet6U::from(dst_addr),
            ip_be_src: Inet6U::from(src_addr),
            port_be_src: l4ctx.src_port,
            port_lb_dst: l4ctx.dst_port,
            next_hdr: ipv6hdr.next_hdr as u32,
        })
    } {
        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        // Unlikely
        if nat.ip_src.eq32(src_addr) && l4ctx.src_port == l4ctx.dst_port {
            if feat.log_enabled(Level::Error) {
                error!(
                    ctx,
                    "[out] drop same src {:i}:{}",
                    unsafe { nat.ip_src.addr8 },
                    (l4ctx.src_port as u16).to_be()
                );
            }
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }

        log_nat6(ctx, &nat, &feat);

        // TBD: for crc32 use crc32_off

        update_inet_csum(
            ctx,
            ipv6hdr,
            &l4ctx,
            &nat.lb_ip,
            &nat.ip_src,
            l4ctx.dst_port << 16 | nat.port_lb,
        )?;

        let action = if nat.flags.contains(EPFlags::XDP_REDIRECT) {
            let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
            unsafe { *macs = nat.mac_addresses };

            let ret = redirect_txport(ctx, &feat, nat.ifindex);

            if nat.flags.contains(EPFlags::XDP_TX) && ret == xdp_action::XDP_REDIRECT {
                stats_inc(stats::XDP_REDIRECT_FULL_NAT);
            }

            ret as xdp_action::Type
        } else if nat.flags.contains(EPFlags::XDP_TX) {
            stats_inc(stats::XDP_TX);
            xdp_action::XDP_TX
        } else {
            stats_inc(stats::XDP_PASS);
            xdp_action::XDP_PASS
        };

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[out] action: {}", action);
        }

        return Ok(action);
    }

    // === request ===

    // Don't track echo replies as there can be a response from the actual source.
    // To avoid messing with the packet routing allow tracking only ICMP requests.
    if ipv6hdr.next_hdr == IpProto::Ipv6Icmp && icmp_type == icmpv6::ECHO_REPLY {
        return Ok(xdp_action::XDP_PASS);
    }

    let group = match unsafe {
        ZLB_LB6.get(&EP6 {
            address: Inet6U::from(dst_addr),
            port: l4ctx.dst_port as u16,
            proto: ipv6hdr.next_hdr as u16,
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
        let index = (inet6_hash16(&src_addr) ^ l4ctx.src_port as u16) % group.becount;
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

    // TBD: need to check BE.src_ip == 0 ?
    let lb_addr = if redirect && be.flags.contains(EPFlags::XDP_TX) && be.src_ip[0] != 0 {
        // TODO: check the arp table and update or insert
        // smac/dmac and derived ip src and redirect ifindex
        &be.src_ip
    } else {
        dst_addr
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
        port_lb_dst: l4ctx.src_port, // use the source port of the endpoint
        next_hdr: ipv6hdr.next_hdr as u32,
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
        nat.ifindex != if_index || !nat.ip_src.eq32(src_addr) || nat.mac_addresses != mac_addresses
    } else {
        true
    };

    if do_insert {
        // TODO: use as temp value at insert point
        let nat6value = NAT6Value {
            ip_src: Inet6U::from(src_addr),
            port_lb: l4ctx.dst_port,
            ifindex: if_index,
            mac_addresses,
            flags: be.flags,
            lb_ip: Inet6U::from(dst_addr), // save the original LB IP
        };

        // TBD: use lock or atomic update ?
        // TBD: use BPF_F_LOCK ?
        match unsafe { ZLB_CONNTRACK6.insert(&nat6key, &nat6value, 0) } {
            Ok(()) => {
                if feat.log_enabled(Level::Info) {
                    info!(
                        ctx,
                        "[ctrk] [{:i}]:{} added",
                        unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
                        (l4ctx.src_port as u16).to_be(),
                    )
                }
            }
            Err(ret) => {
                if feat.log_enabled(Level::Error) {
                    error!(
                        ctx,
                        "[ctrk] [{:i}]:{} not added, err: {}",
                        unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
                        (l4ctx.src_port as u16).to_be(),
                        ret
                    )
                }
                stats_inc(stats::CT_ERROR_UPDATE);
            }
        };
    }

    update_inet_csum(
        ctx,
        ipv6hdr,
        &l4ctx,
        &nat6key.ip_lb_dst,
        &nat6key.ip_be_src,
        (be.port as u32) << 16 | l4ctx.src_port,
    )?;

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

fn redirect_ipv6(ctx: &XdpContext, feat: Features, ipv6hdr: &Ipv6Hdr) -> Result<u32, ()> {
    if let Some(&entry) = unsafe { ZLB_ARP6.get(&ipv6hdr.dst_addr.in6_u.u6_addr32) } {
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
        ipv6hdr.payload_len.to_be(),
        unsafe { (*ctx.ctx).ingress_ifindex },
        ipv6hdr.priority() as u32,
        unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 },
        unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 },
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
    let arp = FibEntry {
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
