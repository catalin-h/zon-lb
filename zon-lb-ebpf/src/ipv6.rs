use crate::{
    is_unicast_mac, ptr_at, redirect_txport, stats_inc, BpfFibLookUp, CTCache, Features, L2Context,
    L4Context, AF_INET6, ZLB_BACKENDS,
};
use aya_ebpf::{
    bindings::{self, bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_F_NO_COMMON_LRU},
    helpers::{bpf_check_mtu, bpf_fib_lookup, bpf_ktime_get_coarse_ns, bpf_xdp_adjust_tail},
    macros::map,
    maps::{HashMap, LruHashMap, LruPerCpuHashMap, PerCpuArray},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, Level};
use core::mem::{self, offset_of};
use ebpf_rshelpers::{csum_add_u32, csum_fold_32_to_16, csum_update_u32};
use network_types::{
    eth::EthHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    stats, ArpEntry, BEGroup, BEKey, EPFlags, FibEntry, Inet6U, Ipv6FragId, Ipv6FragInfo, NAT6Key,
    NAT6Value, EP6, FIB_ENTRY_EXPIRY_INTERVAL, MAX_ARP_ENTRIES, MAX_CONNTRACKS, MAX_FRAG6_ENTRIES,
    MAX_GROUPS, NEIGH_ENTRY_EXPIRY_INTERVAL,
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

type LHMFIB6 = LruHashMap<[u32; 4usize], FibEntry>;
/// Fib used to cache the dest ipv6 to smac/dmac and derived source ip mapping.
/// The derived source ip is the address used as source when redirecting the
/// the packet.
#[map]
static mut ZLB_FIB6: LHMFIB6 = LHMFIB6::pinned(MAX_ARP_ENTRIES, 0);

type NeighborEntry = ArpEntry;
type LHMND = LruHashMap<[u32; 4usize], NeighborEntry>;
/// The Neighbor table is used to answer to VLAN neighbor discovery requests
/// mostly. For non VLAN traffic the system can handle and update the FIB
/// for LB interested IPs.
#[map]
static mut ZLB_ND: LHMND = LHMND::pinned(MAX_ARP_ENTRIES, 0);

/// The Ipv6 Fragment cache used to save the transport info from
/// first IP packer fragment.
type FRAG6LHM = LruHashMap<Ipv6FragId, Ipv6FragInfo>;

#[map]
static mut ZLB_FRAG6: FRAG6LHM = FRAG6LHM::pinned(MAX_FRAG6_ENTRIES, 0);

pub fn coarse_ktime() -> u32 {
    (unsafe { bpf_ktime_get_coarse_ns() } / 1_000_000_000) as u32
}

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
    // BUG: bpf_linker: can't make unroll loop without the if statement
    for i in (0..4).rev() {
        if to[i] != from[i] {
            csum = csum_update_u32(from[i], to[i], csum);
            from[i] = to[i];
        }
    }

    csum
}

/// Compute and update the L4 inet checksum while also updating the IPv6 header
/// src/dst addresses and L4 src/dst ports.
///
/// BUG: can't use #[inline(never)] for now because of the bpf_linker
/// NOTE: Support only inet protocols that rely on inet checksum
/// TODO: make this a macro_rule
/// TODO: pass &[u32;4] instead of Inet6U
/// BUG: NOTE: bpf_linker will throw an error when passing mutable ipv6hdr and
/// also passing imutable ref to src/dst from ipv6hdr. Must split the two cases
/// in order to properly link the code.
fn update_inet_csum(
    ctx: &XdpContext,
    ipv6hdr: &mut Ipv6Hdr,
    l4ctx: &L4Context,
    src: &[u32; 4usize],
    dst: &[u32; 4usize],
    port_combo: u32,
) -> Result<(), ()> {
    // TODO: move this to the place of usage as this function can't be inlined
    if l4ctx.check_off == 0 {
        (*ipv6hdr).src_addr.in6_u.u6_addr32 = *src;
        (*ipv6hdr).dst_addr.in6_u.u6_addr32 = *dst;
        return Ok(());
    }

    let check = ptr_at::<u16>(ctx, l4ctx.check_pkt_off())?.cast_mut();
    let mut csum = unsafe { !(*check) } as u32;

    // NOTE: optimization: cache friendly parallel scan over 8 x 32-bit values.
    // NOTE: looks like loop unroll requires some stack allocation.
    // NOTE: Don't use this statement to get the mutable reference from ptr as it
    // is going to create a temp value:
    // let hdr = &mut unsafe { *ipv6hdr.cast_mut() };
    // To correctly get the mutable ref place the &mut inside the unsafe {}:
    // let hdr = unsafe { &mut (*ipv6hdr.cast_mut()) };
    let from = unsafe { &mut ipv6hdr.src_addr.in6_u.u6_addr32 };
    csum = compute_checksum(csum, from, src);
    let from = unsafe { &mut ipv6hdr.dst_addr.in6_u.u6_addr32 };
    csum = compute_checksum(csum, from, dst);

    // TODO: reduce hop limit by one on xmit and redirect
    // The IPv6 header does not have a csum field that needs to be
    // recalculated every time the hop limit is decreased as it happens
    // when the TTL from IPv4 header is reduced by one.

    // NOTE: to update the ports on TCP and UDP just exploit the fact that
    // both headers start with [src_port:u16][dst_port:u16] and/ just set
    // a single u32 combo value as the begining of the L4 header:
    // port_combo = dst_port << 16 | src_port;
    // NOTE: the destination port remains the same.
    if port_combo != 0 && l4ctx.next_hdr != IpProto::Ipv6Icmp {
        csum = csum_update_u32(l4ctx.dst_port << 16 | l4ctx.src_port, port_combo, csum);
        let ptr = ptr_at::<u32>(ctx, l4ctx.offset)?;
        unsafe { *(ptr.cast_mut()) = port_combo };
    }

    // NOTE: In the absence of an csum in IP header the IPv6 protocol relies
    // on Link and Transport layer for assuring packet integrity. That's
    // why UDP for IPv6 must have a valid csum and for IPv4 is not required.

    unsafe { *check = !csum_fold_32_to_16(csum) };

    Ok(())
}

fn update_destination_inet_csum(
    ctx: &XdpContext,
    ipv6hdr: &mut Ipv6Hdr,
    l4ctx: &L4Context,
    dst: &[u32; 4usize],
    port_combo: u32,
) -> Result<(), ()> {
    // TODO: move this to the place of usage as this function can't be inlined
    if l4ctx.check_off == 0 {
        (*ipv6hdr).src_addr.in6_u.u6_addr32 = unsafe { (*ipv6hdr).dst_addr.in6_u.u6_addr32 };
        (*ipv6hdr).dst_addr.in6_u.u6_addr32 = *dst;
        return Ok(());
    }

    let check = ptr_at::<u16>(ctx, l4ctx.check_pkt_off())?.cast_mut();
    let mut csum = unsafe { !(*check) } as u32;

    let from = unsafe { &mut ipv6hdr.src_addr.in6_u.u6_addr32 };

    for i in (0..4).rev() {
        if dst[i] != from[i] {
            csum = csum_update_u32(from[i], dst[i], csum);
        }
    }

    // TODO: reduce hop limit by one on xmit and redirect
    // The IPv6 header does not have a csum field that needs to be
    // recalculated every time the hop limit is decreased as it happens
    // when the TTL from IPv4 header is reduced by one.

    if port_combo != 0 && l4ctx.next_hdr != IpProto::Ipv6Icmp {
        csum = csum_update_u32(l4ctx.dst_port << 16 | l4ctx.src_port, port_combo, csum);
        let ptr = ptr_at::<u32>(ctx, l4ctx.offset)?;
        unsafe { *(ptr.cast_mut()) = port_combo };
    }

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

#[inline(never)]
fn log_fragexthdr(ctx: &XdpContext, exthdr: &Ipv6FragExtHdr, feat: &Features) {
    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "pkt frag id: 0x{:x} off:M {}:{}",
            exthdr.id,
            exthdr.offset(),
            exthdr.more()
        );
    }
}

// NOTE: It is important to pass args by ref and not as
// pointers in order to contain the aya log stack allocations
// inside the function. For eg. passing the Ipv6Hdr as pointer
// will prevent the function from containing aya allocations.
#[inline(never)]
fn log_ipv6_packet(ctx: &XdpContext, ipv6hdr: &Ipv6Hdr, l4ctx: &L4Context) {
    // NOTE: Looks like the log macro occupies a lot of stack
    // TBD: maybe remove this log ?
    info!(
        ctx,
        "[i:{}, rx:{}] [p:{}] [{:i}]:{} -> [{:i}]:{}, flow: {:x}",
        unsafe { (*ctx.ctx).ingress_ifindex },
        unsafe { (*ctx.ctx).rx_queue_index },
        ipv6hdr.next_hdr as u32,
        unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
        (l4ctx.src_port as u16).to_be(),
        // BUG: depending on current stack usage changing to dst_addr.addr8
        // will generate code that overflows the bpf program 512B stack
        unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 },
        (l4ctx.dst_port as u16).to_be(),
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
#[repr(C, packed(4))]
struct Icmpv6NdHdr {
    type_: u8,
    code: u8,
    check: u16,
    /// Used only for NDA
    flags: u32,
    /// Both NDS and NDA set this field to the target IPv6 address
    tgt_addr: Inet6U,
    /// The source/target link-layer address option
    lladopt: Icmpv6LLAddrOption,
}

pub fn check_mtu(ctx: &XdpContext, ifindex: u32) -> u16 {
    let mut mtu = 1280_u32;
    let _ = unsafe { bpf_check_mtu(ctx.as_ptr(), ifindex, &mut mtu, 0, 0) };

    return mtu as u16;
}

/// Update the neighbour entry for source IPv6 address
/// BUG: FIXED: the bpf_linker need this inline(always) in order to avoid link errors
/// or to increase the stack size over 512.
fn update_neighbors_cache(
    ctx: &XdpContext,
    ip: &[u32; 4usize],
    vlan_id: u16,
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
    let expiry = coarse_ktime() + NEIGH_ENTRY_EXPIRY_INTERVAL;
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let mtu = check_mtu(ctx, ifindex);
    let ndentry = NeighborEntry {
        ifindex,
        mac: *mac,
        if_mac,
        expiry,
        vlan_id,
        mtu,
    };

    // BUG: looks like using Result objects confuses the bpf_linker
    // if it is used in a match statement after later.
    let rc = match unsafe { ZLB_ND.insert(&ip, &ndentry, 0) } {
        Ok(()) => 0,
        Err(e) => e,
    };

    if !Features::new().log_enabled(Level::Info) {
        return;
    }

    let pinet6u = ip as *const _ as *const Inet6U;
    info!(
        ctx,
        "[nd] update if:{} [{:i}] => {:mac}, vlan:{}, mtu:{}, rc={}",
        ifindex,
        unsafe { (*pinet6u).addr8 },
        *mac,
        vlan_id,
        mtu,
        rc
    );
}

fn neighbor_solicit(ctx: &XdpContext, l2ctx: L2Context, l4ctx: L4Context) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth = unsafe { &mut *eth.cast_mut() };
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &mut *ipv6hdr.cast_mut() };
    let ndhdr = ptr_at::<Icmpv6NdHdr>(&ctx, l4ctx.offset)?;
    let ndhdr = unsafe { &mut *ndhdr.cast_mut() };
    let feat = Features::new();
    let log_on = feat.log_enabled(Level::Info);
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let llao = ndhdr.lladopt;

    if !is_unicast_mac(&llao.mac) || llao.otype == 0 || llao.otype > 2 {
        return Ok(xdp_action::XDP_PASS);
    }

    if log_on {
        let opt = if llao.otype == 1 {
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

    // If this is a ND solicitation request
    update_neighbors_cache(
        ctx,
        unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 },
        l2ctx.vlan_id(),
        &llao.mac,
        eth,
    );

    // If this is a ND advertisement
    if llao.otype == 2 {
        update_neighbors_cache(
            ctx,
            unsafe { &ndhdr.tgt_addr.addr32 },
            l2ctx.vlan_id(),
            &llao.mac,
            eth,
        );

        update_neighbors_cache(
            ctx,
            unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 },
            l2ctx.vlan_id(),
            &eth.dst_addr,
            eth,
        );

        return Ok(xdp_action::XDP_PASS);
    }

    // For VLANs answer to requests as this LB can act as a proxy for
    // the endpoints inside VLANs. Without special routing rules the
    // Icmpv6 ND requests are not ignored as they pertain to a different
    // network segment.

    if !l2ctx.has_vlan() || !is_unicast_mac(&eth.src_addr) {
        if log_on {
            info!(ctx, "[nd] no vlan for [{:i}]", unsafe {
                ndhdr.tgt_addr.addr8
            });
        }
        return Ok(xdp_action::XDP_PASS);
    }

    let smac = match unsafe { ZLB_ND.get(&ndhdr.tgt_addr.addr32) } {
        None => {
            if log_on {
                info!(ctx, "[nd] no entry for [{:i}]", unsafe {
                    ndhdr.tgt_addr.addr8
                });
            }
            return Ok(xdp_action::XDP_PASS);
        }
        Some(entry) => {
            // NOTE: most likely the entry.vlan_id would be 0 since it shouldn't be
            // assigned in no VLAN
            if entry.ifindex == ifindex && (l2ctx.vlan_id() == entry.vlan_id || entry.vlan_id == 0)
            {
                if is_unicast_mac(&entry.if_mac) {
                    entry.if_mac
                } else {
                    entry.mac
                }
            } else {
                if log_on {
                    if entry.ifindex != ifindex {
                        info!(
                            ctx,
                            "[nd] if diff: {}!={} for [{:i}]",
                            ifindex,
                            entry.ifindex,
                            unsafe { ndhdr.tgt_addr.addr8 }
                        );
                    } else {
                        info!(
                            ctx,
                            "[nd] vlan id diff: {}!={}, for [{:i}]",
                            l2ctx.vlan_id(),
                            entry.vlan_id,
                            unsafe { ndhdr.tgt_addr.addr8 }
                        );
                    }
                }
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };

    // NOTE: destination is always the B-CAST address
    // BUG: due to aligment constraints can't copy the llao.mac array directly
    for i in 0..6 {
        eth.dst_addr[i] = llao.mac[i];
    }
    eth.src_addr = smac;

    // Compute the IcmpV6 checksum first and update the header
    let mut check = !ndhdr.check as u32;

    check = csum_update_u32(icmpv6::ND_SOLICIT as u32, icmpv6::ND_ADVERT as u32, check);
    ndhdr.type_ = icmpv6::ND_ADVERT;

    // For solicited nd advertisement must set the flags:
    // * Override: to override an existing cache entry)
    // * Solicited: to denote that this is a response to a neighbor solicitation
    // TODO: don't set it for multicast source addresses
    // * TBD: Router: indicates this is a router
    // See: https://datatracker.ietf.org/doc/html/rfc4861#section-4.4
    //  0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // |R|S|O|                     Reserved                            |
    let flags = 0x60_00_00_00_u32.to_be();
    check = csum_update_u32(ndhdr.flags, flags, check);
    ndhdr.flags = flags;

    // Update the option for mark this is the target link-layer address
    ndhdr.lladopt.otype = 2;
    ndhdr.lladopt.len = 1;
    ndhdr.lladopt.mac = smac;

    let from = llao.as_array();
    let to = ndhdr.lladopt.as_array();
    check = csum_update_u32(from[0], to[0], check);
    check = csum_update_u32(from[1], to[1], check);

    check = compute_checksum(
        check,
        unsafe { &mut ipv6hdr.dst_addr.in6_u.u6_addr32 },
        unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 },
    );

    check = compute_checksum(
        check,
        unsafe { &mut ipv6hdr.src_addr.in6_u.u6_addr32 },
        unsafe { &ndhdr.tgt_addr.addr32 },
    );

    ndhdr.check = !csum_fold_32_to_16(check);

    if log_on {
        info!(
            ctx,
            "[eth] [tx] if:{} vlan_id:{} {:mac} -> {:mac}",
            ifindex,
            (l2ctx.vlan_id() as u16).to_be(),
            eth.src_addr,
            eth.dst_addr,
        );

        info!(
            ctx,
            "[nd] [tx] advert-reply [{:i}] -> {:mac} to [{:i}]",
            unsafe { ndhdr.tgt_addr.addr8 },
            smac,
            unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 }
        );
    }

    stats_inc(stats::ICMPV6_ND_SOL_ADVERT);

    Ok(xdp_action::XDP_TX)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv6ExtBase {
    next_header: IpProto,
    len_8b: u8,
}

/// Fragment extention header:
///
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                         Identification                        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
/// * Fragment Offset : 13-bit unsigned integer.  The offset, in
/// 8-octet units, of the data following this header, relative
/// to the start of the Fragmentable Part of the original packet.
/// * Identification  : For every packet that is to be fragmented,
/// the source node generates an Identification value.
/// * M flag         : 1 = more fragments; 0 = last fragment.
///
/// See RFC8200.
#[repr(C)]
#[derive(Clone, Copy)]
struct Ipv6FragExtHdr {
    base: Ipv6ExtBase,
    /// Compact both offset and More flag
    offset_m: u16,
    id: u32,
}

impl Ipv6FragExtHdr {
    fn offset(&self) -> u16 {
        self.offset_m.swap_bytes() & 0xfff8
    }

    fn more(&self) -> u16 {
        (self.offset_m >> 8) & 0x1
    }
}

fn cache_frag_info(fragid: &Ipv6FragId, l4ctx: &L4Context) {
    match unsafe {
        ZLB_FRAG6.insert(
            &fragid,
            &Ipv6FragInfo {
                src_port: l4ctx.src_port as u16,
                dst_port: l4ctx.dst_port as u16,
                reserved: 0,
            },
            0,
        )
    } {
        Ok(()) => {}
        Err(_) => {
            stats_inc(stats::IPV6_FRAGMENT_ERRORS);
        }
    };

    // BUG: aya compiler generates code that exeeds the stack size:
    // 'the BPF_PROG_LOAD syscall failed. Verifier output: combined
    // stack size of 3 calls is 544. Too large'
    // Calling the same log function outside works.
    // info!(ctx, "fino");
}

impl L4Context {
    fn new_for_ipv6(l2ctx: &L2Context, next_hdr: IpProto) -> Self {
        Self {
            offset: l2ctx.ethlen + Ipv6Hdr::LEN,
            check_off: 0,
            src_port: 0,
            dst_port: 0,
            flags: 0,
            next_hdr,
        }
    }
}

#[map]
static ZLB_CT6_CACHE: LruPerCpuHashMap<NAT6Key, CTCache> =
    LruPerCpuHashMap::with_max_entries(256, BPF_F_NO_COMMON_LRU);

fn ct6_handler(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    l4ctx: &L4Context,
    ipv6hdr: &mut Ipv6Hdr,
    ctnat: &CTCache,
    feat: &Features,
) -> Result<u32, ()> {
    if ipv6hdr.payload_len.to_be() > ctnat.mtu as u16 {
        return send_ptb(ctx, &l2ctx, ipv6hdr, ctnat.mtu);
    }

    stats_inc(stats::PACKETS);

    // NOTE: No need to save fragment because this handler is called
    // after the main flows (request & response) caches this conntrack
    // cache handler.

    if !ctnat.flags.contains(EPFlags::DSR_L2) {
        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL
        update_inet_csum(
            ctx,
            ipv6hdr,
            l4ctx,
            &ctnat.src_addr,
            &ctnat.dst_addr,
            ctnat.port_combo,
        )?;
    }

    if ctnat.flags.contains(EPFlags::XDP_REDIRECT) {
        let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
        let macs = unsafe { &mut *macs };
        array_copy(macs, &ctnat.macs);

        // NOTE: This call can shrink or enlarge the packet so all pointers
        // to headers are invalidated.
        l2ctx.vlan_update(ctx, 0, &feat)?;

        // In case of redirect failure just try to query the FIB again
        let action = redirect_txport(ctx, &feat, ctnat.ifindex);

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[c-redirect] oif:{}, action={}", ctnat.ifindex, action);
        }

        return Ok(action);
    }

    // Send back the packet to the same interface
    if ctnat.flags.contains(EPFlags::XDP_TX) {
        // TODO: swap mac addresses

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

// In order to avoid exhausting the 512B ebpf program stack by allocating
// diferent large objects (especially for IPv6 path) one common workaround
// is to use a per cpu (avoids concurrency) struct that contains all the
// objects that can be created on any program execution path.
#[repr(C)]
struct Context6 {
    feat: Features,
    nat6key: NAT6Key,
    nat6val: NAT6Value,
    ctnat: CTCache,
    fiblookup: BpfFibLookUp,
    fibentry: FibEntry,
    fragid: Ipv6FragId,
    ptbprotohdr: ProtoHdr,
}

#[map]
static mut ZLB_CONTEXT6: PerCpuArray<Context6> = PerCpuArray::with_max_entries(1, 0);

fn array_copy<T: Clone + Copy, const N: usize>(to: &mut [T; N], from: &[T; N]) {
    for i in 0..N {
        to[i] = from[i];
    }
}

// NOTE: IPv6 header isn't fixed and the L4 header offset can
// be computed iterating over the extension headers until we
// reach a non-extension next_hdr value. For now we assume
// there are no extensions or fragments.
// TODO: For IPv6 there can be up to 7 linked header types: Hop-by-Hop Options (0),
// Routing (43), Fragment(44), Encapsulating Security Payload (50), Authentication
// Header (51), Destination Options (can appear twice, 60).
// It makes sense to make make 6 calls until reaching a next header we can handle.
// NOTE: Value 59 (No Next Header) in the Next Header field indicates that
// there is no next header whatsoever following this one, not even a header
// of an upper-layer protocol. It means that, from the header's point of view,
// the IPv6 packet ends right after it: the payload should be empty.
// NOTE: All IPv6 extension headers except for 50 and 51 have the format:
// 0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |    Length     |    Options and padding ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// where Length represents size of both the header and options in 8-bytes units.
// NOTE: that extention headers 50 and 51 are not per-fragment headers and always
// are placed _after_ fragment header which is placed last in the per-fragment header
// list:
// +------------------+-------------------------+---//----------------+
// |  Per-Fragment    | Extension & Upper-Layer |   Fragmentable      |
// |    Headers       |       Headers           |      Part           |
// +------------------+-------------------------+---//----------------+
// The Per-Fragment headers must consist of the IPv6 header plus any
// extension headers that must be processed by nodes en route to the
// destination, that is, all headers up to and including the Routing
// header if present, else the Hop-by-Hop Options header if present,
// else no extension headers.
// In other words the headers that needs to pe processed are these in this order:
// IPv6 header, Hop-by-Hop, Destination Options, Routing and Fragment.
pub fn ipv6_lb(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &mut *ipv6hdr.cast_mut() };
    let src_addr = unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 };
    let dst_addr = unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 };
    let ctx6 = unsafe {
        let ptr = ZLB_CONTEXT6.get_ptr_mut(0).ok_or(())?;
        &mut *ptr
    };
    ctx6.feat.fetch();
    let mut l4ctx = L4Context::new_for_ipv6(&l2ctx, ipv6hdr.next_hdr);
    let feat = &ctx6.feat;
    let mut cache_fragment = false;

    for _ in 0..4 {
        match l4ctx.next_hdr {
            IpProto::Tcp => {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, l4ctx.offset)?;
                l4ctx.check_offset(offset_of!(TcpHdr, check));
                l4ctx.sport(unsafe { (*tcphdr).source });
                l4ctx.dport(unsafe { (*tcphdr).dest });
                break;
            }
            IpProto::Udp => {
                let udphdr = ptr_at::<UdpHdr>(&ctx, l4ctx.offset)?;
                l4ctx.check_offset(offset_of!(UdpHdr, check));
                l4ctx.sport(unsafe { (*udphdr).source });
                l4ctx.dport(unsafe { (*udphdr).dest });
                break;
            }
            IpProto::Ipv6Icmp => {
                let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4ctx.offset)?;
                let icmphdr = unsafe { &*icmphdr };
                let echo_id = unsafe { icmphdr.un.echo.id } as u32;
                l4ctx.check_offset(offset_of!(IcmpHdr, checksum));

                match icmphdr.type_ {
                    icmpv6::ND_ADVERT | icmpv6::ND_SOLICIT => {
                        return neighbor_solicit(ctx, l2ctx, l4ctx)
                    }

                    // Handle ICMP echo request / reply to track only messages that
                    // are handled by LB by using the echo identifier.
                    //  0                   1                   2                   3
                    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |     Type      |      Code     |          Checksum             |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |           Identifier          |        Sequence Number        |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // See  https://datatracker.ietf.org/doc/html/rfc792

                    // On ICMP request use the echo id as source port
                    icmpv6::ECHO_REQUEST => {
                        l4ctx.src_port = echo_id;
                    }
                    // On ICMP reply use the echo id destination port
                    icmpv6::ECHO_REPLY => {
                        l4ctx.dst_port = echo_id;
                    }

                    // Other types are not supported
                    _ => return Ok(xdp_action::XDP_PASS),
                }

                break;
            }
            IpProto::HopOpt | IpProto::Ipv6Route | IpProto::Ipv6Opts => {
                let exthdr = ptr_at::<Ipv6ExtBase>(&ctx, l4ctx.offset)?;
                let len = unsafe { (*exthdr).len_8b } as usize;
                l4ctx.offset += len << 3;
                l4ctx.next_hdr = unsafe { (*exthdr).next_header };
            }
            IpProto::Ipv6Frag => {
                // NOTE: Unlike with IPv4, routers never fragment a packet.
                // NOTE: Unlike IPv4, fragmentation in IPv6 is performed only by source
                // nodes, not by routers along a packet's delivery path. Must handle ipv6
                // fragments in case the source decides to fragment the packet due to MTU.
                // NOTE: IPv6 requires that every link in the Internet have an MTU of 1280
                // octets or greater. This is known as the IPv6 minimum link MTU.
                // On any link that cannot convey a 1280-octet packet in one piece,
                // link-specific fragmentation and reassembly must be provided at a layer
                // below IPv6.
                // See: https://www.rfc-editor.org/rfc/rfc8200.html#page-25
                // NOTE: To support IPv6 fragments must use a map for translating the packet
                // identification (32-bit) + src_ip + dst_ip to L4 data. The identification data
                // exists in every fragment exention header but only the first fragment contains
                // the L4 ports.
                // NOTE: For Fragment ext header this field is reserved and
                // initialized to zero for transmission; ignored on
                // reception as the len is implicitly 1 (8 bytes).
                let exthdr = ptr_at::<Ipv6FragExtHdr>(&ctx, l4ctx.offset)?;
                let exthdr = unsafe { &*exthdr };
                l4ctx.offset += 8;
                l4ctx.next_hdr = exthdr.base.next_header;

                // BUG: move the logging inside function to avoid bpf_linker error
                // after adding the call to stats_inc(IPV6_FRAGMENTS);
                log_fragexthdr(ctx, &exthdr, &feat);

                stats_inc(stats::IPV6_FRAGMENTS);

                array_copy(&mut unsafe { ctx6.fragid.src.addr32 }, src_addr);
                array_copy(&mut unsafe { ctx6.fragid.dst.addr32 }, dst_addr);
                ctx6.fragid.id = exthdr.id;

                if exthdr.offset() == 0 {
                    cache_fragment = true;
                } else {
                    // Retrieve cached l4 info and don't set the checksum offset
                    // as there no need to compute the checksum for fragments.
                    // Fragments that are not recognized are passed along.
                    match unsafe { ZLB_FRAG6.get(&ctx6.fragid) } {
                        // Missing first fragment
                        None => {
                            stats_inc(stats::IPV6_FRAGMENT_ERRORS);
                            return Err(());
                        }
                        Some(entry) => {
                            l4ctx.sport(entry.src_port);
                            l4ctx.dport(entry.dst_port);
                            break;
                        }
                    }
                }
            }
            _ => {
                // This includes also IpProto::Ipv6NoNxt
                break;
            }
        };
    }

    if feat.log_enabled(Level::Info) {
        log_ipv6_packet(ctx, ipv6hdr, &l4ctx);
    }

    // === reply ===

    // NOTE: looks like the 512B stack can be exhausted pretty rapidly
    // for 1pv6 lb due to larger structs. One way to avoid the verifier error
    // `combined stack size of 2 calls is 544. Too large` is to:
    // * use temp variables during map searches: e.g. ZLB_CONNTRACK6.get(&NAT6Key {..
    // * use variables inside scopes { .. } so the vars are releases from stack
    // * use per cpu array maps
    // * try remove some log prints
    // * don't create object like NAT6Key as read-only and redefine them as mutable.
    // * move large object to Context object
    // * the stack exhaustion is also the cause of the bpf_linker error
    // * the aya_logger macros consumes a lot of stack so maybe create custom logger
    // that does not consume the stack.

    let nat6key = &mut ctx6.nat6key;

    // NOTE: Copying the address using the utility will only use a single
    // register and the same number of instructions:
    //
    // simple copy                      | w/ array_copy
    // 5473: (61) r1 = *(u32 *)(r8 +8)  | 5473: (61) r1 = *(u32 *)(r8 +8)
    // 5474: (61) r2 = *(u32 *)(r8 +12) | 5474: (63) *(u32 *)(r9 +24) = r1
    // 5475: (61) r3 = *(u32 *)(r8 +16) | 5475: (61) r1 = *(u32 *)(r8 +12)
    // 5476: (61) r5 = *(u32 *)(r8 +20) | 5476: (63) *(u32 *)(r9 +28) = r1
    // 5477: (63) *(u32 *)(r9 +36) = r5 | 5477: (61) r1 = *(u32 *)(r8 +16)
    // 5478: (63) *(u32 *)(r9 +32) = r3 | 5478: (63) *(u32 *)(r9 +32) = r1
    // 5479: (63) *(u32 *)(r9 +28) = r2 | 5479: (61) r1 = *(u32 *)(r8 +20)
    // 5480: (63) *(u32 *)(r9 +24) = r1 | 5480: (63) *(u32 *)(r9 +36) = r1

    // NOTE: Using the NAT6Key kept in Context and used for both conntrack
    // local and global cache searches the top speed for IPv6 DSR_L2
    // is 3.38Gbits/sec at this commit:
    // 304f4a8 bpf6: use the Context Feature object inside the ct6 handler
    //
    nat6key.ip_be_src = Inet6U::from(src_addr);
    nat6key.ip_lb_dst = Inet6U::from(dst_addr);
    nat6key.port_be_src = l4ctx.src_port;
    nat6key.port_lb_dst = l4ctx.dst_port;
    nat6key.next_hdr = l4ctx.next_hdr as u32;

    let now = coarse_ktime();
    if let Some(ctnat) = unsafe { ZLB_CT6_CACHE.get(&nat6key) } {
        if ctnat.time > now {
            return ct6_handler(ctx, &l2ctx, &l4ctx, ipv6hdr, ctnat, feat);
        }
    }

    if let Some(nat) = unsafe { ZLB_CONNTRACK6.get(&nat6key) } {
        if ipv6hdr.payload_len.to_be() > nat.mtu {
            return send_ptb(ctx, &l2ctx, ipv6hdr, nat.mtu as u32);
        }

        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        log_nat6(ctx, &nat, &feat);

        // Save fragment before updating addresses
        if cache_fragment {
            cache_frag_info(&ctx6.fragid, &l4ctx);
        }

        // TBD: for crc32 use crc32_off

        let port_combo = l4ctx.dst_port << 16 | nat.port_lb as u32;
        let src_addr = unsafe { &nat.lb_ip.addr32 };
        let dst_addr = unsafe { &nat.ip_src.addr32 };
        if !nat.flags.contains(EPFlags::DSR_L2) {
            update_inet_csum(ctx, ipv6hdr, &l4ctx, src_addr, dst_addr, port_combo)?;
        }

        let ctnat = &mut ctx6.ctnat;
        ctnat.time = now + 30;
        ctnat.flags = nat.flags;
        ctnat.mtu = nat.mtu as u32;
        array_copy(&mut ctnat.src_addr, src_addr);
        array_copy(&mut ctnat.dst_addr, dst_addr);
        ctnat.port_combo = port_combo;
        ctnat.ifindex = nat.ifindex;
        array_copy(&mut ctx6.ctnat.macs, &nat.mac_addresses);

        let _ = ZLB_CT6_CACHE.insert(&nat6key, &ctx6.ctnat, /* update or insert */ 0);

        let action = if nat.flags.contains(EPFlags::XDP_REDIRECT) {
            // NOTE: BUG: don't use the implicit array copy (*a = mac;)
            // as aya will generate code that will throw the `relocation function` error
            // during the program load.
            let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
            let macs = unsafe { &mut *macs };
            array_copy(macs, &nat.mac_addresses);

            // NOTE: After this call all references derived from ctx must be recreated
            // since this method can change the packet limits.
            // This function is a no-op if no VLAN translation is needed.
            l2ctx.vlan_update(ctx, nat.vlan_hdr, &feat)?;

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
            info!(ctx, "[out] action: {} vlan: {:x}", action, l2ctx.vlanhdr);
        }

        return Ok(action);
    }

    // === request ===

    // Don't track ICMP echo replies sent to LB, only requests are tracked.
    // On request src_port contains the echo id.
    if ipv6hdr.next_hdr as u8 == icmpv6::ECHO_REPLY && l4ctx.src_port == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let be = {
        let group = match unsafe {
            ZLB_LB6.get(&EP6 {
                address: Inet6U::from(dst_addr),
                port: l4ctx.dst_port as u16,
                proto: l4ctx.next_hdr as u16,
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

    // Update the total processed packets when they are destined
    // to a known backend group.
    stats_inc(stats::PACKETS);

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[fwd-bknd] [{:i}]:{}",
            unsafe { Inet6U::from(&be.address).addr8 },
            be.port.to_be()
        );
    }

    if cache_fragment {
        cache_frag_info(&ctx6.fragid, &l4ctx);
    }

    let port_combo = (be.port as u32) << 16 | l4ctx.src_port;

    // Fast exit if packet is not redirected
    if !be.flags.contains(EPFlags::XDP_REDIRECT) {
        update_destination_inet_csum(ctx, ipv6hdr, &l4ctx, &be.address, port_combo)?;

        // Send back the packet to the same interface
        if be.flags.contains(EPFlags::XDP_TX) {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "in => xdp_tx");
            }

            // TODO: swap eth addresses

            stats_inc(stats::XDP_TX);

            return Ok(xdp_action::XDP_TX);
        }

        if feat.log_enabled(Level::Info) {
            info!(ctx, "in => xdp_pass");
        }

        stats_inc(stats::XDP_PASS);

        return Ok(xdp_action::XDP_PASS);
    }

    // TBD: need to check BE.src_ip == 0 ?
    let lb_addr = if be.flags.contains(EPFlags::XDP_TX) && be.src_ip[0] != 0 {
        // TODO: check the ND table and update or insert
        // smac/dmac and derived ip src and redirect ifindex
        &be.src_ip
    } else {
        unsafe { &nat6key.ip_lb_dst.addr32 }
    };

    // NOTE: Check if packet can be redirected and it does not exceed the interface MTU
    let (fib, fib_rc) = fetch_fib6(ctx, ipv6hdr, lb_addr, &be.address, now)?;
    let fib = unsafe { &*fib };
    match fib_rc {
        bindings::BPF_FIB_LKUP_RET_SUCCESS => {
            if fib.mtu as u16 >= ipv6hdr.payload_len.to_be() {
                /* go ahead an update the packet */
            } else {
                /* send packet to big */
                return send_ptb(ctx, &l2ctx, ipv6hdr, fib.mtu);
            }
        }
        bindings::BPF_FIB_LKUP_RET_FRAG_NEEDED => {
            /* send  packet to big */
            return send_ptb(ctx, &l2ctx, ipv6hdr, fib.mtu);
        }
        bindings::BPF_FIB_LKUP_RET_BLACKHOLE
        | bindings::BPF_FIB_LKUP_RET_UNREACHABLE
        | bindings::BPF_FIB_LKUP_RET_PROHIBIT => {
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        _ => {
            // When the MTU is lower than 1280 the FIB lookup will return
            // bindings::BPF_FIB_LKUP_RET_NOT_FWDED.
            // TODO: search in the ND map for the destination IP
            // and see if the MTU matches.
            stats_inc(stats::XDP_PASS);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if !be.flags.contains(EPFlags::DSR_L2) {
        update_inet_csum(ctx, ipv6hdr, &l4ctx, lb_addr, &be.address, port_combo)?;
    }

    // NOTE: look like aya can't convert the '*eth = entry.macs' into
    // a 3 load instructions block that doesn't panic the bpf verifier
    // with 'invalid access to packet'. The same statement when modifying
    // stack data passes the verifier check.

    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };
    ctx6.nat6val.mac_addresses = [
        macs[2] << 16 | macs[1] >> 16,
        macs[0] << 16 | macs[2] >> 16,
        macs[1] << 16 | macs[0] >> 16,
    ];
    array_copy(macs, &fib.macs);

    // TODO: use the vlan info from fib lookup to update the frame vlan.
    // Till then assume we redirect to backends outside of any VLAN.
    // NOTE: This call can shrink or enlarge the packet so all pointers
    // to headers are invalidated.
    l2ctx.vlan_update(ctx, 0, &feat)?;

    // In case of redirect failure just try to query the FIB again
    let action = redirect_txport(ctx, &feat, fib.ifindex);

    if feat.log_enabled(Level::Info) {
        info!(ctx, "[redirect] oif:{}, action={}", fib.ifindex, action);
    }

    /* === connection tracking === */

    // Add conntrack cache entry to skip searching for the group,
    // the backend and the fib entry that provides the neighbor
    // mac address.
    // NOTE: Since the cache is a per CPU map the insert with flags=0
    // will update only the value for the current CPU.

    ctx6.ctnat.time = now + 30;
    ctx6.ctnat.flags = be.flags;
    ctx6.ctnat.mtu = fib.mtu;
    array_copy(&mut ctx6.ctnat.src_addr, lb_addr);
    array_copy(&mut ctx6.ctnat.dst_addr, &(be.address));
    ctx6.ctnat.port_combo = port_combo;
    ctx6.ctnat.ifindex = fib.ifindex;
    array_copy(&mut ctx6.ctnat.macs, &fib.macs);

    let _ = ZLB_CT6_CACHE.insert(&nat6key, &ctx6.ctnat, /* update or insert */ 0);

    // TODO: Don't insert entry if no connection tracking is enabled for this backend.
    // For e.g. if the backend can reply directly to the source endpoint.
    // if !be.flags.contains(EPFlags::NO_CONNTRACK) {
    // NOTE: The LB will use the source port since there can be multiple
    // connection to the same backend and it needs to track all of them.
    // On reply the source port is used to identify the connection track entry.
    // NOTE: for DSR the key does not change.
    //
    // Normal NAT mappings
    //             Request         Reply
    // ----------------------------------
    // ip_be_src   Backend         Source
    // ip_lb_dst   Dest | src_ip   Dest
    // port_be_src Backend         Source
    // port_lb_dst Source          Dest
    //
    // DSR NAT mappings: swap source with dest
    //             Request         Reply
    // ----------------------------------
    // ip_be_src   Dest            Source
    // ip_lb_dst   Source          Dest
    // port_be_src Dest            Source
    // port_lb_dst Source          Dest
    let ip_src = nat6key.ip_be_src;
    let lb_ip = nat6key.ip_lb_dst;
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    if be.flags.contains(EPFlags::DSR_L2) {
        // NOTE: for DSR L2 the reply flow will search for source as current destination
        // and destination as current source.
        nat6key.ip_be_src = lb_ip;
        nat6key.ip_lb_dst = ip_src;
        nat6key.port_be_src = l4ctx.dst_port;
        nat6key.port_lb_dst = l4ctx.src_port;
    } else {
        nat6key.ip_lb_dst = Inet6U::from(lb_addr);
        nat6key.ip_be_src = Inet6U::from(&be.address);
        nat6key.port_be_src = be.port as u32;
        nat6key.port_lb_dst = l4ctx.src_port;
    }

    ctx6.nat6val.ip_src = ip_src;
    ctx6.nat6val.lb_ip = lb_ip;
    ctx6.nat6val.port_lb = l4ctx.dst_port as u16;
    ctx6.nat6val.ifindex = ifindex;
    ctx6.nat6val.mtu = check_mtu(ctx, ifindex);
    ctx6.nat6val.vlan_hdr = l2ctx.vlanhdr;
    ctx6.nat6val.flags = be.flags;
    // NOTE: the original MAC addresses are cached right before redirect

    // TBD: use lock or atomic update ?
    // TBD: use BPF_F_LOCK ?

    let rc = match unsafe { ZLB_CONNTRACK6.insert(&nat6key, &ctx6.nat6val, 0) } {
        Ok(()) => 0, // add stats for insert
        Err(ret) => {
            stats_inc(stats::CT_ERROR_UPDATE);
            ret
        }
    };

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[ctrk] [{:i}]:{} vlanhdr: {:x}, rc={}",
            unsafe { ip_src.addr8 },
            (l4ctx.src_port as u16).to_be(),
            l2ctx.vlanhdr,
            rc
        )
    }

    Ok(action)
}

/// This buffer must hold any IPv6 per-fragment header extentions plus
/// the largest supported protocol header.For now Tcp has the biggest header.
/// TODO: Make these values configurable to be able to handle multiple stacked
/// IPv6 extension headers.
const MAX_HDR_EXT: usize = 4 * 8; // Up to 4 per-fragment headers
const MAX_HDR_PROTO: usize = TcpHdr::LEN; // 40B
type ProtoHdr = [u32; (MAX_HDR_EXT + MAX_HDR_PROTO) >> 2];

/// The ICMPv6 Packet Too Big message as defined in RFC 4443:
///
/// 0               1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     Type:2    |     Code:0    |          Checksum             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                             MTU                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                    As much of invoking packet                 |
/// +               as possible without the ICMPv6 packet           +
/// |               exceeding the minimum IPv6 MTU [IPv6]           |
///
/// See: https://datatracker.ietf.org/doc/html/rfc4443#section-3.2
///
#[repr(C)]
struct Icmpv6Ptb {
    type_: u8,
    code: u8,
    csum: u16,
    mtu: u32,
    /// The quoted IpV6 header is required as mentioned in RFC 4443.
    ipv6hdr: Ipv6Hdr,
    /// The quoted protocol header field is also required in order
    /// to find the connection session or process.
    protohdr: ProtoHdr,
}

const PTB_SIZE: u32 = mem::size_of::<Icmpv6Ptb>() as u32;
const PTB_WSIZE: usize = (PTB_SIZE >> 2) as usize;

fn send_ptb(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    ipv6hdr: &mut Ipv6Hdr,
    size: u32,
) -> Result<u32, ()> {
    let feat = Features::new();

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "PTB, actual:{} max:{}",
            ipv6hdr.payload_len.to_be(),
            size
        );
    }

    let ctx6 = unsafe {
        let ptr = ZLB_CONTEXT6.get_ptr_mut(0).ok_or(())?;
        &mut *ptr
    };

    // NOTE: the bellow pointer getter are unlikely to fail because
    // on IPv6 the minimum MTU is 1280.

    let ptb_offset = l2ctx.ethlen + Ipv6Hdr::LEN;
    let phdr = ptr_at::<ProtoHdr>(&ctx, ptb_offset)?;
    array_copy(&mut ctx6.ptbprotohdr, unsafe { &*phdr });

    // NOTE: the new ICMPv6 header can be located at another offset than
    // the original L4 header.
    let ptb = ptr_at::<Icmpv6Ptb>(&ctx, ptb_offset)?;
    let ptb = unsafe { &mut *ptb.cast_mut() };

    // Copy the original IPv6 header as data for the Icmpv6 PTB message
    ptb.ipv6hdr = *ipv6hdr;
    array_copy(&mut ptb.protohdr, &ctx6.ptbprotohdr);

    ptb.type_ = 2; // Packet To Big error id
    ptb.code = 0; // always zero
    ptb.csum = 0; // initialize the checksum with 0
    ptb.mtu = size.to_be();

    // Update the Ethernet header
    let eth = ptr_at::<EthHdr>(&ctx, 0)?.cast_mut();
    let eth = unsafe { &mut *eth };
    core::mem::swap(&mut eth.src_addr, &mut eth.dst_addr);

    // Update the Ipv6 header
    core::mem::swap(&mut ipv6hdr.src_addr, &mut ipv6hdr.dst_addr);
    ipv6hdr.next_hdr = IpProto::Ipv6Icmp;
    let payload_len = PTB_SIZE as u16;
    ipv6hdr.payload_len = payload_len.to_be();

    // Build the Icmpv6 checksum
    // a) Icmpv6 pseudo-header

    // NOTE: ICMPv6 checksum differs from ICMPv4 csum as it requires
    // a pseudo-IPv6 header initial csum.
    // NOTE: The fields used to build the initial pseudo header csum
    // must be added as big-endian values.
    let mut csum = csum_add_u32((IpProto::Ipv6Icmp as u32).to_be(), 0);
    csum = csum_add_u32(PTB_SIZE.to_be(), csum);
    let dst_addr = unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 };
    let src_addr = unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 };
    for i in 0..4 {
        csum = csum_add_u32(src_addr[i], csum);
        csum = csum_add_u32(dst_addr[i], csum);
    }

    // b) actual Icmpv6 packet
    let data = ptr_at::<[u32; PTB_WSIZE]>(&ctx, ptb_offset)?;
    let data = unsafe { &*data };
    for i in 0..PTB_WSIZE {
        csum = csum_add_u32(data[i], csum);
    }

    // NOTE: always negate before coverting to u32
    ptb.csum = !csum_fold_32_to_16(csum);

    // NOTE: looks like there is no need to adjust the frame size and
    // setting the IP header payload length field is enough.
    // However, for latency and debug reasons must adjust the buffer to
    // reflect the actual packet size.

    let pkt_len = ctx.data_end() - ctx.data();
    let delta = PTB_SIZE as i32 + ptb_offset as i32 - pkt_len as i32;
    let rc = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "adjust tail by delta:{}, pkt_len:{}, rc={}", delta, pkt_len, rc
        );
    }

    stats_inc(stats::ICMPV6_PTB);

    return Ok(xdp_action::XDP_TX);
}

impl BpfFibLookUp {
    fn init_inet6(
        &mut self,
        paylod_len: u16,
        ifindex: u32,
        tc: u32,
        src: &[u32; 4],
        dst: &[u32; 4],
    ) {
        self.family = AF_INET6;
        self.l4_protocol = 0;
        self.sport = 0;
        self.dport = 0;
        self.tot_len = paylod_len;
        self.ifindex = ifindex;
        self.tos = tc;
        array_copy(&mut self.src, src);
        array_copy(&mut self.dst, dst);
    }
}

impl Context6 {
    fn init_fibentry(&mut self, expiry: u32) {
        self.fibentry.ifindex = self.fiblookup.ifindex;
        self.fiblookup.copy_swapped_macs(&mut self.fibentry.macs);
        array_copy(&mut self.fibentry.ip_src, &mut self.fiblookup.src); // not used for now
        self.fibentry.mtu = self.fiblookup.tot_len as u32;
        self.fibentry.expiry = expiry;
    }
}

fn fetch_fib6(
    ctx: &XdpContext,
    ipv6hdr: &Ipv6Hdr,
    src: &[u32; 4],
    dst: &[u32; 4],
    now: u32,
) -> Result<(*const FibEntry, u32), ()> {
    match unsafe { ZLB_FIB6.get_ptr(&dst) } {
        Some(entry) => {
            if now <= unsafe { (*entry).expiry } {
                return Ok((entry, bindings::BPF_FIB_LKUP_RET_SUCCESS as u32));
            }
        }
        None => {}
    }

    let ctx6 = unsafe {
        let ptr = ZLB_CONTEXT6.get_ptr_mut(0).ok_or(())?;
        &mut *ptr
    };

    ctx6.fiblookup.init_inet6(
        ipv6hdr.payload_len.to_be(),
        unsafe { (*ctx.ctx).ingress_ifindex },
        ipv6hdr.priority() as u32,
        src,
        dst,
    );

    let p_fib_param = &ctx6.fiblookup as *const BpfFibLookUp;
    let rc = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            p_fib_param as *mut bpf_fib_lookup_param_t,
            mem::size_of::<BpfFibLookUp>() as i32,
            0,
        )
    };

    stats_inc(stats::FIB_LOOKUPS);
    let expiry = if rc != bindings::BPF_FIB_LKUP_RET_SUCCESS as i64 {
        stats_inc(stats::FIB_LOOKUP_FAILS);
        // Retry on next try but create the entry
        now - 1
    } else {
        // TODO: make the expiry time a runvar
        now + FIB_ENTRY_EXPIRY_INTERVAL
    };

    if ctx6.feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[fib] lkp_ret: {}, fw if: {}, src: {:i}, \
            gw: {:i}, dmac: {:mac}, smac: {:mac}, mtu: {}",
            rc,
            ctx6.fiblookup.ifindex,
            unsafe { Inet6U::from(&ctx6.fiblookup.src).addr8 },
            unsafe { Inet6U::from(&ctx6.fiblookup.dst).addr8 },
            ctx6.fiblookup.dest_mac(),
            ctx6.fiblookup.src_mac(),
            ctx6.fiblookup.tot_len
        );
    }
    ctx6.init_fibentry(expiry);

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_FIB6.insert(&dst, &ctx6.fibentry, 0) } {
        Ok(()) => {}
        Err(_) => {
            stats_inc(stats::FIB_ERROR_UPDATE);
            return Err(());
        }
    }

    match unsafe { ZLB_FIB6.get_ptr(&dst) } {
        Some(entry) => Ok((entry, rc as u32)),
        None => Err(()),
    }
}
