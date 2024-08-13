use crate::{
    is_unicast_mac, ptr_at, redirect_txport, stats_inc, BpfFibLookUp, Features, L2Context,
    L4Context, AF_INET6, ZLB_BACKENDS,
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
    NAT6Value, EP6, FIB_ENTRY_EXPIRY_INTERVAL, MAX_ARP_ENTRIES, MAX_CONNTRACKS, MAX_GROUPS,
    NEIGH_ENTRY_EXPIRY_INTERVAL,
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
static mut ZLB_FRAG6: FRAG6LHM = FRAG6LHM::pinned(MAX_ARP_ENTRIES, 0);

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
    if port_combo != 0 {
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

    if port_combo != 0 {
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
    let expiry = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32 + NEIGH_ENTRY_EXPIRY_INTERVAL;
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
        // TODO: fix bpf_linker error
        // update_neighbors_cache(
        //     ctx,
        //     unsafe { &ndhdr.tgt_addr.addr32 },
        //     l2ctx.vlan_id(),
        //     &llao.mac,
        //     eth,
        // );

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

struct Ipv6L4Context {
    base: L4Context,
    frag_id: u32,
    next_hdr: IpProto,
}

impl Ipv6L4Context {
    fn new(ethlen: usize, next_hdr: IpProto) -> Self {
        Self {
            base: L4Context {
                offset: ethlen + Ipv6Hdr::LEN,
                check_off: 0,
                src_port: 0,
                dst_port: 0,
            },
            frag_id: 0,
            next_hdr,
        }
    }

    fn check_offset(&mut self, off: usize) {
        self.base.check_off = off;
    }

    fn sport(&mut self, port: u16) {
        self.base.src_port = port as u32;
    }

    fn dport(&mut self, port: u16) {
        self.base.dst_port = port as u32;
    }
}

fn cache_frag_info(ipv6hdr: &Ipv6Hdr, l4ctx: &Ipv6L4Context) {
    if l4ctx.frag_id == 0 {
        return;
    }

    match unsafe {
        ZLB_FRAG6.insert(
            &Ipv6FragId {
                id: l4ctx.frag_id,
                src: Inet6U::from(&ipv6hdr.src_addr.in6_u.u6_addr32),
                dst: Inet6U::from(&ipv6hdr.dst_addr.in6_u.u6_addr32),
            },
            &Ipv6FragInfo {
                src_port: l4ctx.base.src_port as u16,
                dst_port: l4ctx.base.dst_port as u16,
                reserved: 0,
            },
            0,
        )
    } {
        Ok(()) => {}
        Err(_) => {}
    };

    // BUG: aya compiler generates code that exeeds the stack size:
    // 'the BPF_PROG_LOAD syscall failed. Verifier output: combined
    // stack size of 3 calls is 544. Too large'
    // Calling the same log function outside works.
    // info!(ctx, "fino");
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
    let mut l4ctx = Ipv6L4Context::new(l2ctx.ethlen, ipv6hdr.next_hdr);
    let mut is_icmp_reply = false;
    let feat = Features::new();

    for _ in 0..4 {
        match l4ctx.next_hdr {
            IpProto::Tcp => {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, l4ctx.base.offset)?;
                l4ctx.check_offset(offset_of!(TcpHdr, check));
                l4ctx.sport(unsafe { (*tcphdr).source });
                l4ctx.dport(unsafe { (*tcphdr).dest });
                break;
            }
            IpProto::Udp => {
                let udphdr = ptr_at::<UdpHdr>(&ctx, l4ctx.base.offset)?;
                l4ctx.check_offset(offset_of!(UdpHdr, check));
                l4ctx.sport(unsafe { (*udphdr).source });
                l4ctx.dport(unsafe { (*udphdr).dest });
                break;
            }
            IpProto::Ipv6Icmp => {
                let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4ctx.base.offset)?;
                l4ctx.check_offset(offset_of!(IcmpHdr, checksum));

                match unsafe { (*icmphdr).type_ } {
                    icmpv6::ND_ADVERT | icmpv6::ND_SOLICIT => {
                        return neighbor_solicit(ctx, l2ctx, l4ctx.base)
                    }
                    icmpv6::ECHO_REPLY => {
                        is_icmp_reply = true;
                    }
                    icmpv6::ECHO_REQUEST => { /* handled below */ }
                    _ => return Ok(xdp_action::XDP_PASS),
                }

                break;
            }
            IpProto::HopOpt | IpProto::Ipv6Route | IpProto::Ipv6Opts => {
                let exthdr = ptr_at::<Ipv6ExtBase>(&ctx, l4ctx.base.offset)?;
                let len = unsafe { (*exthdr).len_8b } as usize;
                l4ctx.base.offset += len << 3;
                l4ctx.next_hdr = unsafe { (*exthdr).next_header };
                continue;
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
                let exthdr = ptr_at::<Ipv6FragExtHdr>(&ctx, l4ctx.base.offset)?;
                let exthdr = unsafe { &*exthdr };
                l4ctx.base.offset += 8;
                l4ctx.next_hdr = exthdr.base.next_header;

                if feat.log_enabled(Level::Info) {
                    info!(
                        ctx,
                        "pkt frag id: 0x{:x} off:M {}:{}",
                        exthdr.id,
                        exthdr.offset(),
                        exthdr.more()
                    );
                }

                if exthdr.offset() == 0 {
                    // The id will be needed to cache the L4 info entry after
                    // checking if this packet belongs to a LB flow.
                    l4ctx.frag_id = exthdr.id;
                } else {
                    // Retrieve cached l4 info and don't set the checksum offset
                    // as there no need to compute the checksum for fragments.
                    // Fragments that are not recognized are passed along.
                    match unsafe {
                        ZLB_FRAG6.get(&Ipv6FragId {
                            id: exthdr.id,
                            src: Inet6U::from(src_addr),
                            dst: Inet6U::from(dst_addr),
                        })
                    } {
                        // Missing first fragment
                        None => return Err(()),
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
            port_be_src: l4ctx.base.src_port,
            port_lb_dst: l4ctx.base.dst_port,
            next_hdr: l4ctx.next_hdr as u32,
        })
    } {
        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        // Unlikely
        if nat.ip_src.eq32(src_addr) && l4ctx.base.src_port == l4ctx.base.dst_port {
            if feat.log_enabled(Level::Error) {
                error!(
                    ctx,
                    "[out] drop same src {:i}:{}",
                    unsafe { nat.ip_src.addr8 },
                    (l4ctx.base.src_port as u16).to_be()
                );
            }
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }

        log_nat6(ctx, &nat, &feat);

        // Save fragment before updating addresses
        cache_frag_info(ipv6hdr, &l4ctx);

        // TBD: for crc32 use crc32_off

        update_inet_csum(
            ctx,
            ipv6hdr,
            &l4ctx.base,
            unsafe { &nat.lb_ip.addr32 },
            unsafe { &nat.ip_src.addr32 },
            l4ctx.base.dst_port << 16 | nat.port_lb,
        )?;

        let action = if nat.flags.contains(EPFlags::XDP_REDIRECT) {
            let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
            unsafe { *macs = nat.mac_addresses };

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

    // Don't track echo replies as there can be a response from the actual source.
    // To avoid messing with the packet routing allow tracking only ICMP requests.
    if is_icmp_reply {
        return Ok(xdp_action::XDP_PASS);
    }

    let group = match unsafe {
        ZLB_LB6.get(&EP6 {
            address: Inet6U::from(dst_addr),
            port: l4ctx.base.dst_port as u16,
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

    cache_frag_info(ipv6hdr, &l4ctx);

    let be = {
        let index = (inet6_hash16(&src_addr) ^ l4ctx.base.src_port as u16) % group.becount;
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

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[fwd-bknd] [{:i}]:{}",
            unsafe { Inet6U::from(&be.address).addr8 },
            be.port.to_be()
        );
    }

    // Fast exit if packet is not redirected
    if !be.flags.contains(EPFlags::XDP_REDIRECT) {
        update_destination_inet_csum(
            ctx,
            ipv6hdr,
            &l4ctx.base,
            &be.address,
            (be.port as u32) << 16 | l4ctx.base.src_port,
        )?;

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
        port_lb_dst: l4ctx.base.src_port, // use the source port of the endpoint
        next_hdr: l4ctx.next_hdr as u32,
    };

    // NOTE: use a single eth ptr
    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };
    let if_index = unsafe { (*ctx.ctx).ingress_ifindex };
    let mac_addresses = [
        macs[2] << 16 | macs[1] >> 16,
        macs[0] << 16 | macs[2] >> 16,
        macs[1] << 16 | macs[0] >> 16,
    ];

    // Update the nat entry only if the source details changes.
    // This will boost performance and less error prone on tests like iperf.
    // TODO: check every x sec for each src address + src_port + proto if NAT was set
    let do_insert = match unsafe { ZLB_CONNTRACK6.get(&nat6key) } {
        // TODO: use a inet 32-bit hash instead of
        // the 3 comparations or 32B/32B total matching bytes ?
        Some(&nat) => {
            nat.ifindex != if_index
                || !nat.ip_src.eq32(src_addr)
                || nat.mac_addresses != mac_addresses
                || !nat.vlan_hdr == l2ctx.vlanhdr
        }
        None => true,
    };

    if do_insert {
        // TODO: use as temp value at insert point
        let nat6value = NAT6Value {
            ip_src: Inet6U::from(src_addr),
            port_lb: l4ctx.base.dst_port,
            ifindex: if_index,
            mac_addresses,
            vlan_hdr: l2ctx.vlanhdr,
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
                        "[ctrk] [{:i}]:{} added vlanhdr: {:x}",
                        unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
                        (l4ctx.base.src_port as u16).to_be(),
                        l2ctx.vlanhdr
                    )
                }
            }
            Err(ret) => {
                if feat.log_enabled(Level::Error) {
                    error!(
                        ctx,
                        "[ctrk] [{:i}]:{} not added, err: {}",
                        unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
                        (l4ctx.base.src_port as u16).to_be(),
                        ret
                    )
                }
                stats_inc(stats::CT_ERROR_UPDATE);
            }
        };
    }

    // NOTE: Check if packet can be redirected and it does not exceed the interface MTU
    let (fib, fib_rc) = fetch_fib6(ctx, ipv6hdr, &lb_addr, &be.address)?;
    let fib = unsafe { &*fib };
    match fib_rc {
        bindings::BPF_FIB_LKUP_RET_SUCCESS => {
            if fib.mtu as u16 >= ipv6hdr.payload_len { /* go ahead an update the packet */
            } else { /* send packet to big */
            }
        }
        bindings::BPF_FIB_LKUP_RET_FRAG_NEEDED => { /* send  packet to big */ }
        bindings::BPF_FIB_LKUP_RET_BLACKHOLE
        | bindings::BPF_FIB_LKUP_RET_UNREACHABLE
        | bindings::BPF_FIB_LKUP_RET_PROHIBIT => {
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }
        _ => {
            stats_inc(stats::XDP_PASS);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    update_inet_csum(
        ctx,
        ipv6hdr,
        &l4ctx.base,
        unsafe { &nat6key.ip_lb_dst.addr32 },
        unsafe { &nat6key.ip_be_src.addr32 },
        (be.port as u32) << 16 | l4ctx.base.src_port,
    )?;

    // NOTE: look like aya can't convert the '*eth = entry.macs' into
    // a 3 load instructions block that doesn't panic the bpf verifier
    // with 'invalid access to packet'. The same statement when modifying
    // stack data passes the verifier check.

    macs[2] = fib.macs[2];
    macs[1] = fib.macs[1];
    macs[0] = fib.macs[0];

    // TODO: use the vlan info from fib lookup to update the frame vlan.
    // Till then assume we redirect to backends outside of any VLAN.
    l2ctx.vlan_update(ctx, 0, &feat)?;

    // In case of redirect failure just try to query the FIB again
    let action = redirect_txport(ctx, &feat, fib.ifindex);

    if feat.log_enabled(Level::Info) {
        info!(ctx, "[redirect] oif:{}, action={}", fib.ifindex, action);
    }

    return Ok(action);
}

#[map]
static ZLB_FIB_LKP_RES: HashMap<u32, BpfFibLookUp> = HashMap::with_max_entries(256, 0);

fn fetch_fib6(
    ctx: &XdpContext,
    ipv6hdr: &Ipv6Hdr,
    src: &[u32; 4],
    dst: &[u32; 4],
) -> Result<(*const FibEntry, u32), ()> {
    let now = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32;

    match unsafe { ZLB_FIB6.get_ptr(&dst) } {
        Some(entry) => {
            if now <= unsafe { (*entry).expiry } {
                return Ok((entry, bindings::BPF_FIB_LKUP_RET_SUCCESS as u32));
            }
        }
        None => {}
    }

    let fib_param = BpfFibLookUp::new_inet6(
        ipv6hdr.payload_len.to_be(),
        unsafe { (*ctx.ctx).ingress_ifindex },
        ipv6hdr.priority() as u32,
        src,
        dst,
    );
    let p_fib_param = &fib_param as *const BpfFibLookUp;
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

    let feat = Features::new();

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[fib] lkp_ret: {}, fw if: {}, src: {:i}, \
            gw: {:i}, dmac: {:mac}, smac: {:mac}, mtu: {}",
            rc,
            fib_param.ifindex,
            unsafe { Inet6U::from(&fib_param.src).addr8 },
            unsafe { Inet6U::from(&fib_param.dst).addr8 },
            fib_param.dest_mac(),
            fib_param.src_mac(),
            fib_param.tot_len
        );
    }

    let entry = FibEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src, // not used for now
        expiry,
        mtu: fib_param.tot_len as u32,
    };

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_FIB6.insert(&dst, &entry, 0) } {
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

#[inline(never)]
fn _fib6_lookup_redirect(ctx: &XdpContext, l2ctx: &L2Context, feat: &Features) -> Result<u32, ()> {
    // Must re-check the ip header here because the packet might
    // be adjusted because the vlan header was stripped when first
    // attempt to redirect with cache values.
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &*ipv6hdr };
    let if_index = unsafe { (*ctx.ctx).ingress_ifindex };
    let p_fib_param = match { ZLB_FIB_LKP_RES.get_ptr_mut(&if_index) } {
        Some(ptr) => {
            unsafe {
                (*ptr).family = AF_INET6;
                (*ptr).tot_len = ipv6hdr.payload_len.to_be();
                (*ptr).tos = ipv6hdr.priority() as u32;
                // BUG: aya loader throws `error relocating function` if direct
                // assignment is used
                for i in 0..3 {
                    (*ptr).src[i] = ipv6hdr.src_addr.in6_u.u6_addr32[i];
                    (*ptr).dst[i] = ipv6hdr.dst_addr.in6_u.u6_addr32[i];
                }
            }
            ptr
        }
        None => {
            let param = BpfFibLookUp::new_inet6(
                ipv6hdr.payload_len.to_be(),
                unsafe { (*ctx.ctx).ingress_ifindex },
                ipv6hdr.priority() as u32,
                unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 },
                unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 },
            );
            match { ZLB_FIB_LKP_RES.insert(&if_index, &param, 0) } {
                Ok(_) => match { ZLB_FIB_LKP_RES.get_ptr_mut(&if_index) } {
                    Some(p) => p,
                    None => return Err(()),
                },
                Err(_) => return Err(()),
            }
        }
    };

    let rc = unsafe {
        bpf_fib_lookup(
            ctx.as_ptr(),
            p_fib_param as *mut bpf_fib_lookup_param_t,
            mem::size_of::<BpfFibLookUp>() as i32,
            0,
        )
    };

    stats_inc(stats::FIB_LOOKUPS);

    let fib_param = unsafe { &*p_fib_param };
    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[redirect] output, lkp_ret: {}, fw if: {}, src: {:i}, \
            gw: {:i}, dmac: {:mac}, smac: {:mac}, mtu: {}",
            rc,
            fib_param.ifindex,
            unsafe { Inet6U::from(&fib_param.src).addr8 },
            unsafe { Inet6U::from(&fib_param.dst).addr8 },
            fib_param.dest_mac(),
            fib_param.src_mac(),
            fib_param.tot_len
        );
    }

    if rc == bindings::BPF_FIB_LKUP_RET_SUCCESS as i64 {
        let action = unsafe {
            let eth = ptr_at::<EthHdr>(&ctx, 0)?;
            fib_param.fill_ethdr_macs(eth.cast_mut());

            // TODO: use the vlan info from fib lookup to update the frame vlan.
            // Till then assume we redirect to backends outside of any VLAN.
            l2ctx.vlan_update(ctx, 0, &feat)?;

            redirect_txport(ctx, &feat, fib_param.ifindex)
        };

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[redirect] action => {}", action);
        }

        _update_fib6_cache(ctx, &feat, fib_param);

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

    // TODO: use the vlan info from fib lookup to update the frame vlan.
    // Till then assume we redirect to backends outside of any VLAN.
    l2ctx.vlan_update(ctx, 0, &feat)?;

    stats_inc(stats::XDP_PASS);

    Ok(xdp_action::XDP_PASS)
}

fn _redirect_ipv6(
    ctx: &XdpContext,
    feat: &Features,
    ipv6hdr: &Ipv6Hdr,
    l2ctx: &L2Context,
) -> Result<u32, ()> {
    if let Some(&entry) = unsafe { ZLB_FIB6.get(&ipv6hdr.dst_addr.in6_u.u6_addr32) } {
        // NOTE: check expiry before using this entry
        let now = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32;

        if now <= entry.expiry {
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

            // TODO: use the vlan info from fib lookup to update the frame vlan.
            // Till then assume we redirect to backends outside of any VLAN.
            l2ctx.vlan_update(ctx, 0, &feat)?;

            // In case of redirect failure just try to query the FIB again
            if xdp_action::XDP_REDIRECT == redirect_txport(ctx, &feat, entry.ifindex) {
                if feat.log_enabled(Level::Info) {
                    info!(ctx, "[redirect] [nd-cache] oif: {}", entry.ifindex,);
                }

                return Ok(xdp_action::XDP_REDIRECT);
            }
        }
    }

    // NOTE: to avoid verifier stack overflow error just do a tail call
    _fib6_lookup_redirect(ctx, l2ctx, feat)
}

fn _update_fib6_cache(ctx: &XdpContext, feat: &Features, fib_param: &BpfFibLookUp) {
    let fib6 = FibEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src, // not used for now
        // TODO: make the expiry time a runvar
        expiry: unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32 + FIB_ENTRY_EXPIRY_INTERVAL,
        mtu: fib_param.tot_len as u32,
    };

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_FIB6.insert(&fib_param.dst, &fib6, 0) } {
        Ok(()) => {
            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[fib6] insert {:i} -> if:{}, smac: {:mac}, dmac: {:mac}, src: {:i}",
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
                error!(ctx, "[fib6] fail to insert entry, err:{}", e)
            }
            stats_inc(stats::FIB_ERROR_UPDATE);
        }
    };
}
