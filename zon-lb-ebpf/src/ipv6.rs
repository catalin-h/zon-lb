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
    stats, ArpEntry, BEGroup, BEKey, EPFlags, FibEntry, Inet6U, NAT6Key, NAT6Value, EP6,
    FIB_ENTRY_EXPIRY_INTERVAL, MAX_ARP_ENTRIES, MAX_CONNTRACKS, MAX_GROUPS,
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
// BUG: linker: must use inline(never), which version ? llvm ?
#[inline(never)]
pub fn compute_l4_context(
    ctx: &XdpContext,
    mut next_hdr: IpProto,
    ethlen: usize,
) -> Result<L4Context, ()> {
    let mut offset = ethlen + Ipv6Hdr::LEN;

    for _ in 0..4 {
        match next_hdr {
            IpProto::Tcp => {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, offset)?;
                return Ok(L4Context {
                    offset,
                    check_off: offset_of!(TcpHdr, check),
                    src_port: unsafe { (*tcphdr).source as u32 },
                    dst_port: unsafe { (*tcphdr).dest as u32 },
                    proto: IpProto::Tcp,
                });
            }
            IpProto::Udp => {
                let udphdr = ptr_at::<UdpHdr>(&ctx, offset)?;
                return Ok(L4Context {
                    offset,
                    check_off: offset_of!(UdpHdr, check),
                    src_port: unsafe { (*udphdr).source as u32 },
                    dst_port: unsafe { (*udphdr).dest as u32 },
                    proto: IpProto::Udp,
                });
            }
            IpProto::Ipv6Icmp => {
                return Ok(L4Context {
                    offset,
                    check_off: offset_of!(IcmpHdr, checksum),
                    src_port: 0,
                    dst_port: 0,
                    proto: IpProto::Ipv6Icmp,
                })
            }
            IpProto::HopOpt | IpProto::Ipv6Route | IpProto::Ipv6Opts => {
                let exthdr = ptr_at::<Ipv6ExtBase>(&ctx, offset)?;
                let len = unsafe { (*exthdr).len_8b } as usize;
                offset += len << 3;
                next_hdr = unsafe { (*exthdr).next_header };
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
                let exthdr = ptr_at::<Ipv6FragExtHdr>(&ctx, offset)?;
                let exthdr = unsafe { &*exthdr };
                offset += 8;
                next_hdr = exthdr.base.next_header;
                info!(
                    ctx,
                    "pkt frag id: 0x{:x} off:M {}:{}",
                    exthdr.id,
                    exthdr.offset(),
                    exthdr.more()
                );
                break;
            }
            IpProto::Ipv6NoNxt => return Err(()),
            _ => {
                break;
            }
        };
    }

    Ok(L4Context {
        offset,
        check_off: 0,
        src_port: 0,
        dst_port: 0,
        proto: next_hdr,
    })
}

pub fn ipv6_lb(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &mut *ipv6hdr.cast_mut() };
    let l4ctx = compute_l4_context(ctx, ipv6hdr.next_hdr, l2ctx.ethlen)?;
    let next_hdr = l4ctx.proto;
    let src_addr = unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 };
    let dst_addr = unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 };

    // TODO: move this if in main protocol match case
    let icmp_type = if next_hdr == IpProto::Ipv6Icmp {
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
            next_hdr: next_hdr as u32,
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
    if next_hdr == IpProto::Ipv6Icmp && icmp_type == icmpv6::ECHO_REPLY {
        return Ok(xdp_action::XDP_PASS);
    }

    let group = match unsafe {
        ZLB_LB6.get(&EP6 {
            address: Inet6U::from(dst_addr),
            port: l4ctx.dst_port as u16,
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
        port_lb_dst: l4ctx.src_port, // use the source port of the endpoint
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
        nat.ifindex != if_index
            || !nat.ip_src.eq32(src_addr)
            || nat.mac_addresses != mac_addresses
            || nat.vlan_hdr != l2ctx.vlanhdr
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
                        (l4ctx.src_port as u16).to_be(),
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

    return redirect_ipv6(ctx, &feat, ipv6hdr, &l2ctx);
}

fn fib6_lookup_redirect(ctx: &XdpContext, l2ctx: &L2Context, feat: &Features) -> Result<u32, ()> {
    // Must re-check the ip header here because the packet might
    // be adjusted because the vlan header was stripped when first
    // attempt to redirect with cache values.
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv6hdr = unsafe { &*ipv6hdr };

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

            // TODO: use the vlan info from fib lookup to update the frame vlan.
            // Till then assume we redirect to backends outside of any VLAN.
            l2ctx.vlan_update(ctx, 0, &feat)?;

            redirect_txport(ctx, &feat, fib_param.ifindex)
        };

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[redirect] action => {}", action);
        }

        update_fib6_cache(ctx, &feat, fib_param);

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

fn redirect_ipv6(
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
    fib6_lookup_redirect(ctx, l2ctx, feat)
}

fn update_fib6_cache(ctx: &XdpContext, feat: &Features, fib_param: BpfFibLookUp) {
    let fib6 = FibEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src, // not used for now
        // TODO: make the expiry time a runvar
        expiry: unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32 + FIB_ENTRY_EXPIRY_INTERVAL,
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
