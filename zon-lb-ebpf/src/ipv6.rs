use crate::{
    array_copy, is_unicast_mac, ptr_at, redirect_txport, stats_inc, zlb_context, BpfFibLookUp,
    CTCache, Context, FIBLookUp, Features, IpFragment, L2Context, L4Context, Log, AF_INET6, NAT,
    ZLB_BACKENDS,
};
use aya_ebpf::{
    bindings::{self, bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_F_NO_COMMON_LRU},
    helpers::{
        bpf_check_mtu, bpf_fib_lookup, bpf_ktime_get_coarse_ns, bpf_xdp_adjust_head,
        bpf_xdp_adjust_tail,
    },
    macros::map,
    maps::{HashMap, LruHashMap, LruPerCpuHashMap},
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
};
use zon_lb_common::{
    stats, ArpEntry, BEGroup, BEKey, EPFlags, FibEntry, Inet6U, Ipv6FragId, Ipv6FragInfo, NAT6Key,
    NAT6Value, BE, EP6, MAX_ARP_ENTRIES, MAX_CONNTRACKS, MAX_FRAG6_ENTRIES, MAX_GROUPS,
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
    ctnat: &CTCache,
) -> Result<(), ()> {
    // TODO: move this to the place of usage as this function can't be inlined
    if l4ctx.check_off == 0 {
        (*ipv6hdr).src_addr.in6_u.u6_addr32 = ctnat.src_addr;
        (*ipv6hdr).dst_addr.in6_u.u6_addr32 = ctnat.dst_addr;
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
    csum = compute_checksum(csum, from, &ctnat.src_addr);
    let from = unsafe { &mut ipv6hdr.dst_addr.in6_u.u6_addr32 };
    csum = compute_checksum(csum, from, &ctnat.dst_addr);

    // TODO: reduce hop limit by one on xmit and redirect
    // The IPv6 header does not have a csum field that needs to be
    // recalculated every time the hop limit is decreased as it happens
    // when the TTL from IPv4 header is reduced by one.

    // NOTE: to update the ports on TCP and UDP just exploit the fact that
    // both headers start with [src_port:u16][dst_port:u16] and/ just set
    // a single u32 combo value as the begining of the L4 header:
    // port_combo = dst_port << 16 | src_port;
    // NOTE: the destination port remains the same.
    if ctnat.port_combo != 0 && l4ctx.next_hdr != IpProto::Ipv6Icmp {
        csum = csum_update_u32(
            l4ctx.dst_port << 16 | l4ctx.src_port,
            ctnat.port_combo,
            csum,
        );
        let ptr = ptr_at::<u32>(ctx, l4ctx.offset)?;
        unsafe { *(ptr.cast_mut()) = ctnat.port_combo };
    }

    // NOTE: In the absence of an csum in IP header the IPv6 protocol relies
    // on Link and Transport layer for assuring packet integrity. That's
    // why UDP for IPv6 must have a valid csum and for IPv4 is not required.
    // NOTE: ICMPv6, TCP or UDP checksums must be contructed from an pseudo-header
    // that contains the two addresses, the upper layer packet length as an 32-bit
    // value and the next header also as an 32-bit value:
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                         Source Address 4 x 32-bit             |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                      Destination Address 4 x 32-bit           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                   Upper-Layer Packet Length  32-bit           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                      zero  24-bit             | Next Header 8b|
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // See https://datatracker.ietf.org/doc/html/rfc2460#section-8.1

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
impl Log {
    // NOTE: It is important to pass args by ref and not as
    // pointers in order to contain the aya log stack allocations
    // inside the function. For eg. passing the Ipv6Hdr as pointer
    // will prevent the function from containing aya allocations.
    // NOTE: Looks like the log macro occupies a lot of stack
    #[inline(never)]
    fn ipv6_packet(&self, ctx: &XdpContext, ipv6hdr: &Ipv6Hdr) {
        self.hw_info(ctx);

        info!(
            ctx,
            "[{:x}] p={} [{:i}]:{} -> [{:i}]:{}",
            self.hash,
            self.next_hdr,
            unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
            self.src_port_be,
            // BUG: depending on current stack usage changing to dst_addr.addr8
            // will generate code that overflows the bpf program 512B stack
            unsafe { ipv6hdr.dst_addr.in6_u.u6_addr8 },
            self.dst_port_be,
        );

        let flow = ipv6hdr.flow_label;
        let flow = u32::from_be_bytes([0, flow[0], flow[1], flow[2]]);

        info!(
            ctx,
            "[{:x}] flow=0x{:x}, payload_len={}",
            self.hash,
            flow,
            ipv6hdr.payload_len.to_be()
        );

        if IpProto::Ipv6Icmp as u32 == self.next_hdr {
            self.log_icmp(ctx);
        }
    }

    #[inline(never)]
    fn conntrack6(&self, ctx: &XdpContext, nat: &NAT) {
        info!(
            ctx,
            "[{:x}] [ctrk] [{:i}]:{} vlanhdr: {:x}, rc={}",
            self.hash,
            unsafe { nat.v6info.ip_src.addr8 },
            self.src_port_be,
            nat.v6info.vlan_hdr.to_be(),
            nat.ret_code
        );
    }

    #[inline(never)]
    fn fib_lkup_inet6(&self, ctx: &XdpContext, fib: &FIBLookUp) {
        info!(
            ctx,
            "[{:x}] [fib] lkp_ret: {}, fw if: {}, src: {:i}, \
                 gw: {:i}, dmac: {:mac}, smac: {:mac}, mtu: {}",
            self.hash,
            fib.rc,
            fib.param.ifindex,
            unsafe { Inet6U::from(&fib.param.src).addr8 },
            unsafe { Inet6U::from(&fib.param.dst).addr8 },
            fib.param.dest_mac(),
            fib.param.src_mac(),
            fib.param.tot_len
        );
    }

    #[inline(never)]
    fn show_backend6(&self, ctx: &XdpContext, be: &BE, bekey: &BEKey) {
        info!(
            ctx,
            "[{:x}] [bknd] [{}:{}] [{:i}]:{}",
            self.hash,
            bekey.gid,
            bekey.index,
            unsafe { Inet6U::from(&be.address).addr8 },
            be.port.to_be()
        );
    }

    #[inline(never)]
    fn reply_nat6(&self, ctx: &XdpContext, nat: &NAT6Value) {
        info!(
            ctx,
            "[{:x}] [nat] src={:i} lb_port={}",
            self.hash,
            unsafe { nat.ip_src.addr8 },
            (nat.port_lb as u16).to_be()
        );
    }

    #[inline(never)]
    fn frag_exthdr(&self, ctx: &XdpContext, exthdr: &Ipv6FragExtHdr) {
        info!(
            ctx,
            "[{:x}] [frag] id=0x{:x} offset={} more={}",
            self.hash,
            exthdr.id.to_be(),
            exthdr.offset(),
            exthdr.more()
        );
    }
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

fn neighbor_solicit(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    ipv6hdr: &mut Ipv6Hdr,
    l4ctx: &L4Context,
    feat: &Features,
) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth = unsafe { &mut *eth.cast_mut() };
    let ndhdr = ptr_at::<Icmpv6NdHdr>(&ctx, l4ctx.offset)?;
    let ndhdr = unsafe { &mut *ndhdr.cast_mut() };
    let offset = l4ctx.offset + mem::size_of::<Icmpv6NdHdr>();
    let lladopt = ptr_at::<Icmpv6LLAddrOption>(&ctx, offset);

    if feat.log_enabled(Level::Info) {
        let nt = ndhdr.type_ == icmpv6::ND_SOLICIT;
        let nt = if nt { "sol-req" } else { "adver-reply" };
        let opt = if lladopt.is_ok() { " +" } else { " no " };
        info!(
            ctx,
            "[nd] {} if:{} src:[{:i}]/{:mac}/vlan={} for target [{:i}]{}llddar",
            nt,
            unsafe { (*ctx.ctx).ingress_ifindex },
            unsafe { ipv6hdr.src_addr.in6_u.u6_addr8 },
            eth.src_addr,
            (l2ctx.vlan_id() as u16).to_be(),
            unsafe { ndhdr.tgt_addr.addr8 },
            opt
        );
    }

    // The source/target link-layer address option
    let lladopt = match lladopt {
        Ok(ptr) => unsafe { &mut *(ptr.cast_mut()) },
        Err(_) => {
            // Update the neighbors table if the ND message contains a link layer option
            // Some IPv6 implementations don't send the link layer option
            return Ok(xdp_action::XDP_PASS);
        }
    };

    if !is_unicast_mac(&lladopt.mac) || lladopt.otype == 0 || lladopt.otype > 2 {
        return Ok(xdp_action::XDP_PASS);
    }

    // If this is a ND solicitation request
    update_neighbors_cache(
        ctx,
        unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 },
        l2ctx.vlan_id(),
        &lladopt.mac,
        eth,
    );

    // If this is a ND advertisement
    if lladopt.otype == 2 {
        update_neighbors_cache(
            ctx,
            unsafe { &ndhdr.tgt_addr.addr32 },
            l2ctx.vlan_id(),
            &lladopt.mac,
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

    // === Reply to neighbor solicitation ===

    // For VLANs answer to requests as this LB can act as a proxy for
    // the endpoints inside VLANs. Without special routing rules the
    // Icmpv6 ND requests are not ignored as they pertain to a different
    // network segment.

    if !l2ctx.has_vlan() || !is_unicast_mac(&eth.src_addr) {
        if feat.log_enabled(Level::Info) {
            info!(ctx, "[nd] no vlan for [{:i}]", unsafe {
                ndhdr.tgt_addr.addr8
            });
        }
        return Ok(xdp_action::XDP_PASS);
    }

    let smac = match unsafe { ZLB_ND.get(&ndhdr.tgt_addr.addr32) } {
        None => {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "[nd] no entry for [{:i}]", unsafe {
                    ndhdr.tgt_addr.addr8
                });
            }
            return Ok(xdp_action::XDP_PASS);
        }
        Some(entry) => {
            // NOTE: most likely the entry.vlan_id would be 0 since it shouldn't be
            // assigned in no VLAN
            if entry.ifindex == unsafe { (*ctx.ctx).ingress_ifindex }
                && (l2ctx.vlan_id() == entry.vlan_id || entry.vlan_id == 0)
            {
                if is_unicast_mac(&entry.if_mac) {
                    entry.if_mac
                } else {
                    entry.mac
                }
            } else {
                // Nothing to update
                return Ok(xdp_action::XDP_PASS);
            }
        }
    };

    // NOTE: destination is always the B-CAST address
    // BUG: due to aligment constraints can't copy the llao.mac array directly
    array_copy(&mut eth.dst_addr, &lladopt.mac);
    array_copy(&mut eth.src_addr, &smac);

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

    // Save received option in order to computed the checksum
    let from = *lladopt.as_array();

    // Update the option for mark this is the target link-layer address
    lladopt.otype = 2;
    lladopt.len = 1;
    lladopt.mac = smac;

    let to = lladopt.as_array();
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

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[eth] [tx] if:{} vlan_id:{} {:mac} -> {:mac}",
            unsafe { (*ctx.ctx).ingress_ifindex },
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

// NOTE: use a separate for src and dst addresses in order
// to differentiate request and reply flows if the flow label
// does not change.
// NOTE: The flow label is not enough as the ICMPv6 protocol
// sends the same value
#[repr(C)]
pub struct CT6CacheKey {
    next_hdr: IpProto,
    flow_label: [u8; 3],
    // src:dest
    port_combo: u32,
    src_hash: u32,
    dst_hash: u32,
}

impl CT6CacheKey {
    fn init(&mut self, ipv6hdr: &Ipv6Hdr, l4ctx: &L4Context) {
        self.next_hdr = l4ctx.next_hdr;

        // NOTE: must manually copy the array if the prog can't
        // be loaded at runtime due to the function  relocation
        // error.
        self.flow_label = ipv6hdr.flow_label;

        // NOTE: The flow label is not enough as the ICMPv6 protocol
        // sends the same value
        self.port_combo = l4ctx.port_combo();

        // NOTE: the iteration will be unrolled to 4 copy ops
        self.src_hash = unsafe { ipv6hdr.src_addr.in6_u.u6_addr32.iter().sum() };
        self.dst_hash = unsafe { ipv6hdr.dst_addr.in6_u.u6_addr32.iter().sum() };
    }
}

impl IpFragment {
    fn search6(
        &mut self,
        ipv6hdr: &Ipv6Hdr,
        exthdr: &Ipv6FragExtHdr,
        l4ctx: &mut L4Context,
    ) -> Option<bool> {
        array_copy(unsafe { &mut self.v6id.src.addr32 }, unsafe {
            &ipv6hdr.src_addr.in6_u.u6_addr32
        });
        array_copy(unsafe { &mut self.v6id.dst.addr32 }, unsafe {
            &ipv6hdr.dst_addr.in6_u.u6_addr32
        });
        self.v6id.id = exthdr.id;

        // First fragment always start at offset 0
        if exthdr.offset() == 0 {
            // Cache the fragment later with the key set above and the
            // info set when the actual L4 protocol header is found.
            l4ctx.set_flag(L4Context::CACHE_FRAG);
            return Some(false);
        }

        // Retrieve cached l4 info and don't set the checksum offset
        // as there no need to compute the checksum for fragments.
        // Fragments that are not recognized are passed along.
        match unsafe { ZLB_FRAG6.get(&self.v6id) } {
            // Not an error as there can be legitimate fragment that is not
            // tracked by current LB config.
            None => None,
            Some(entry) => {
                // No need to set the checksum offset as for IP fragments
                // there is no checksum except the first one.
                l4ctx.src_port = entry.src_port as u32;
                l4ctx.dst_port = entry.dst_port as u32;
                l4ctx.flags = entry.reserved;
                // Searching for L4 protol headr should stop as we found
                // the cached fragment info.
                Some(true)
            }
        }
    }

    fn cache6(&mut self, l4ctx: &L4Context) {
        if !l4ctx.get_flag(L4Context::CACHE_FRAG) {
            return;
        }

        self.v6inf.src_port = l4ctx.src_port as u16;
        self.v6inf.dst_port = l4ctx.dst_port as u16;
        self.v6inf.reserved = l4ctx.flags;

        match unsafe { ZLB_FRAG6.insert(&self.v6id, &self.v6inf, 0) } {
            Ok(()) => {}
            Err(_) => {
                stats_inc(stats::IPV6_FRAGMENT_ERRORS);
            }
        };
    }
}

impl NAT {
    fn init_v6key(&mut self, ipv6hdr: &Ipv6Hdr, l4ctx: &L4Context) {
        self.v6key.ip_be_src = Inet6U::from(unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 });
        self.v6key.ip_lb_dst = Inet6U::from(unsafe { &ipv6hdr.dst_addr.in6_u.u6_addr32 });
        self.v6key.port_be_src = l4ctx.src_port;
        self.v6key.port_lb_dst = l4ctx.dst_port;
        self.v6key.next_hdr = l4ctx.next_hdr as u32;
    }

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
    //
    fn updatev6(&mut self, ctx: &XdpContext, l4ctx: &L4Context, ctnat: &CTCache) {
        self.v6info.ip_src = self.v6key.ip_be_src;
        self.v6info.lb_ip = self.v6key.ip_lb_dst;

        if ctnat.flags.contains(EPFlags::DSR_L2) {
            // NOTE: for DSR L2 the reply flow will search for source as current destination
            // and destination as current source.
            self.v6key.ip_be_src = self.v6info.lb_ip;
            self.v6key.ip_lb_dst = self.v6info.ip_src;
            self.v6key.port_be_src = l4ctx.dst_port;
            self.v6key.port_lb_dst = l4ctx.src_port;
        } else {
            self.v6key.ip_lb_dst = Inet6U::from(&ctnat.src_addr);
            self.v6key.ip_be_src = Inet6U::from(&ctnat.dst_addr);
            if l4ctx.next_hdr == IpProto::Ipv6Icmp {
                // For ICMP flow the echo id and sequence number are saved as
                // source and destination port in L4Context. However, the ICMP
                // reply will has the same echo id and sequence number as the
                // request. In order to distinguish the request from the reply
                // we must swap the two values.
                self.v6key.port_be_src = l4ctx.dst_port;
            } else {
                // use the port set in BE info
                self.v6key.port_be_src = ctnat.port_combo >> 16;
            }
            self.v6key.port_lb_dst = l4ctx.src_port;
        }

        self.v6info.port_lb = l4ctx.dst_port as u16;
        self.v6info.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
        self.v6info.mtu = check_mtu(ctx, self.v6info.ifindex);
        self.v6info.flags = ctnat.flags;
        // NOTE: the original MAC addresses and VLAN header are cached right before redirect

        // TBD: use lock or atomic update ?
        // TBD: use BPF_F_LOCK ?

        self.ret_code = match unsafe { ZLB_CONNTRACK6.insert(&self.v6key, &self.v6info, 0) } {
            Ok(()) => {
                // TODO: add counter for how many times the conntrack cache is updated
                // stats_inc(stats::CT_ERROR_UPDATE);
                0
            }
            Err(ret) => {
                stats_inc(stats::CT_ERROR_UPDATE);
                ret
            }
        };
    }
}

#[map]
static ZLB_CT6_CACHE: LruPerCpuHashMap<CT6CacheKey, CTCache> =
    LruPerCpuHashMap::with_max_entries(256, BPF_F_NO_COMMON_LRU);

fn ct6_handler(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    l4ctx: &L4Context,
    ipv6hdr: &mut Ipv6Hdr,
    ctnat: &CTCache,
    ctx6: &Context,
) -> Result<u32, ()> {
    stats_inc(stats::PACKETS);

    // NOTE: No need to save fragment because this handler is called
    // after the main flows (request & response) caches this conntrack
    // cache handler.

    if do_update_csum(ctnat.flags) {
        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL
        update_inet_csum(ctx, ipv6hdr, l4ctx, &ctnat)?;
    }

    if !ctnat.flags.contains(EPFlags::XDP_REDIRECT) {
        // Send back the packet to the same interface
        if ctnat.flags.contains(EPFlags::XDP_TX) {
            // TODO: swap mac addresses
            stats_inc(stats::XDP_TX);
            return Ok(xdp_action::XDP_TX);
        }

        stats_inc(stats::XDP_PASS);
        return Ok(xdp_action::XDP_PASS);
    }

    // Encapsulate packet in tunnel
    if ctnat.flags.contains(EPFlags::DSR_L3) {
        ip6tnl_encap_ipv6(ctx, &l2ctx, ctnat, &ctx6.feat)?;
    }

    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };
    array_copy(macs, &ctnat.macs);

    // NOTE: This call can shrink or enlarge the packet so all pointers
    // to headers are invalidated.
    l2ctx.vlan_update(ctx, ctnat.vlan_hdr, &ctx6.feat)?;

    // In case of redirect failure just try to query the FIB again
    let action = redirect_txport(ctx, &ctx6.feat, ctnat.ifindex);

    if ctx6.feat.log_enabled(Level::Info) {
        ctx6.log.redirect_pkt(ctx, ctnat.ifindex, action);
    }

    return Ok(action);
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
    let ctx6 = unsafe { &mut *zlb_context()? };
    ctx6.feat.fetch();

    // BUG: aya: Can't move L4Context to the per-cpu heap Context yet (kernel 6.1)
    // due to verifier as it has an issue with modifying a field in l4ctx and then
    // doing math with context pointer, for e.g. getting a pointer to the L4 header:
    // "math between pkt pointer and register with unbounded min value is not allowed"
    // https://elixir.bootlin.com/linux/v6.1.119/source/kernel/bpf/verifier.c#L8116
    let mut l4ctx = L4Context::new_for_ipv6(&l2ctx, ipv6hdr.next_hdr);

    for _ in 0..4 {
        match l4ctx.next_hdr {
            IpProto::Tcp => {
                l4ctx.set_tcp(ctx)?;
                break;
            }
            IpProto::Udp => {
                l4ctx.set_udp(ctx)?;
                break;
            }
            IpProto::Ipv6Icmp => {
                let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4ctx.offset)?;
                let icmphdr = unsafe { &*icmphdr };

                l4ctx.check_offset(offset_of!(IcmpHdr, checksum));

                match icmphdr.type_ {
                    icmpv6::ND_ADVERT | icmpv6::ND_SOLICIT => {
                        return neighbor_solicit(ctx, &l2ctx, ipv6hdr, &l4ctx, &ctx6.feat)
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
                    icmpv6::ECHO_REQUEST => unsafe {
                        l4ctx.src_port = icmphdr.un.echo.id as u32;
                        l4ctx.dst_port = icmphdr.un.echo.sequence as u32;
                    },
                    // On ICMP reply use the echo id destination port
                    icmpv6::ECHO_REPLY => unsafe {
                        l4ctx.dst_port = icmphdr.un.echo.id as u32;
                        l4ctx.src_port = icmphdr.un.echo.sequence as u32;
                        // If this is a ICMP reply that is not expected and not tracked
                        // then just pass it to the stack. Most likely the echo request
                        // was initiated from another source.
                        l4ctx.set_flag(L4Context::PASS_UNKNOWN_REPLY);
                    },

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

                if ctx6.feat.log_enabled(Level::Info) {
                    ctx6.log.frag_exthdr(ctx, exthdr);
                }
                stats_inc(stats::IPV6_FRAGMENTS);

                match ctx6.frag.search6(ipv6hdr, exthdr, &mut l4ctx) {
                    Some(found) => {
                        if found {
                            // The fragment was identified as tracked flow
                            break;
                        } else {
                            // Continue to process the next header
                        }
                    }
                    None => {
                        // Unknown fragment or legit non-LB fragment
                        stats_inc(stats::IPV6_UNKNOWN_FRAGMENTS);
                        return Ok(xdp_action::XDP_PASS);
                    }
                }
            }
            _ => {
                // This includes also IpProto::Ipv6NoNxt
                break;
            }
        };
    }

    if ctx6.feat.log_enabled(Level::Info) {
        ctx6.log.init(&l4ctx);
        ctx6.log.ipv6_packet(ctx, ipv6hdr);
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
    // * to get an idea of the amount of stack the app used just generate a verifier
    // error like accessing a packet pointer without checking.

    ctx6.sv.now = coarse_ktime();
    ctx6.sv.pkt_len = (ctx.data_end() - ctx.data() - l2ctx.ethlen) as u32;

    ctx6.ct6key.init(&ipv6hdr, &l4ctx);

    if let Some(ctnat) = unsafe { ZLB_CT6_CACHE.get(&ctx6.ct6key) } {
        if ctnat.time > ctx6.sv.now {
            if ctx6.sv.pkt_len > ctnat.mtu {
                return send_ptb(ctx, &l2ctx, ipv6hdr, ctnat.mtu);
            } else {
                return ct6_handler(ctx, &l2ctx, &l4ctx, ipv6hdr, ctnat, ctx6);
            }
        }
    }

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

    // NOTE: using ctx6 to directly modify the NAT6 key will generate
    // a borrower error because the ctx6 var is already borrowed as mut.
    ctx6.nat.init_v6key(ipv6hdr, &l4ctx);

    if let Some(nat) = unsafe { ZLB_CONNTRACK6.get(&ctx6.nat.v6key) } {
        if ctx6.sv.pkt_len > nat.mtu as u32 {
            return send_ptb(ctx, &l2ctx, ipv6hdr, nat.mtu as u32);
        }

        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        if !ctx6.feat.log_enabled(Level::Info) {
            ctx6.log.reply_nat6(ctx, &nat);
        }

        // Save fragment before updating addresses
        ctx6.frag.cache6(&l4ctx);

        // TBD: for crc32 use crc32_off

        // Set the port combo and src/dst addresses before updating the
        // IP protocol inet checsum.
        ctx6.ctnat.port_combo = l4ctx.dst_port << 16 | nat.port_lb as u32;

        array_copy(&mut ctx6.ctnat.src_addr, unsafe { &nat.lb_ip.addr32 });
        array_copy(&mut ctx6.ctnat.dst_addr, unsafe { &nat.ip_src.addr32 });

        if do_update_csum(nat.flags) {
            update_inet_csum(ctx, ipv6hdr, &l4ctx, &ctx6.ctnat)?;
        }

        ctx6.ctnat.time = ctx6.sv.now + 30;
        ctx6.ctnat.flags = nat.flags;
        ctx6.ctnat.mtu = nat.mtu as u32;
        ctx6.ctnat.ifindex = nat.ifindex;
        ctx6.ctnat.vlan_hdr = nat.vlan_hdr;
        array_copy(&mut ctx6.ctnat.macs, &nat.mac_addresses);

        let _ = ZLB_CT6_CACHE.insert(&ctx6.ct6key, &ctx6.ctnat, /* update or insert */ 0);

        if !ctx6.ctnat.flags.contains(EPFlags::XDP_REDIRECT) {
            if ctx6.ctnat.flags.contains(EPFlags::XDP_TX) {
                stats_inc(stats::XDP_TX);
                return Ok(xdp_action::XDP_TX);
            }

            stats_inc(stats::XDP_PASS);
            return Ok(xdp_action::XDP_PASS);
        }

        // NOTE: BUG: don't use the implicit array copy (*a = mac;)
        // as aya will generate code that will throw the `relocation function` error
        // during the program load.
        let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
        let macs = unsafe { &mut *macs };
        array_copy(macs, &ctx6.ctnat.macs);

        // NOTE: After this call all references derived from ctx must be recreated
        // since this method can change the packet limits.
        // This function is a no-op if no VLAN translation is needed.
        l2ctx.vlan_update(ctx, ctx6.ctnat.vlan_hdr, &ctx6.feat)?;

        let action = redirect_txport(ctx, &ctx6.feat, ctx6.ctnat.ifindex);

        if ctx6.ctnat.flags.contains(EPFlags::XDP_TX) && action == xdp_action::XDP_REDIRECT {
            stats_inc(stats::XDP_REDIRECT_FULL_NAT);
        }

        if ctx6.feat.log_enabled(Level::Info) {
            ctx6.log.redirect_pkt(ctx, ctx6.ctnat.ifindex, action);
        }

        return Ok(action);
    }

    // === request ===

    // Don't search for a backend group that when the packet is actually
    // a "reply" message and it is not tracked.
    if l4ctx.get_flag(L4Context::PASS_UNKNOWN_REPLY) {
        if l4ctx.get_flag(L4Context::CACHE_FRAG) {
            stats_inc(stats::IPV6_UNKNOWN_FRAGMENTS);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    let be = {
        ctx6.ep6key.address = ctx6.nat.v6key.ip_lb_dst;
        // ICMP backend groups are searched using the IP and protocol id
        if l4ctx.next_hdr == IpProto::Ipv6Icmp {
            ctx6.ep6key.port = 0;
        } else {
            ctx6.ep6key.port = l4ctx.dst_port as u16;
        }
        ctx6.ep6key.proto = l4ctx.next_hdr as u16;
        match unsafe { ZLB_LB6.get(&ctx6.ep6key) } {
            Some(group) => {
                ctx6.sv.becount = group.becount;
                ctx6.bekey.gid = group.gid;

                if ctx6.feat.log_enabled(Level::Info) {
                    ctx6.log.show_begroup(ctx, group)
                }
            }
            None => {
                if ctx6.feat.log_enabled(Level::Info) {
                    ctx6.log.log_info(ctx, "no LB found");
                }
                // *** This is the exit point for non-LB packets ***
                // These packets are not counted as they are not destined
                // to any backend group. By counting them would mean that
                // XDP_PASS would by far the outlier and would prevent
                // knowing which packets were actually modified.
                return Ok(xdp_action::XDP_PASS);
            }
        };

        if ctx6.sv.becount == 0 {
            stats_inc(stats::XDP_PASS);
            stats_inc(stats::LB_ERROR_NO_BE);
            return Ok(xdp_action::XDP_PASS);
        }

        ctx6.bekey.index = (inet6_hash16(unsafe { &ipv6hdr.src_addr.in6_u.u6_addr32 })
            ^ l4ctx.src_port as u16)
            % ctx6.sv.becount;

        match unsafe { ZLB_BACKENDS.get(&ctx6.bekey) } {
            Some(be) => be,
            None => {
                if ctx6.feat.log_enabled(Level::Error) {
                    ctx6.log.no_backend_error(ctx, &ctx6.bekey);
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

    if ctx6.feat.log_enabled(Level::Info) {
        ctx6.log.show_backend6(ctx, &be, &ctx6.bekey);
    }

    ctx6.frag.cache6(&l4ctx);

    ctx6.ctnat.port_combo = (be.port as u32) << 16 | l4ctx.src_port;

    // Fast exit if packet is not redirected
    if !be.flags.contains(EPFlags::XDP_REDIRECT) {
        update_destination_inet_csum(ctx, ipv6hdr, &l4ctx, &be.address, ctx6.ctnat.port_combo)?;

        // Send back the packet to the same interface
        if be.flags.contains(EPFlags::XDP_TX) {
            // TODO: swap eth addresses
            stats_inc(stats::XDP_TX);
            return Ok(xdp_action::XDP_TX);
        }

        stats_inc(stats::XDP_PASS);
        return Ok(xdp_action::XDP_PASS);
    }

    // Initialize src/dst addresses before FIB lookup as the
    // fetch_fib6() uses these fields from this struct.
    ctx6.ctnat.init_from_be(&be, ipv6hdr);
    ctx6.ctnat.time = ctx6.sv.now + 30;

    // The following fields are initialized for FIB lookup and
    // then overridden after the search
    ctx6.ctnat.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    ctx6.ctnat.mtu = ctx6.sv.pkt_len;
    ctx6.ctnat.iph[0] = ipv6hdr.priority() as u32;

    // NOTE: Check if packet can be redirected and it does not exceed the interface MTU
    // TODO: make fetch_fib6() update the ctnat and return only fib_rc
    let fib = ctx6.fetch_fib6(ctx)?;

    ctx6.ctnat.init_from_fib(fib);

    match ctx6.fib.rc {
        bindings::BPF_FIB_LKUP_RET_SUCCESS => {
            if ctx6.sv.pkt_len > ctx6.ctnat.mtu {
                /* send packet to big */
                return send_ptb(ctx, &l2ctx, ipv6hdr, ctx6.ctnat.mtu);
            }
        }
        bindings::BPF_FIB_LKUP_RET_FRAG_NEEDED => {
            /* send  packet to big */
            return send_ptb(ctx, &l2ctx, ipv6hdr, ctx6.ctnat.mtu);
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

    if ctx6.ctnat.flags.contains(EPFlags::DSR_L3) {
        // For L3 DSR the destination address is the tunnel address
        // from the backend netns.
        array_copy(&mut ctx6.ctnat.dst_addr, &(be.alt_address));
        ctx6.ctnat.init_ip6ip6(&ipv6hdr);
        ip6tnl_encap_ipv6(ctx, &l2ctx, &ctx6.ctnat, &ctx6.feat)?;
    } else if do_update_csum(ctx6.ctnat.flags) {
        update_inet_csum(ctx, ipv6hdr, &l4ctx, &ctx6.ctnat)?;
    }

    // NOTE: look like aya can't convert the '*eth = entry.macs' into
    // a 3 load instructions block that doesn't panic the bpf verifier
    // with 'invalid access to packet'. The same statement when modifying
    // stack data passes the verifier check.

    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };

    if !ctx6.ctnat.flags.contains(EPFlags::DSR_L3) {
        ctx6.nat.v6info.mac_addresses = [
            macs[2] << 16 | macs[1] >> 16,
            macs[0] << 16 | macs[2] >> 16,
            macs[1] << 16 | macs[0] >> 16,
        ];
        // Save the VLAN header here before removing it below
        ctx6.nat.v6info.vlan_hdr = l2ctx.vlanhdr;
    }

    array_copy(macs, &ctx6.ctnat.macs);

    // TODO: use the vlan info from fib lookup to update the frame vlan.
    // Till then assume we redirect to backends outside of any VLAN.
    // NOTE: This call can shrink or enlarge the packet so all pointers
    // to headers are invalidated.
    l2ctx.vlan_update(ctx, 0, &ctx6.feat)?;

    // In case of redirect failure just try to query the FIB again
    let action = redirect_txport(ctx, &ctx6.feat, ctx6.ctnat.ifindex);

    if ctx6.feat.log_enabled(Level::Info) {
        ctx6.log.redirect_pkt(ctx, ctx6.ctnat.ifindex, action);
    }

    /* === connection tracking === */

    // NOTE: Add conntrack cache entry to skip searching for the group,
    // the backend and the fib entry that provides the neighbor
    // mac address.
    // NOTE: Since the cache is a per CPU map the insert with flags=0
    // will update only the value for the current CPU.
    // NOTE: the source address is actually the lb_addr and
    // it is copied above when checking the redirect flag
    // The destination addr is copyied above.
    // array_copy(&mut ctx6.ctnat.dst_addr, &(be.address));
    // The ctx6.ctnat.port_combo is set above before recomputing the csum

    let _ = ZLB_CT6_CACHE.insert(&ctx6.ct6key, &ctx6.ctnat, /* update or insert */ 0);

    // There is no need to conntrack the L3 DSR flow
    if !ctx6.ctnat.flags.contains(EPFlags::DSR_L3) {
        ctx6.nat.updatev6(ctx, &l4ctx, &ctx6.ctnat);
        if ctx6.feat.log_enabled(Level::Info) {
            ctx6.log.conntrack6(ctx, &ctx6.nat);
        }
    }

    Ok(action)
}

/// This buffer must hold any IPv6 per-fragment header extentions plus
/// the largest supported protocol header.For now Tcp has the biggest header.
/// TODO: Make these values configurable to be able to handle multiple stacked
/// IPv6 extension headers.
const MAX_HDR_EXT: usize = 4 * 8; // Up to 4 per-fragment headers
const MAX_HDR_PROTO: usize = TcpHdr::LEN; // 40B
pub type Icmpv6ProtoHdr = [u32; (MAX_HDR_EXT + MAX_HDR_PROTO) >> 2];

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
    protohdr: Icmpv6ProtoHdr,
}

const PTB_SIZE: u32 = mem::size_of::<Icmpv6Ptb>() as u32;
const PTB_WSIZE: usize = (PTB_SIZE >> 2) as usize;

fn send_ptb(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    ipv6hdr: &mut Ipv6Hdr,
    size: u32,
) -> Result<u32, ()> {
    let ctx6 = unsafe { &mut *zlb_context()? };

    if ctx6.feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "PTB, actual:{} max:{}",
            ipv6hdr.payload_len.to_be(),
            size
        );
    }

    // NOTE: the bellow pointer getter are unlikely to fail because
    // on IPv6 the minimum MTU is 1280.

    let ptb_offset = l2ctx.ethlen + Ipv6Hdr::LEN;
    let phdr = ptr_at::<Icmpv6ProtoHdr>(&ctx, ptb_offset)?;
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

    if ctx6.feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "adjust tail by delta:{}, pkt_len:{}, rc={}", delta, pkt_len, rc
        );
    }

    stats_inc(stats::ICMPV6_PTB);

    return Ok(xdp_action::XDP_TX);
}

impl BpfFibLookUp {
    fn init_inet6(&mut self, ctnat: &CTCache) {
        self.family = AF_INET6;
        self.l4_protocol = 0;
        self.sport = 0;
        self.dport = 0;
        self.tot_len = ctnat.mtu as u16;
        self.ifindex = ctnat.ifindex;
        self.tos = ctnat.iph[0];
        array_copy(&mut self.src, &ctnat.src_addr);
        array_copy(&mut self.dst, &ctnat.dst_addr);
    }
}

impl Context {
    pub fn fetch_fib6(&mut self, ctx: &XdpContext) -> Result<&'static FibEntry, ()> {
        if let Some(entry) = unsafe { ZLB_FIB6.get(&self.ctnat.dst_addr) } {
            if self.sv.now <= (*entry).expiry {
                self.fib.rc = bindings::BPF_FIB_LKUP_RET_SUCCESS;
                return Ok(entry);
            }
        }

        // NOTE: the IPv6 header is fixed 40 bytes.
        // NOTE: the length of the IPv6 payload, i.e., the rest of the packet
        // following this IPv6 header, in octets.  (Note that any extension headers
        // (see Section 4) present are considered part of the payload,
        // i.e., included in the length count.
        // See: https://datatracker.ietf.org/doc/html/rfc8200#section-4.5

        self.fib.param.init_inet6(&self.ctnat);

        let p_fib_param = &self.fib.param as *const BpfFibLookUp;
        self.fib.rc = unsafe {
            bpf_fib_lookup(
                ctx.as_ptr(),
                p_fib_param as *mut bpf_fib_lookup_param_t,
                mem::size_of::<BpfFibLookUp>() as i32,
                0,
            ) as u32
        };

        stats_inc(stats::FIB_LOOKUPS);

        if self.feat.log_enabled(Level::Info) {
            self.log.fib_lkup_inet6(ctx, &self.fib);
        }

        self.fib.init_entry(self.sv.now);

        // NOTE: The result is always cached even if the lookup returned an error or
        // it couldn't obtain the MAC addresses.

        // NOTE: after updating the value or key struct size must remove the pinned map
        // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
        match unsafe { ZLB_FIB6.insert(&self.ctnat.dst_addr, &self.fib.entry, 0) } {
            Ok(()) => {}
            Err(_) => {
                stats_inc(stats::FIB_ERROR_UPDATE);
                return Err(());
            }
        }

        match unsafe { ZLB_FIB6.get(&self.ctnat.dst_addr) } {
            Some(entry) => Ok(entry),
            None => Err(()),
        }
    }
}

const IP6TNL_HOPLIMIT: u32 = 4;

impl CTCache {
    // Updates the first 2 words of the IPv6 header:
    //
    // 0       3              11      15              23              31
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |Version| Traffic Class |           Flow Label                  |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |         Payload Length        |  Next Header  |   Hop Limit   |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // Version = 6
    // Traffic Class = DSCP + ECN
    // Flow Label = flow label
    // Next header = IPv6 (41) or IPv6-in-IPv4 tunnelling
    // Hop limit = constant
    // The payload length will be set when the actual packet is
    // adjusted.
    fn init_ip6ip6(&mut self, ipv6hdr: &Ipv6Hdr) {
        // For now copy the DSCP and flow label
        let first = ipv6hdr as *const _ as *const u32;
        self.iph[0] = unsafe { *first };
        self.iph[1] = IP6TNL_HOPLIMIT << 24;
        self.iph[1] |= (IpProto::Ipv6 as u32) << 16;
    }

    fn init_from_be(&mut self, be: &BE, ipv6hdr: &mut Ipv6Hdr) {
        // Choose the source address for FIB lookup and use the src_ip
        // if this field is not empty. Use the LB address otherwise.
        // TODO: need to check BE.src_ip == 0 ?
        if be.src_ip[0] != 0 {
            // TODO: check the ND table and update or insert
            // smac/dmac and derived ip src and redirect ifindex
            array_copy(&mut self.src_addr, &be.src_ip);
        } else {
            array_copy(&mut self.src_addr, unsafe {
                &ipv6hdr.dst_addr.in6_u.u6_addr32
            });
        };
        array_copy(&mut self.dst_addr, &(be.address));

        // Set flags before setting the MTU
        self.flags = be.flags;
    }
}

/// RFC 2473
/// https://datatracker.ietf.org/doc/html/rfc2473
///
/// BUG: using #[inline(always)] and ebpf logger will trigger the
/// linker error aka not enough stack.
fn ip6tnl_encap_ipv6(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    ctnat: &CTCache,
    feat: &Features,
) -> Result<(), ()> {
    let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx, -(Ipv6Hdr::LEN as i32)) };

    if rc != 0 {
        if feat.log_enabled(Level::Error) {
            error!(ctx, "[ip6encap] failed adjust, rc: {}", rc);
        }
        return Err(());
    }

    let hdr = ptr_at::<[u32; 11]>(&ctx, l2ctx.ethlen - 4)?.cast_mut();
    let hdr = unsafe { &mut *hdr };

    // Copy the ethertype
    hdr[0] = (EtherType::Ipv6 as u32) << 16;

    // 1st word - constant for each connection
    hdr[1] = ctnat.iph[0];

    // 2nd word - only payload changes
    let payload = (ctx.data_end() - ctx.data() - Ipv6Hdr::LEN - l2ctx.ethlen) as u16;
    hdr[2] = ctnat.iph[1] | payload.to_be() as u32;

    // copy src/dst addresses
    for i in 0..4 {
        hdr[3 + i] = ctnat.src_addr[i];
        hdr[7 + i] = ctnat.dst_addr[i];
    }

    stats_inc(stats::IP6TNL_IPV6);

    Ok(())
}
