#![no_std]
#![no_main]

mod ipv6;

use aya_ebpf::{
    bindings::{
        self, bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_F_MMAPABLE,
        BPF_F_NO_COMMON_LRU,
    },
    helpers::{
        bpf_fib_lookup, bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_redirect,
        bpf_xdp_adjust_head, bpf_xdp_adjust_tail,
    },
    macros::{map, xdp},
    maps::{Array, DevMap, HashMap, LruHashMap, LruPerCpuHashMap, PerCpuArray},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, Level};
use core::mem::{self, offset_of};
use ebpf_rshelpers::{csum_add_u32, csum_fold_32_to_16, csum_update_u32};
use ipv6::{check_mtu, coarse_ktime, ip6tnl_encap_ipv6, ipv6_lb, CT6CacheKey, Icmpv6ProtoHdr};
use network_types::{
    eth::EthHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    runvars, stats, ArpEntry, BEGroup, BEKey, EPFlags, FibEntry, GroupInfo, Ipv4FragId,
    Ipv4FragInfo, Ipv6FragId, Ipv6FragInfo, NAT4Key, NAT4Value, NAT6Key, NAT6Value, BE, EP4, EP6,
    FIB_ENTRY_EXPIRY_INTERVAL, MAX_ARP_ENTRIES, MAX_BACKENDS, MAX_CONNTRACKS, MAX_FRAG4_ENTRIES,
    MAX_GROUPS, NEIGH_ENTRY_EXPIRY_INTERVAL,
};

const ETH_ALEN: usize = 6;

// Address families
const AF_INET: u8 = 2; // Internet IP Protocol
const AF_INET6: u8 = 10; // Internet IP Protocol// Fused variables

#[no_mangle]
static VERSION: u64 = 0;

#[no_mangle]
static FEATURES: u64 = 1;

/// Stores the program instance runtime (unfused) variables.
#[map]
static ZLB_RUNVAR: Array<u64> = Array::with_max_entries(runvars::MAX_RUNTIME_VARS, BPF_F_MMAPABLE);

/// Stores the program statistics.
/// NOTE: can't use BPF_F_MMAPABLE on BPF_MAP_TYPE_PERCPU_ARRAY. This flag is
/// available only for BPF_MAP_TYPE_ARRAY.
#[map]
static ZLB_STATS: PerCpuArray<u64> = PerCpuArray::with_max_entries(stats::MAX, 0);

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

/// Used to boost performance when redirecting the packets as the kernel will batch
/// process them. This array map is just a one-2-one with the current created interfaces.
/// The user app must initialize this map once on first program load.
#[map]
static ZLB_TXPORT: DevMap = DevMap::pinned(256, 0);

type LHM4 = LruHashMap<NAT4Key, NAT4Value>;
/// Used for IPV4 connection tracking and NAT between backend and source endpoint.
/// This map will be updated upon forwarding the packet to backend and searched
/// upon returning the backend reply.
/// NOTE: BPF_F_NO_COMMON_LRU will increase the performance but in the user space
/// the conntrack listing will be affected as there are different LRU lists per CPU.
/// NOTE: This map needs to be global for all CPUs and any programs as we don't
/// know on which interface the packet can arrive.
#[map]
static mut ZLB_CONNTRACK4: LHM4 = LHM4::pinned(MAX_CONNTRACKS, BPF_F_NO_COMMON_LRU);

type HMFIB4 = HashMap<u32, FibEntry>;
/// Fib used to cache the dest ipv4 to smac/dmac and derived source ip mapping.
/// The derived source ip is the address used as source when redirecting the
/// the packet.
#[map]
static mut ZLB_FIB4: HMFIB4 = HMFIB4::pinned(MAX_ARP_ENTRIES, 0);

type LHMARP = LruHashMap<u32, ArpEntry>;
/// The ARP table is used to answer to VLAN ARP requests mostly.
/// For non VLAN traffic the system can handle and update the
/// FIB for LB interested IPs.
#[map]
static mut ZLB_ARP: LHMARP = LHMARP::pinned(MAX_ARP_ENTRIES, 0);

/// This map is intended to track IPv4 fragments for backend connections
type FRAG4LHM = LruHashMap<Ipv4FragId, Ipv4FragInfo>;

#[map]
static mut ZLB_FRAG4: FRAG4LHM = FRAG4LHM::pinned(MAX_FRAG4_ENTRIES, 0);

// TODO: collect errors and put them into an lru error queue or map

// In order to avoid exhausting the 512B ebpf program stack by allocating
// diferent large objects (especially for IPv6 path) one common workaround
// is to use a per cpu (avoids concurrency) struct that contains all the
// objects that can be created on any program execution path.
#[repr(C)]
struct Context {
    feat: Features,
    log: Log,
    ct6key: CT6CacheKey,
    ctnat: CTCache,
    ep6key: EP6,
    ep4key: EP4,
    bekey: BEKey,
    nat: NAT,
    fib: FIBLookUp,
    frag: IpFragment,
    redirect: Redirect,
    ptbprotohdr: Icmpv6ProtoHdr,
    sv: StackVars,
}

#[map]
static mut ZLB_CONTEXT: PerCpuArray<Context> = PerCpuArray::with_max_entries(1, 0);

fn zlb_context() -> Result<*mut Context, ()> {
    unsafe { ZLB_CONTEXT.get_ptr_mut(0).ok_or(()) }
}

fn array_copy<T: Clone + Copy, const N: usize>(to: &mut [T; N], from: &[T; N]) {
    for i in 0..N {
        to[i] = from[i];
    }
}

#[repr(C)]
struct FIBLookUp {
    param: BpfFibLookUp,
    entry: FibEntry,
    rc: u32,
}

#[repr(C)]
struct Redirect {
    /// The interface index to redirect the packet.
    ifindex: u32,
    /// After a successful  redirect this should be XDP_REDIRECT.
    /// Any other value means that there was an error with redirect.
    action: xdp_action::Type,
}

// Instead of saving data on stack use this heap memory for unrelated
// variables. Add here result codes, return values saved IP addresses
// or any computed values for current packet.
#[repr(C)]
struct StackVars {
    /// Stores the last return code of the last function call
    ret_code: i64,
    /// Holds the current timestamp
    now: u32,
    /// The packet length
    pkt_len: u32,
    /// Backend count
    becount: u16,
}

#[repr(C)]
struct IpFragment {
    v6id: Ipv6FragId,
    v6inf: Ipv6FragInfo,
    v4id: Ipv4FragId,
    v4inf: Ipv4FragInfo,
}

struct Features {
    log_level: u64,
}

impl Features {
    fn new() -> Self {
        let log_level = if FEATURES == 0 {
            0
        } else {
            match ZLB_RUNVAR.get(runvars::LOG_FILTER) {
                None => 0,
                Some(rvlevel) => *rvlevel,
            }
        };
        Self { log_level }
    }

    fn fetch(&mut self) {
        self.log_level = if FEATURES == 0 {
            0
        } else {
            match ZLB_RUNVAR.get(runvars::LOG_FILTER) {
                None => 0,
                Some(rvlevel) => *rvlevel,
            }
        };
    }

    #[inline(always)]
    fn log_enabled(&self, level: Level) -> bool {
        self.log_level >= level as u64
    }
}

pub mod icmpv4 {
    pub const ECHO_REPLY: u8 = 0_u8;
    pub const ECHO_REQUEST: u8 = 8_u8;
}

#[inline(always)]
fn stats_inc(idx: u32) {
    if let Some(ctr) = ZLB_STATS.get_ptr_mut(idx) {
        unsafe {
            *ctr += 1;
        }
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let offset = ctx.data() + offset;

    if offset + mem::size_of::<T>() <= ctx.data_end() {
        return Ok(offset as *const T);
    }

    Err(())
}

#[xdp]
pub fn zon_lb(ctx: XdpContext) -> u32 {
    match try_zon_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => {
            stats_inc(stats::RT_ERRORS);
            xdp_action::XDP_PASS
        }
    }
}

#[repr(u16)]
#[derive(Copy, Clone)]
pub enum EtherType {
    Ipv4 = 0x0800_u16.to_be(),
    Arp = 0x0806_u16.to_be(),
    Ipv6 = 0x86DD_u16.to_be(),
    VlanDot1Q = 0x8100_u16.to_be(),
    VlanDot1AD = 0x88A8_u16.to_be(),
    Others = 0,
}

#[repr(C, packed(2))]
#[derive(Debug, Copy, Clone)]
struct ArpHdr {
    /// Hardware address type; e.g. Ethernet 1
    htype: u16,
    /// Protocol type, same as EtherType values; e.g. 0x800 for Ipv4
    ptype: u16,
    /// Hardware address length; e.g. the Ethernet addr is 6
    hlen: u8,
    /// Protocol address length; e.g. the Ipv4 addr is 4
    plen: u8,
    /// Operation, 1 for request and 2 for reply
    oper: u16,
    /// Sender hw address
    sha: [u8; 6],
    /// Sender protocol address
    spa: u32,
    /// Target hw address
    tha: [u8; 6],
    /// Target protocol address
    tpa: u32,
}

pub fn is_8021q_hdr(vlanhdr: u32) -> bool {
    vlanhdr as u16 == EtherType::VlanDot1Q as u16
}

#[repr(C)]
pub struct L2Context {
    pub ethlen: usize,
    pub vlanhdr: u32,
}

impl L2Context {
    pub fn vlan_id(&self) -> u16 {
        ((self.vlanhdr >> 16) & 0xFFF0) as u16
    }

    pub fn has_vlan(&self) -> bool {
        is_8021q_hdr(self.vlanhdr)
    }

    pub fn vlan_offset(&self) -> usize {
        self.ethlen - mem::size_of::<EtherType>() - mem::size_of::<u32>()
    }

    fn vlan_push(&self, ctx: &XdpContext, vlanhdr: u32) -> Result<i64, ()> {
        let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx, -4) };
        let hdr = ptr_at::<[u32; 4]>(&ctx, 0)?.cast_mut();
        let hdr = unsafe { &mut *hdr };

        hdr[0] = hdr[1];
        hdr[1] = hdr[2];
        hdr[2] = hdr[3];
        hdr[3] = vlanhdr;

        Ok(rc)
    }

    fn vlan_change(&self, ctx: &XdpContext, vlanhdr: u32) -> Result<i64, ()> {
        let vhdr = ptr_at::<u32>(&ctx, self.vlan_offset())?.cast_mut();

        unsafe { *vhdr = vlanhdr };

        Ok(0)
    }

    fn vlan_pop(&self, ctx: &XdpContext) -> Result<i64, ()> {
        let hdr = ptr_at::<[u32; 4]>(&ctx, 0)?.cast_mut();
        let hdr = unsafe { &mut *hdr };

        hdr[3] = hdr[2];
        hdr[2] = hdr[1];
        hdr[1] = hdr[0];

        let rc = unsafe { bpf_xdp_adjust_head(ctx.ctx, 4 as i32) };

        Ok(rc)
    }

    /// Updates vlan header as follows:
    /// ---------------------------------
    /// l2ctx vlan | target vlan | action
    /// ---------------------------------
    ///         no |          no |   none
    ///        yes |          no |    pop
    ///        yes |         yes | update
    ///         no |         yes |   push
    /// ---------------------------------
    /// NOTE: no support for vlan on 802.ad
    fn vlan_update(&self, ctx: &XdpContext, vlanhdr: u32, feat: &Features) -> Result<(), ()> {
        let rc = if is_8021q_hdr(vlanhdr) {
            if self.has_vlan() {
                self.vlan_change(ctx, vlanhdr)
            } else {
                self.vlan_push(ctx, vlanhdr)
            }
        } else {
            if self.has_vlan() {
                self.vlan_pop(&ctx)
            } else {
                return Ok(());
            }
        }?;

        if feat.log_enabled(Level::Info) {
            info!(
                ctx,
                "[vlan] update vlan 0x{:x} -> 0x{:x}, adj_hdr rc={}",
                self.vlanhdr.to_be(),
                vlanhdr.to_be(),
                rc
            );
        }

        Ok(())
    }
}

fn is_unicast_mac(mac: &[u8; 6]) -> bool {
    *mac != [0_u8; 6] && (mac[0] & 0x1) == 0_u8
}

// BUG: bpf_linker: can't pass the Features ref as arg as the linker will throw the
// `LLVM issued diagnostic with error severity` error if it used in the match statement:
// match rc {
//    Ok(()) => if feat.log_enabled(Level::info) { info!(ctx, "ok") },
//    Err(e) => if feat.log_enabled(Level::error) { error!(ctx, "error") },
// }
// BUG: the same bpf_linker is thrown when using a  bool param and pass a local bool arg
fn update_arp_table(ctx: &XdpContext, ip: u32, vlan_id: u16, mac: &[u8; 6], eth: &EthHdr) {
    if !is_unicast_mac(mac) {
        return;
    }

    // NOTE: This won't work in promiscuous mode
    let if_mac = if is_unicast_mac(&eth.dst_addr) {
        eth.dst_addr
    } else {
        match unsafe { ZLB_ARP.get(&ip) } {
            None => [0_u8; 6],
            Some(entry) => entry.if_mac,
        }
    };

    // TODO: move ArpEntry in context and make update_arp_table() a context method

    // Set the expiry to 2 min but it can be used as last resort
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let expiry = unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32 + NEIGH_ENTRY_EXPIRY_INTERVAL;
    let mtu = check_mtu(ctx, ifindex);
    let arpentry = ArpEntry {
        ifindex,
        mac: *mac,
        if_mac,
        expiry,
        vlan_id,
        mtu,
    };
    let rc = unsafe { ZLB_ARP.insert(&ip, &arpentry, 0) };

    // BUG: the aya compiler generates code that inflates the stack above 512 bytes
    // when using a moved array like mac or if_mac. Just use the values from arpentry.
    // This happens only when writing:
    // match rc {
    //    Ok(()) => if feat.log_enabled(Level::info) { info!(ctx, "{:mac}", *mac) },
    //    Err(e) => if feat.log_enabled(Level::error) { error!(ctx, "error") },
    // }

    let feat = Features::new();
    if !feat.log_enabled(Level::Info) {
        return;
    }

    match rc {
        Ok(()) => info!(
            ctx,
            "[arp] add {:i} => {:mac}/vlan={} if:{}/{:mac}",
            ip.to_be(),
            arpentry.mac,
            (vlan_id as u16).to_be(),
            ifindex,
            arpentry.if_mac
        ),
        Err(e) => {
            if feat.log_enabled(Level::Error) {
                error!(ctx, "[arp] can't add entry for {:i}, err={}", ip.to_be(), e);
            }
        }
    }
}

//
// BUG: bpf_linker: move the logging here in order to avoid
// the linker error due to stack exhaustion.
#[inline(never)]
fn arp_snoop_log(ctx: &XdpContext, eth: &EthHdr, l2ctx: &L2Context, arphdr: &ArpHdr, way: &str) {
    info!(
        ctx,
        "[eth] [{}] if:{} vlan_id:{} {:mac} -> {:mac}",
        way,
        unsafe { (*ctx.ctx).ingress_ifindex },
        (l2ctx.vlan_id() as u16).to_be(),
        eth.src_addr,
        eth.dst_addr,
    );

    info!(
        ctx,
        "[arp] [{}] oper:{} sha={:mac} spa:{:i} tha={:mac} tpa:{:i}",
        way,
        arphdr.oper.to_be(),
        arphdr.sha,
        arphdr.spa.to_be(),
        arphdr.tha,
        arphdr.tpa.to_be()
    );
}

fn arp_snoop(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let arphdr = ptr_at::<ArpHdr>(&ctx, l2ctx.ethlen)?;
    let arphdr = unsafe { &mut *arphdr.cast_mut() };
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth = unsafe { &mut *eth.cast_mut() };
    let feat = Features::new();
    let log_on = feat.log_enabled(Level::Info);

    // TODO: add arp to stats
    // TODO: use only info! and ditch error! to generate less code
    if log_on {
        arp_snoop_log(ctx, eth, &l2ctx, arphdr, "rx");
    }

    update_arp_table(ctx, arphdr.spa, l2ctx.vlan_id(), &arphdr.sha, eth);
    update_arp_table(ctx, arphdr.tpa, l2ctx.vlan_id(), &arphdr.tha, eth);

    // For VLANs answer to requests as this LB can act as a proxy for
    // the endpoints inside VLANs. Without special routing rules the
    // ARP requests are not ignored as they pertain to a different
    // network segment.
    if !l2ctx.has_vlan()
        || arphdr.oper.to_be() != 1
        || !is_unicast_mac(&eth.src_addr)
        || !is_unicast_mac(&arphdr.sha)
    {
        if log_on {
            info!(ctx, "[arp] no vlan for tpa: {:i}", arphdr.tpa.to_be());
        }
        return Ok(xdp_action::XDP_PASS);
    }

    // NOTE: can't directly pass reference to packed(2) struct like ArpHdr even if
    // the field is 32-bit.
    let tpa = arphdr.tpa;
    let smac = match unsafe { ZLB_ARP.get(&tpa) } {
        None => return Ok(xdp_action::XDP_PASS),
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
    eth.dst_addr = eth.src_addr;
    eth.src_addr = smac;

    arphdr.tpa = arphdr.spa;
    arphdr.tha = arphdr.sha;
    arphdr.spa = tpa;
    arphdr.sha = smac;
    arphdr.oper = 2_u16.to_be();

    if log_on {
        arp_snoop_log(ctx, eth, &l2ctx, arphdr, "tx");
    }

    stats_inc(stats::ARP_REPLY);

    Ok(xdp_action::XDP_TX)
}

// TODO: check the feature flags and see if the ipv6 is enabled or not
// TODO: investigate ~1Gbits/s performance degradation on normal redirect
// and 2 netns on both IPv4 and IPv6.
// Best perf. setup: server (TCP window size:128K default), client (-w 64K)
// - disable vlan_update: no
// - disable arp: no
fn try_zon_lb(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr = ptr_at::<[EtherType; 3]>(&ctx, ETH_ALEN << 1)?;
    let eth_hdr = unsafe { &*eth_hdr };
    let mut l2ctx = L2Context {
        ethlen: EthHdr::LEN,
        vlanhdr: 0,
    };
    let mut ether_type = eth_hdr[0];

    if eth_hdr[0] as u16 == EtherType::VlanDot1Q as u16 {
        l2ctx.ethlen = EthHdr::LEN + 4;
        l2ctx.vlanhdr = ((eth_hdr[1] as u32) << 16) | (eth_hdr[0] as u32);
        ether_type = eth_hdr[2];
    }

    match ether_type {
        EtherType::Ipv4 => ipv4_lb(&ctx, l2ctx),
        EtherType::Ipv6 => ipv6_lb(&ctx, l2ctx),
        EtherType::Arp => arp_snoop(&ctx, l2ctx),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

/// Update both IP and Transport layers checksums along with the source
/// and destination addresses and ports and others like TTL.
fn update_inet_csum(
    ctx: &XdpContext,
    ipv4hdr: &mut Ipv4Hdr,
    l4ctx: &L4Context,
    ctnat: &CTCache,
) -> Result<(), ()> {
    // NOTE: since the destination IP (LB) 'remains' in the csum
    // we can recompute it as if only the source IP changes.
    // However, this optimization requires two checks that doesn't seem
    // to just simple compute the checksum anyway. Also, by not using
    // a branch instruction (if-else) there is a small increase in throughput
    // in iperf test.
    // OPTIMIZATION: compute the checksum update one time for both IP and L4
    // checksums and just update them as if some packet value was update
    // from 0 to computed checksum.
    // WARNING: This checksum seems to work for iperf but if there is
    // a case when it doesn't just use the bpftrace to investigate it.
    // See the scripts folder for bpftrace scripts.
    let mut cso = csum_update_u32(ipv4hdr.src_addr, ctnat.src_addr[0], 0);
    cso = csum_update_u32(ipv4hdr.dst_addr, ctnat.dst_addr[0], cso);

    ipv4hdr.src_addr = ctnat.src_addr[0];
    ipv4hdr.dst_addr = ctnat.dst_addr[0];

    let csum = csum_update_u32(0, cso, !ipv4hdr.check as u32);
    ipv4hdr.check = !csum_fold_32_to_16(csum);

    // For some protocols like ICMP the inet csum is computed only on the
    // L4 header and data without the IP pseudo header.
    if l4ctx.check_off == 0 {
        return Ok(());
    }

    // NOTE: Update the csum from TCP/UDP header. This csum
    // is computed from the pseudo header (e.g. addresses
    // from IP header) + header (checksum is 0) + the
    // text (payload data).
    // NOTE: in order to compute the L4 csum must use bpf_loop
    // as the verifier doesn't allow loops. Without loop support
    // can't iterate over the entire packet as the number of iterations
    // are limited; e.g. for _ 0..100 {..}
    // Recomputing the L4 csum seems to be necessary only if the packet
    // is forwarded between local interfaces.
    let check = ptr_at::<u16>(ctx, l4ctx.check_pkt_off())?.cast_mut();
    let mut csum = unsafe { !(*check) } as u32;
    csum = csum_update_u32(0, cso, csum);
    csum = csum_update_u32(
        l4ctx.dst_port << 16 | l4ctx.src_port,
        ctnat.port_combo,
        csum,
    );
    unsafe { *check = !csum_fold_32_to_16(csum) };

    let ports = ptr_at::<u32>(ctx, l4ctx.offset)?.cast_mut();
    unsafe { *ports = ctnat.port_combo };

    Ok(())
}

/// This type must hold the first 64-bit of the protocol header
/// according to RFC 1191.
type ProtoHdr = [u32; 2];

/// ICMP Datagram Too Big as mentioned in RFC 1191
///
/// When a router is unable to forward a datagram because it exceeds the
/// MTU of the next-hop network and its Don't Fragment bit is set, the
/// router is required to return an ICMP Destination Unreachable message
/// to the source of the datagram, with the Code indicating
/// fragmentation needed and DF set.  To support the Path MTU Discovery
/// technique specified in this memo, the router MUST include the MTU of
/// that next-hop network in the low-order 16 bits of the ICMP header
/// field that is labelled "unused" in the ICMP specification [7].  The
/// high-order 16 bits remain unused, and MUST be set to zero.  Thus, the
/// message has the following format:
///
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Type = 3    |   Code = 4    |           Checksum            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           unused = 0          |         Next-Hop MTU          |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |      Internet Header + 64 bits of Original Datagram Data      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// (RFC 1191)
#[repr(C)]
struct IcmpDtb {
    type_: u8,
    code: u8,
    csum: u16,
    _unused: u16,
    mtu: u16,
    /// The quoted IpV4 header is required as mentioned in RFC 1191.
    ipv4hdr: Ipv4Hdr,
    /// The quoted protocol header field is also required in order
    /// to find the connection session or process.
    protohdr: ProtoHdr,
}

const DTB_SIZE: u32 = mem::size_of::<IcmpDtb>() as u32;
const DTB_WSIZE: usize = (DTB_SIZE >> 2) as usize;
const IPV4HDR_WSIZE: usize = Ipv4Hdr::LEN >> 2;

/// Send Datagram Too Big message or ICMP destination unreachable
/// with fragment required and don't fragment IP flag on as mentioned
/// in RFC 1191 for Path MTU discovery:
///
/// See:
/// * https://datatracker.ietf.org/doc/html/rfc4884#section-4.1
/// * https://datatracker.ietf.org/doc/html/rfc792
/// * https://datatracker.ietf.org/doc/html/rfc1191
fn send_dtb(
    ctx: &XdpContext,
    ipv4hdr: &mut Ipv4Hdr,
    l4ctx: &L4Context,
    size: u16,
) -> Result<u32, ()> {
    let feat = Features::new();

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "datagram Too Big, actual:{} max:{}",
            ipv4hdr.tot_len.to_be(),
            size
        );
    }

    // Save the 64-bit part of the protocol header here
    // as the L4 offset will became irrelevant after
    // building the ICMP header.
    let phdr = ptr_at::<ProtoHdr>(&ctx, l4ctx.offset)?;
    let phdr = unsafe { *phdr };

    // Update the ICMP header
    let icmp_offset = EthHdr::LEN + Ipv4Hdr::LEN;
    let ptb = ptr_at::<IcmpDtb>(&ctx, icmp_offset)?;
    let ptb = unsafe { &mut *ptb.cast_mut() };

    // First, copy the original IPv4 header as data for the
    // ICMPv4 datagram too big message.
    ptb.ipv4hdr = *ipv4hdr;
    ptb.protohdr = phdr;

    ptb.type_ = 3; // Destination Ureachable
    ptb.code = 4; // Fragmentation required
    ptb.csum = 0; // initialize the checksum with 0
    ptb._unused = 0;
    ptb.mtu = size.to_be();

    // NOTE: The ICMPv4 checksum is required for error messages like
    // Datagram too big.
    // NOTE: ICMPv4 checksum differs from ICMPv6 one as it doesn't require
    // an initial csum built from IP pseudo header.
    let data = ptr_at::<[u32; DTB_WSIZE]>(&ctx, icmp_offset)?;
    let data = unsafe { &*data };
    let mut cs = 0_u32;
    for i in 0..DTB_WSIZE {
        cs = csum_add_u32(data[i], cs);
    }
    ptb.csum = !csum_fold_32_to_16(cs);

    // Update the Ethernet header
    let eth = ptr_at::<EthHdr>(&ctx, 0)?.cast_mut();
    let eth = unsafe { &mut *eth };
    core::mem::swap(&mut eth.src_addr, &mut eth.dst_addr);

    // Update the Ipv4 header and checksum
    core::mem::swap(&mut ipv4hdr.src_addr, &mut ipv4hdr.dst_addr);

    // Update the packet length
    let tot_len = Ipv4Hdr::LEN as u16 + DTB_SIZE as u16;
    ipv4hdr.tot_len = tot_len.to_be();

    // Update the next protocol to ICMP
    ipv4hdr.proto = IpProto::Icmp;

    // Remove id
    ipv4hdr.id = 0;

    // Add Don't Fragment flag and remove offset
    ipv4hdr.frag_off = 1 << 6;

    // The inet checksum is computed with the header csum = 0
    ipv4hdr.check = 0;
    let mut cs = 0;
    let data = ptr_at::<[u32; IPV4HDR_WSIZE]>(&ctx, EthHdr::LEN)?;
    let data = unsafe { &*data };
    for i in 0..IPV4HDR_WSIZE {
        cs = csum_add_u32(data[i], cs);
    }
    ipv4hdr.check = !csum_fold_32_to_16(cs);

    // Lastly, adjust the frame to actual ICMP PTB packet bounds
    let delta = tot_len as i32 - (ptb.ipv4hdr.tot_len.to_be() as i32);
    let rc = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };

    if feat.log_enabled(Level::Info) {
        info!(ctx, "adjust tail by delta: {}, rc={}", delta, rc,);
    }

    stats_inc(stats::ICMP_DU_FR);

    Ok(xdp_action::XDP_TX)
}

#[repr(C)]
struct Log {
    hash: u32,
    src_port_be: u16,
    dst_port_be: u16,
    next_hdr: u32,
}

impl Log {
    #[inline(never)]
    fn init(&mut self, l4ctx: &L4Context) {
        self.hash = unsafe { bpf_get_smp_processor_id() } << 16;
        self.hash |= (l4ctx.next_hdr as u32) ^ l4ctx.src_port ^ l4ctx.dst_port;
        self.next_hdr = l4ctx.next_hdr as u32;
        if (l4ctx.next_hdr == IpProto::Icmp || l4ctx.next_hdr == IpProto::Ipv6Icmp)
            && l4ctx.get_flag(L4Context::PASS_UNKNOWN_REPLY)
        {
            self.src_port_be = (l4ctx.dst_port as u16).to_be();
            self.dst_port_be = (l4ctx.src_port as u16).to_be();
        } else {
            self.src_port_be = (l4ctx.src_port as u16).to_be();
            self.dst_port_be = (l4ctx.dst_port as u16).to_be();
        };
    }

    #[inline(never)]
    fn hw_info(&self, ctx: &XdpContext) {
        info!(
            ctx,
            "[{:x}] i={} rx={}",
            self.hash,
            unsafe { (*ctx.ctx).ingress_ifindex },
            unsafe { (*ctx.ctx).rx_queue_index },
        );
    }

    #[inline(never)]
    fn ipv4_packet(&self, ctx: &XdpContext, ipv4hdr: &Ipv4Hdr) {
        self.hw_info(ctx);
        info!(
            ctx,
            "[{:x}] p={} {:i}:{} -> {:i}:{}",
            self.hash,
            self.next_hdr,
            ipv4hdr.src_addr.to_be(),
            self.src_port_be,
            ipv4hdr.dst_addr.to_be(),
            self.dst_port_be,
        );
        info!(
            ctx,
            "[{:x}] tot_len={}, id=0x{:x}, off=0x{:x}",
            self.hash,
            ipv4hdr.tot_len.to_be(),
            ipv4hdr.id.to_be(),
            ipv4hdr.frag_off.to_be() & 0x1fff
        );

        if IpProto::Icmp == ipv4hdr.proto {
            self.log_icmp(ctx);
        }
    }

    #[inline(never)]
    fn log_icmp(&self, ctx: &XdpContext) {
        info!(
            ctx,
            "[{:x}] icmp id: 0x{:x} seq: 0x{:x}", self.hash, self.src_port_be, self.dst_port_be,
        );
    }

    #[inline(never)]
    fn log_info(&self, ctx: &XdpContext, text: &str) {
        info!(ctx, "[{:x}] {}", self.hash, text);
    }

    #[inline(never)]
    fn conntrack4(&self, ctx: &XdpContext, nat: &NAT) {
        info!(
            ctx,
            "[{:x}] [ctrk] [{:i}]:{} vlanhdr: {:x}, rc={}",
            self.hash,
            nat.v4info.ip_src.to_be(),
            self.src_port_be,
            nat.v4info.vlan_hdr.to_be(),
            nat.ret_code
        );
    }

    #[inline(never)]
    fn fib_lkup_inet(&self, ctx: &XdpContext, fib: &FIBLookUp) {
        info!(
            ctx,
            "[{:x}] [fib] lkp_ret: {}, fw if: {}, src: {:i}, \
            gw: {:i}, dmac: {:mac}, smac: {:mac}, mtu: {}",
            self.hash,
            fib.rc,
            fib.param.ifindex,
            fib.param.src[0].to_be(),
            fib.param.dst[0].to_be(),
            fib.param.dest_mac(),
            fib.param.src_mac(),
            fib.param.tot_len
        );
    }

    #[inline(never)]
    fn show_backend(&self, ctx: &XdpContext, be: &BE, bekey: &BEKey) {
        info!(
            ctx,
            "[{:x}] [bknd] [{}:{}] {:i}:{}",
            self.hash,
            bekey.gid,
            bekey.index,
            be.address[0].to_be(),
            be.port.to_be()
        );
    }

    #[inline(never)]
    fn show_begroup(&self, ctx: &XdpContext, beg: &BEGroup) {
        info!(
            ctx,
            "[{:x}] [group] [{}] count={}", self.hash, beg.gid, beg.becount
        );
    }

    #[inline(never)]
    fn no_backend_error(&self, ctx: &XdpContext, bekey: &BEKey) {
        error!(
            ctx,
            "[{:x}] [bknd] [{}:{}] not found", self.hash, bekey.gid, bekey.index
        );
    }

    #[inline(never)]
    fn reply_nat4(&self, ctx: &XdpContext, nat: &NAT4Value) {
        info!(
            ctx,
            "[{:x}] [nat] src={:i} lb_port={}",
            self.hash,
            nat.ip_src.to_be(),
            (nat.port_lb as u16).to_be()
        );
    }

    #[inline(never)]
    fn redirect_xmit(&self, ctx: &XdpContext, redirect: &Redirect, tag: &str) {
        info!(
            ctx,
            "[{:x}] [redirect] {} oif={} action={} eaction={}",
            self.hash,
            tag,
            redirect.ifindex,
            redirect.action,
            Redirect::EACTION,
        );
    }
}

impl IpFragment {
    fn search4(&mut self, ipv4hdr: &Ipv4Hdr, l4ctx: &mut L4Context) -> Option<bool> {
        /// Matches the IPv4 more fragments (MF) flag in the u16 following
        /// big-endian value combo: 0b[1111_1111][0 DF MF 1_1111]
        const MORE_FRAGMENTS: u32 = 1 << 5;

        /// Matches the IPv4 fragment offset
        const FRAGMENT_OFFSET: u32 = 0xFF1F;

        /// Matches the IPv4 fragment offset and MF flag
        const FRAGMENT_MATCH: u32 = FRAGMENT_OFFSET | MORE_FRAGMENTS;

        // NOTE: For fragments, the L4 data (ports, sequences, etc.) must be obtained
        // from L4 info cache. The exception is the first fragment in the sequence
        // at offset 0 which contains the L4 info and it is used to update the L4 cache
        // for the next fragments.
        // NOTE: The fragment offset field layout is like this:
        // 0b[1111_1111][0 DF MF 1_1111]
        // NOTE: Most packets are not fragments so must exit faster if MF (more fragments)
        // flag is unset and/or fragment offset is not 0
        if ((ipv4hdr.frag_off as u32) & FRAGMENT_MATCH) == 0 {
            // Not a fragment: continue process the packet
            return None;
        }

        stats_inc(stats::IP_FRAGMENTS);

        self.v4id.id = ipv4hdr.id;
        self.v4id.proto = ipv4hdr.proto as u16;
        self.v4id.src = ipv4hdr.src_addr;
        self.v4id.dst = ipv4hdr.dst_addr;

        // NOTE: The 1st fragment has offset '0x0' and MF flag set.
        if (ipv4hdr.frag_off & 0xFF1F) == 0 {
            l4ctx.set_flag(L4Context::CACHE_FRAG);
            // Must cache the first fragment and continue process the packet
            return None;
        }

        // 2nd..N fragment
        match unsafe { ZLB_FRAG4.get(&self.v4id) } {
            // Legit or untracked fragment
            None => Some(false),
            Some(frag) => {
                // No need to process the L4 header as this fragment is tracked
                l4ctx.set_from_ipv4_frag(frag);
                Some(true)
            }
        }
    }

    // NOTE: only the first fragment containing the L4 header is cached
    fn cache4(&mut self, l4ctx: &L4Context) {
        if !l4ctx.get_flag(L4Context::CACHE_FRAG) {
            return;
        }

        self.v4inf.src_port = l4ctx.src_port as u16;
        self.v4inf.dst_port = l4ctx.dst_port as u16;
        self.v4inf.reserved = l4ctx.flags;

        match unsafe { ZLB_FRAG4.insert(&self.v4id, &self.v4inf, 0) } {
            Ok(()) => {}
            Err(_) => stats_inc(stats::IP_FRAGMENT_ERRORS),
        }
    }
}

#[repr(C)]
struct NAT {
    v6key: NAT6Key,
    v6info: NAT6Value,
    v4key: NAT4Key,
    v4info: NAT4Value,
    ret_code: i64,
}

impl NAT {
    fn init_v4key(&mut self, ipv4hdr: &Ipv4Hdr, l4ctx: &L4Context) {
        self.v4key.proto = ipv4hdr.proto as u32;
        self.v4key.ip_be_src = ipv4hdr.src_addr;
        self.v4key.ip_lb_dst = ipv4hdr.dst_addr;

        if l4ctx.next_hdr == IpProto::Icmp {
            // NOTE: Must differentiate between the request and reply flows
            // but also use the cached entry for fragments and echo messages
            // that share the same sequence id.
            if l4ctx.get_flag(L4Context::PASS_UNKNOWN_REPLY) {
                self.v4key.port_be_src = 0;
                self.v4key.port_lb_dst = l4ctx.dst_port as u16;
            } else {
                self.v4key.port_be_src = l4ctx.src_port as u16;
                self.v4key.port_lb_dst = 0;
            }
        } else {
            self.v4key.port_be_src = l4ctx.src_port as u16;
            self.v4key.port_lb_dst = l4ctx.dst_port as u16;
        }
    }

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
    fn updatev4(&mut self, ctx: &XdpContext, l4ctx: &L4Context, ctnat: &CTCache) {
        self.v4info.ip_src = self.v4key.ip_be_src;
        self.v4info.lb_ip = self.v4key.ip_lb_dst;

        if ctnat.flags.contains(EPFlags::DSR_L2) {
            // NOTE: for DSR L2 the reply flow will search for source as current destination
            // and destination as current source.
            self.v4key.ip_be_src = self.v4info.lb_ip;
            self.v4key.ip_lb_dst = self.v4info.ip_src;
            self.v4key.port_be_src = l4ctx.dst_port as u16;
            self.v4key.port_lb_dst = l4ctx.src_port as u16;
        } else {
            self.v4key.ip_be_src = ctnat.dst_addr[0]; //  be_addr;
            self.v4key.ip_lb_dst = ctnat.src_addr[0]; // lb_addr;
            if l4ctx.next_hdr == IpProto::Icmp {
                // For ICMP flow the echo id and sequence number are saved as
                // source and destination port in L4Context. However, the ICMP
                // reply will has the same echo id and sequence number as the
                // request. In order to distinguish the request from the reply
                // we must swap the two values.
                self.v4key.port_be_src = l4ctx.dst_port as u16;
            } else {
                self.v4key.port_be_src = (ctnat.port_combo >> 16) as u16; //be.port;
            }
            // NOTE: the LB will use the source port since there can be multiple
            // connection to the same backend and it needs to track all of them.
            // NOTE: On ICMP request is set with the echo id.
            self.v4key.port_lb_dst = l4ctx.src_port as u16;
        }

        self.v4info.port_lb = l4ctx.dst_port as u16;
        self.v4info.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
        self.v4info.mtu = check_mtu(ctx, self.v4info.ifindex);
        self.v4info.flags = ctnat.flags;
        // NOTE: the original MAC addresses and VLAN header are cached right before redirect

        // TBD: use lock or atomic update ?
        // TBD: use BPF_F_LOCK ?

        self.ret_code = match unsafe { ZLB_CONNTRACK4.insert(&self.v4key, &self.v4info, 0) } {
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

#[repr(C)]
struct L4Context {
    offset: usize,
    check_off: usize,
    src_port: u32,
    dst_port: u32,
    /// bit_0: cache current fragment
    flags: u32,
    next_hdr: IpProto,
}

impl L4Context {
    /// Cache current fragment flag bit
    const CACHE_FRAG: u32 = 1;

    /// Set this flag in order to pass the packet when there is no
    /// conntrack entry and the packet is identified as a reply
    /// message, for e.g. ICMP echo reply.
    const PASS_UNKNOWN_REPLY: u32 = 2;

    fn new_for_ipv4(l2ctx: &L2Context, ipv4hdr: &Ipv4Hdr) -> Self {
        Self {
            // NOTE: compute the l4 header start based on ipv4hdr.IHL
            offset: l2ctx.ethlen + ((ipv4hdr.ihl() as usize) << 2),
            check_off: 0,
            src_port: 0,
            dst_port: 0,
            flags: 0,
            next_hdr: ipv4hdr.proto,
        }
    }

    fn check_pkt_off(&self) -> usize {
        self.offset + self.check_off
    }

    fn check_offset(&mut self, off: usize) {
        self.check_off = off;
    }

    fn port_combo(&self) -> u32 {
        self.src_port << 16 | self.dst_port
    }

    fn set_tcp(&mut self, ctx: &XdpContext) -> Result<(), ()> {
        let tcphdr = ptr_at::<TcpHdr>(&ctx, self.offset)?;
        self.check_offset(offset_of!(TcpHdr, check));
        self.src_port = unsafe { (*tcphdr).source } as u32;
        self.dst_port = unsafe { (*tcphdr).dest } as u32;
        Ok(())
    }

    fn set_udp(&mut self, ctx: &XdpContext) -> Result<(), ()> {
        let udphdr = ptr_at::<UdpHdr>(&ctx, self.offset)?;
        self.check_off = offset_of!(UdpHdr, check);
        self.src_port = unsafe { (*udphdr).source } as u32;
        self.dst_port = unsafe { (*udphdr).dest } as u32;
        Ok(())
    }

    fn set_from_ipv4_frag(&mut self, frag: &Ipv4FragInfo) {
        // No need to set the checksum offset as for IP fragments
        // there is no checksum except the first one.
        self.src_port = frag.src_port as u32;
        self.dst_port = frag.dst_port as u32;
        self.flags = frag.reserved;
    }

    fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }

    fn get_flag(&self, flag: u32) -> bool {
        (self.flags & flag) == flag
    }
}

const IPH_SIZE: usize = 2;

#[repr(C)]
#[derive(Copy, Clone)]
struct CTCache {
    time: u32,
    /// Backend flags merged with conntrack ones
    flags: EPFlags,
    /// Used to hold the MTU for interface denited by ifindex.
    /// For FIB lookup it holds the packet payload.
    mtu: u32,
    /// The IP header space is used in L3 DSR mode to
    /// fill the outer IP header.
    /// For FIB lookup the iph[0] contains the Type of Service (ToS)
    // or the priority.
    iph: [u32; IPH_SIZE],
    /// The source address to change in current packet IP header.
    /// For FIB lookup it holds the source address.
    src_addr: [u32; 4],
    /// The dest address to change in current packet IP header.
    /// For FIB lookup it holds the dest address.
    dst_addr: [u32; 4],
    port_combo: u32,
    /// The interface to reditect the packet.
    /// For FIB lookup holds the current interface index.
    ifindex: u32,
    macs: [u32; 3],
    vlan_hdr: u32,
}

#[map]
static ZLB_CT4_CACHE: LruPerCpuHashMap<NAT4Key, CTCache> =
    LruPerCpuHashMap::with_max_entries(256, BPF_F_NO_COMMON_LRU);

fn ct4_handler(
    ctx: &XdpContext,
    l2ctx: &L2Context,
    l4ctx: &L4Context,
    ipv4hdr: &mut Ipv4Hdr,
    ctnat: &CTCache,
    ctx4: &mut Context,
) -> Result<u32, ()> {
    stats_inc(stats::PACKETS);

    // NOTE: No need to save fragment because this handler is called
    // after the main flows (request & response) caches this conntrack
    // cache handler.

    if do_update_csum(ctnat.flags) {
        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL
        update_inet_csum(ctx, ipv4hdr, &l4ctx, &ctnat)?;
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

    // === redirect path ===

    // Encapsulate packet in tunnel
    if ctnat.flags.contains(EPFlags::DSR_L3) {
        ip6tnl_encap_ipv6(ctx, &l2ctx, ctnat, &ctx4.feat)?;
    }

    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };
    array_copy(macs, &ctnat.macs);

    // NOTE: This call can shrink or enlarge the packet so all pointers
    // to headers are invalidated.
    l2ctx.vlan_update(ctx, ctnat.vlan_hdr, &ctx4.feat)?;

    ctx4.redirect.xmit_port(ctnat.ifindex);

    if ctx4.feat.log_enabled(Level::Info) {
        ctx4.log.redirect_xmit(ctx, &ctx4.redirect, "[cache]");
    }

    return Ok(ctx4.redirect.action);
}

// TODO: check if moving the XdpContext boosts performance
fn ipv4_lb(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv4hdr = unsafe { &mut *ipv4hdr.cast_mut() };
    let mut l4ctx = L4Context::new_for_ipv4(&l2ctx, ipv4hdr);
    let ctx4 = unsafe { &mut *zlb_context()? };

    ctx4.feat.fetch();

    match ctx4.frag.search4(ipv4hdr, &mut l4ctx) {
        Some(found) => {
            if found {
                // The fragment was identified
            } else {
                stats_inc(stats::IPV4_UNKNOWN_FRAGMENTS);
                // Pass the fragment if is not tracked
                return Ok(xdp_action::XDP_PASS);
            }
        }
        None => {
            match ipv4hdr.proto {
                IpProto::Tcp => l4ctx.set_tcp(ctx)?,
                IpProto::Udp => l4ctx.set_udp(ctx)?,
                IpProto::Icmp => {
                    // Handle ICMP echo request / reply to track only messages that
                    // are handled by LB.
                    //  0                   1                   2                   3
                    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |     Type      |      Code     |          Checksum             |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // |           Identifier          |        Sequence Number        |
                    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                    // See  https://datatracker.ietf.org/doc/html/rfc792
                    let icmphdr = ptr_at::<IcmpHdr>(&ctx, l4ctx.offset)?;
                    let icmphdr = unsafe { &*icmphdr };
                    match icmphdr.type_ {
                        icmpv4::ECHO_REQUEST => unsafe {
                            // On ICMP request use the echo id as source port
                            l4ctx.src_port = icmphdr.un.echo.id as u32;
                            l4ctx.dst_port = icmphdr.un.echo.sequence as u32;
                        },
                        icmpv4::ECHO_REPLY => unsafe {
                            // On ICMP reply use the echo id destination port
                            l4ctx.dst_port = icmphdr.un.echo.id as u32;
                            l4ctx.src_port = icmphdr.un.echo.sequence as u32;

                            // If this is a ICMP reply that is not expected and not tracked
                            // then just pass it to the stack. Most likely the echo request
                            // was initiated from another source.
                            l4ctx.set_flag(L4Context::PASS_UNKNOWN_REPLY);
                        },
                        _ => {
                            // Pass any non Echo messages
                            return Ok(xdp_action::XDP_PASS);
                        }
                    }
                }
                _ => return Ok(xdp_action::XDP_PASS),
            }
        }
    }

    if ctx4.feat.log_enabled(Level::Info) {
        ctx4.log.init(&l4ctx);
        ctx4.log.ipv4_packet(ctx, &ipv4hdr);
    }

    ctx4.nat.init_v4key(ipv4hdr, &l4ctx);
    ctx4.sv.now = coarse_ktime();
    ctx4.sv.pkt_len = (ctx.data_end() - ctx.data() - l2ctx.ethlen) as u32;

    if let Some(ctnat) = unsafe { ZLB_CT4_CACHE.get(&ctx4.nat.v4key) } {
        if ctnat.time > ctx4.sv.now {
            if ctx4.sv.pkt_len > ctnat.mtu {
                return send_dtb(ctx, ipv4hdr, &l4ctx, ctnat.mtu as u16);
            } else {
                return ct4_handler(ctx, &l2ctx, &l4ctx, ipv4hdr, ctnat, ctx4);
            }
        }
    }

    // TBD: monitor RST flag to remove the conntrack entry
    // NOTE: the ref returned by map.get() can be accessed only
    // within the pattern match scope.
    // NOTE: using a cache map for the contrack map doesn't have
    // any impact on the total performance.
    if let Some(nat) = unsafe { ZLB_CONNTRACK4.get(&ctx4.nat.v4key) } {
        // TODO: move it to own function
        if ctx4.feat.log_enabled(Level::Info) {
            ctx4.log.reply_nat4(ctx, nat);
        }

        if ctx4.sv.pkt_len > nat.mtu as u32 {
            return send_dtb(ctx, ipv4hdr, &l4ctx, nat.mtu);
        }

        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        // Save fragment before updating the header
        ctx4.frag.cache4(&l4ctx);

        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL.
        ctx4.ctnat.port_combo = l4ctx.dst_port << 16 | (nat.port_lb as u32);
        ctx4.ctnat.src_addr[0] = nat.lb_ip;
        ctx4.ctnat.dst_addr[0] = nat.ip_src;

        if do_update_csum(nat.flags) {
            update_inet_csum(ctx, ipv4hdr, &l4ctx, &ctx4.ctnat)?;
        }

        ctx4.ctnat.time = ctx4.sv.now + 30;
        ctx4.ctnat.flags = nat.flags;
        ctx4.ctnat.mtu = nat.mtu as u32;
        ctx4.ctnat.ifindex = nat.ifindex;
        ctx4.ctnat.vlan_hdr = nat.vlan_hdr;
        array_copy(&mut ctx4.ctnat.macs, &nat.mac_addresses);

        let _ = ZLB_CT4_CACHE.insert(&ctx4.nat.v4key, &ctx4.ctnat, /* update or insert */ 0);

        if !ctx4.ctnat.flags.contains(EPFlags::XDP_REDIRECT) {
            if ctx4.ctnat.flags.contains(EPFlags::XDP_TX) {
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
        array_copy(macs, &ctx4.ctnat.macs);

        // NOTE: After this call all references derived from ctx must be recreated
        // since this method can change the packet limits.
        // This function is a no-op if no VLAN translation is needed.
        l2ctx.vlan_update(ctx, ctx4.ctnat.vlan_hdr, &ctx4.feat)?;

        ctx4.redirect.xmit_port(ctx4.ctnat.ifindex);

        if ctx4.feat.log_enabled(Level::Info) {
            ctx4.log.redirect_xmit(ctx, &ctx4.redirect, "[nat]");
        }

        if ctx4.ctnat.flags.contains(EPFlags::XDP_TX)
            && ctx4.redirect.action == xdp_action::XDP_REDIRECT
        {
            stats_inc(stats::XDP_REDIRECT_FULL_NAT);
        }

        return Ok(ctx4.redirect.action);
    }

    // === request ===

    // Don't track ICMP echo replies sent to LB, only requests are tracked.
    if l4ctx.get_flag(L4Context::PASS_UNKNOWN_REPLY) {
        if l4ctx.get_flag(L4Context::CACHE_FRAG) {
            stats_inc(stats::IPV4_UNKNOWN_FRAGMENTS);
        }
        return Ok(xdp_action::XDP_PASS);
    }

    if l4ctx.next_hdr == IpProto::Icmp {
        // For ICMP there is no fixed L4 port or id
        ctx4.ep4key.port = 0;
    } else {
        ctx4.ep4key.port = l4ctx.dst_port as u16;
    }
    ctx4.ep4key.address = ipv4hdr.dst_addr;
    ctx4.ep4key.proto = ipv4hdr.proto as u16;

    let be = match unsafe { ZLB_LB4.get(&ctx4.ep4key) } {
        Some(group) => {
            if ctx4.feat.log_enabled(Level::Info) {
                ctx4.log.show_begroup(ctx, &group);
            }

            if group.becount == 0 {
                stats_inc(stats::XDP_PASS);
                stats_inc(stats::LB_ERROR_NO_BE);
                return Ok(xdp_action::XDP_PASS);
            }

            ctx4.bekey.gid = group.gid;
            ctx4.bekey.index =
                (csum_fold_32_to_16(ipv4hdr.src_addr) ^ l4ctx.src_port as u16) % group.becount;

            match unsafe { ZLB_BACKENDS.get(&ctx4.bekey) } {
                Some(be) => be,
                None => {
                    if ctx4.feat.log_enabled(Level::Error) {
                        ctx4.log.no_backend_error(ctx, &ctx4.bekey);
                    }
                    stats_inc(stats::XDP_PASS);
                    stats_inc(stats::LB_ERROR_BAD_BE);
                    return Ok(xdp_action::XDP_PASS);
                }
            }
        }
        None => {
            if ctx4.feat.log_enabled(Level::Info) {
                ctx4.log.log_info(ctx, "no LB found");
            }
            // *** This is the exit point for non-LB packets ***
            // These packets are not counted as they are not destined
            // to any backend group. By counting them would mean that
            // XDP_PASS would by far the outlier and would prevent
            // knowing which packets were actually modified.
            return Ok(xdp_action::XDP_PASS);
        }
    };

    // Update the total processed packets when they are destined to a known backend group
    stats_inc(stats::PACKETS);

    if ctx4.feat.log_enabled(Level::Info) {
        if be.flags.contains(EPFlags::DSR_L3) {
            // For L3 DSR show the ip6tnl IPv6 backend address
            ctx4.log.show_backend6(ctx, &be, &ctx4.bekey);
        } else {
            ctx4.log.show_backend(ctx, &be, &ctx4.bekey);
        }
    }

    ctx4.ctnat.dst_addr[0] = be.address[0];
    ctx4.ctnat.port_combo = (be.port as u32) << 16 | l4ctx.src_port;

    // Fast exit if packet is not redirected
    if !be.flags.contains(EPFlags::XDP_REDIRECT) {
        // Save fragment before updating the header and before forwading the packet
        ctx4.frag.cache4(&l4ctx);

        ctx4.ctnat.src_addr[0] = ipv4hdr.dst_addr;
        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL
        update_inet_csum(ctx, ipv4hdr, &l4ctx, &ctx4.ctnat)?;

        // Send back the packet to the same interface
        if be.flags.contains(EPFlags::XDP_TX) {
            // TODO: swap mac addresses
            stats_inc(stats::XDP_TX);
            return Ok(xdp_action::XDP_TX);
        }

        stats_inc(stats::XDP_PASS);
        return Ok(xdp_action::XDP_PASS);
    }

    ctx4.ctnat.flags = be.flags;
    ctx4.ctnat.time = ctx4.sv.now + 30;

    // The following fields are initialized for FIB lookup and
    // then overridden after the search:
    ctx4.ctnat.ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    ctx4.ctnat.mtu = ctx4.sv.pkt_len;
    ctx4.ctnat.iph[0] = ipv4hdr.tos as u32;
    // end

    let fib = if be.flags.contains(EPFlags::DSR_L3) {
        // In L3 DSR the IPv4 packet will be sent through the ip6tnl tunnel
        // and to search the interface to redirect must use the IPv6 addresses
        // that the backend was configured.
        // Note that the actual IPv6 destination address will be changed as the
        // ip6tnl endpoint may have a different address but from the same subnet.
        array_copy(&mut ctx4.ctnat.src_addr, &be.src_ip);
        array_copy(&mut ctx4.ctnat.dst_addr, &(be.address));

        ctx4.fetch_fib6(ctx)?
    } else {
        // NOTE: can't use the custom source IP for non-conntracked connections
        // because the backend will reply to this custom source IP instead of
        // the actual source IP.
        if be.src_ip[0] != 0 {
            ctx4.ctnat.src_addr[0] = be.src_ip[0];
        } else {
            ctx4.ctnat.src_addr[0] = ipv4hdr.dst_addr;
        }

        ctx4.fetch_fib4(ctx)?
    };

    // TODO: check the arp table and update or insert smac/dmac and derived ip src
    // and redirect ifindex
    // NOTE: Check if packet can be redirected and it does not exceed the interface MTU
    // or the tunnel MTU. The tunnel MTU is set in init_from_fib() for now.

    ctx4.ctnat.init_from_fib(fib);

    match ctx4.fib.rc {
        bindings::BPF_FIB_LKUP_RET_SUCCESS => {
            if ctx4.sv.pkt_len > ctx4.ctnat.mtu {
                /* send datagram Too Big message */
                return send_dtb(ctx, ipv4hdr, &l4ctx, ctx4.ctnat.mtu as u16);
            }
        }
        bindings::BPF_FIB_LKUP_RET_FRAG_NEEDED => {
            /* send datagram Too Big message */
            return send_dtb(ctx, ipv4hdr, &l4ctx, ctx4.ctnat.mtu as u16);
        }
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

    // Save fragment before updating the header and before forwading the packet
    // and after checking for packet too big.
    ctx4.frag.cache4(&l4ctx);

    if ctx4.ctnat.flags.contains(EPFlags::DSR_L3) {
        // For L3 DSR the destination address is the tunnel address
        // from the backend netns.
        array_copy(&mut ctx4.ctnat.dst_addr, &(be.alt_address));
        ctx4.ctnat.init_ip6ip4(ipv4hdr);
        ip6tnl_encap_ipv6(ctx, &l2ctx, &ctx4.ctnat, &ctx4.feat)?;
    } else if do_update_csum(ctx4.ctnat.flags) {
        update_inet_csum(ctx, ipv4hdr, &l4ctx, &ctx4.ctnat)?;
    }

    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };

    if !ctx4.ctnat.flags.contains(EPFlags::DSR_L3) {
        ctx4.nat.v4info.mac_addresses = [
            macs[2] << 16 | macs[1] >> 16,
            macs[0] << 16 | macs[2] >> 16,
            macs[1] << 16 | macs[0] >> 16,
        ];
        // Save the VLAN header here before removing it below
        ctx4.nat.v4info.vlan_hdr = l2ctx.vlanhdr;
    }

    array_copy(macs, &ctx4.ctnat.macs);

    // TODO: use the vlan info from fib lookup to update the frame vlan.
    // Till then assume we redirect to backends outside of any VLAN.
    // NOTE: This call can shrink or enlarge the packet so all pointers
    // to headers are invalidated.
    l2ctx.vlan_update(ctx, 0, &ctx4.feat)?;

    ctx4.redirect.xmit_port(ctx4.ctnat.ifindex);

    if ctx4.feat.log_enabled(Level::Info) {
        ctx4.log.redirect_xmit(ctx, &ctx4.redirect, "[fwd]");
    }

    /* === connection tracking === */

    // Add conntrack cache entry to skip searching for the group,
    // the backend and the fib entry that provides the neighbor
    // mac address.
    // NOTE: Since the cache is a per CPU map the insert with flags=0
    // will update only the value for the current CPU.
    let _ = ZLB_CT4_CACHE.insert(&ctx4.nat.v4key, &ctx4.ctnat, /* update or insert */ 0);

    // TBD: Don't insert entry if no connection tracking is enabled for this backend.
    // For e.g. if the backend can reply directly to the source endpoint.
    // if !be.flags.contains(EPFlags::NO_CONNTRACK) {
    // This is done by tunneling and encapsulate the current packet in:
    // - ipv4 GRE
    // - ip6tnl
    // - fou

    // There is no need to conntrack the L3 DSR flow
    if !ctx4.ctnat.flags.contains(EPFlags::DSR_L3) {
        ctx4.nat.updatev4(ctx, &l4ctx, &ctx4.ctnat);
        if ctx4.feat.log_enabled(Level::Info) {
            ctx4.log.conntrack4(ctx, &ctx4.nat);
        }
    }

    Ok(ctx4.redirect.action)
}

impl Redirect {
    const EACTION: u64 = xdp_action::XDP_PASS as u64;

    /// Do bpf_redirect_map() and as fallback do simple bpf_redirect().
    /// NOTE: use bpf_redirect_map(map, ifindex) to boost performance as it supports
    /// packet batch processing instead of single/immediate packet redirect.
    /// The devmap must be update by the user application.
    /// See:
    /// - https://lwn.net/Articles/728146/
    /// - https://docs.kernel.org/bpf/map_devmap.html
    /// - https://docs.kernel.org/bpf/redirect.html
    fn xmit_port(&mut self, ifindex: u32) {
        self.ifindex = ifindex;
        // NOTE: aya embeds the bpf_redirect_map in map struct impl
        // NOTE: the last 2 bits are used to be returned as error.
        // For now just pass the packet on error.
        if let Ok(action) = ZLB_TXPORT.redirect(ifindex, Self::EACTION) {
            self.action = action;

            stats_inc(stats::XDP_REDIRECT_MAP);
            return;
        }

        stats_inc(stats::XDP_REDIRECT_ERRORS);

        self.action = unsafe { bpf_redirect(ifindex, Self::EACTION) as xdp_action::Type };

        if self.action != xdp_action::XDP_REDIRECT {
            stats_inc(stats::XDP_REDIRECT_ERRORS);
        }
    }
}

const IP6TNL_HOPLIMIT: u32 = 4;
const DSR_L3_OVERHEAD: u32 = Ipv6Hdr::LEN as u32;

fn do_update_csum(flags: EPFlags) -> bool {
    !flags.intersects(EPFlags::DSR_L2 | EPFlags::DSR_L3)
}

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
    // Flow Label = Identification
    // Next header = IPv4
    // Hop limit = constant
    // The payload length will be set when the actual packet is
    // adjusted.
    fn init_ip6ip4(&mut self, ipv4hdr: &Ipv4Hdr) {
        self.iph[0] = 6 << 4;
        // NOTE: DSCP and ECN bits must be correct in order for the ip6tnl driver
        // won't drop the packet because of ECN error.
        // The ECN errors are evident from the dmesg log:
        // ip6_tunnel: non-ECT from 2001:0db8:0000:0000:0000:0000:0002:0001 with DS=0x7
        // See: https://elixir.bootlin.com/linux/v6.1.121/source/net/ipv6/ip6_tunnel.c#L863
        self.iph[0] |= (ipv4hdr.tos as u32) << 4;
        self.iph[0] |= (ipv4hdr.id as u32) << 16;
        self.iph[1] = IP6TNL_HOPLIMIT << 24;
        self.iph[1] |= (IpProto::Ipv4 as u32) << 16;
    }

    fn init_from_fib(&mut self, fib: &FibEntry) {
        if self.flags.contains(EPFlags::DSR_L3) {
            // Since we use ip6tnl must substract the IPv6 header size
            self.mtu = fib.mtu - DSR_L3_OVERHEAD;
        } else {
            self.mtu = fib.mtu;
        }

        self.ifindex = fib.ifindex;
        array_copy(&mut self.macs, &fib.macs);
        self.vlan_hdr = 0;
    }
}

impl FIBLookUp {
    fn init_entry(&mut self, now: u32) {
        self.entry.ifindex = self.param.ifindex;
        self.param.copy_swapped_macs(&mut self.entry.macs);
        array_copy(&mut self.entry.ip_src, &mut self.param.src); // not used for now
        self.entry.mtu = self.param.tot_len as u32;

        if self.rc != bindings::BPF_FIB_LKUP_RET_SUCCESS {
            stats_inc(stats::FIB_LOOKUP_FAILS);
            // Retry on next try but create the entry
            self.entry.expiry = now - 1;
        } else {
            // TODO: make the expiry time a runvar
            self.entry.expiry = now + FIB_ENTRY_EXPIRY_INTERVAL;
        };
    }
}

impl Context {
    // NOTE: the next function uses
    // long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags);
    // in order to compute the source/dest mac + vlan info from IP source,destination
    // before redirecting a packet to the backend. This feature is different from
    // XDP_REDIRECT as it is used to redirect the source packet to an backend
    // via configured interface on the ingress flow. In the egress flow we already have
    // the ifindex and the mac addresses info, which are saved in the conntrack map
    // on the ingress flow.
    // NOTE: sometimes the network stack to which the packet is redirected doesn't
    // know how to forward the packet back to the LB. In this case we must do a full
    // NAT for both L2/L3 src and dst addresses.
    // NOTE: using BPF_FIB_LOOKUP_OUTPUT doesn't work when reversing src and destination.
    // NOTE: in order to obtain the _right_ source IP for the network on which the packet
    // is redirected must use a newer kernel (>=6.7) that implements 'source IP addr
    // derivation via bpf_*_fib_lookup()' by passing flag BPF_FIB_LOOKUP_SRC:
    // See:
    // Extend the bpf_fib_lookup() helper by making it to return the source
    // IPv4/IPv6 address if the BPF_FIB_LOOKUP_SRC flag is set.
    // https://github.com/torvalds/linux/commit/dab4e1f06cabb6834de14264394ccab197007302
    // NOTE: Use an arp table to map destination IP (both v4/v6) to the smac/dmac and
    // ifindex used to redirect the packet.
    fn fetch_fib4(&mut self, ctx: &XdpContext) -> Result<&'static FibEntry, ()> {
        if let Some(entry) = unsafe { ZLB_FIB4.get(&self.ctnat.dst_addr[0]) } {
            if self.sv.now <= entry.expiry {
                self.fib.rc = bindings::BPF_FIB_LKUP_RET_SUCCESS;
                return Ok(entry);
            }
        }

        self.fib.param.init_inet(&self.ctnat);

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
            self.log.fib_lkup_inet(ctx, &self.fib);
        }

        self.fib.init_entry(self.sv.now);

        // NOTE: after updating the value or key struct size must remove the pinned map
        // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
        match unsafe { ZLB_FIB4.insert(&self.ctnat.dst_addr[0], &self.fib.entry, 0) } {
            Ok(()) => {}
            Err(_) => {
                stats_inc(stats::FIB_ERROR_UPDATE);
                return Err(());
            }
        }

        match unsafe { ZLB_FIB4.get(&self.ctnat.dst_addr[0]) } {
            Some(entry) => Ok(entry),
            None => Err(()),
        }
    }
}

#[repr(C)]
struct BpfFibLookUp {
    /// input: network family for lookup (AF_INET, AF_INET6)
    /// output: network family of egress nexthop
    family: u8,

    /// Set if lookup is to consider L4 data - e.g., FIB rules
    l4_protocol: u8,
    sport: u16,
    dport: u16,

    /// input: L3 length from network hdr (iph->tot_len)
    /// ouput: output: MTU value
    tot_len: u16,

    /// input: L3 device index for lookup
    /// output: device index from FIB lookup
    ifindex: u32,

    /// input:
    /// - AF_INET: tos
    /// - AF_INET6: flow label + priority
    /// output: rt_metric or metric of fib result (IPv4/IPv6 only)
    tos: u32,

    /// input:  source address, network order
    src: [u32; 4],
    /// input:  destination address, network order
    dst: [u32; 4],

    /// output
    h_vlan_proto: u16,
    h_vlan_tci: u16,
    /// Optimization done for easy memcopy
    macs: [u32; 3],
    //smac: [u8; 6],
    //dmac: [u8; 6],
}

impl BpfFibLookUp {
    fn init_inet(&mut self, ctnat: &CTCache) {
        self.family = AF_INET;
        self.l4_protocol = 0;
        self.sport = 0;
        self.dport = 0;
        self.tot_len = ctnat.mtu as u16;
        self.ifindex = ctnat.ifindex;
        self.tos = ctnat.iph[0];
        self.src[0] = ctnat.src_addr[0];
        self.dst[0] = ctnat.dst_addr[0];
    }

    unsafe fn _fill_ethdr_macs(&self, ethdr: *mut EthHdr) {
        let mac = ethdr as *mut [u32; 3];
        (*mac)[0] = self.macs[2] << 16 | self.macs[1] >> 16;
        (*mac)[1] = self.macs[0] << 16 | self.macs[2] >> 16;
        (*mac)[2] = self.macs[1] << 16 | self.macs[0] >> 16;
    }

    fn _ethdr_macs(&self) -> [u32; 3] {
        [
            self.macs[2] << 16 | self.macs[1] >> 16,
            self.macs[0] << 16 | self.macs[2] >> 16,
            self.macs[1] << 16 | self.macs[0] >> 16,
        ]
    }

    fn copy_swapped_macs(&self, macs: &mut [u32; 3]) {
        macs[2] = self.macs[1] << 16 | self.macs[0] >> 16;
        macs[1] = self.macs[0] << 16 | self.macs[2] >> 16;
        macs[0] = self.macs[2] << 16 | self.macs[1] >> 16;
    }

    fn dest_mac(&self) -> [u8; ETH_ALEN] {
        unsafe { *((self.macs.as_ptr() as *const [u8; ETH_ALEN]).offset(1)) }
    }

    fn src_mac(&self) -> [u8; ETH_ALEN] {
        unsafe { *(self.macs.as_ptr() as *const [u8; ETH_ALEN]) }
    }
}
