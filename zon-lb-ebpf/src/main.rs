#![no_std]
#![no_main]

mod ipv6;

use aya_ebpf::{
    bindings::{
        self, bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_FIB_LKUP_RET_BLACKHOLE,
        BPF_FIB_LKUP_RET_PROHIBIT, BPF_FIB_LKUP_RET_SUCCESS, BPF_FIB_LKUP_RET_UNREACHABLE,
        BPF_F_NO_COMMON_LRU,
    },
    helpers::{
        bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect, bpf_xdp_adjust_head, bpf_xdp_adjust_tail,
    },
    macros::{map, xdp},
    maps::{Array, DevMap, HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, Level};
use core::mem::{self, offset_of};
use ebpf_rshelpers::{csum_add_u32, csum_fold_32_to_16, csum_update_u16, csum_update_u32};
use ipv6::{check_mtu, coarse_ktime, ipv6_lb};
use network_types::{
    eth::EthHdr,
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    runvars, stats, ArpEntry, BEGroup, BEKey, EPFlags, FibEntry, GroupInfo, Ipv4FragId,
    Ipv4FragInfo, NAT4Key, NAT4Value, BE, EP4, FIB_ENTRY_EXPIRY_INTERVAL, MAX_ARP_ENTRIES,
    MAX_BACKENDS, MAX_CONNTRACKS, MAX_FRAG4_ENTRIES, MAX_GROUPS, NEIGH_ENTRY_EXPIRY_INTERVAL,
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
static ZLB_RUNVAR: Array<u64> = Array::with_max_entries(runvars::MAX_RUNTIME_VARS, 0);

/// Stores the program statistics.
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

fn arp_snoop(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let arphdr = ptr_at::<ArpHdr>(&ctx, l2ctx.ethlen)?;
    let arphdr = unsafe { &mut *arphdr.cast_mut() };
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    let eth = unsafe { &mut *eth.cast_mut() };
    let ifindex = unsafe { (*ctx.ctx).ingress_ifindex };
    let vlan_id = l2ctx.vlan_id();
    let feat = Features::new();
    let log_on = feat.log_enabled(Level::Info);

    // TODO: add arp to stats
    // TODO: use only info! and ditch error! to generate less code
    if log_on {
        info!(
            ctx,
            "[eth] if:{} vlan_id:{} {:mac} -> {:mac}",
            ifindex,
            (vlan_id as u16).to_be(),
            eth.src_addr,
            eth.dst_addr,
        );

        info!(
            ctx,
            "[arp] oper:{} sha={:mac} spa:{:i} tha={:mac} tpa:{:i}",
            arphdr.oper.to_be(),
            arphdr.sha,
            arphdr.spa.to_be(),
            arphdr.tha,
            arphdr.tpa.to_be()
        );
    }

    update_arp_table(ctx, arphdr.spa, vlan_id, &arphdr.sha, eth);
    update_arp_table(ctx, arphdr.tpa, vlan_id, &arphdr.tha, eth);

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
        None => {
            if log_on {
                info!(ctx, "[arp] no entry for tpa: {:i}", tpa);
            }
            return Ok(xdp_action::XDP_PASS);
        }
        Some(entry) => {
            // NOTE: most likely the entry.vlan_id would be 0 since it shouldn't be
            // assigned in no VLAN
            if entry.ifindex == ifindex && (vlan_id == entry.vlan_id || entry.vlan_id == 0) {
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
                            "[arp] if diff: {}!={} for {:i}",
                            ifindex,
                            entry.ifindex,
                            tpa.to_be()
                        );
                    } else {
                        info!(
                            ctx,
                            "[arp] vlan id diff: {}!={}, for {:i}",
                            vlan_id,
                            entry.vlan_id,
                            tpa.to_be()
                        );
                    }
                }

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
        info!(
            ctx,
            "[eth] [tx] if:{} vlan_id:{} {:mac} -> {:mac}",
            ifindex,
            (vlan_id as u16).to_be(),
            eth.src_addr,
            eth.dst_addr,
        );

        info!(
            ctx,
            "[arp] reply sha={:mac} spa:{:i} -> tha={:mac} tpa:{:i}",
            arphdr.sha,
            arphdr.spa.to_be(),
            arphdr.tha,
            arphdr.tpa.to_be()
        );
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
    let ether_type = ptr_at::<[EtherType; 5]>(&ctx, ETH_ALEN << 1)?;
    let ether_type = unsafe { &*ether_type };
    let l2ctx = L2Context {
        ethlen: EthHdr::LEN,
        vlanhdr: 0,
    };

    // BUG: Unfortunately the bpf-linker does not allow mixing
    // match-arms that call return with function calls and match-arms
    // that just return values. Looks like only match-arms that return
    // compile time constant lile `Ok(xdp_action::XDP_PASS)` are allowed.`
    //    let (idx, vlanhdr, next_ether_type) =
    if ether_type[0] as u16 != EtherType::VlanDot1Q as u16 {
        return match ether_type[0] {
            EtherType::Ipv4 => ipv4_lb(&ctx, l2ctx),
            EtherType::Ipv6 => ipv6_lb(&ctx, l2ctx),
            EtherType::Arp => arp_snoop(&ctx, l2ctx),
            _ => Ok(xdp_action::XDP_PASS),
        };
    }

    let l2ctx = L2Context {
        ethlen: EthHdr::LEN + 4,
        vlanhdr: ((ether_type[1] as u32) << 16) | (ether_type[0] as u32),
    };

    match ether_type[0] {
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

/// Compute delta checksum after switching header addresses,
/// updates ipv4 checksum, source and destination addresses.
/// It returns the delta checksum to be used to update the
/// the transport header.
///
/// BUG: the bpf_linker throws the following error if this
/// function attribute is `inline(always)` or no attribute:
/// error: LLVM issued diagnostic with error severity
// Found that only inline(always) works here.
#[inline(never)]
fn update_ipv4hdr(ipv4hdr: &mut Ipv4Hdr, src: u32, dst: u32) -> u32 {
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
    let cso = csum_update_u32(ipv4hdr.src_addr, src, 0);
    let cso = csum_update_u32(ipv4hdr.dst_addr, dst, cso);
    let csum = csum_update_u32(0, cso, !ipv4hdr.check as u32);

    ipv4hdr.src_addr = src;
    ipv4hdr.dst_addr = dst;
    ipv4hdr.check = !csum_fold_32_to_16(csum);

    cso
}

/// BUG: bpf_linker requires inline(always) or no attribute because
/// with inline(never) it throws LLVM diagnostigs error.
/// NOTE: without any attribute the linker optimizes the code better
/// as the iperf throughput is slightly higher (~0.03Gbits/sec).
fn update_inet_csum(
    ctx: &XdpContext,
    ipv4hdr: &mut Ipv4Hdr,
    l4ctx: &L4Context,
    src: u32,
    dst: u32,
    port_combo: u32,
) -> Result<(), ()> {
    let cso = update_ipv4hdr(ipv4hdr, src, dst);

    if l4ctx.check_off != 0 && port_combo != 0 && ipv4hdr.proto != IpProto::Icmp {
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
        let csum = unsafe { !(*check) } as u32;
        let csum = csum_update_u32(0, cso, csum);
        let csum = csum_update_u32(l4ctx.dst_port << 16 | l4ctx.src_port, port_combo, csum);
        unsafe { *check = !csum_fold_32_to_16(csum) };

        let ports = ptr_at::<u32>(ctx, l4ctx.offset)?.cast_mut();
        unsafe { *ports = port_combo };
    }

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

    let phdr = ptr_at::<ProtoHdr>(&ctx, l4ctx.offset)?;
    let phdr = unsafe { *phdr };

    let ptb = ptr_at::<IcmpDtb>(&ctx, l4ctx.offset)?;
    let ptb = unsafe { &mut *ptb.cast_mut() };

    ptb.type_ = 3; // Destination Ureachable
    ptb.code = 4; // Fragmentation required
    ptb.csum = 0; // initialize the checksum with 0
    ptb._unused = 0;
    ptb.mtu = size.to_be();

    // Copy the original IPv6 header as data for the Icmpv6 PTB message
    ptb.ipv4hdr = *ipv4hdr;
    ptb.protohdr = phdr;

    // Update the Ethernet header
    let eth = ptr_at::<EthHdr>(&ctx, 0)?.cast_mut();
    let eth = unsafe { &mut *eth };
    core::mem::swap(&mut eth.src_addr, &mut eth.dst_addr);

    // Update the Ipv4 header and checksum
    core::mem::swap(&mut ipv4hdr.src_addr, &mut ipv4hdr.dst_addr);

    let mut csum = !ipv4hdr.check as u32;

    // Update the packet length
    let tot_len = Ipv4Hdr::LEN as u16 + DTB_SIZE as u16;
    csum = csum_update_u16(ipv4hdr.tot_len, tot_len.to_be(), csum);
    ipv4hdr.tot_len = tot_len.to_be();

    // Update the next protocol to ICMP
    let ttl = (ipv4hdr.ttl as u16) << 8;
    csum = csum_update_u16(ttl | ipv4hdr.proto as u16, ttl | IpProto::Icmp as u16, csum);
    ipv4hdr.proto = IpProto::Icmp;

    // Remove id
    csum = csum_update_u16(ipv4hdr.id, 0, csum);
    ipv4hdr.id = 0;

    // Add Don't Fragment flag and remove offset
    csum = csum_update_u16(ipv4hdr.frag_off, 1 << 6, csum);
    ipv4hdr.frag_off = 1 << 6;

    ipv4hdr.check = !csum_fold_32_to_16(csum);

    // NOTE: The ICMPv4 checksum is required for error messages like
    // Datagram too big.
    // NOTE: ICMPv4 checksum differs from ICMPv6 one as it doesn't require
    // an initial csum built from IP pseudo header.
    let data = ptr_at::<[u32; DTB_WSIZE]>(&ctx, l4ctx.offset)?;
    let data = unsafe { &*data };
    let mut cs = 0_u32;
    for i in 0..DTB_WSIZE {
        cs = csum_add_u32(data[i], cs);
    }
    ptb.csum = !csum_fold_32_to_16(cs);

    let delta = tot_len as i32 - (ptb.ipv4hdr.tot_len.to_be() as i32);
    let rc = unsafe { bpf_xdp_adjust_tail(ctx.ctx, delta) };

    if feat.log_enabled(Level::Info) {
        info!(ctx, "adjust tail by delta: {}, rc={}", delta, rc,);
    }

    stats_inc(stats::ICMP_DU_FR);

    Ok(xdp_action::XDP_TX)
}

#[inline(never)]
fn log_packet(ctx: &XdpContext, ipv4hdr: &Ipv4Hdr, l4ctx: &L4Context) {
    let rx_queue = unsafe { (*ctx.ctx).rx_queue_index };
    let if_index = unsafe { (*ctx.ctx).ingress_ifindex };
    info!(
        ctx,
        "[i:{}, rx:{}] [p:{}] {:i}:{} -> {:i}:{}",
        if_index,
        rx_queue,
        ipv4hdr.proto as u8,
        ipv4hdr.src_addr.to_be(),
        (l4ctx.src_port as u16).to_be(),
        ipv4hdr.dst_addr.to_be(),
        (l4ctx.dst_port as u16).to_be(),
    );

    info!(
        ctx,
        "frag, id:0x{:x}, off:0x{:x}",
        ipv4hdr.id,
        ipv4hdr.frag_off.to_be() & 0x1fff
    );
}

/// Matches the IPv4 more fragments (MF) flag in the u16 following
/// big-endian value combo: 0b[1111_1111][0 DF MF 1_1111]
const MORE_FRAGMENTS: u32 = 1 << 5;

#[inline(always)]
fn cache_frag_info(ipv4hdr: &Ipv4Hdr, l4ctx: &L4Context) {
    // Cache only the first fragment contains the L4 header
    if (l4ctx.flags & MORE_FRAGMENTS) != 0 {
        match unsafe {
            ZLB_FRAG4.insert(
                &Ipv4FragId {
                    id: ipv4hdr.id,
                    proto: ipv4hdr.proto as u16,
                    src: ipv4hdr.src_addr,
                    dst: ipv4hdr.dst_addr,
                },
                &Ipv4FragInfo {
                    src_port: l4ctx.src_port as u16,
                    dst_port: l4ctx.dst_port as u16,
                    reserved: 0,
                },
                0,
            )
        } {
            Ok(()) => stats_inc(stats::IP_FRAGMENTS),
            Err(_) => stats_inc(stats::IP_FRAGMENT_ERRORS),
        }
    }
}

#[derive(Default)]
struct L4Context {
    offset: usize,
    check_off: usize,
    src_port: u32,
    dst_port: u32,
    flags: u32,
}

impl L4Context {
    fn new_for_ipv4(ctx: &XdpContext, ipv4hdr: &Ipv4Hdr, mut offset: usize) -> Result<Self, ()> {
        // All fragments besides the fragment at offset 0 requires the cached L4 info.
        // The fragment offset field layout is like this:
        // 0b[1111_1111][0 DF MF 1_1111]
        if (ipv4hdr.frag_off & 0xFF1F) != 0 {
            match unsafe {
                ZLB_FRAG4.get(&Ipv4FragId {
                    id: ipv4hdr.id,
                    proto: ipv4hdr.proto as u16,
                    src: ipv4hdr.src_addr,
                    dst: ipv4hdr.dst_addr,
                })
            } {
                // Pass any non tracked fragments
                None => return Ok(Self::default()),
                Some(frag) => {
                    stats_inc(stats::IP_FRAGMENTS);
                    return Ok(Self {
                        offset,
                        check_off: 0, // No need to update the checksum
                        src_port: frag.src_port as u32,
                        dst_port: frag.dst_port as u32,
                        flags: 0,
                    });
                }
            }
        }

        let flags = (ipv4hdr.frag_off as u32) & MORE_FRAGMENTS;

        let (check_off, src_port, dst_port) = match ipv4hdr.proto {
            IpProto::Tcp => {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, offset)?;
                (
                    offset_of!(TcpHdr, check),
                    unsafe { (*tcphdr).source as u32 },
                    unsafe { (*tcphdr).dest as u32 },
                )
            }
            IpProto::Udp => {
                let udphdr = ptr_at::<UdpHdr>(&ctx, offset)?;
                (
                    offset_of!(UdpHdr, check),
                    unsafe { (*udphdr).source as u32 },
                    unsafe { (*udphdr).dest as u32 },
                )
            }
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
                let icmphdr = ptr_at::<IcmpHdr>(&ctx, offset)?;
                let icmphdr = unsafe { &*icmphdr };
                match icmphdr.type_ {
                    icmpv4::ECHO_REQUEST => {
                        // On ICMP request use the echo id as source port
                        (0, unsafe { icmphdr.un.echo.id } as u32, 0)
                    }
                    icmpv4::ECHO_REPLY => {
                        // On ICMP reply use the echo id destination port
                        (0, 0, unsafe { icmphdr.un.echo.id } as u32)
                    }
                    _ => {
                        // Pass any non Echo messages
                        offset = 0;
                        (0, 0, 0)
                    }
                }
            }
            _ => (0, 0, 0),
        };

        Ok(Self {
            offset,
            check_off,
            src_port,
            dst_port,
            flags,
        })
    }

    fn check_pkt_off(&self) -> usize {
        self.offset + self.check_off
    }
}

// TODO: check if moving the XdpContext boosts performance
fn ipv4_lb(ctx: &XdpContext, l2ctx: L2Context) -> Result<u32, ()> {
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv4hdr = unsafe { &mut *ipv4hdr.cast_mut() };
    let src_addr = ipv4hdr.src_addr;
    let dst_addr = ipv4hdr.dst_addr;
    let if_index = unsafe { (*ctx.ctx).ingress_ifindex };
    // NOTE: compute the l4 header start based on ipv4hdr.IHL
    let l4hdr_offset = (ipv4hdr.ihl() as usize) << 2;
    let l4hdr_offset = l4hdr_offset + l2ctx.ethlen;
    let l4ctx = L4Context::new_for_ipv4(ctx, &ipv4hdr, l4hdr_offset)?;
    let feat = Features::new();

    if l4ctx.offset == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    if feat.log_enabled(Level::Info) {
        log_packet(ctx, &ipv4hdr, &l4ctx);
    }

    let mut natkey = NAT4Key {
        ip_be_src: src_addr,
        ip_lb_dst: dst_addr,
        port_be_src: l4ctx.src_port as u16,
        port_lb_dst: l4ctx.dst_port as u16,
        proto: ipv4hdr.proto as u32,
    };

    // TBD: monitor RST flag to remove the conntrack entry
    // TODO: Check conntrack first for non-connection oriented, eg. icmp.
    // Alternatively add another key element to differentiate between connections
    // for e.g. the request.
    // Also we can ignore all non-connection protocols like icmp.
    if let Some(&nat) = unsafe { ZLB_CONNTRACK4.get(&natkey) } {
        // Update the total processed packets when they are from a tracked connection
        stats_inc(stats::PACKETS);

        if feat.log_enabled(Level::Info) {
            info!(
                ctx,
                "[out] nat, src: {:i}, lb_port: {}",
                nat.ip_src.to_be(),
                (nat.port_lb as u16).to_be()
            );
        }

        // Unlikely
        if nat.ip_src == src_addr && l4ctx.src_port == l4ctx.dst_port {
            if feat.log_enabled(Level::Error) {
                error!(
                    ctx,
                    "[out] drop same src {:i}:{}",
                    nat.ip_src.to_be(),
                    (l4ctx.src_port as u16).to_be()
                );
            }
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }

        if ipv4hdr.tot_len.to_be() > nat.mtu {
            return send_dtb(ctx, ipv4hdr, &l4ctx, nat.mtu);
        }

        // Save fragment before updating the header
        cache_frag_info(ipv4hdr, &l4ctx);

        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL.
        update_inet_csum(
            ctx,
            ipv4hdr,
            &l4ctx,
            nat.lb_ip,
            nat.ip_src,
            l4ctx.dst_port << 16 | (nat.port_lb as u32),
        )?;

        let action = if nat.flags.contains(EPFlags::XDP_REDIRECT) {
            // TODO: Try use:
            // long bpf_fib_lookup(void *ctx, struct bpf_fib_lookup *params, int plen, u32 flags);
            // in order to compute the source/dest mac + vlan info from IP source,destination
            // before redirecting a packet to the backend.

            // NOTE: use bpf_redirect_map(map, ifindex) to boost performance as it supports
            // packet batch processing instead of single/immediate packet redirect.
            // The devmap must be update by the user application.
            // See:
            // - https://lwn.net/Articles/728146/
            // - https://docs.kernel.org/bpf/map_devmap.html
            // - https://docs.kernel.org/bpf/redirect.html
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
            info!(ctx, "[out] action: {}", action);
        }

        return Ok(action);
    }

    // === request ===

    // Don't track ICMP echo replies sent to LB, only requests are tracked.
    // On request src_port contains the echo id.
    if ipv4hdr.proto == IpProto::Icmp && l4ctx.src_port == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    let group = match unsafe {
        ZLB_LB4.get(&EP4 {
            address: dst_addr,
            port: (l4ctx.dst_port as u16),
            proto: ipv4hdr.proto as u16,
        })
    } {
        Some(group) => *group,
        None => {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "No LB4 entry");
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
        index: (((src_addr >> 16) ^ src_addr) ^ l4ctx.src_port) as u16 % group.becount,
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

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[ctrk] fw be: {:i}:{}",
            be.address[0].to_be(),
            be.port.to_be()
        );
    }

    let be_addr = be.address[0];

    // Save fragment before updating the header and before forwading the packet
    cache_frag_info(ipv4hdr, &l4ctx);

    // Fast exit if packet is not redirected
    if !be.flags.contains(EPFlags::XDP_REDIRECT) {
        // Update both IP and Transport layers checksums along with the source
        // and destination addresses and ports and others like TTL
        update_inet_csum(
            ctx,
            ipv4hdr,
            &l4ctx,
            dst_addr,
            be_addr,
            (be.port as u32) << 16 | l4ctx.src_port,
        )?;

        // Send back the packet to the same interface
        if be.flags.contains(EPFlags::XDP_TX) {
            if feat.log_enabled(Level::Info) {
                info!(ctx, "in => xdp_tx");
            }

            // TODO: swap mac addresses

            stats_inc(stats::XDP_TX);

            return Ok(xdp_action::XDP_TX);
        }

        if feat.log_enabled(Level::Info) {
            info!(ctx, "in => xdp_pass");
        }

        stats_inc(stats::XDP_PASS);

        return Ok(xdp_action::XDP_PASS);
    }

    let lb_addr = if be.flags.contains(EPFlags::XDP_TX) && be.src_ip[0] != 0 {
        // TODO: check the arp table and update or insert
        // smac/dmac and derived ip src and redirect ifindex
        be.src_ip[0]
    } else {
        dst_addr
    };

    let now = coarse_ktime();

    // NOTE: Check if packet can be redirected and it does not exceed the interface MTU
    let (fib, fib_rc) = fetch_fib4(ctx, ipv4hdr, lb_addr, be_addr, now)?;
    let fib = unsafe { &*fib };
    match fib_rc {
        bindings::BPF_FIB_LKUP_RET_SUCCESS => {
            if fib.mtu as u16 >= ipv4hdr.tot_len.to_be() {
                /* go ahead an update the packet */
            } else {
                /* send datagram Too Big message */
                return send_dtb(ctx, ipv4hdr, &l4ctx, fib.mtu as u16);
            }
        }
        bindings::BPF_FIB_LKUP_RET_FRAG_NEEDED => {
            /* send datagram Too Big message */
            return send_dtb(ctx, ipv4hdr, &l4ctx, fib.mtu as u16);
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

    // Update both IP and Transport layers checksums along with the source
    // and destination addresses and ports and others like TTL.
    update_inet_csum(
        ctx,
        ipv4hdr,
        &l4ctx,
        lb_addr,
        be.address[0],
        (be.port as u32) << 16 | l4ctx.src_port,
    )?;

    let macs = ptr_at::<[u32; 3]>(&ctx, 0)?.cast_mut();
    let macs = unsafe { &mut *macs };
    let mac_addresses = [
        macs[2] << 16 | macs[1] >> 16,
        macs[0] << 16 | macs[2] >> 16,
        macs[1] << 16 | macs[0] >> 16,
    ];

    macs[2] = fib.macs[2];
    macs[1] = fib.macs[1];
    macs[0] = fib.macs[0];

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

    // TBD: Don't insert entry if no connection tracking is enabled for this backend.
    // For e.g. if the backend can reply directly to the source endpoint.
    // if !be.flags.contains(EPFlags::NO_CONNTRACK) {
    // This is done by tunneling and encapsulate the current packet in:
    // - ipv4 GRE
    // - ip6tnl
    // - fou

    let ip_src = natkey.ip_be_src;
    let lb_ip = natkey.ip_lb_dst;

    natkey.ip_be_src = be_addr;
    natkey.ip_lb_dst = lb_addr;
    natkey.port_be_src = be.port;
    // NOTE: the LB will use the source port since there can be multiple
    // connection to the same backend and it needs to track all of them.
    // NOTE: On ICMP request is set with the echo id.
    natkey.port_lb_dst = l4ctx.src_port as u16;

    // Update the nat entry only if the source details changes.
    // This will boost performance and less error prone on tests like iperf.
    match unsafe { ZLB_CONNTRACK4.get(&natkey) } {
        Some(&nat) => {
            if nat.ifindex != if_index
                || nat.ip_src != ip_src
                || nat.mac_addresses != mac_addresses
                || nat.vlan_hdr != l2ctx.vlanhdr
            {
                /* do insert */
            } else {
                return Ok(action);
            }
        }
        None => { /* do insert */ }
    }

    // TBD: use lock or atomic update ?
    // TBD: use BPF_F_LOCK ?
    let rc = match unsafe {
        ZLB_CONNTRACK4.insert(
            &natkey,
            &NAT4Value {
                ip_src,
                port_lb: l4ctx.dst_port as u16,
                mtu: check_mtu(ctx, if_index),
                ifindex: if_index,
                mac_addresses,
                vlan_hdr: l2ctx.vlanhdr,
                flags: be.flags,
                lb_ip,
            },
            0,
        )
    } {
        Ok(()) => 0,
        Err(ret) => {
            stats_inc(stats::CT_ERROR_UPDATE);
            ret
        }
    };

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[ctrk] [{:i}]:{} vlanhdr: {:x}, rc={}",
            ip_src.to_be(),
            (l4ctx.src_port as u16).to_be(),
            l2ctx.vlanhdr,
            rc
        )
    }

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

    Ok(action)
}

fn redirect_txport(ctx: &XdpContext, feat: &Features, ifindex: u32) -> xdp_action::Type {
    // NOTE: aya embeds the bpf_redirect_map in map struct impl
    match ZLB_TXPORT.redirect(ifindex, 0) {
        Ok(action) => {
            stats_inc(stats::XDP_REDIRECT_MAP);
            action
        }
        Err(e) => {
            if feat.log_enabled(Level::Error) {
                error!(ctx, "[redirect] No tx port: {}, {}", ifindex, e);
            }
            stats_inc(stats::XDP_REDIRECT_ERRORS);
            let rda = unsafe { bpf_redirect(ifindex, 0) as xdp_action::Type };
            if rda == xdp_action::XDP_REDIRECT {
                stats_inc(stats::XDP_REDIRECT_ERRORS);
            }
            rda
        }
    }
}

fn fetch_fib4(
    ctx: &XdpContext,
    ipv4hdr: &Ipv4Hdr,
    src: u32,
    dst: u32,
    now: u32,
) -> Result<(*const FibEntry, u32), ()> {
    match unsafe { ZLB_FIB4.get_ptr(&dst) } {
        Some(entry) => {
            if now <= unsafe { (*entry).expiry } {
                return Ok((entry, bindings::BPF_FIB_LKUP_RET_SUCCESS as u32));
            }
        }
        None => {}
    }

    let fib_param = BpfFibLookUp::new_inet(
        ipv4hdr.tot_len.to_be(),
        unsafe { (*ctx.ctx).ingress_ifindex },
        ipv4hdr.tos as u32,
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
            fib_param.src[0].to_be(),
            fib_param.dst[0].to_be(),
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
    match unsafe { ZLB_FIB4.insert(&dst, &entry, 0) } {
        Ok(()) => {}
        Err(_) => {
            stats_inc(stats::FIB_ERROR_UPDATE);
            return Err(());
        }
    }

    match unsafe { ZLB_FIB4.get_ptr(&dst) } {
        Some(entry) => Ok((entry, rc as u32)),
        None => Err(()),
    }
}

fn _redirect_ipv4(
    ctx: &XdpContext,
    feat: Features,
    ipv4hdr: &Ipv4Hdr,
    l2ctx: &L2Context,
) -> Result<u32, ()> {
    if let Some(&entry) = unsafe { ZLB_FIB4.get(&ipv4hdr.dst_addr) } {
        // NOTE: check expiry before using this entry
        // TODO: check performance
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
                    info!(ctx, "[redirect] [fib-cache] oif: {}", entry.ifindex);
                }
                return Ok(xdp_action::XDP_REDIRECT);
            }
        }
    }

    // If the packet was already adjusted after the vlan header was stripped
    // on first attempt to redirect the packet with cached fib data must
    // recompute the ip header ref before accessing it again.
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, l2ctx.ethlen)?;
    let ipv4hdr = unsafe { &*ipv4hdr };

    let fib_param = unsafe {
        BpfFibLookUp::new_inet(
            ipv4hdr.tot_len.to_be(),
            (*ctx.ctx).ingress_ifindex,
            ipv4hdr.tos as u32,
            ipv4hdr.src_addr,
            ipv4hdr.dst_addr,
        )
    };

    // NOTE: with veth first ping returns no macs because the FIB is not initialized
    // redirect] output, lkp_ret: 7, fw if: 54, src: 10.2.0.1, gw: 10.2.0.2,
    // dmac: 00:00:00:00:00:00, smac: 00:00:00:00:00:00
    // This happens because ARP failed.
    // To debug run `ip netns exec $NS ip neigh show`
    // Also make sure that `forwarding` for the expected redirect interface is on.
    // If not set it with sysctl -w net.ipv4.conf.$IF0.forwarding=1
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
        "[redirect] output, lkp_ret: {}, fw if: {}, tot_len: {}, tos: {}, src: {:i}, gw: {:i}, dmac: {:mac}, smac: {:mac}",
        rc,
        fib_param.ifindex,
        fib_param.tot_len,
        fib_param.tos,
        fib_param.src[0].to_be(),
        fib_param.dst[0].to_be(),
        fib_param.dest_mac(),
        fib_param.src_mac(),
    );
    }

    if rc == BPF_FIB_LKUP_RET_SUCCESS as i64 {
        // TODO: decrease the ipv4 ttl or ipv6 hop limit + ip hdr csum

        let action = unsafe {
            let eth = ptr_at::<EthHdr>(&ctx, 0)?;
            fib_param._fill_ethdr_macs(eth.cast_mut());

            // TODO: use the vlan info from fib lookup to update the frame vlan.
            // Till then assume we redirect to backends outside of any VLAN.
            l2ctx.vlan_update(ctx, 0, &feat)?;

            redirect_txport(ctx, &feat, fib_param.ifindex)
        };

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[redirect] action => {}", action);
        }

        _update_fib(ctx, &feat, fib_param);

        return Ok(action);
    }

    // All other result codes represent a fib loopup fail,
    // even though the packet is eventually XDP_PASS-ed
    stats_inc(stats::FIB_LOOKUP_FAILS);

    if rc == BPF_FIB_LKUP_RET_BLACKHOLE as i64
        || rc == BPF_FIB_LKUP_RET_UNREACHABLE as i64
        || rc == BPF_FIB_LKUP_RET_PROHIBIT as i64
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

fn _update_fib(ctx: &XdpContext, feat: &Features, fib_param: BpfFibLookUp) {
    let arp = FibEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src,
        expiry: unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32 + FIB_ENTRY_EXPIRY_INTERVAL,
        mtu: fib_param.tot_len as u32,
    };

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_FIB4.insert(&fib_param.dst[0], &arp, 0) } {
        Ok(()) => {
            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[fib] insert {:i} -> if:{}, smac: {:mac}, dmac: {:mac}, src: {:i}",
                    fib_param.dst[0].to_be(),
                    fib_param.ifindex,
                    fib_param.src_mac(),
                    fib_param.dest_mac(),
                    fib_param.src[0].to_be(),
                )
            }
        }
        Err(e) => {
            if feat.log_enabled(Level::Error) {
                error!(ctx, "[fib] fail to insert entry, err:{}", e)
            }
            stats_inc(stats::FIB_ERROR_UPDATE);
        }
    };
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
    fn new_inet(tot_len: u16, ifindex: u32, tos: u32, src: u32, dst: u32) -> Self {
        let mut fib: BpfFibLookUp = unsafe { core::mem::zeroed() };
        fib.family = AF_INET;
        fib.tot_len = tot_len;
        fib.ifindex = ifindex;
        fib.tos = tos;
        fib.src[0] = src;
        fib.dst[0] = dst;
        fib
    }

    fn new_inet6(paylod_len: u16, ifindex: u32, tc: u32, src: &[u32; 4], dst: &[u32; 4]) -> Self {
        let mut fib: BpfFibLookUp = unsafe { core::mem::zeroed() };
        fib.family = AF_INET6;
        fib.tot_len = paylod_len;
        fib.ifindex = ifindex;
        fib.tos = tc;
        fib.src = *src;
        fib.dst = *dst;
        fib
    }

    unsafe fn _fill_ethdr_macs(&self, ethdr: *mut EthHdr) {
        let mac = ethdr as *mut [u32; 3];
        (*mac)[0] = self.macs[2] << 16 | self.macs[1] >> 16;
        (*mac)[1] = self.macs[0] << 16 | self.macs[2] >> 16;
        (*mac)[2] = self.macs[1] << 16 | self.macs[0] >> 16;
    }

    fn ethdr_macs(&self) -> [u32; 3] {
        [
            self.macs[2] << 16 | self.macs[1] >> 16,
            self.macs[0] << 16 | self.macs[2] >> 16,
            self.macs[1] << 16 | self.macs[0] >> 16,
        ]
    }

    fn dest_mac(&self) -> [u8; ETH_ALEN] {
        unsafe { *((self.macs.as_ptr() as *const [u8; ETH_ALEN]).offset(1)) }
    }

    fn src_mac(&self) -> [u8; ETH_ALEN] {
        unsafe { *(self.macs.as_ptr() as *const [u8; ETH_ALEN]) }
    }
}
