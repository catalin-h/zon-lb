#![no_std]
#![no_main]

mod ipv6;

use aya_ebpf::{
    bindings::{
        bpf_fib_lookup as bpf_fib_lookup_param_t, xdp_action, BPF_FIB_LKUP_RET_BLACKHOLE,
        BPF_FIB_LKUP_RET_PROHIBIT, BPF_FIB_LKUP_RET_SUCCESS, BPF_FIB_LKUP_RET_UNREACHABLE,
        BPF_F_NO_COMMON_LRU,
    },
    helpers::{bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect},
    macros::{map, xdp},
    maps::{Array, DevMap, HashMap, LruHashMap, PerCpuArray},
    programs::XdpContext,
    EbpfContext,
};
use aya_log_ebpf::{error, info, Level};
use core::mem::{self, offset_of};
use ebpf_rshelpers::{csum_fold_32_to_16, csum_update_u16, csum_update_u32};
use ipv6::ipv6_lb;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    runvars, stats, ArpEntry, BEGroup, BEKey, EPFlags, GroupInfo, NAT4Key, NAT4Value, BE, EP4,
    MAX_ARP_ENTRIES, MAX_BACKENDS, MAX_CONNTRACKS, MAX_GROUPS,
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

type HMARP4 = HashMap<u32, ArpEntry>;
/// ARP table for caching destination ip to smac/dmac and derived source ip.
/// The derived source ip is the address used as source when redirecting the
/// the packet.
#[map]
static mut ZLB_ARP4: HMARP4 = HMARP4::pinned(MAX_ARP_ENTRIES, 0);

// TODO: collect errors and put them into an lru error queue or map

// TODO: add ipv6 arp table

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

struct L4Context {
    offset: usize,
    check_off: usize,
    src_port: u32,
    dst_port: u32,
}

impl L4Context {
    fn new_with_offset(ctx: &XdpContext, offset: usize, proto: IpProto) -> Result<Self, ()> {
        let (src_port, dst_port, check_off) = match proto {
            IpProto::Tcp => {
                let tcphdr = ptr_at::<TcpHdr>(&ctx, offset)?;
                (
                    unsafe { (*tcphdr).source as u32 },
                    unsafe { (*tcphdr).dest as u32 },
                    offset_of!(TcpHdr, check),
                )
            }
            IpProto::Udp => {
                let udphdr = ptr_at::<UdpHdr>(&ctx, offset)?;
                (
                    unsafe { (*udphdr).source as u32 },
                    unsafe { (*udphdr).dest as u32 },
                    offset_of!(UdpHdr, check),
                )
            }
            IpProto::Ipv6Icmp => (0, 0, offset_of!(IcmpHdr, checksum)),
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

        Ok(Self {
            offset,
            check_off,
            src_port,
            dst_port,
        })
    }

    fn check_pkt_off(&self) -> usize {
        self.offset + self.check_off
    }
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

// TODO: check the feature flags and see if the ipv6 is enabled or not
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

// TODO: check if moving the XdpContext boosts performance
fn ipv4_lb(ctx: &XdpContext) -> Result<u32, ()> {
    // TODO: support vlan tags
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let ipv4hdr = unsafe { &mut *ipv4hdr.cast_mut() };
    let src_addr = ipv4hdr.src_addr;
    let dst_addr = ipv4hdr.dst_addr;
    let proto = ipv4hdr.proto;
    let check = !ipv4hdr.check as u32;
    let (if_index, rx_queue) = unsafe { ((*ctx.ctx).ingress_ifindex, (*ctx.ctx).rx_queue_index) };

    // NOTE: compute the l4 header start based on ipv4hdr.IHL
    let l4hdr_offset = (ipv4hdr.ihl() as usize) << 2;
    let l4hdr_offset = l4hdr_offset + EthHdr::LEN;

    let l4ctx = L4Context::new_with_offset(ctx, l4hdr_offset, ipv4hdr.proto)?;

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

    let feat = Features::new();

    if feat.log_enabled(Level::Info) {
        info!(
            ctx,
            "[i:{}, rx:{}] [p:{}] {:i}:{} -> {:i}:{}",
            if_index,
            rx_queue,
            proto as u8,
            src_addr.to_be(),
            l4ctx.src_port.to_be(),
            dst_addr.to_be(),
            l4ctx.dst_port.to_be()
        );
    }

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
        if nat.ip_src == src_addr && src_port == dst_port {
            if feat.log_enabled(Level::Error) {
                error!(
                    ctx,
                    "[out] drop same src {:i}:{}",
                    nat.ip_src.to_be(),
                    src_port.to_be()
                );
            }
            stats_inc(stats::XDP_DROP);
            return Ok(xdp_action::XDP_DROP);
        }

        let full_nat = nat.lb_ip != dst_addr;
        let diff_src_ip = src_addr != nat.ip_src;

        // NOTE: optimization: since the destination IP (LB)
        // 'remains' in the csum we can recompute it as if
        // only the source IP changes.

        // TODO: both path mut set the src_addr to current LB
        ipv4hdr.dst_addr = nat.ip_src;

        if full_nat {
            // NOTE: both src and dest IPs must be translated
            ipv4hdr.src_addr = nat.lb_ip;

            let csum = csum_update_u32(src_addr, nat.lb_ip, check);
            let csum = csum_update_u32(dst_addr, nat.ip_src, csum);

            ipv4hdr.check = !csum_fold_32_to_16(csum);
        } else {
            ipv4hdr.src_addr = dst_addr;

            // NOTE: optimization: skip csum computation if the addresses
            // don't actually change.
            if diff_src_ip {
                //csum = csum_update_u32(src_addr, dst_addr, csum);
                //csum = csum_update_u32(dst_addr, nat.ip_src, csum);
                let csum = csum_update_u32(src_addr, nat.ip_src, check);
                ipv4hdr.check = !csum_fold_32_to_16(csum);
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

                // The source and destination IPs are part of the TCP pseudo header
                if full_nat {
                    tcs = csum_update_u32(src_addr, nat.lb_ip, tcs);
                    tcs = csum_update_u32(dst_addr, nat.ip_src, tcs);
                } else if diff_src_ip {
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

                // The source and destination IPs are part of the UDP pseudo header
                if full_nat {
                    ucs = csum_update_u32(src_addr, nat.lb_ip, ucs);
                    ucs = csum_update_u32(dst_addr, nat.ip_src, ucs);
                } else if diff_src_ip {
                    ucs = csum_update_u32(src_addr, nat.ip_src, ucs);
                }

                // The destination port is part of the header
                ucs = csum_update_u32(src_port as u32, nat.port_lb, ucs);
                (*udphdr).check = !csum_fold_32_to_16(ucs);
            },
            _ => {}
        };

        let ret = if nat.flags.contains(EPFlags::XDP_REDIRECT) {
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
            let ret = redirect_txport(ctx, &feat, nat.ifindex);

            if full_nat && ret == xdp_action::XDP_REDIRECT {
                stats_inc(stats::XDP_REDIRECT_FULL_NAT);
            }

            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[out] redirect to {:i}:{} via {}, ret={}",
                    nat.ip_src.to_be(),
                    dst_port.to_be(),
                    nat.ifindex,
                    ret,
                );
            }
            ret
        } else if nat.flags.contains(EPFlags::XDP_TX) {
            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[out] tx to {:i}:{}",
                    nat.ip_src.to_be(),
                    dst_port.to_be(),
                );
            }
            stats_inc(stats::XDP_TX);
            xdp_action::XDP_TX
        } else {
            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[out] pass to {:i}:{}",
                    nat.ip_src.to_be(),
                    dst_port.to_be(),
                );
            }
            stats_inc(stats::XDP_PASS);
            xdp_action::XDP_PASS
        };
        return Ok(ret);
    } else {
        // TODO: to remove ?
        if feat.log_enabled(Level::Info) {
            info!(ctx, "No conntrack entry");
        }
    }

    let ep4 = EP4 {
        address: dst_addr,
        port: dst_port,
        proto: proto as u16,
    };

    let group = match unsafe { ZLB_LB4.get(&ep4) } {
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
        index: ((((src_addr >> 16) ^ src_addr) as u16) ^ src_port) % group.becount,
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
    let redirect = be.flags.contains(EPFlags::XDP_REDIRECT);

    let lb_addr = if redirect && be.flags.contains(EPFlags::XDP_TX) && be.src_ip[0] != 0 {
        // TODO: check the arp table and update or insert
        // smac/dmac and derived ip src and redirect ifindex
        be.src_ip[0]
    } else {
        dst_addr
    };

    // NOTE: Don't insert entry if no connection tracking is enabled for this backend.
    // For e.g. if the backend can reply directly to the source endpoint.
    if !be.flags.contains(EPFlags::NO_CONNTRACK) {
        // NOTE: the LB will use the source port since there can be multiple
        // connection to the same backend and it needs to track all of them.
        let nat4key = NAT4Key {
            ip_be_src: be.address[0],
            ip_lb_dst: lb_addr,
            port_be_src: be.port,
            port_lb_dst: src_port, // use the source port of the endpoint
            proto: proto as u32,
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

        // Update the nat entry only if the source details changes.
        // This will boost performance and less error prone on tests like iperf.
        let do_insert = if let Some(nat4) = unsafe { ZLB_CONNTRACK4.get(&nat4key) } {
            nat4.ifindex != if_index
                || nat4.ip_src != src_addr
                || nat4.mac_addresses != mac_addresses
        } else {
            true
        };

        if do_insert {
            let nat4value = NAT4Value {
                ip_src: src_addr,
                port_lb: dst_port as u32,
                ifindex: if_index,
                mac_addresses,
                flags: be.flags,
                lb_ip: dst_addr, // save the original LB IP
            };

            // TBD: use lock or atomic update ?
            // TBD: use BPF_F_LOCK ?
            match unsafe { ZLB_CONNTRACK4.insert(&nat4key, &nat4value, 0) } {
                Ok(()) => {
                    if feat.log_enabled(Level::Info) {
                        info!(ctx, "[ctrk] {:i} added", src_addr.to_be())
                    }
                }
                Err(ret) => {
                    if feat.log_enabled(Level::Error) {
                        error!(ctx, "[ctrk] {:i} not added, err: {}", src_addr.to_be(), ret)
                    }
                    stats_inc(stats::CT_ERROR_UPDATE);
                }
            };
        }
    }

    // NOTE: optimization: compute the IP csum as if only
    // the source address changes.
    ipv4hdr.src_addr = lb_addr;
    ipv4hdr.dst_addr = be.address[0];

    // TODO: check if we can compute delta diff and just apply the delta
    // to the tcp/udp check sum.
    if lb_addr != dst_addr {
        let csum = csum_update_u32(dst_addr, be.address[0], check);
        let csum = csum_update_u32(src_addr, lb_addr, csum);
        ipv4hdr.check = !csum_fold_32_to_16(csum);
    } else if src_addr != be.address[0] {
        //csum = csum_update_u32(dst_addr, be.address.v4, csum);
        //csum = csum_update_u32(src_addr, dst_addr, csum);
        let csum = csum_update_u32(src_addr, be.address[0], check);
        ipv4hdr.check = !csum_fold_32_to_16(csum);
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
            if lb_addr != dst_addr {
                tcs = csum_update_u32(dst_addr, be.address[0], tcs);
                tcs = csum_update_u32(src_addr, lb_addr, tcs);
            } else if src_addr != be.address[0] {
                tcs = csum_update_u32(src_addr, be.address[0], tcs);
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
            if lb_addr != dst_addr {
                ucs = csum_update_u32(dst_addr, be.address[0], ucs);
                ucs = csum_update_u32(src_addr, lb_addr, ucs);
            } else if src_addr != be.address[0] {
                ucs = csum_update_u32(src_addr, be.address[0], ucs);
            }

            // The destination port is part of the header
            ucs = csum_update_u16(dst_port, be.port, ucs);
            (*udphdr).check = !csum_fold_32_to_16(ucs);
        },
        _ => {}
    };

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

    return redirect_ipv4(ctx, feat, ipv4hdr);
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

fn redirect_ipv4(ctx: &XdpContext, feat: Features, ipv4hdr: &Ipv4Hdr) -> Result<u32, ()> {
    if let Some(&entry) = unsafe { ZLB_ARP4.get(&ipv4hdr.dst_addr) } {
        // NOTE: check expiry before using this entry
        // TODO: check performance
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

    let fib_param = unsafe {
        BpfFibLookUp::new_inet(
            ipv4hdr.tot_len.to_be(),
            (*ctx.ctx).ingress_ifindex,
            ipv4hdr.tos as u32,
            ipv4hdr.src_addr,
            ipv4hdr.dst_addr,
        )
    };

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
        "[redirect] output, lkp_ret: {}, fw if: {}, src: {:i}, gw: {:i}, dmac: {:mac}, smac: {:mac}",
        rc,
        fib_param.ifindex,
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
            fib_param.fill_ethdr_macs(eth.cast_mut());
            redirect_txport(ctx, &feat, fib_param.ifindex)
        };

        if feat.log_enabled(Level::Info) {
            info!(ctx, "[redirect] action => {}", action);
        }

        update_arp(ctx, &feat, fib_param);

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

    stats_inc(stats::XDP_PASS);
    Ok(xdp_action::XDP_PASS)
}

fn update_arp(ctx: &XdpContext, feat: &Features, fib_param: BpfFibLookUp) {
    let arp = ArpEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src,
        expiry: unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32,
    };

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_ARP4.insert(&fib_param.dst[0], &arp, 0) } {
        Ok(()) => {
            if feat.log_enabled(Level::Info) {
                info!(
                    ctx,
                    "[arp] insert {:i} -> if:{}, smac: {:mac}, dmac: {:mac}, src: {:i}",
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
                error!(ctx, "[arp] fail to insert entry, err:{}", e)
            }
            stats_inc(stats::ARP_ERROR_UPDATE);
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

    unsafe fn fill_ethdr_macs(&self, ethdr: *mut EthHdr) {
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
