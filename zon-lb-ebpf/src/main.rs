#![no_std]
#![no_main]

use aya_bpf::{
    bindings::{
        bpf_fib_lookup as bpf_fib_lookup_param_t,
        xdp_action::{self, XDP_DROP, XDP_PASS, XDP_TX},
        BPF_FIB_LKUP_RET_BLACKHOLE, BPF_FIB_LKUP_RET_PROHIBIT, BPF_FIB_LKUP_RET_SUCCESS,
        BPF_FIB_LKUP_RET_UNREACHABLE, BPF_F_NO_COMMON_LRU,
    },
    helpers::{bpf_fib_lookup, bpf_ktime_get_ns, bpf_redirect},
    macros::{map, xdp},
    maps::{Array, DevMap, HashMap, LruHashMap},
    programs::XdpContext,
    BpfContext,
};
use aya_log_ebpf::{error, info};
use core::mem;
use ebpf_rshelpers::{csum_fold_32_to_16, csum_update_u16, csum_update_u32};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    runvars::*, ArpEntry, BEGroup, BEKey, EPFlags, GroupInfo, NAT4Key, NAT4Value, ZonInfo, BE, EP4,
    EP6, MAX_ARP_ENTRIES, MAX_BACKENDS, MAX_CONNTRACKS, MAX_GROUPS,
};

/// Stores the program instance runtime variables.
#[map]
static ZLB_RUNVAR: Array<u64> = Array::with_max_entries(MAX_RUNTIME_VARS, 0);

// TODO: change it to array to add:
// - packet counters
// - enable / disable logging
/// Keeps runtime config data.
#[map]
static ZLB_INFO: Array<ZonInfo> = Array::with_max_entries(1, 0);

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

/// Same as ZLB_LB4 but for IPv6 packets.
#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::pinned(MAX_GROUPS, 0);

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

// TODO: add ipv6 arp table

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
        Err(_) => xdp_action::XDP_PASS,
    }
}

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

fn ipv4_lb(ctx: &XdpContext) -> Result<u32, ()> {
    // TODO: support vlan tags
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv4hdr).src_addr };
    let dst_addr = unsafe { (*ipv4hdr).dst_addr };
    let proto = unsafe { (*ipv4hdr).proto };
    let check = !unsafe { (*ipv4hdr).check } as u32;
    let (if_index, rx_queue) = unsafe { ((*ctx.ctx).ingress_ifindex, (*ctx.ctx).rx_queue_index) };

    // NOTE: compute the l4 header start based on ipv4hdr.IHL
    let l4hdr_offset = (unsafe { (*ipv4hdr).ihl() as usize } << 2);
    info!(ctx, "ipv4 hdr size {}", l4hdr_offset);
    let l4hdr_offset = l4hdr_offset + EthHdr::LEN;

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

    info!(
        ctx,
        "[i:{}, rx:{}] [p:{}] {:i}:{} -> {:i}:{}",
        if_index,
        rx_queue,
        proto as u8,
        src_addr.to_be(),
        src_port.to_be(),
        dst_addr.to_be(),
        dst_port.to_be()
    );

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
        info!(
            ctx,
            "[out] nat, src: {:i}, lb_port: {}",
            nat.ip_src.to_be(),
            (nat.port_lb as u16).to_be()
        );

        // Unlikely
        if nat.ip_src == src_addr && src_port == dst_port {
            error!(
                ctx,
                "[out] drop same src {:i}:{}",
                nat.ip_src.to_be(),
                src_port.to_be()
            );
            return Ok(xdp_action::XDP_DROP);
        }

        let full_nat = nat.lb_ip != dst_addr;
        let diff_src_ip = src_addr != nat.ip_src;

        // NOTE: optimization: since the destination IP (LB)
        // 'remains' in the csum we can recompute it as if
        // only the source IP changes.
        unsafe {
            let hdr = ipv4hdr.cast_mut();
            (*hdr).dst_addr = nat.ip_src;

            if full_nat {
                // NOTE: both src and dest IPs must be translated

                (*hdr).src_addr = nat.lb_ip;
                (*hdr).dst_addr = nat.ip_src;

                let csum = csum_update_u32(src_addr, nat.lb_ip, check);
                let csum = csum_update_u32(dst_addr, nat.ip_src, csum);

                (*hdr).check = !csum_fold_32_to_16(csum);
            } else {
                (*hdr).src_addr = dst_addr;

                // NOTE: optimization: skip csum computation if the addresses
                // don't actually change.
                if diff_src_ip {
                    //csum = csum_update_u32(src_addr, dst_addr, csum);
                    //csum = csum_update_u32(dst_addr, nat.ip_src, csum);
                    let csum = csum_update_u32(src_addr, nat.ip_src, check);
                    (*hdr).check = !csum_fold_32_to_16(csum);
                }
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
            let ret = unsafe {
                *macs = nat.mac_addresses;
                // NOTE: aya embeds the bpf_redirect_map in map struct impl
                match ZLB_TXPORT.redirect(nat.ifindex, 0) {
                    Ok(action) => action,
                    Err(e) => {
                        error!(ctx, "No tx port for if key: {}, error: {}", nat.ifindex, e);
                        bpf_redirect(nat.ifindex, 0) as xdp_action::Type
                    }
                }
            };
            info!(
                ctx,
                "[out] redirect to {:i}:{} via {}, ret={}",
                nat.ip_src.to_be(),
                dst_port.to_be(),
                nat.ifindex,
                ret,
            );
            ret
        } else if nat.flags.contains(EPFlags::XDP_TX) {
            info!(
                ctx,
                "[out] tx to {:i}:{}",
                nat.ip_src.to_be(),
                dst_port.to_be(),
            );
            XDP_TX
        } else {
            info!(
                ctx,
                "[out] pass to {:i}:{}",
                nat.ip_src.to_be(),
                dst_port.to_be(),
            );
            XDP_PASS
        };

        return Ok(ret);
    } else {
        info!(ctx, "No conntrack entry");
    }

    let ep4 = EP4 {
        address: dst_addr,
        port: dst_port,
        proto: proto as u16,
    };

    let group = match unsafe { ZLB_LB4.get(&ep4) } {
        Some(group) => *group,
        None => {
            info!(ctx, "No LB4 entry");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    info!(ctx, "[in] gid: {} match", group.gid);

    if group.becount == 0 {
        info!(ctx, "[in] gid: {}, no backends", group.gid);
        return Ok(xdp_action::XDP_PASS);
    }

    let key = BEKey {
        gid: group.gid,
        index: ((((src_addr >> 16) ^ src_addr) as u16) ^ src_port) % group.becount,
    };

    let be = match unsafe { ZLB_BACKENDS.get(&key) } {
        Some(be) => be,
        None => {
            info!(ctx, "[in] gid: {}, no BE at: {}", group.gid, key.index);
            return Ok(xdp_action::XDP_PASS);
        }
    };

    info!(
        ctx,
        "[ctrk] fw be: {:i}:{}",
        be.address[0].to_be(),
        be.port.to_be()
    );

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
                Ok(()) => info!(ctx, "[ctrk] {:i} added", src_addr.to_be()),
                Err(ret) => error!(ctx, "[ctrk] {:i} not added, err: {}", src_addr.to_be(), ret),
            };
        }
    }

    // NOTE: optimization: compute the IP csum as if only
    // the source address changes.
    unsafe {
        let hdr = ipv4hdr.cast_mut();
        (*hdr).src_addr = lb_addr;
        (*hdr).dst_addr = be.address[0];

        // TODO: check if we can compute delta diff and just apply the delta
        // to the tcp/udp check sum.
        if lb_addr != dst_addr {
            let csum = csum_update_u32(dst_addr, be.address[0], check);
            let csum = csum_update_u32(src_addr, lb_addr, csum);
            (*hdr).check = !csum_fold_32_to_16(csum);
        } else if src_addr != be.address[0] {
            //csum = csum_update_u32(dst_addr, be.address.v4, csum);
            //csum = csum_update_u32(src_addr, dst_addr, csum);
            let csum = csum_update_u32(src_addr, be.address[0], check);
            (*hdr).check = !csum_fold_32_to_16(csum);
        }
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

    // Send back the packet to the same interface
    if !redirect && be.flags.contains(EPFlags::XDP_TX) {
        info!(ctx, "in => xdp_tx");
        return Ok(xdp_action::XDP_TX);
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

    return redirect_ipv4(ctx, ipv4hdr);
}

fn redirect_txport(ctx: &XdpContext, ifindex: u32) -> xdp_action::Type {
    // NOTE: aya embeds the bpf_redirect_map in map struct impl
    match ZLB_TXPORT.redirect(ifindex, 0) {
        Ok(action) => action,
        Err(e) => {
            error!(ctx, "[redirect] No tx port: {}, {}", ifindex, e);
            unsafe { bpf_redirect(ifindex, 0) as xdp_action::Type }
        }
    }
}

fn redirect_ipv4(ctx: &XdpContext, ipv4hdr: *const Ipv4Hdr) -> Result<u32, ()> {
    let dest_ip = unsafe { (*ipv4hdr).dst_addr };

    if let Some(&entry) = unsafe { ZLB_ARP4.get(&dest_ip) } {
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

            let action = redirect_txport(ctx, entry.ifindex);

            info!(
                ctx,
                "[redirect] [arp-cache] oif: {} action => {}", entry.ifindex, action
            );
            return Ok(action);
        }
    }

    let fib_param = unsafe {
        BpfFibLookUp::new_inet(
            (*ipv4hdr).tot_len.to_be(),
            (*ctx.ctx).ingress_ifindex,
            (*ipv4hdr).tos as u32,
            (*ipv4hdr).src_addr,
            dest_ip,
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

    if rc == BPF_FIB_LKUP_RET_SUCCESS as i64 {
        // TODO: decrease the ipv4 ttl or ipv6 hop limit + ip hdr csum

        let action = unsafe {
            let eth = ptr_at::<EthHdr>(&ctx, 0)?;
            fib_param.fill_ethdr_macs(eth.cast_mut());
            redirect_txport(ctx, fib_param.ifindex)
        };

        info!(ctx, "[redirect] action => {}", action);

        update_arp(ctx, fib_param);

        return Ok(action);
    }

    if rc == BPF_FIB_LKUP_RET_BLACKHOLE as i64
        || rc == BPF_FIB_LKUP_RET_UNREACHABLE as i64
        || rc == BPF_FIB_LKUP_RET_PROHIBIT as i64
    {
        error!(ctx, "[redirect] can't fw, fib rc: {}", rc);
        return Ok(XDP_DROP);
    }

    if rc < 0 {
        error!(ctx, "[redirect] invalid arg, fib rc: {}", rc);
    } else {
        // let it pass to the stack to handle it
        info!(ctx, "[redirect] packet not fwd, fib rc: {}", rc);
    }

    Ok(XDP_PASS)
}

fn update_arp(ctx: &XdpContext, fib_param: BpfFibLookUp) {
    let arp = ArpEntry {
        ifindex: fib_param.ifindex,
        macs: fib_param.ethdr_macs(),
        ip_src: fib_param.src,
        expiry: unsafe { bpf_ktime_get_ns() / 1_000_000_000 } as u32,
    };

    // NOTE: after updating the value or key struct size must remove the pinned map
    // from bpffs. Otherwise, the verifier will throw 'invalid indirect access to stack'.
    match unsafe { ZLB_ARP4.insert(&fib_param.dst[0], &arp, 0) } {
        Ok(()) => info!(
            ctx,
            "[arp] insert {:i} -> if:{}, smac: {:mac}, dmac: {:mac}, src: {:i}",
            fib_param.dst[0].to_be(),
            fib_param.ifindex,
            fib_param.src_mac(),
            fib_param.dest_mac(),
            fib_param.src[0].to_be(),
        ),
        Err(e) => error!(ctx, "[arp] fail to insert entry, err:{}", e),
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

const ETH_ALEN: usize = 6;

// Address families
const AF_INET: u8 = 2; // Internet IP Protocol

// TODO: ipv6
//const AF_INET6: u8 = 10; // Internet IP Protocol

fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let _proto = unsafe { (*ipv6hdr).next_hdr };

    info!(ctx, "received a ipv6 packet");

    Ok(xdp_action::XDP_PASS)
}
