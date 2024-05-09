use crate::{ptr_at, stats_inc, Features};
use aya_ebpf::{bindings::xdp_action, macros::map, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::{info, Level};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{stats, BEGroup, EP6, MAX_GROUPS};

/// Same as ZLB_LB4 but for IPv6 packets.
#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::pinned(MAX_GROUPS, 0);

pub fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let _src_addr = unsafe { (*ipv6hdr).src_addr };
    let dst_addr = unsafe { (*ipv6hdr).dst_addr.in6_u.u6_addr8 };
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // NOTE: IPv6 header isn't fixed and the L4 header offset can
    // be computed iterating over the extension headers until we
    // reach a non-extension next_hdr value. For now we assume
    // there are no extensions or fragments.
    let l4hdr_offset = Ipv6Hdr::LEN + EthHdr::LEN;

    let (_src_port, dst_port) = match next_hdr {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*udphdr).source, (*udphdr).dest) }
        }
        // TODO: drop extention headers or fragments because unlike with
        // IPv4, routers never fragment a packet. This LB works like a
        // router so it should drop any IPv6 fragments.
        _ => (0, 0),
    };

    let feat = Features::new();
    if feat.log_enabled(Level::Info) {
        info!(ctx, "received a ipv6 packet");
    }

    let ep6 = EP6 {
        // TODO: copy the 32-bit array instead
        address: dst_addr,
        port: dst_port,
        proto: next_hdr as u16,
    };

    let _group = match unsafe { ZLB_LB6.get(&ep6) } {
        Some(group) => *group,
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

    // Update the total processed packets when they are destined to a known backend group
    stats_inc(stats::PACKETS);

    Ok(xdp_action::XDP_PASS)
}
