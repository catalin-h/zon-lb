use crate::{ptr_at, stats_inc, Features};
use aya_ebpf::{bindings::xdp_action, macros::map, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::{info, Level};
use network_types::{
    eth::EthHdr,
    ip::{IpProto, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{stats, BEGroup, Inet6U, EP6, MAX_GROUPS};

/// Same as ZLB_LB4 but for IPv6 packets.
#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::pinned(MAX_GROUPS, 0);

pub fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { Inet6U::from((*ipv6hdr).src_addr.in6_u.u6_addr32) };
    let dst_addr = unsafe { Inet6U::from((*ipv6hdr).dst_addr.in6_u.u6_addr32) };
    let next_hdr = unsafe { (*ipv6hdr).next_hdr };

    // NOTE: IPv6 header isn't fixed and the L4 header offset can
    // be computed iterating over the extension headers until we
    // reach a non-extension next_hdr value. For now we assume
    // there are no extensions or fragments.
    let l4hdr_offset = Ipv6Hdr::LEN + EthHdr::LEN;

    // TODO: For IPv6 there can be only 6 linked header types: Hop-by-Hop Options,
    // Fragment, Destination Options, Routing, Authentication and Encapsulating
    // Security Payload. I makes sense to make make 6 calls until reaching a
    // next header we can handle.
    let (src_port, dst_port) = match next_hdr {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, l4hdr_offset)?;
            unsafe { ((*udphdr).source, (*udphdr).dest) }
        }
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
        _ => (0, 0),
    };

    let feat = Features::new();
    if feat.log_enabled(Level::Info) {
        let (if_index, rx_queue) =
            unsafe { ((*ctx.ctx).ingress_ifindex, (*ctx.ctx).rx_queue_index) };
        info!(
            ctx,
            "[i:{}, rx:{}] [p:{}] [{:i}]:{} -> *[{:i}]:{}",
            if_index,
            rx_queue,
            next_hdr as u8,
            unsafe { src_addr.addr8 },
            src_port.to_be(),
            unsafe { dst_addr.addr8 },
            dst_port.to_be()
        );
    }

    let ep6 = EP6 {
        // TODO: copy the 32-bit array instead
        address: dst_addr,
        port: dst_port,
        proto: next_hdr as u16,
    };

    let group = match unsafe { ZLB_LB6.get(&ep6) } {
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

    Ok(xdp_action::XDP_PASS)
}
