use crate::{ptr_at, Features};
use aya_ebpf::{bindings::xdp_action, macros::map, maps::HashMap, programs::XdpContext};
use aya_log_ebpf::{info, Level};
use network_types::{eth::EthHdr, ip::Ipv6Hdr};
use zon_lb_common::{BEGroup, EP6, MAX_GROUPS};

/// Same as ZLB_LB4 but for IPv6 packets.
#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::pinned(MAX_GROUPS, 0);

pub fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let _proto = unsafe { (*ipv6hdr).next_hdr };
    let feat = Features::new();

    if feat.log_enabled(Level::Info) {
        info!(ctx, "received a ipv6 packet");
    }

    Ok(xdp_action::XDP_PASS)
}
