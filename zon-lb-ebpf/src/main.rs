#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{in6_addr, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use zon_lb_common::{
    BEGroup, BEKey, EPFlags, GroupInfo, ZonInfo, BE, EP4, EP6, MAX_BACKENDS, MAX_GROUPS,
};

// Per interface maps start with ZLB.
// Global common maps start just with ZLBX
#[map]
static ZLB_INFO: Array<ZonInfo> = Array::with_max_entries(1, 0);

/// Shared meta data between multiples groups and interfaces. Used only by userspace
/// application but loaded by the first program.
#[map]
static ZLBX_GMETA: HashMap<u64, GroupInfo> =
    HashMap::<u64, GroupInfo>::with_max_entries(MAX_GROUPS, 0);

#[map]
static ZLB_LB4: HashMap<EP4, BEGroup> = HashMap::<EP4, BEGroup>::with_max_entries(MAX_GROUPS, 0);

#[map]
static ZLB_LB6: HashMap<EP6, BEGroup> = HashMap::<EP6, BEGroup>::with_max_entries(MAX_GROUPS, 0);

#[map]
static ZLBX_BACKENDS: HashMap<BEKey, BE> = HashMap::<BEKey, BE>::with_max_entries(MAX_BACKENDS, 0);

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
    let ipv4hdr = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    //let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    //let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let proto = unsafe { (*ipv4hdr).proto };

    let (src_port, dst_port) = match proto {
        IpProto::Tcp => {
            let tcphdr = ptr_at::<TcpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { ((*tcphdr).source, (*tcphdr).dest) }
        }
        IpProto::Udp => {
            let udphdr = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;
            unsafe { ((*udphdr).source, (*udphdr).dest) }
        }
        _ => (0, 0),
    };

    let mut ep4 = EP4 {
        address: unsafe { (*ipv4hdr).dst_addr }.to_le_bytes(),
        port: dst_port.to_le(),
        proto: (proto as u16).to_le(),
    };

    unsafe {
        info!(
            ctx,
            "Receive packet from {:i} to {:i}",
            (*ipv4hdr).src_addr,
            (*ipv4hdr).dst_addr
        );
    }

    let (group, ingress) = match unsafe { ZLB_LB4.get(&ep4) } {
        None => {
            ep4.address = unsafe { (*ipv4hdr).src_addr }.to_le_bytes();
            ep4.port = src_port;
            match unsafe { ZLB_LB4.get(&ep4) } {
                Some(group) => (group, 0),
                None => return Ok(xdp_action::XDP_PASS),
            }
        }
        Some(group) => (group, 1),
    };

    info!(ctx, "Group {} match, ingress {}", group.gid, ingress);

    if group.becount == 0 {
        return Ok(xdp_action::XDP_PASS);
    }

    Ok(xdp_action::XDP_PASS)
}

fn ipv6_lb(ctx: &XdpContext) -> Result<u32, ()> {
    let ipv6hdr = ptr_at::<Ipv6Hdr>(&ctx, EthHdr::LEN)?;
    let proto = unsafe { (*ipv6hdr).next_hdr };

    info!(ctx, "received a ipv6 packet");

    Ok(xdp_action::XDP_PASS)
}
