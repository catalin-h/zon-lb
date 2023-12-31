#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    icmp::IcmpHdr,
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

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

// Per interface maps start with ZLB.
// Global common maps start just with ZLBX
#[map]
static ZLB_BACKENDS: HashMap<u32, u32> = HashMap::<u32, u32>::with_max_entries(1024, 0);

fn get_backend(ip: u32) -> u32 {
    *unsafe { ZLB_BACKENDS.get(&ip).unwrap_or(&0) }
}

#[xdp]
pub fn zon_lb(ctx: XdpContext) -> u32 {
    match try_zon_lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_zon_lb(ctx: XdpContext) -> Result<u32, ()> {
    info!(&ctx, "received a packet");

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {
            info!(&ctx, "received a ipv4 packet");
        }
        _ => {
            info!(&ctx, "received a non-ipv4 packet");
            return Ok(xdp_action::XDP_PASS);
        }
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });

    if get_backend(src_addr) != 0 {
        unsafe {
            (*(ipv4hdr as *mut Ipv4Hdr)).src_addr = dst_addr;
        }
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
