use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, Map, MapData},
    programs::{links::FdLink, Xdp, XdpFlags},
    BpfLoader, Btf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use std::path::{Path, PathBuf};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "lo")]
    iface: String,
}

// This will include your eBPF object file as raw bytes at compile-time and load it at
// runtime. This approach is recommended for most real-world use cases. If you would
// like to specify the eBPF program at runtime rather than at compile-time, you can
// reach for `Bpf::load_file` instead.
#[cfg(debug_assertions)]
const ZONLB: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/zon-lb");
#[cfg(not(debug_assertions))]
const ZONLB: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/release/zon-lb");

//
// Pinned link naming scheme used by the loading user app
//  program: zlb_<ifname>
//  prog maps: zlb_<ifname>_<map-name>
//  common maps: zlbx_<lowcase_name>
//
fn pinned_link_name(ifname: &str, map_name: &str) -> Option<String> {
    if map_name.is_empty() {
        Some(format!("zlb_{}", ifname))
    } else if ifname.is_empty() && map_name.starts_with("ZLBX") {
        Some(map_name.to_ascii_lowercase())
    } else if !ifname.is_empty() && map_name.starts_with("ZLB") && map_name.len() >= 5 {
        let mut name = map_name.to_ascii_lowercase();
        if map_name.starts_with("ZLB_") {
            name.insert(3, '_');
        } else {
            name.insert_str(3, "__");
        }
        name.insert_str(4, ifname);
        Some(name)
    } else {
        None
    }
}

fn pinned_link_bpffs_path(ifname: &str, map_name: &str) -> Option<PathBuf> {
    pinned_link_name(ifname, map_name).map(|pname| Path::new("/sys/fs/bpf").join(pname))
}

fn mapdata_from_pinned_map(ifname: &str, map_name: &str) -> Option<MapData> {
    pinned_link_bpffs_path(ifname, map_name).map_or(None, |path| match MapData::from_pin(&path) {
        Err(e) => {
            warn!(
                "Failed to get pinned map from link {:?}, {}",
                &path,
                e.to_string()
            );
            None
        }
        Ok(m) => Some(m),
    })
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    let c_interface = std::ffi::CString::new((&opt.iface).as_str()).unwrap();
    let if_index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if if_index == 0 {
        return Err(anyhow!("No interface {}", &opt.iface));
    }

    // Default location for bpffs
    let zdpath = pinned_link_bpffs_path(&opt.iface, "").unwrap();

    // Load the BTF data from /sys/kernel/btf/vmlinux and the lb program
    let mut bpf = BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .load(ZONLB)?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("zon_lb").unwrap().try_into()?;
    program.load()?;

    // There is an exiting pinned link to the program
    if zdpath.exists() {
        info!(
            "Found zon-lb pinned link, try attach from: {}",
            zdpath.to_str().unwrap()
        );

        let link = aya::programs::links::PinnedLink::from_pin(zdpath)?;
        let link = FdLink::from(link);
        program.attach_to_link(link.try_into()?)?;
    } else {
        info!(
            "No pinned link for zon-lb at {}, try attach program to interface: {}",
            zdpath.to_str().unwrap(),
            &opt.iface
        );

        // TODO: add flag to force remove existing xdp program attached to interface

        // Try changing XdpFlags::default() to XdpFlags::SKB_MODE if it failed to attach
        // the XDP program with default flags
        let xdplinkid = program
            .attach(&opt.iface, XdpFlags::default())
            .context("Failed to attach to interface with attachment type")?;

        // Pin the program link to bpf file system (bpffs)
        let xdplink = program.take_link(xdplinkid)?;
        let fdlink: FdLink = xdplink.try_into()?;
        fdlink.pin(zdpath)?;

        for (name, map) in bpf.maps() {
            if let Some(path) = pinned_link_bpffs_path(&opt.iface, name) {
                map.pin(path)?;
            }
        }
    }

    let map = mapdata_from_pinned_map(&opt.iface, "ZLB_BACKENDS").unwrap();
    let map = Map::HashMap(map);
    let mut blocklist: HashMap<_, u32, u32> = map.try_into()?;
    let key = blocklist.keys().count();

    match blocklist.insert(key as u32, 0, 0) {
        Ok(_) => info!("Key: {} inserted", key),
        _ => warn!("Key: {} not inserted", key),
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
