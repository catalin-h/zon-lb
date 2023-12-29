use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::{HashMap, Map, MapData},
    programs::{
        links::{FdLink, PinnedLink},
        Xdp, XdpFlags,
    },
    Bpf, BpfLoader, Btf,
};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
use std::path::{Path, PathBuf};
use tokio::signal;

#[derive(Debug, Parser)]
#[clap(group(clap::ArgGroup::new("xdp")
            .required(false)
            .multiple(false)
            .args(&["xdp_replace","xdp_teardown", "teardown"])))]
struct Opt {
    /// The target network interface name
    #[clap(short, long, default_value = "lo")]
    ifname: String,
    /// By default the user app won't replace the current xdp program attached to the interface.
    /// This flag will instruct the user app to override the existing program.
    #[clap(long)]
    xdp_replace: bool,
    /// Tears down the current attached program
    #[clap(long)]
    xdp_teardown: bool,
    // Tears down both the attached program and the associated maps for the input interface
    #[clap(long)]
    teardown: bool,
    /// Repin all links for unpinned maps. It should be used after fixing the bpffs error
    /// that prevented the pinned link creation. The program and other created maps are not
    /// affected.
    #[clap(long)]
    maps_fix_pinning: bool,
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

fn teardown_maps(prefix: &str) -> Result<(), anyhow::Error> {
    let iter = std::fs::read_dir("/sys/fs/bpf/").context("Failed to iterate bpffs")?;

    for path in iter
        .into_iter()
        .filter_map(|entry| entry.map_or(None, |p| Some(p.path())))
        .filter_map(|path| if path.is_file() { Some(path) } else { None })
        .filter_map(|path| {
            if path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .starts_with(prefix)
            {
                Some(path)
            } else {
                None
            }
        })
    {
        match std::fs::remove_file(&path) {
            Ok(_) => {
                info!(
                    "Removing pinned link: {}",
                    &path.to_str().unwrap_or_default()
                );
            }
            Err(e) => {
                warn!(
                    "Failed to remove pinned link: {}, e: {}",
                    &path.to_str().unwrap_or_default(),
                    e.to_string()
                );
            }
        };
    }

    Ok(())
}

fn create_pinned_links_for_maps(bpf: &mut Bpf, ifname: &str) -> Result<(), anyhow::Error> {
    for (name, map) in bpf.maps() {
        if let Some(path) = pinned_link_bpffs_path(ifname, name) {
            let path_str = path.to_str().unwrap_or_default();
            match path.try_exists() {
                Ok(false) => {
                    map.pin(&path)
                        .context("Failed to create pinned link for map")?;
                    info!("Pinned link created for map {} at {}", name, path_str);
                }
                Ok(true) => {
                    info!("Map {} already pinned at {}", name, path_str);
                }
                Err(e) => {
                    warn!(
                        "Failed to check if pinned link exists for map {} at {}, {}",
                        name,
                        path_str,
                        e.to_string()
                    );
                }
            }
        } else {
            info!("Skip non zon-lb map: {}", name);
        }
    }
    Ok(())
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

    let c_interface = std::ffi::CString::new((&opt.ifname).as_str()).unwrap();
    let if_index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if if_index == 0 {
        return Err(anyhow!("No interface {}", &opt.ifname));
    }

    // Default location for bpffs
    let zdpath = pinned_link_bpffs_path(&opt.ifname, "").unwrap();
    let zdpath_str = zdpath.to_str().unwrap_or_default();

    info!("Using zon-lb bpffs: {}", zdpath_str);
    let zlblink_exists = zdpath
        .try_exists()
        .context("Can't verify if zon-lb bpffs exists")?;

    // Tear down the program only
    if zlblink_exists && (opt.xdp_teardown || opt.teardown) {
        info!(
            "Try unpin link for program attached to interface: {}",
            &opt.ifname
        );

        let link =
            PinnedLink::from_pin(&zdpath).context("Failed to load pinned link for zon-lb bpffs")?;
        link.unpin().context("Can't unpin program link")?;
    }

    // Teardown the maps associated with the interface
    if opt.teardown {
        match pinned_link_name(&opt.ifname, "") {
            None => {
                warn!("Invalid link for interface: {}", &opt.ifname);
            }
            Some(prefix) => {
                teardown_maps(&prefix)?;
            }
        };
    }

    if opt.teardown || opt.xdp_teardown {
        info!("Tear down program for interface: {} complete", &opt.ifname);
        return Ok(());
    }

    // TODO: aya::programs::loaded_programs iterate over all programs and
    // check if zon-lb is running. Also, check if there is another xdp
    // program attached to current interface.

    if opt.xdp_replace || !zlblink_exists {
        // Load the BTF data from /sys/kernel/btf/vmlinux and the lb program
        let mut bpf = BpfLoader::new()
            .btf(Btf::from_sys_fs().ok().as_ref())
            .load(ZONLB)
            .context("Failed to load the program blob")?;

        if let Err(e) = BpfLogger::init(&mut bpf) {
            // This can happen if all log statements are removed from eBPF program.
            warn!("Failed to initialize eBPF logger: {}", e);
        }

        let program: &mut Xdp = bpf.program_mut("zon_lb").unwrap().try_into()?;
        program.load().context("Failed to load program in kernel")?;

        let mut pinned_maps = opt.maps_fix_pinning;

        // There is an exiting pinned link to the program
        if zlblink_exists && opt.xdp_replace {
            // TODO: show found and current program versions
            info!(
                "Found zon-lb pinned link, try replace existing program for interface: {}",
                &opt.ifname
            );

            let link = PinnedLink::from_pin(zdpath)
                .context("Failed to load pinned link for zon-lb bpffs")?;
            let link = FdLink::from(link);
            program
                .attach_to_link(link.try_into()?)
                .context("Failed to attach new program to existing link")?;
        } else {
            info!("Try attach current program to interface: {}", &opt.ifname);

            // TODO: add option to choose skb or driver mode

            // Try changing XdpFlags::default() to XdpFlags::SKB_MODE if it failed to attach
            // the XDP program with default flags
            let xdpflags = XdpFlags::default();

            //for flag in xdpflags {
            //    info!("Flags: {:?}", flag);
            //}

            let xdplinkid = program
                .attach(&opt.ifname, xdpflags)
                .context("Failed to attach program link to interface")?;

            // Pin the program link to bpf file system (bpffs)
            let xdplink = program.take_link(xdplinkid)?;
            let fdlink: FdLink = xdplink.try_into()?;
            fdlink
                .pin(zdpath)
                .context("Failed to create pinned link for program")?;

            pinned_maps = true;
        }

        if pinned_maps {
            create_pinned_links_for_maps(&mut bpf, &opt.ifname)?;
        }
    } else {
        info!("No Xdp program was loaded, access maps only mode");
    }

    // TODO: add option to reset a single map or all maps

    let map = mapdata_from_pinned_map(&opt.ifname, "ZLB_BACKENDS").unwrap();
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
