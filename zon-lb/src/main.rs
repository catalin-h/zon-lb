mod helpers;

use anyhow::{anyhow, Context};
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, Map, MapData, MapInfo},
    programs::{
        links::{FdLink, PinnedLink},
        loaded_links, loaded_programs, ProgramInfo, Xdp, XdpFlags,
    },
    BpfLoader, Btf,
};
use aya_log::BpfLogger;
use aya_obj::generated::bpf_prog_type;
use chrono::{DateTime, Local};
use clap::Parser;
use helpers::*;
use log::{debug, info, warn};
use std::collections::HashMap as StdHashMap;
use tokio::signal;
use zon_lb_common::{BEKey, ZonInfo, BE};

#[derive(Debug, Parser)]
#[clap(group(clap::ArgGroup::new("xdp")
            .required(false)
            .multiple(false)
            .args(&["xdp_replace","xdp_teardown", "teardown", "reload"])))]
#[clap(group(clap::ArgGroup::new("xdp_mode")
            .required(false)
            .multiple(false)
            .args(&["xdp_driver_mode","xdp_skb_mode"])))]
struct Opt {
    #[clap(long)]
    list: bool,

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

    /// Try attach the program in driver mode. In this mode the network interface driver must
    /// support XDP. Linux kernels with versions 5.x support virtual interfaces like veth or tun.
    /// For physical network cards must check the kernel version and the driver XDP support.
    #[clap(long)]
    xdp_driver_mode: bool,

    /// Try attach the program in skb mode. This is the default attach mode and it is supported even
    /// if the network interface driver doesn't support XDP.
    #[clap(long)]
    xdp_skb_mode: bool,

    /// Repin all links for unpinned maps. It should be used after fixing the bpffs error
    /// that prevented the pinned link creation. The program and other created maps are not
    /// affected.
    #[clap(long)]
    maps_fix_pinning: bool,

    /// Tears down both the attached program and the associated maps for the input interface
    #[clap(long)]
    teardown: bool,

    /// Tears downs ands reloads both xdp program and maps for the input interface
    #[clap(long)]
    reload: bool,
}

// This will include your eBPF object file as raw bytes at compile-time and load it at
// runtime. This approach is recommended for most real-world use cases. If you would
// like to specify the eBPF program at runtime rather than at compile-time, you can
// reach for `Bpf::load_file` instead.
#[cfg(debug_assertions)]
const ZONLB: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/zon-lb");
#[cfg(not(debug_assertions))]
const ZONLB: &[u8] = include_bytes_aligned!("../../target/bpfel-unknown-none/release/zon-lb");

/// Program name or main function of xdp program
const PROG_NAME: &str = "zon_lb";

// TODO: add struct to set/get ZLB_INFO data
fn get_zon_info(ifname: &str) -> Result<Array<MapData, ZonInfo>, anyhow::Error> {
    match mapdata_from_pinned_map(ifname, "ZLB_INFO") {
        Some(map) => {
            let map = Map::Array(map);
            let map: Array<_, ZonInfo> = map.try_into()?;
            Ok(map)
        }
        _ => Err(anyhow!("No ZLB_INFO map")),
    }
}

/// List formatting
fn list_info() -> Result<(), anyhow::Error> {
    struct ZLBInfo {
        prog: ProgramInfo,
        link_id: u32,
        ifindex: u32,
    }
    let mut pmap: StdHashMap<u32, ZLBInfo> = StdHashMap::new();

    let header = "Loaded zon-lb programs";
    println!("\r\n{0:-<1$}\r\n{header}\r\n{0:-<1$}", "-", header.len());

    for p in loaded_programs().filter_map(|p| match p {
        Ok(prog) => {
            if prog.program_type() == bpf_prog_type::BPF_PROG_TYPE_XDP as u32
                && prog
                    .name_as_str()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case(PROG_NAME)
            {
                Some(prog)
            } else {
                None
            }
        }
        Err(e) => {
            warn!("Failed to get program info, {}", e.to_string());
            None
        }
    }) {
        pmap.insert(
            p.id(),
            ZLBInfo {
                prog: p,
                link_id: 0,
                ifindex: 0,
            },
        );
    }

    // NOTE: since the zon-lb programs are attached to interface via links,
    // the if index is from aya_obj::generated::bpf_prog_info is invalid (0).
    // To get the actual attached interface must iterate over all links and match
    // the program id that the link refers.
    for l in loaded_links() {
        match l {
            Ok(link) => {
                if let Some(pinfo) = pmap.get_mut(&(link.prog_id as u32)) {
                    pinfo.link_id = link.id as u32;
                    pinfo.ifindex = unsafe { link.__bindgen_anon_1.xdp.ifindex as u32 };
                }
            }
            Err(e) => {
                warn!("Failed to get link info, {}", e.to_string());
            }
        }
    }

    // NOTE: use if_indextoname to get the interface name from index
    // NOTE: the maps must be used inside the program in order to be
    // present in the program info id list

    for (id, info) in pmap.iter() {
        println!("\r\nprogram_id: {}", id);
        println!("tag: {:>x}", info.prog.tag());
        let dt: DateTime<Local> = info.prog.loaded_at().into();
        println!("loaded_at: {}", dt.format("%H:%M:%S %d-%m-%Y"));
        let ifname = if_index_to_name(info.ifindex);
        match &ifname {
            Some(name) => {
                println!("ifname: {}", name);
                if let Some(pb) = pinned_link_bpffs_path(&name, "") {
                    match pb.try_exists() {
                        Ok(true) => println!("pin: {}", pb.to_string_lossy()),
                        _ => {}
                    }
                }
                match get_zon_info(&name) {
                    Ok(map) => match map.get(&0, 0) {
                        Ok(info) => {
                            println!("version: {}", info.version);
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            None => {
                println!("ifindex: {}", info.ifindex);
            }
        }
        if info.link_id != 0 {
            println!("link_id: {}", info.link_id);
        }

        let mut ids = info.prog.map_ids().unwrap_or_default();
        ids.sort();

        println!(
            "maps_ids: {}",
            ids.iter()
                .map(|id| id.to_string() + " ")
                .collect::<String>()
        );

        let mut tab: Vec<Vec<String>> = vec![vec![
            "name".to_string(),
            "id".to_string(),
            "type".to_string(),
            "max".to_string(),
            "flags".to_string(),
            "pin".to_string(),
        ]];
        let mut sizes = tab[0].iter().map(|s| s.len()).collect::<Vec<_>>();
        for (name, map) in ids.iter().filter_map(|&id| {
            MapInfo::from_id(id).map_or(None, |map| match map.name_as_str() {
                Some(name) => Some((name.to_string(), map)),
                _ => None,
            })
        }) {
            let pin = match &ifname {
                Some(iname) => {
                    if let Some(pb) = pinned_link_bpffs_path(iname, &name) {
                        match pb.try_exists() {
                            Ok(true) => pb.to_string_lossy().to_string(),
                            Ok(false) => "n/a".to_string(),
                            Err(e) => e.to_string(),
                        }
                    } else {
                        "n/a".to_string()
                    }
                }
                _ => "err".to_string(),
            };
            let row = vec![
                name,
                map.id().to_string(),
                map.map_type().to_string(),
                map.max_entries().to_string(),
                format!("{:x}h", map.map_flags()),
                pin,
            ];
            for (i, s) in row.iter().enumerate() {
                sizes[i] = sizes[i].max(s.len());
            }
            tab.push(row);
        }

        let mut hdr_len = 0_usize;
        for (i, row) in tab.iter().enumerate() {
            let line = format!(
                "{}",
                sizes
                    .iter()
                    .enumerate()
                    .map(|(i, &size)| format!("{0:<1$}", row[i], size + 1))
                    .collect::<String>()
            );
            println!("{}", line);
            if i == 0 {
                hdr_len = line.len() - sizes[row.len() - 1] + row[row.len() - 1].len() - 1;
                println!("{0:-<1$}", '-', hdr_len);
            } else if i == tab.len() - 1 {
                println!("{0:-<1$}", '-', hdr_len);
            }
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

    // Show loaded xdp programs on interfaces
    if opt.list {
        list_info()?;
        return Ok(());
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
    let mut zlblink_exists = zdpath
        .try_exists()
        .context("Can't verify if zon-lb bpffs exists")?;

    // Tear down the program only
    if zlblink_exists && (opt.xdp_teardown || opt.teardown || opt.reload) {
        let link =
            PinnedLink::from_pin(&zdpath).context("Failed to load pinned link for zon-lb bpffs")?;
        link.unpin().context("Can't unpin program link")?;

        info!(
            "Pinned link for program attached to {} removed: {}",
            &opt.ifname, zdpath_str
        );
        zlblink_exists = false;
    }

    // Teardown the maps associated with the interface
    if opt.teardown || opt.reload {
        match pinned_link_name(&opt.ifname, "") {
            None => {
                warn!("Invalid link for interface: {}", &opt.ifname);
            }
            Some(prefix) => {
                teardown_maps(&prefix)?;
            }
        };
    }

    if opt.teardown || opt.xdp_teardown || opt.reload {
        info!("Tear down for interface: {} complete", &opt.ifname);

        if !opt.reload {
            return Ok(());
        }
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

            let xdpflags = XdpFlags::default()
                | if opt.xdp_driver_mode {
                    info!("Attach program to {} in DRIVER mode", &opt.ifname);
                    XdpFlags::DRV_MODE
                } else if opt.xdp_skb_mode {
                    info!("Attach program to {} in SKB mode", &opt.ifname);
                    XdpFlags::SKB_MODE
                } else {
                    info!(
                        "Attach program to {} using default kernel mode",
                        &opt.ifname
                    );
                    XdpFlags::default()
                };

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

        // Initialize program info and start params
        let mut info: Array<_, ZonInfo> = Array::try_from(bpf.map_mut("ZLB_INFO").unwrap())?;
        info.set(0, ZonInfo::new(), 0)
            .context("Failed to set zon info")?;
    } else {
        info!("No Xdp program was loaded, access maps only mode");
    }

    // TODO: add option to reset a specific map
    // TODO: add option to add/update/delete a specific value from a specific map
    // TODO: add option to dump entries from a specific map

    let map = mapdata_from_pinned_map(&opt.ifname, "ZLB_BACKENDS").unwrap();
    let map = Map::HashMap(map);
    let mut blocklist: HashMap<_, BEKey, BE> = map.try_into()?;
    let key = blocklist.keys().count() as u32;
    let bekey: BEKey = key.into();

    match blocklist.insert(&bekey, BE::default(), 0) {
        Ok(_) => info!("Key: {} inserted", key),
        _ => warn!("Key: {} not inserted", key),
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
