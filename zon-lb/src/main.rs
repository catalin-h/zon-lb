mod helpers;
mod info;
mod prog;

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{Array, HashMap, Map},
    programs::{
        links::{FdLink, PinnedLink},
        Xdp, XdpFlags,
    },
    BpfLoader, Btf,
};
use aya_log::BpfLogger;
use clap::{Parser, ValueEnum};
use helpers::*;
use info::*;
use log::{info, warn};
use prog::*;
use tokio::signal;
use zon_lb_common::{BEKey, ZonInfo, BE};

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum ProgAttachMode {
    /// Try attach the program in driver mode. In this mode the network interface driver must
    /// support XDP. Linux kernels with versions 5.x support virtual interfaces like veth or tun.
    /// For physical network cards must check the kernel version and the driver XDP support.
    Driver,
    /// Try attach the program in skb mode. This is the default attach mode and it is supported even
    /// if the network interface driver doesn't support XDP.
    Skb,
}

#[derive(clap::Args, Debug)]
struct ProgLoadOpt {
    #[arg(value_enum)]
    mode: Option<ProgAttachMode>,
}

impl ProgLoadOpt {
    fn xdp_flags(&self) -> XdpFlags {
        match self.mode {
            None => XdpFlags::default(),
            Some(attach_mode) => match attach_mode {
                ProgAttachMode::Driver => XdpFlags::DRV_MODE,
                ProgAttachMode::Skb => XdpFlags::SKB_MODE,
            },
        }
    }
}

#[derive(clap::Subcommand, Debug)]
enum ProgAction {
    /// Loads the xdp program to target interface
    Load(ProgLoadOpt),
    /// Unloads only the current xdp program but leaves any maps untouched
    Unload,
    /// Atomically replaces the current program for current interface
    Replace,
    /// Tears down both the program and any attached maps and link for the provided interface
    Teardown,
    /// Reloads both the program and maps for the input interface
    Reload(ProgLoadOpt),
}

#[derive(clap::Args, Debug)]
struct ProgOpt {
    #[clap(default_value = "lo")]
    ifname: String,
    #[clap(subcommand)]
    action: ProgAction,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Shows information about loaded programs and the used maps
    Info,
    /// Program only options: load, unload and replace
    Prog(ProgOpt),
}

#[derive(Debug, Parser)]
#[clap(group(clap::ArgGroup::new("xdp")
            .required(false)
            .multiple(false)
            .args(&["xdp_replace","xdp_teardown", "teardown", "reload"])))]
#[clap(group(clap::ArgGroup::new("xdp_mode")
            .required(false)
            .multiple(false)
            .args(&["xdp_driver_mode","xdp_skb_mode"])))]
#[clap(propagate_version = false)]
struct Cli {
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

    #[clap(subcommand)]
    command: Command,
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
pub const PROG_NAME: &str = "zon_lb";

fn bpf_instance(ebpf: &[u8]) -> Result<aya::Bpf, anyhow::Error> {
    let mut bpf = BpfLoader::new()
        .btf(Btf::from_sys_fs().ok().as_ref())
        .load(ebpf)
        .context("Failed to load the program blob")?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if all log statements are removed from eBPF program.
        warn!("Failed to initialize eBPF logger: {}", e);
    }
    Ok(bpf)
}

fn handle_prog(opt: &ProgOpt) -> Result<(), anyhow::Error> {
    let mut prg = Prog::new(&opt.ifname)?;

    info!("Using zon-lb bpffs: {}", prg.link_path_str);

    match &opt.action {
        ProgAction::Teardown => prg.teardown(),
        ProgAction::Unload => prg.unload(),
        ProgAction::Replace => prg.replace(&mut bpf_instance(ZONLB)?),
        ProgAction::Load(load_opt) => {
            info!("Try attach program to interface: {}", &opt.ifname);
            prg.load(&mut bpf_instance(ZONLB)?, load_opt.xdp_flags())
        }
        ProgAction::Reload(load_opt) => {
            info!("Try reattach program to interface: {}", &opt.ifname);
            prg.teardown()?;
            prg.load(&mut bpf_instance(ZONLB)?, load_opt.xdp_flags())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    env_logger::init();

    let result = match &cli.command {
        Command::Info => list_info(),
        Command::Prog(opt) => handle_prog(opt),
    };

    if result.is_ok() {
        return Ok(());
    }

    let opt: &Cli = &cli;

    let (zdpath, mut zlblink_exists) = prog_bpffs(&cli.ifname)?;
    let zdpath_str = zdpath.to_str().unwrap_or_default();
    info!("Using zon-lb bpffs: {}", zdpath_str);

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
