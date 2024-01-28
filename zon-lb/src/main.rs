mod backends;
mod helpers;
mod info;
mod prog;
mod protocols;
mod services;

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::{HashMap, Map},
    programs::XdpFlags,
    BpfLoader, Btf,
};
use aya_log::BpfLogger;
use backends::EndPoint;
use clap::{Parser, ValueEnum};
use helpers::*;
use info::*;
use log::{info, warn};
use prog::*;
use protocols::Protocol;
use tokio::signal;
use zon_lb_common::{BEKey, BE};

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

#[derive(clap::Args, Clone, Debug)]
struct PortOpt {
    /// Port number
    port: u16,
}

#[derive(clap::Subcommand, Debug)]
#[command(flatten_help = false, disable_help_flag = true)]
enum ProtocolInfo {
    /// Add TCP flow and port number
    Tcp(PortOpt),
    /// Add UDP flow and port number
    Udp(PortOpt),
    /// A service with a known ip protocol and port number,
    Service { service: services::Service },
    /// Other IP protocols besides TCP and UDP. For eg. ICMP
    Proto { protocol: Protocol },
}

#[derive(clap::Args, Debug)]
//#[command(args_conflicts_with_subcommands = true)]
#[command(flatten_help = false)]
struct AddEpOpt {
    /// Endpoint IP address. Both IP v4 and v6 formats are accepted.
    ip_address: String,
    /// The IP protocol details
    #[command(subcommand)]
    protocol_info: ProtocolInfo,
}

#[derive(clap::Subcommand, Debug)]
enum GroupAction {
    /// Add a new group of backends for load balancing
    Add(AddEpOpt),
    /// List all backend groups attached to current interface
    List,
    /// Remove group
    Remove {
        /// The group Id returned by 'group add' or 'group list' commands
        gid: u16,
    },
}

#[derive(clap::Args, Debug)]
//#[command(flatten_help = true)]
struct GroupOpt {
    /// Target net interface name, eg. eth0
    #[clap(default_value = "lo")]
    ifname: String,
    /// Group action
    #[clap(subcommand)]
    action: GroupAction,
}

#[derive(clap::Subcommand, Debug)]
enum BackendAction {
    /// Add a new backend for load balancing
    Add(AddEpOpt),
    /// List all backends in the group
    List,
    /// Remove backend
    Remove {
        /// The backend id returned by 'backend add' or 'backend list' commands
        bid: u64,
    },
}

#[derive(clap::Args, Debug)]
struct BackendOpt {
    /// Target backend group id.
    gid: u64,
    /// Backend actions
    #[clap(subcommand)]
    action: BackendAction,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Shows information about loaded programs and the used maps
    Info,
    /// Program only options: load, unload and replace
    Prog(ProgOpt),
    /// Backend group manage options
    Group(GroupOpt),
    /// Backends manage options
    Backend(BackendOpt),
    /// Debug and monitor program activity
    Debug,
}

#[derive(Debug, Parser)]
#[clap(propagate_version = false)]
struct Cli {
    /// The target network interface name
    #[clap(short, long, default_value = "lo")]
    ifname: String,

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

fn handler_add_ep(opt: &AddEpOpt) -> Result<EndPoint, anyhow::Error> {
    let (proto, port) = match &opt.protocol_info {
        ProtocolInfo::Tcp(port_opt) => (Protocol::Tcp, Some(port_opt.port)),
        ProtocolInfo::Udp(port_opt) => (Protocol::Udp, Some(port_opt.port)),
        ProtocolInfo::Service { service } => (service.protocol(), Some(service.port())),
        ProtocolInfo::Proto { protocol } => (*protocol, None),
    };

    let ep = EndPoint::new(&opt.ip_address, proto, port)?;

    Ok(ep)
}

fn handle_group(opt: &GroupOpt) -> Result<(), anyhow::Error> {
    let group = backends::Group::new(&opt.ifname)?;

    match &opt.action {
        GroupAction::Add(add_opt) => {
            let ep = handler_add_ep(&add_opt)?;
            let gid = group.add(&ep)?;
            info!("[{}] group {} added => {}", &opt.ifname, ep, gid);
        }
        GroupAction::List => group.list()?,
        GroupAction::Remove { gid } => {
            let eps = group.remove(*gid as u64)?;
            for ep in eps {
                info!("[{}] group {} deleted => {}", &opt.ifname, ep, gid);
            }
        }
    }

    Ok(())
}

fn handle_backends(opt: &BackendOpt) -> Result<(), anyhow::Error> {
    // TODO: add option to reset a specific map
    // TODO: add option to add/update/delete a specific value from a specific map
    // TODO: add option to dump entries from a specific map

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    env_logger::init();

    match &cli.command {
        Command::Info => list_info(),
        Command::Prog(opt) => handle_prog(opt),
        Command::Group(opt) => handle_group(opt),
        Command::Backend(opt) => handle_backends(opt),
        Command::Debug => {
            info!("Waiting for Ctrl-C...");
            signal::ctrl_c().await?;
            info!("Exiting...");
            Ok(())
        }
    }?;

    // TODO: aya::programs::loaded_programs iterate over all programs and
    // check if zon-lb is running. Also, check if there is another xdp
    // program attached to current interface.
    // TODO: add option to enable debug mode and listen for messages

    Ok(())
}
