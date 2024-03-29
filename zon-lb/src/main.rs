mod backends;
mod config;
mod conntrack;
mod helpers;
mod info;
mod logging;
mod prog;
mod protocols;
mod services;

use anyhow::Context;
use aya::{include_bytes_aligned, programs::XdpFlags, BpfLoader};
use aya_log::BpfLogger;
use backends::{Backend, EndPoint, ToEndPoint};
use clap::{Parser, ValueEnum};
use config::ConfigFile;
use conntrack::conntrack_list;
use core::fmt;
use info::*;
use log::{info, warn};
use logging::init_log;
use prog::*;
use protocols::Protocol;
use std::collections::BTreeMap;
use tokio::signal;
use zon_lb_common::EPFlags;

pub(crate) trait ToMapName {
    fn map_name() -> &'static str;
}

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

mod options {
    pub const DISABLE: &str = "disable";
    pub const REDIRECT: &str = "redirect";
    pub const TX: &str = "tx";
    pub const NO_NAT: &str = "no_nat";
}

#[derive(Clone)]
pub struct EpOptions {
    pub props: BTreeMap<String, String>,
    pub flags: EPFlags,
}

impl Default for EpOptions {
    fn default() -> Self {
        Self {
            props: BTreeMap::default(),
            flags: EPFlags::default(),
        }
    }
}

impl fmt::Display for EpOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for opt in self.to_options() {
            write!(f, "{} ", opt)?
        }
        Ok(())
    }
}

impl EpOptions {
    pub fn to_options(&self) -> Vec<String> {
        let mut opt = vec![];
        for flag in self.flags {
            let name = match flag {
                EPFlags::DISABLE => options::DISABLE,
                EPFlags::XDP_TX => options::TX,
                EPFlags::XDP_REDIRECT => options::REDIRECT,
                EPFlags::NO_CONNTRACK => options::NO_NAT,
                _ => continue,
            };
            opt.push(name.to_string());
        }
        for (k, v) in &self.props {
            opt.push(format!("{}={}", k, v));
        }
        opt
    }

    pub fn new(flags: EPFlags) -> Self {
        Self {
            props: BTreeMap::new(),
            flags,
        }
    }

    pub fn from_option_args(args: &Vec<String>) -> Self {
        let mut props = BTreeMap::new();
        let mut flags = EPFlags::empty();

        for arg in args {
            let kv = arg.split_once('=');
            let (key, value) = match kv {
                None => {
                    match arg.as_str() {
                        options::DISABLE => flags.insert(EPFlags::DISABLE),
                        options::TX => flags.insert(EPFlags::XDP_TX),
                        options::NO_NAT | "no_conntrack" | "no_ct" => {
                            flags.insert(EPFlags::NO_CONNTRACK)
                        }
                        options::REDIRECT => flags.insert(EPFlags::XDP_REDIRECT),
                        _ => log::error!("Unknown flag '{}' ", arg),
                    }
                    continue;
                }
                Some(kv) => kv,
            };
            match key {
                "redirect" => match helpers::ifindex(value) {
                    Ok(_) => {
                        flags.insert(EPFlags::XDP_REDIRECT);
                        props.insert(key.to_string(), value.to_string());
                    }
                    Err(_) => {
                        log::error!("No '{}' interface, see option '{}'", value, arg)
                    }
                },
                _ => log::error!("Unknown key '{}' in option '{}'", key, arg),
            };
        }
        Self { props, flags }
    }
}

#[derive(clap::Subcommand, Debug)]
#[command(flatten_help = false, disable_help_flag = true)]
enum ProtocolInfo {
    /// Add TCP flow, port number and options
    Tcp {
        /// The port number
        port: u16,
        /// Per context options, for e.g. packet forwarding option.
        options: Vec<String>,
    },
    /// Add UDP flow and port number
    Udp {
        /// The port number
        port: u16,
        /// Per context options, for e.g. packet forwarding option.
        options: Vec<String>,
    },
    /// A service with a known ip protocol and port number,
    Service {
        service: services::Service,
        /// Per context options, for e.g. packet forwarding option.
        options: Vec<String>,
    },
    /// Other IP protocols besides TCP and UDP. For eg. ICMP
    Proto {
        protocol: Protocol,
        /// Per context options, for e.g. packet forwarding option.
        options: Vec<String>,
    },
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
    /// List backend groups assigned to current interface [default]
    List,
    /// Add a new group of backends for load balancing
    Add(AddEpOpt),
    /// Remove group
    Remove {
        /// The group Id returned by 'group add' or 'group list' commands
        gid: u16,
    },
    // TODO: add disable/enable group
    // TODO: remove groups with missing ifnames
}

#[derive(clap::Args, Debug)]
//#[command(flatten_help = true)]
struct GroupOpt {
    /// Target net interface name, eg. eth0
    #[clap(default_value = "lo")]
    ifname: String,
    /// Group action
    #[clap(subcommand)]
    action: Option<GroupAction>,
}

#[derive(clap::Subcommand, Debug)]
enum BackendAction {
    /// List all backends in the group [default]
    List,
    /// Add a new backend for load balancing
    Add(AddEpOpt),
    /// Remove backend
    Remove {
        /// The backend index returned by 'backend add' or 'backend list' commands
        index: u16,
    },
    /// Clear all backends from group
    Clear,
    /// Clear stray backends without groups
    ClearStray,
}

#[derive(clap::Args, Debug)]
struct BackendOpt {
    /// Target backend group id.
    #[clap(default_value_t = 0)]
    gid: u16,
    /// Backend actions
    #[clap(subcommand)]
    action: Option<BackendAction>,
}

#[derive(clap::Subcommand, Debug)]
enum ConfigAction {
    /// Load config file into bpf space. This will override the current loaded maps.
    Load,
    /// Save current zon-lb bfs state into toml configuration file.
    Save,
}

#[derive(clap::Args, Debug)]
struct ConfigOpt {
    /// Configuration file path
    #[clap(default_value = "zonlb.toml")]
    file_path: String,
    /// Configuration file actions
    #[clap(subcommand)]
    action: ConfigAction,
}

#[derive(clap::Args, Debug)]
struct DebugOpt {
    /// Target net interface name, eg. eth0
    #[clap(default_value = "lo")]
    ifname: String,
}

#[derive(clap::Subcommand, Debug)]
enum ConnTrackAction {
    /// List all NAT entries for target group(s)
    List,
    /// Remove all conntrack entries
    Remove,
}

#[derive(clap::Args, Debug)]
struct ConnTrackOpt {
    /// Filter conntrack entries by id
    #[clap(default_value_t = 0)]
    gid: u32,
    /// Conntrack actions
    #[clap(subcommand)]
    action: Option<ConnTrackAction>,
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
    Debug(DebugOpt),
    /// Config persistence
    Config(ConfigOpt),
    /// Connection tracking actions: view, remove unused
    Conntrack(ConnTrackOpt),
}

#[derive(Debug, Parser)]
#[clap(propagate_version = false)]
struct Cli {
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
pub(crate) const PROG_NAME: &str = "zon_lb";
pub(crate) const BPFFS: &str = "/sys/fs/bpf/";

pub(crate) fn bpf_instance() -> Result<aya::Bpf, anyhow::Error> {
    let mut bpf = BpfLoader::new()
        .load(ZONLB)
        .context("Failed to load the maps and program blob")?;

    // NOTE: initialize the log here in order to catch the verifier errors
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if all log statements are removed from eBPF program.
        warn!("Failed to initialize eBPF logger: {}", e);
    }

    Ok(bpf)
}

fn handle_prog(opt: &ProgOpt) -> Result<(), anyhow::Error> {
    let mut prg = Prog::new(&opt.ifname)?;

    match &opt.action {
        ProgAction::Teardown => prg.teardown(),
        ProgAction::Unload => prg.unload(),
        ProgAction::Replace => prg.replace(&mut bpf_instance()?),
        ProgAction::Load(load_opt) => {
            info!("Try attach program to interface: {}", &opt.ifname);
            prg.load(&mut bpf_instance()?, load_opt.xdp_flags())
        }
        ProgAction::Reload(load_opt) => {
            // TODO: save config and restore
            info!("Try reattach program to interface: {}", &opt.ifname);
            prg.teardown()?;
            prg.load(&mut bpf_instance()?, load_opt.xdp_flags())
        }
    }
}

fn handler_add_ep(opt: &AddEpOpt) -> Result<EndPoint, anyhow::Error> {
    let (proto, port, options) = match &opt.protocol_info {
        ProtocolInfo::Tcp { port, options } => (Protocol::Tcp, Some(*port), options.clone()),
        ProtocolInfo::Udp { port, options } => (Protocol::Udp, Some(*port), options.clone()),
        ProtocolInfo::Service { service, options } => {
            (service.protocol(), Some(service.port()), options.clone())
        }
        ProtocolInfo::Proto { protocol, options } => (*protocol, None, options.clone()),
    };
    let options = EpOptions::from_option_args(&options);
    let ep = EndPoint::new(&opt.ip_address, proto, port, Some(options))?;

    Ok(ep)
}

fn handle_group(opt: &GroupOpt) -> Result<(), anyhow::Error> {
    let group = backends::Group::new(&opt.ifname)?;
    let action = opt.action.as_ref().unwrap_or(&GroupAction::List);
    match &action {
        GroupAction::Add(add_opt) => {
            let ep = handler_add_ep(&add_opt)?;
            let gid = group.add(&ep)?;
            info!("[{}] group {} added => {}", &opt.ifname, ep, gid);
        }
        GroupAction::List => backends::Group::list()?,
        GroupAction::Remove { gid } => group.remove(*gid)?,
    }

    Ok(())
}

fn handle_backends(opt: &BackendOpt) -> Result<(), anyhow::Error> {
    let action = opt.action.as_ref().unwrap_or(&BackendAction::List);
    match action {
        BackendAction::Add(add_opt) => {
            let backend = Backend::new(opt.gid);
            let ep = handler_add_ep(&add_opt)?;
            let group = backend.add(&ep)?;
            info!(
                "[{}] backend {} added for group {}",
                group.ifname, ep, backend.gid
            );
        }
        BackendAction::List => Backend::list(opt.gid)?,
        BackendAction::Remove { index } => {
            let backend = Backend::new(opt.gid);
            let be = backend.remove(*index)?;
            info!("backend {} removed for group {}", be.as_endpoint(), be.gid);
        }
        BackendAction::Clear => {
            let backend = Backend::new(opt.gid);
            let bes = backend.clear()?;
            for be in bes {
                info!("backend {} removed for group {}", be.as_endpoint(), be.gid);
            }
        }
        BackendAction::ClearStray => {
            for be in Backend::clear_stray()? {
                info!("backend {} removed for group {}", be.as_endpoint(), be.gid);
            }
        }
    };
    Ok(())
}

fn handle_config(opt: &ConfigOpt) -> Result<(), anyhow::Error> {
    let mut config = ConfigFile::new(&opt.file_path);

    match &opt.action {
        ConfigAction::Load => config.load(),
        ConfigAction::Save => config.save(),
    }
}

fn handle_conntrack(opt: &ConnTrackOpt) -> Result<(), anyhow::Error> {
    let action = opt.action.as_ref().unwrap_or(&ConnTrackAction::List);
    match action {
        ConnTrackAction::List => conntrack_list(opt.gid),
        ConnTrackAction::Remove => conntrack::remove_all(),
    }
}

async fn handle_debug(opt: &DebugOpt) -> Result<(), anyhow::Error> {
    init_log(&opt.ifname)?;
    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    env_logger::init();

    let res = match &cli.command {
        Command::Info => list_info(),
        Command::Prog(opt) => handle_prog(opt),
        Command::Group(opt) => handle_group(opt),
        Command::Backend(opt) => handle_backends(opt),
        Command::Config(opt) => handle_config(opt),
        Command::Debug(opt) => handle_debug(opt).await,
        Command::Conntrack(opt) => handle_conntrack(opt),
    };

    if let Err(e) = res {
        log::error!("{}", e);
    }

    // TODO: aya::programs::loaded_programs iterate over all programs and
    // check if zon-lb is running. Also, check if there is another xdp
    // program attached to current interface.
    // TODO: add option to enable debug mode and listen for messages

    Ok(())
}
