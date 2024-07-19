mod backends;
mod config;
mod conntrack;
mod fib;
mod helpers;
mod info;
mod logging;
mod neighbors;
mod options;
mod prog;
mod protocols;
mod runvars;
mod services;
mod stats;

use crate::{logging::init_log_with_replace, runvars::RunVars};
use aya::{include_bytes_aligned, programs::XdpFlags, EbpfLoader};
use aya_log::EbpfLogger;
use backends::{Backend, EndPoint, ToEndPoint};
use clap::{Parser, ValueEnum};
use config::ConfigFile;
use conntrack::conntrack_list;
use info::*;
use log::{info, warn};
use logging::init_log;
use options::Options;
use prog::*;
use protocols::Protocol;
use stats::Stats;
use std::str::FromStr;
use tokio::signal;

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
    /// Additional options to debug the program.
    /// Current options are:
    /// * `replace`  starts reading the log after replacing current program
    /// * `log_filter=<arg>`  Sets the log filter to `arg`. Possible values are `OFF|ERROR|INFO|DEBUG|TRACE`.
    #[clap(verbatim_doc_comment)]
    options: Vec<String>,
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
#[command(flatten_help = true, disable_help_flag = false)]
enum StatsAction {
    /// List all stats
    List {
        /// If provided shows all counters containing the pattern (case sensitive).
        /// Otherwise, all counters will be printed.
        counter_pattern: Option<String>,
    },
    /// Reset one or all stats
    Reset {
        /// The statistics counter to reset. If none is provided
        /// all counters will be reset.
        counter_name: Option<String>,
    },
}

#[derive(clap::Args, Debug)]
struct StatsOpt {
    /// Target net interface name, eg. eth0
    #[clap(default_value = "lo")]
    ifname: String,
    // TODO:
    // Filter conntrack entries by id
    // #[clap(default_value_t = 0)]
    // gid: u32,
    /// Stattistics actions
    #[clap(subcommand)]
    action: Option<StatsAction>,
}

#[derive(clap::Subcommand, Debug)]
#[command(flatten_help = true, disable_help_flag = false)]
enum RunVarAction {
    /// List all runtime variables and features
    List {
        /// If provided shows all variables containing the pattern (case sensitive).
        /// Otherwise, all variables will be printed.
        #[clap(verbatim_doc_comment)]
        var_pattern: Option<String>,
    },
    /// Sets a runtime variable and enables or disables a runtime feature.
    Set {
        /// Key-value pairs of variable or feature names and values.
        /// For e.g. `log_filter=info`.
        /// For features accepted values are `on|off`: `ipv6=on`
        /// The following variables and features can be modified:
        /// * `log_filter=<OFF|ERROR|INFO|DEBUG|TRACE>`
        #[clap(verbatim_doc_comment)]
        key_value_pairs: Vec<String>,
    },
}

#[derive(clap::Args, Debug)]
struct RunVarOpt {
    /// Target net interface name, eg. eth0
    #[clap(default_value = "lo")]
    ifname: String,
    /// Runtime variable actions
    #[clap(subcommand)]
    action: Option<RunVarAction>,
}

#[derive(clap::Args, Debug)]
struct NeighAddOpt {
    /// The neighbor IP address
    ip_address: String,
    /// Neighbor key pair options:
    /// mac=<hw addr>    mac address of the neighbor
    /// if=<name>        interface to access the neighbor
    /// if_mac=<hw addr> mac address of the interface
    /// vlan=<VLAN id>   vlan id of the neighbor
    ///
    /// If no options are provided the program will assume the ip
    /// is local and will try to search for the local interface
    /// that has this address. If it can't find such interface it
    /// will trigger a neighbor  discovery trying a TCP connection.
    #[clap(verbatim_doc_comment)]
    options: Vec<String>,
}

#[derive(clap::Args, Debug)]
struct NeighProbeOpt {
    /// The neighbor IP address
    ip_address: String,
    /// Neighbor key pair options:
    /// port=<TCP port> mac address of the neighbor
    // TODO: if=<name>       interface to access the neighbor
    #[clap(verbatim_doc_comment)]
    options: Vec<String>,
}

#[derive(clap::Subcommand, Debug)]
enum NeighAction {
    /// List neighbor entries
    List {
        /// Filter options:
        /// all   By default only neighbors with existing interfaces are displayed.
        ///       To list all entries must pass this argument. This filter applies last.
        /// ipv4  List only IPv4 or ARP entries
        /// ipv6  List only IPv6 neighbor entries
        // TODO: list by netmask
        #[clap(verbatim_doc_comment)]
        filter_options: Vec<String>,
    },
    /// Remove neighbor entries
    Remove {
        /// Filter options:
        /// all       By default only neighbors with non-existing interfaces are removed.
        ///           To remove all pass this flag.
        /// ip=<addr> Removes only the entry with this ip address. Can't be used with other filters.
        // TODO: add remove by netmask
        #[clap(verbatim_doc_comment)]
        filter_options: Vec<String>,
    },
    /// Inserts or updates a neighbor
    Insert(NeighAddOpt),
    /// Probes a neighbor ip using a tcp connection.
    /// This can be used to fill ND tables because before the connection
    /// it initiated the system triggers the neighbor discovery mechanism.
    Probe(NeighProbeOpt),
    /// Shows local network interfaces details. This command can be used
    /// to insert local neighbors. These entries are used to respond to
    /// ARP/ND requests in the VLAN proxy scenario.
    ShowIfs {
        /// Filter options:
        /// all  By default some addresses are not shown like link-local or localhost.
        ///      This option will allow to show all available addresses.
        #[clap(verbatim_doc_comment)]
        filter_options: Vec<String>,
    },
}

#[derive(clap::Args, Debug)]
struct NeighOpt {
    /// Neighbor actions
    #[clap(subcommand)]
    action: Option<NeighAction>,
}

#[derive(clap::Subcommand, Debug)]
enum FibAction {
    /// List FIB entries
    List {
        /// Filter options:
        /// * `all`  : By default only FIB with existing interfaces are displayed.
        ///            To list all entries must pass this argument. This filter applies last.
        /// * `ipv4` : List only IPv4 FIB entries
        /// * `ipv6` : List only IPv6 FIB entries
        #[clap(verbatim_doc_comment)]
        filter_options: Vec<String>,
    },
    /// Remove FIB entries
    Remove {
        /// Filter options:
        /// * `all`  : By default only FIB with non-existing interfaces are removed.
        ///            To remove all pass this flag.
        #[clap(verbatim_doc_comment)]
        filter_options: Vec<String>,
    },
}

#[derive(clap::Args, Debug)]
struct FibOpt {
    /// FIB actions
    #[clap(subcommand)]
    action: Option<FibAction>,
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
    /// Program statistics
    Stats(StatsOpt),
    /// Allows to set or get runtime variables and enable or disable runtime features
    Runvar(RunVarOpt),
    /// Access the discovered neighbors cache from remote and local interfaces.
    /// The cache maps IP addresses to hardware addresses, if id and vlan id.
    /// It is constructed from ARP (IPv4) requests and neighbor solicitations (IPv6).
    /// and it is used mainly to respond the neighbor requests from within VLANs.
    #[clap(verbatim_doc_comment)]
    Neighbors(NeighOpt),
    /// Forward informational database cache access.
    /// This cache is used during redirects in order to set the proper interface index
    /// to redirect and the mac addresses for that interface. This cache is updated after
    /// querying the kernel FIB.
    #[clap(verbatim_doc_comment)]
    Fib(FibOpt),
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

pub(crate) fn bpf_instance() -> Result<aya::Ebpf, anyhow::Error> {
    let mut bpf = EbpfLoader::new().load(ZONLB)?;
    //.with_context(|| "Failed to load the maps and program blob")?;

    // NOTE: initialize the log here in order to catch the verifier errors
    if let Err(e) = EbpfLogger::init(&mut bpf) {
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
    let options = Options::from_option_args(&options);
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
    let options = Options::from_option_args(&opt.options);

    if options.props.contains_key(&options::REPLACE.to_string()) {
        init_log_with_replace(&opt.ifname)?;
    } else {
        init_log(&opt.ifname)?;
    }

    if let Some(v) = options.props.get(&options::LOG_FILTER.to_string()) {
        RunVars::new(&opt.ifname)?.set_log_filter(log::LevelFilter::from_str(v)?);
        info!("Set log filter {} to {}", v, opt.ifname);
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

fn handle_stats(opt: &StatsOpt) -> Result<(), anyhow::Error> {
    let mut stats = Stats::new(&opt.ifname)?;
    let action = opt.action.as_ref().unwrap_or(&StatsAction::List {
        counter_pattern: None,
    });

    // TODO: list stats for all loaded programs is no ifname is provided
    match action {
        StatsAction::List { counter_pattern } => {
            stats.print_all(counter_pattern.as_ref().map(|cname| cname.as_str()))
        }
        StatsAction::Reset { counter_name } => {
            stats.reset_counter(counter_name.as_ref().map(|cname| cname.as_str()))
        }
    };

    Ok(())
}

fn handle_runvar(opt: &RunVarOpt) -> Result<(), anyhow::Error> {
    let mut rv = RunVars::new(&opt.ifname)?;
    let action = opt
        .action
        .as_ref()
        .unwrap_or(&RunVarAction::List { var_pattern: None });

    match action {
        RunVarAction::List { var_pattern } => {
            rv.print_all(var_pattern.as_ref().map(|cname| cname.as_str()))
        }
        RunVarAction::Set { key_value_pairs } => rv.bulk_set(key_value_pairs)?,
    };

    Ok(())
}

fn handle_neighbors(opt: &NeighOpt) -> Result<(), anyhow::Error> {
    let def_cmd = NeighAction::List {
        filter_options: Vec::new(),
    };
    let action = opt.action.as_ref().unwrap_or(&def_cmd);
    match action {
        NeighAction::List { filter_options } => neighbors::list(filter_options),
        NeighAction::Remove { filter_options } => neighbors::remove(filter_options),
        NeighAction::Insert(opt) => neighbors::insert(&opt.ip_address, &opt.options),
        NeighAction::Probe(opt) => neighbors::probe(&opt.ip_address, &opt.options),
        NeighAction::ShowIfs { filter_options } => neighbors::show_ifs(filter_options),
    }
}

fn handle_fib(opt: &FibOpt) -> Result<(), anyhow::Error> {
    let def_cmd = FibAction::List {
        filter_options: Vec::new(),
    };
    let action = opt.action.as_ref().unwrap_or(&def_cmd);
    match action {
        FibAction::List { filter_options } => fib::list(filter_options),
        FibAction::Remove { filter_options } => fib::remove(filter_options),
    }
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
        Command::Stats(opt) => handle_stats(opt),
        Command::Runvar(opt) => handle_runvar(opt),
        Command::Neighbors(opt) => handle_neighbors(opt),
        Command::Fib(opt) => handle_fib(opt),
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
