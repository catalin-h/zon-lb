use anyhow::{anyhow, Context};
use aya::programs::{links::FdLink, xdp::XdpLink, Xdp, XdpFlags};
use aya::{include_bytes_aligned, maps::HashMap, Bpf, BpfLoader, Btf};
use aya_log::BpfLogger;
use clap::Parser;
use log::{debug, info, warn};
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

fn link_name(ifname: &str, map_name: &str) -> String {
    if map_name.is_empty() {
        format!("zon-lb_{}_xdp", ifname)
    } else if ifname.is_empty() {
        format!("zon-lb_{}_map", map_name.to_ascii_lowercase())
    } else {
        format!("zon-lb_{}_{}_map", ifname, map_name.to_ascii_lowercase())
    }
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

    //
    // Name scheme set by the loading user app
    //  program: zon-lb_<ifname>_xdp
    //  prog maps: zon-lb_<lowcase_name>_<map-name>_map
    //  common maps: zon-lb_<lowcase_name>_map
    //

    // Default location for bpffs
    let mut zdpath = std::path::PathBuf::from("/sys/fs/bpf");
    zdpath.push(link_name(&opt.iface, ""));
    let zdpath = zdpath.as_path();

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

        // try changing XdpFlags::default() to XdpFlags::SKB_MODE if it failed to attach
        // the XDP program with default flags
        let xdplinkid = program
            .attach(&opt.iface, XdpFlags::default())
            .context("Failed to attach to interface with attachment type")?;

        // Pin the program link to bpf file system (bpffs)
        let xdplink = program.take_link(xdplinkid)?;
        let fdlink: FdLink = xdplink.try_into()?;
        fdlink.pin(zdpath)?;
    }

    let mut blocklist: HashMap<_, u32, u32> = HashMap::try_from(bpf.map_mut("BACKENDS").unwrap())?;
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
