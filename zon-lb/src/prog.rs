use crate::{backends, conntrack, helpers::*, ToMapName};
use anyhow::{anyhow, Context};
use aya::{
    maps::{Array, DevMap, Map, MapData},
    programs::{
        links::{FdLink, PinnedLink},
        Xdp, XdpFlags,
    },
    Ebpf,
};
use log::info;
use std::path::PathBuf;
use zon_lb_common::runvars;
use zon_lb_common::ZonInfo;

struct RunVar;

impl ToMapName for RunVar {
    fn map_name() -> &'static str {
        "ZLB_RUNVAR"
    }
}

struct TxPorts;

impl ToMapName for TxPorts {
    fn map_name() -> &'static str {
        "ZLB_TXPORT"
    }
}

impl TxPorts {
    fn init() -> Result<(), anyhow::Error> {
        let ports = mapdata_from_pinned_map("", Self::map_name())
            .ok_or(anyhow!("No tx port map, must reload program"))?;
        let ports = Map::DevMap(ports);
        let mut ports: DevMap<_> = ports.try_into()?;
        let len = ports.len();
        // TODO: setting an ifindex that currently does not exist will return an error.
        // To set only the interfaces that exist must iterate over all interfaces.
        // Next, must use netdev crate to iterate and retrieve the indecses.
        for p in 1..len {
            match ports.set(p, p, None, 0) {
                Ok(()) => info!("Map tx port: {} to ifindex: {}", p, p),
                Err(_) => {} //error!("Failed to map tx port: {} to ifindex: {}, {}", p, p, e),
            }
        }
        Ok(())
    }
}

// Manages the life cycle of a program for a specific network interface
pub struct Prog {
    ifname: String,
    link_path: PathBuf,
    pub link_path_str: String,
    pub link_exists: bool,
}

impl Prog {
    pub fn new(ifname: &str) -> Result<Self, anyhow::Error> {
        let (zdpath, zlblink_exists) = prog_bpffs(ifname)?;
        let path_str = zdpath.to_string_lossy().to_string();

        Ok(Self {
            ifname: ifname.to_string(),
            link_path: zdpath,
            link_path_str: path_str,
            link_exists: zlblink_exists,
        })
    }

    fn unload_by_pinned_link(&mut self) -> Result<bool, anyhow::Error> {
        if !self.link_exists {
            return Ok(true);
        }

        let link = PinnedLink::from_pin(&self.link_path)
            .context("Failed to load pinned link for zon-lb bpffs")?;

        // NOTE: although the file is removed from fs the FDs for the link
        // and program are not closed until the user app exists.
        // This means that the link and program remain attached
        // attached to the interface until we attach a new link
        // and program.
        link.unpin().context("Can't unpin program link")?;

        let (_, zlblink_exists) = prog_bpffs(&self.ifname)?;
        self.link_exists = zlblink_exists;

        info!(
            "[{}] Pinned link {} {}removed",
            &self.ifname,
            &self.link_path_str,
            if zlblink_exists { "not " } else { "" }
        );

        Ok(zlblink_exists)
    }

    pub fn unload(&mut self) -> Result<(), anyhow::Error> {
        if let Some(link_info) = get_xdp_link_info(&self.ifname) {
            log::info!(
                "[{}] Found attached the link (id: {}) and program (id: {})",
                &self.ifname,
                link_info.id,
                link_info.program_id
            );
        };

        let file_exists = match self.unload_by_pinned_link() {
            Ok(exists) => exists,
            Err(e) => {
                log::warn!("[{}] Failed to remove pinned, {}", &self.ifname, e);
                true
            }
        };

        if file_exists {
            if let Err(e) = std::fs::remove_file(&self.link_path) {
                log::warn!(
                    "[{}] Failed to remove bpffs {}, {}",
                    &self.ifname,
                    self.link_path_str,
                    e
                );
            }
        }

        Ok(())
    }

    pub fn teardown(&mut self) -> Result<(), anyhow::Error> {
        backends::teardown_all_maps()?;
        conntrack::teardown_all_maps()?;
        self.unload()
    }

    fn load_program(bpf: &mut Ebpf) -> Result<&mut Xdp, anyhow::Error> {
        let program: &mut Xdp = bpf.program_mut("zon_lb").unwrap().try_into()?;
        program.load()?;
        Ok(program)
    }

    /// Initialize program info or fused parameters that don't change at runtime.
    fn init_info(&self) {
        let map = match get_mapdata_by_name(&self.ifname, ZonInfo::map_name()) {
            Some(map) => Map::Array(map),
            None => {
                log::error!(
                    "Can't find map {} for program loaded on {}",
                    ZonInfo::map_name(),
                    &self.ifname
                );
                return;
            }
        };
        let mut map: Array<MapData, ZonInfo> = match map.try_into() {
            Ok(map) => map,
            Err(e) => {
                log::error!("Failed to match ZonInfo metadata, {}", e);
                return;
            }
        };
        match map.set(0, ZonInfo::new(), 0) {
            Ok(()) => {}
            Err(e) => log::error!("Failed to set ZonInfo, {}", e),
        };
    }

    pub fn replace(&self, bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
        if !self.link_exists {
            return Err(anyhow!(
                "Can't replace program, link {} doesn't exist, try load the program first",
                self.link_path_str
            ));
        }

        match get_xdp_link_info(&self.ifname) {
            Some(info) => log::info!(
                "Found pinned link for program id: {} binded to {}",
                info.program_id,
                self.ifname
            ),
            None => {
                return Err(anyhow!(
                    "No pinned link for {}, try load program",
                    self.ifname
                ))
            }
        };

        let program = Self::load_program(bpf)?;

        let link = PinnedLink::from_pin(&self.link_path)
            .context("Failed to load pinned link for zon-lb bpffs")?;
        let link = FdLink::from(link);
        program
            .attach_to_link(link.try_into()?)
            .context("Failed to attach new program to existing link")?;

        match program.info() {
            Ok(info) => log::info!(
                "Pinned link attached to program id: {} binded to {}",
                info.id(),
                self.ifname
            ),
            Err(e) => log::error!("Failed to get proram info, {}", e),
        };

        self.post_load_init()?;

        info!(
            "Successfully replace the program on interface {}",
            self.ifname
        );

        Ok(())
    }

    pub fn load(&self, bpf: &mut Ebpf, flags: XdpFlags) -> Result<(), anyhow::Error> {
        if self.link_exists {
            return Err(anyhow!(
                "Can't load program, link {} already exists, try reload instead",
                self.link_path_str
            ));
        }

        let program = Self::load_program(bpf)?;
        let xdplinkid = program
            .attach(&self.ifname, flags)
            .context("Failed to attach program link to interface")?;

        // Pin the program link to bpf file system (bpffs).
        // Pinning the program its self is not helping since
        // aya creates a bpf link to the interface for the program
        // and it will get dropped after the user app exists
        // effectively disconnecting the program from netdev.
        let xdplink = program.take_link(xdplinkid)?;
        let fdlink: FdLink = xdplink.try_into()?;
        fdlink
            .pin(&self.link_path)
            .context("Failed to create pinned link for program")?;

        self.post_load_init()?;

        info!("Successfully load the program on interface {}", self.ifname);

        Ok(())
    }

    fn post_load_init(&self) -> Result<(), anyhow::Error> {
        self.init_info();
        self.set_logging_level();

        TxPorts::init()
    }

    fn set_logging_level(&self) {
        let level = log::max_level();
        match self.set_runvar(runvars::LOG_LEVEL_IDX, level as u64) {
            Ok(()) => {}
            Err(e) => eprintln!("Failed to set log level to {}, {}", level, e),
        };
    }

    // TODO: cache the map for later usage
    fn runvar_map(&self) -> Result<Array<MapData, u64>, anyhow::Error> {
        let map = get_mapdata_by_name(&self.ifname, RunVar::map_name())
            .ok_or(anyhow!("Can't find map {}", RunVar::map_name()))?;
        let map = Map::Array(map);
        let map: Array<_, u64> = map.try_into()?;
        Ok(map)
    }

    pub fn set_runvar(&self, rv_idx: u32, value: u64) -> Result<(), anyhow::Error> {
        let mut runvars = self.runvar_map()?;
        runvars.set(rv_idx, &value, 0)?;
        Ok(())
    }
}
