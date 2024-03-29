use crate::{backends, conntrack, helpers::*};
use anyhow::{anyhow, Context};
use aya::{
    maps::Array,
    programs::{
        links::{FdLink, PinnedLink},
        Xdp, XdpFlags,
    },
    Ebpf,
};
use log::info;
use std::path::PathBuf;
use zon_lb_common::ZonInfo;

// Manages the life cycle of a program for a specific network interface
pub struct Prog {
    ifname: String,
    link_path: PathBuf,
    pub link_path_str: String,
    link_exists: bool,
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

    fn unload_by_pinned_link(&mut self) -> Result<(), anyhow::Error> {
        if !self.link_exists {
            return Ok(());
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

        Ok(())
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

        if let Err(e) = &self.unload_by_pinned_link() {
            log::warn!("[{}] Failed to remove pinned, {}", &self.ifname, e);
        }

        // TODO: pin the program also and effectively unload() the program
        // from kernel. This will detach the links also (TBD).
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

    /// Initialize program info and start params   
    fn init_info(&self, bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
        let mut info: Array<_, ZonInfo> = Array::try_from(bpf.map_mut("ZLB_INFO").unwrap())?;
        info.set(0, ZonInfo::new(), 0)
            .context("Failed to set zon info")?;
        Ok(())
    }

    pub fn replace(&self, bpf: &mut Ebpf) -> Result<(), anyhow::Error> {
        if !self.link_exists {
            return Err(anyhow!(
                "Can't replace program, link {} doesn't exist, try load the program first",
                self.link_path_str
            ));
        }

        let program = Self::load_program(bpf)?;

        let link = PinnedLink::from_pin(&self.link_path)
            .context("Failed to load pinned link for zon-lb bpffs")?;
        let link = FdLink::from(link);
        program
            .attach_to_link(link.try_into()?)
            .context("Failed to attach new program to existing link")?;
        self.init_info(bpf)
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
        self.init_info(bpf)?;

        info!("Successfully load the program on interface {}", self.ifname);

        Ok(())
    }
}
