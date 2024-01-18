use std::path::PathBuf;

use crate::helpers::*;
use anyhow::{anyhow, Context};
use aya::{
    maps::Array,
    programs::{
        links::{FdLink, PinnedLink},
        Xdp, XdpFlags,
    },
};
use log::{info, warn};
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
    pub fn unload(&mut self) -> Result<(), anyhow::Error> {
        if self.link_exists {
            let link = PinnedLink::from_pin(&self.link_path)
                .context("Failed to load pinned link for zon-lb bpffs")?;
            link.unpin().context("Can't unpin program link")?;

            info!(
                "Pinned link for program attached to {} removed: {}",
                &self.ifname, &self.link_path_str
            );
            self.link_exists = false;
        }
        Ok(())
    }

    fn remove_maps(&self) -> Result<(), anyhow::Error> {
        match pinned_link_name(&self.ifname, "") {
            None => {
                warn!("Invalid name for interface: {}", &self.ifname);
            }
            Some(prefix) => {
                teardown_maps(&prefix)?;
            }
        };
        Ok(())
    }

    pub fn teardown(&mut self) -> Result<(), anyhow::Error> {
        self.unload()?;
        self.remove_maps()
    }

    fn load_program(bpf: &mut aya::Bpf) -> Result<&mut aya::programs::Xdp, anyhow::Error> {
        let program: &mut Xdp = bpf.program_mut("zon_lb").unwrap().try_into()?;
        program.load().context("Failed to load program in kernel")?;
        Ok(program)
    }

    /// Initialize program info and start params   
    fn init_info(&self, bpf: &mut aya::Bpf) -> Result<(), anyhow::Error> {
        let mut info: Array<_, ZonInfo> = Array::try_from(bpf.map_mut("ZLB_INFO").unwrap())?;
        info.set(0, ZonInfo::new(), 0)
            .context("Failed to set zon info")?;
        Ok(())
    }

    pub fn replace(&self, bpf: &mut aya::Bpf) -> Result<(), anyhow::Error> {
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

    pub fn load(&self, bpf: &mut aya::Bpf, flags: XdpFlags) -> Result<(), anyhow::Error> {
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

        // Pin the program link to bpf file system (bpffs)
        let xdplink = program.take_link(xdplinkid)?;
        let fdlink: FdLink = xdplink.try_into()?;
        fdlink
            .pin(&self.link_path)
            .context("Failed to create pinned link for program")?;

        // Last step is to pin used maps so the program can use them
        // after this process exits
        create_pinned_links_for_maps(bpf, &self.ifname)?;

        self.init_info(bpf)
    }
}
