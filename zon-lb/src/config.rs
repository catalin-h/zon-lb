use crate::{
    backends::{Backend as BCKND, EndPoint, Group, ToEndPoint},
    helpers::if_index_to_name,
    prog::Prog,
    protocols::Protocol,
    Options,
};
use anyhow::{anyhow, Context};
use aya::programs::XdpFlags;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    io::{Read, Write},
    net::IpAddr,
    path::Path,
};
use zon_lb_common::BEKey;

#[derive(Serialize, Deserialize)]
struct EP {
    ip: IpAddr,
    #[serde(default)]
    proto: u8,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    options: Vec<String>,
}

impl Into<EndPoint> for &EP {
    fn into(self) -> EndPoint {
        EndPoint {
            ipaddr: self.ip,
            proto: Protocol::from(self.proto),
            port: self.port,
            options: Options::from_option_args(&self.options),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct NetIf {
    #[serde(flatten)]
    groups: BTreeMap<String, EP>,
}

impl NetIf {
    fn new() -> Self {
        Self {
            groups: BTreeMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Config {
    netif: BTreeMap<String, NetIf>,
    backend: BTreeMap<String, EP>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            netif: BTreeMap::new(),
            backend: BTreeMap::new(),
        }
    }

    fn group_count(&self) -> usize {
        self.netif
            .iter()
            .fold(0, |acc, (_, g)| acc + g.groups.len())
    }

    pub fn description(&self) -> String {
        let gcount = self.group_count();
        format!(
            "Groups: {gcount} in {} netifs and {} backends",
            self.netif.len(),
            self.backend.len()
        )
    }
}

pub struct ConfigFile {
    path: String,
}

impl ConfigFile {
    pub fn new<S: AsRef<str>>(filename: &S) -> Self {
        Self {
            path: String::from(filename.as_ref()),
        }
    }

    pub fn load(&mut self) -> Result<(), anyhow::Error> {
        if !Path::new(&self.path).try_exists()? {
            return Err(anyhow!("Config file does not exits, {}", self.path));
        }
        let mut file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .context(format!("Can't read config file: {}", self.path))?;
        let mut contents = String::new();
        let size = file.read_to_string(&mut contents)?;

        log::info!("Read {} bytes from: {}", size, self.path);

        let cfg: Config = toml::from_str(&contents)?;

        log::info!("Found in config: {}", cfg.description());

        let cfgw = ConfigWriter::new();
        cfgw.write(&cfg)?;

        Ok(())
    }

    pub fn save(&self) -> Result<(), anyhow::Error> {
        if Path::new(&self.path).try_exists()? {
            log::info!("Config file will be overridden, {}", self.path);
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.path)
            .context(format!("Can't write to config file: {}", self.path))?;

        let cfg = self.fetch()?;

        log::info!("Saving config: {}", cfg.description());

        let contents = toml::to_string(&cfg)?;

        file.write_all(contents.as_bytes())?;

        log::info!(
            "Wrote {} bytes to config file: {}",
            contents.len(),
            self.path
        );

        Ok(())
    }

    fn to_backend_key(key: &BEKey) -> String {
        format!("{}_{}", key.gid, key.index)
    }

    fn from_backend_key(key: &str) -> BEKey {
        let (gid, index) = key.split_once("_").unwrap_or(("0", "0"));
        let gid = gid.parse::<u16>().unwrap_or(0);
        let index = index.parse::<u16>().unwrap_or(0);
        BEKey { gid, index }
    }

    fn fetch(&self) -> Result<Config, anyhow::Error> {
        let mut cfg = Config::new();

        log::info!("fetching state ...");

        for (key, be) in BCKND::backends()?.iter().filter_map(|pair| pair.ok()) {
            let ep = be.as_endpoint();
            let ep = EP {
                ip: ep.ipaddr,
                proto: ep.proto as u8,
                port: ep.port,
                options: ep.options.to_options(),
            };
            cfg.backend.entry(Self::to_backend_key(&key)).or_insert(ep);
        }

        Group::iterate_all(|ep, group| {
            let ifname = group.ifindex.to_string();
            let ifname = if_index_to_name(group.ifindex).unwrap_or(ifname);
            let netif = cfg.netif.entry(ifname).or_insert(NetIf::new());
            let ep = EP {
                ip: ep.ipaddr,
                proto: ep.proto as u8,
                port: ep.port,
                options: ep.options.to_options(),
            };
            netif.groups.entry(group.gid.to_string()).or_insert(ep);
        })?;

        Ok(cfg)
    }
}

struct ConfigWriter {
    mapping: BTreeMap<u16, u16>,
    gcount: usize,
    bcount: usize,
}

impl ConfigWriter {
    fn new() -> Self {
        Self {
            mapping: BTreeMap::new(),
            gcount: 0,
            bcount: 0,
        }
    }

    // TODO: add program options in config file to automatically
    // load, reload, teardown  programs on the interfaces.
    // Also, this will automatically create the necessary maps.
    fn if_init(&self, ifname: &str) -> Result<(), anyhow::Error> {
        let mut prog = Prog::new(ifname)?;

        if !prog.link_exists {
            return prog.load(&mut crate::bpf_instance()?, XdpFlags::default());
        }

        // Always reload the program of interface and update the txport map
        // with current net device index. The device can be recreated with
        // another index by the kernel. This affects the redirect map used
        // to redirect packets by the program.
        prog.unload()?;
        prog.load(&mut crate::bpf_instance()?, XdpFlags::default())
    }

    fn write(mut self, cfg: &Config) -> Result<(), anyhow::Error> {
        log::info!("Writing config ...");

        for (name, nif) in cfg.netif.iter() {
            self.if_init(name)?;
            match Group::new(&name) {
                Ok(group) => self.load_groups(group, &nif),
                Err(e) => {
                    log::error!("Failed to load all groups in {}, {}", name, e)
                }
            }
        }

        for (key, ep) in &cfg.backend {
            let key = ConfigFile::from_backend_key(&key);
            let ep: EndPoint = ep.into();
            let actual_gid = match self.mapping.get(&key.gid) {
                Some(actual) => *actual,
                None => {
                    log::warn!(
                        "Backend {} not loaded, no group id {} in config or group not loaded",
                        ep,
                        key.gid
                    );
                    continue;
                }
            };
            let bemgr = crate::Backend::new(actual_gid);
            match bemgr.add(&ep) {
                Ok(group) => {
                    self.bcount += 1;
                    log::info!(
                        "Backend {} added for group {} on {}",
                        ep,
                        key.gid,
                        group.ifname,
                    )
                }
                Err(e) => log::error!("Can't add backend {} for group {}, {}", ep, key.gid, e),
            }
        }

        log::info!(
            "Write summary: {}/{} groups, {}/{} backends",
            self.gcount,
            cfg.group_count(),
            self.bcount,
            cfg.backend.len()
        );
        Ok(())
    }

    fn load_groups(&mut self, group: Group, netif: &NetIf) {
        match group.remove_all() {
            Ok(()) => log::info!("All groups binded to {} were removed", group.ifname),
            Err(e) => log::error!("Failed to remove groups binded to {}, {}", group.ifname, e),
        };
        for (gid, ep) in netif.groups.iter() {
            let gid = match gid.parse::<u16>() {
                Ok(g) => g,
                Err(e) => {
                    log::error!(
                        "Invalid group id {} for netdev: {}, {}",
                        gid,
                        group.ifname,
                        e
                    );
                    continue;
                }
            };
            let ep = ep.into();
            // Do a replace as the interface can be removed but
            // the group can still exist in the maps
            let actual_gid = match group.replace(&ep) {
                Ok(id) => id,
                Err(e) => {
                    log::error!(
                        "Failed to add backend group {} to {}, {}",
                        ep,
                        group.ifname,
                        e
                    );
                    continue;
                }
            };
            log::info!(
                "Backend group {} added for {} => id: {} (config:{})",
                ep,
                group.ifname,
                actual_gid,
                gid
            );
            self.mapping.insert(gid, actual_gid as u16);
            self.gcount += 1;
        }
    }
}
