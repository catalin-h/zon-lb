use crate::{
    backends::{Backend as BCKND, EndPoint, Group, ToEndPoint},
    helpers,
    protocols::Protocol,
};
use anyhow::{anyhow, Context};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::OpenOptions,
    io::{Read, Write},
    net::IpAddr,
    path::Path,
};

#[derive(Serialize, Deserialize)]
struct EP {
    ip: IpAddr,
    proto: u8,
    port: u16,
}

impl Into<EndPoint> for &EP {
    fn into(self) -> EndPoint {
        EndPoint {
            ipaddr: self.ip,
            proto: Protocol::from(self.proto),
            port: self.port,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct NetIf {
    #[serde(flatten)]
    groups: HashMap<String, EP>,
}

impl NetIf {
    fn new() -> Self {
        Self {
            groups: HashMap::new(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Config {
    netif: HashMap<String, NetIf>,
    backend: HashMap<String, EP>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            netif: HashMap::new(),
            backend: HashMap::new(),
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

    fn fetch(&self) -> Result<Config, anyhow::Error> {
        let mut cfg = Config::new();

        log::info!("fetching state ...");

        for (key, be) in BCKND::backends()?.iter().filter_map(|pair| pair.ok()) {
            let ep = be.as_endpoint();
            let ep = EP {
                ip: ep.ipaddr,
                proto: ep.proto as u8,
                port: ep.port,
            };
            cfg.backend
                .entry(format!("{}_{}", key.gid, key.index))
                .or_insert(ep);
        }

        for (gid, ginfo) in Group::group_meta()?.iter().filter_map(|pair| pair.ok()) {
            let ifname = ginfo.ifindex.to_string();
            let ifname = helpers::if_index_to_name(ginfo.ifindex).unwrap_or(ifname);
            let netif = cfg.netif.entry(ifname).or_insert(NetIf::new());
            let ep = ginfo.key.as_endpoint();
            let ep = EP {
                ip: ep.ipaddr,
                proto: ep.proto as u8,
                port: ep.port,
            };
            netif.groups.entry(gid.to_string()).or_insert(ep);
        }

        Ok(cfg)
    }
}

struct ConfigWriter {
    mapping: HashMap<u16, u16>,
    gcount: usize,
    bcount: usize,
}

impl ConfigWriter {
    fn new() -> Self {
        Self {
            mapping: HashMap::new(),
            gcount: 0,
            bcount: 0,
        }
    }

    fn write(mut self, cfg: &Config) -> Result<(), anyhow::Error> {
        log::info!("Writing config ...");

        for (name, nif) in cfg.netif.iter() {
            match Group::new(&name) {
                Ok(group) => self.load_groups(group, &nif),
                Err(e) => {
                    log::error!("Skip group in {}, {}", name, e)
                }
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
            log::info!("Adding backend group {} to {}", ep, group.ifname);
            let actual_gid = match group.add(&ep) {
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
            self.mapping.insert(gid, actual_gid as u16);
            self.gcount += 1;
        }
    }
}
