use crate::{
    backends::{Backend as BCKND, Group, ToEndPoint},
    helpers,
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
    ifaces: HashMap<String, NetIf>,
    backends: HashMap<String, EP>,
}

impl Config {
    pub fn new() -> Self {
        Self {
            ifaces: HashMap::new(),
            backends: HashMap::new(),
        }
    }

    pub fn description(&self) -> String {
        let gcount = self
            .ifaces
            .iter()
            .fold(0, |acc, (_, g)| acc + g.groups.len());
        format!(
            "Groups: {gcount} in {} netifs and {} backends",
            self.ifaces.len(),
            self.backends.len()
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
            cfg.backends
                .entry(format!("{}:{}", key.gid, key.index))
                .or_insert(ep);
        }

        for (gid, ginfo) in Group::group_meta()?.iter().filter_map(|pair| pair.ok()) {
            let ifname = ginfo.ifindex.to_string();
            let ifname = helpers::if_index_to_name(ginfo.ifindex).unwrap_or(ifname);
            let netif = cfg.ifaces.entry(ifname).or_insert(NetIf::new());
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
