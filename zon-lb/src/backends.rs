use crate::helpers::prog_bpffs;
use crate::protocols::Protocol;
use crate::services::Service;
use anyhow::{anyhow, Result};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

/// Little endian
pub struct EndPoint {
    pub ipaddr: IpAddr,
    pub proto: Protocol,
    pub port: u16,
}

impl Default for EndPoint {
    fn default() -> Self {
        Self {
            ipaddr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            proto: Protocol::None,
            port: 0,
        }
    }
}

impl fmt::Display for EndPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.port == 0 {
            write!(f, "{:?}: {}", &self.proto, &self.ipaddr)
        } else {
            write!(f, "{:?}: [{}]:{}", &self.proto, &self.ipaddr, &self.port)
        }
    }
}

impl EndPoint {
    pub fn new(
        ip_address: &str,
        proto: Protocol,
        port: Option<u16>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            ipaddr: ip_address.parse().map_err(|e| e)?,
            proto: proto.clone(),
            port: port.unwrap_or_default(),
        })
    }
}

pub struct Group {
    pub ifname: String,
    pub ep: EndPoint,
}

impl Group {
    pub fn new(ifname: &str) -> Result<Self, anyhow::Error> {
        let (_, exists) = prog_bpffs(ifname)?;

        if exists {
            Ok(Self {
                ifname: ifname.to_string(),
                ep: EndPoint::default(),
            })
        } else {
            Err(anyhow!("No program loaded for interface: {}", ifname))
        }
    }

    pub fn add(&self, ep: &EndPoint) -> Result<u32, anyhow::Error> {
        Ok(0)
    }
}

#[cfg(todo_code)]
fn _handle_backends(opt: &GroupOpt) -> Result<(), anyhow::Error> {
    // TODO: add option to reset a specific map
    // TODO: add option to add/update/delete a specific value from a specific map
    // TODO: add option to dump entries from a specific map

    let map = mapdata_from_pinned_map(&opt.ifname, "ZLB_BACKENDS").unwrap();
    let map = Map::HashMap(map);
    let mut blocklist: HashMap<_, BEKey, BE> = map.try_into()?;
    let key = blocklist.keys().count() as u32;
    let bekey: BEKey = key.into();

    match blocklist.insert(&bekey, BE::default(), 0) {
        Ok(_) => info!("Key: {} inserted", key),
        _ => warn!("Key: {} not inserted", key),
    }

    Ok(())
}
