use crate::helpers::{mapdata_from_pinned_map, BpfMapUpdateFlags as MUFlags};
use crate::info::InfoTable;
use crate::protocols::Protocol;
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, Map};
use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use zon_lb_common::{BEGroup, EPFlags, EP4, EP6};

/// Little endian
#[derive(Hash)]
pub struct EndPoint {
    pub ipaddr: IpAddr,
    pub proto: Protocol,
    pub port: u16,
}

impl From<&EP4> for EndPoint {
    fn from(value: &EP4) -> Self {
        Self {
            ipaddr: IpAddr::from(value.address),
            proto: Protocol::from(value.proto as u8),
            port: value.port,
        }
    }
}

impl From<&EP6> for EndPoint {
    fn from(value: &EP6) -> Self {
        Self {
            ipaddr: IpAddr::from(value.address),
            proto: Protocol::from(value.proto as u8),
            port: value.port,
        }
    }
}

pub trait ToEndPoint {
    fn as_endpoint(&self) -> EndPoint;
}

impl ToEndPoint for EP4 {
    fn as_endpoint(&self) -> EndPoint {
        EndPoint {
            ipaddr: IpAddr::V4(Ipv4Addr::from(self.address)),
            proto: Protocol::from(self.proto as u8),
            port: self.port,
        }
    }
}

impl ToEndPoint for EP6 {
    fn as_endpoint(&self) -> EndPoint {
        EndPoint {
            ipaddr: IpAddr::V6(Ipv6Addr::from(self.address)),
            proto: Protocol::from(self.proto as u8),
            port: self.port,
        }
    }
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

enum EPIp {
    EPIpV4(EP4),
    EPIpV6(EP6),
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

    fn id(&self) -> u64 {
        let mut hasher = DefaultHasher::new();
        self.hash(&mut hasher);
        hasher.finish()
    }

    fn ep_key(&self) -> EPIp {
        match &self.ipaddr {
            IpAddr::V4(ip) => EPIp::EPIpV4(EP4 {
                address: ip.octets(),
                port: self.port,
                proto: self.proto as u16,
            }),
            IpAddr::V6(ip) => EPIp::EPIpV6(EP6 {
                address: ip.octets(),
                port: self.port,
                proto: self.proto as u16,
            }),
        }
    }
}

pub struct Group {
    pub ifname: String,
}

impl Group {
    pub fn new(ifname: &str) -> Result<Self, anyhow::Error> {
        Ok(Self {
            ifname: ifname.to_string(),
        })
    }

    fn group_mapdata(&self, gmap: &str) -> Result<Map, anyhow::Error> {
        let map = mapdata_from_pinned_map(&self.ifname, gmap).ok_or(anyhow!(
            "Failed to get group map: {} on interface: {}",
            gmap,
            &self.ifname
        ))?;
        Ok(Map::HashMap(map))
    }

    pub fn add(&self, ep: &EndPoint) -> Result<u64, anyhow::Error> {
        let mut beg = BEGroup::new(ep.id());

        match ep.ep_key() {
            EPIp::EPIpV4(ep4) => {
                beg.flags |= EPFlags::IPV4;
                let map = self.group_mapdata("ZLB_LB4")?;
                let mut gmap: HashMap<_, EP4, BEGroup> = map.try_into().context("IPv4 group")?;
                gmap.insert(ep4, beg, MUFlags::NOEXIST.bits())
            }
            EPIp::EPIpV6(ep6) => {
                beg.flags |= EPFlags::IPV6;
                let map = self.group_mapdata("ZLB_LB6")?;
                let mut gmap: HashMap<_, EP6, BEGroup> = map.try_into().context("IPv6 group")?;
                gmap.insert(ep6, beg, MUFlags::NOEXIST.bits())
            }
        }?;

        Ok(beg.gid)
    }

    fn iterate_mut<K, F>(&self, name: &str, mut apply: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(&EndPoint, &BEGroup),
        K: aya::Pod + ToEndPoint,
    {
        let map = self.group_mapdata(name)?;
        let gmap = HashMap::<_, K, BEGroup>::try_from(&map)?;

        for (e, g) in gmap.iter().filter_map(|res| res.ok()) {
            let ep = e.as_endpoint();
            apply(&ep, &g);
        }
        Ok(())
    }

    pub fn list(&self) -> Result<(), anyhow::Error> {
        let mut table = InfoTable::new(vec!["gid", "endpoint", "flags", "be_count"]);
        let mut to_row = |ep: &EndPoint, g: &BEGroup| {
            let row = vec![
                format!("{:x}", g.gid),
                ep.to_string(),
                format!("{:x}", g.flags),
                format!("{}", g.becount),
            ];
            table.push_row(row);
        };

        self.iterate_mut::<EP4, _>("ZLB_LB4", &mut to_row)
            .context("IPv4 group")?;
        self.iterate_mut::<EP6, _>("ZLB_LB6", &mut to_row)
            .context("IPv6 group")?;

        table.print("Backend groups");

        table.reset();
        Ok(())
    }
}

// TODO: add BPF_F_LOCK

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
