use crate::helpers::mapdata_from_pinned_map;
use crate::info::InfoTable;
use crate::protocols::Protocol;
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, Map};
use std::{
    collections::hash_map::DefaultHasher,
    fmt,
    hash::{Hash, Hasher},
    net::{IpAddr, Ipv4Addr},
};
use zon_lb_common::{BEGroup, EPFlags, EP4, EP6, EPX};

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
                gmap.insert(ep4, beg, 0)
            }
            EPIp::EPIpV6(ep6) => {
                beg.flags |= EPFlags::IPV6;
                let map = self.group_mapdata("ZLB_LB6")?;
                let mut gmap: HashMap<_, EP6, BEGroup> = map.try_into().context("IPv6 group")?;
                gmap.insert(ep6, beg, 0)
            }
        }?;

        Ok(beg.gid)
    }

    fn group_iterate<K: aya::Pod, F>(
        &self,
        name: &str,
        mut apply: F,
        on_error: &mut impl FnMut(),
    ) -> Result<(), anyhow::Error>
    where
        F: FnMut(&K, &BEGroup),
    {
        let map = self.group_mapdata(name)?;
        let gmap = HashMap::<_, K, BEGroup>::try_from(&map)?;
        for res in gmap.iter() {
            match res {
                Ok((epx, group)) => apply(&epx, &group),
                _ => on_error(),
            }
        }
        Ok(())
    }

    pub fn list(&self) -> Result<(), anyhow::Error> {
        let mut table = InfoTable::new(vec!["gid", "endpoint", "flags", "be_count"]);
        let mut err_cnt = 0;
        let mut on_error = || {
            err_cnt += 1;
        };
        let to_row = |ep: &EndPoint, g: &BEGroup| {
            vec![
                format!("{:x}", g.gid),
                ep.to_string(),
                format!("{:x}", g.flags),
                format!("{}", g.becount),
            ]
        };

        self.group_iterate::<EP4, _>(
            "ZLB_LB4",
            |ep4, begroup| table.push_row(to_row(&EndPoint::from(ep4), begroup)),
            &mut on_error,
        )
        .context("IPv4 group")?;

        self.group_iterate::<EP6, _>(
            "ZLB_LB6",
            |ep6, begroup| table.push_row(to_row(&EndPoint::from(ep6), begroup)),
            &mut on_error,
        )
        .context("IPv6 group")?;

        table.print("Backend groups");
        if err_cnt != 0 {
            println!("there were {} errors", err_cnt);
        }
        table.reset();
        Ok(())
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
