use crate::helpers::{
    self, if_index_to_name, mapdata_from_pinned_map, BpfMapUpdateFlags as MUFlags,
};
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
use zon_lb_common::{BEGroup, EPFlags, GroupInfo, EP4, EP6, EPX};

/// Little endian
#[derive(Hash, Copy, Clone)]
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

    fn as_group_info(&self, ifname: &str) -> Result<GroupInfo, anyhow::Error> {
        let (key, flags) = match &self.ipaddr {
            IpAddr::V4(ip) => (
                EPX::V4(EP4 {
                    address: ip.octets(),
                    port: self.port,
                    proto: self.proto as u16,
                }),
                EPFlags::IPV4,
            ),
            IpAddr::V6(ip) => (
                EPX::V6(EP6 {
                    address: ip.octets(),
                    port: self.port,
                    proto: self.proto as u16,
                }),
                EPFlags::IPV6,
            ),
        };

        let ifindex = helpers::ifindex(ifname)?;

        Ok(GroupInfo {
            becount: 0,
            flags,
            ifindex,
            key,
        })
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

    fn allocate_group(&self, ginfo: &GroupInfo) -> Result<u64, anyhow::Error> {
        let map = self.group_mapdata("ZLBX_GMETA")?;
        let mut map: HashMap<_, u64, GroupInfo> = map.try_into().context("Groups meta")?;
        let max_id = map.keys().filter_map(|x| x.ok()).max().unwrap_or_default();
        let mut id = max_id + 1;
        while id != max_id {
            if let Ok(_) = map.insert(id, ginfo, MUFlags::NOEXIST.bits()) {
                return Ok(id);
            }
            id = (id + 1) % (u16::MAX as u64 + 1);
        }

        Err(anyhow!(
            "Failed to allocate backend group, try reload application!"
        ))
    }

    fn free_group(&self, gid: u64) -> Result<(), anyhow::Error> {
        let map = self.group_mapdata("ZLBX_GMETA")?;
        let mut map: HashMap<_, u64, GroupInfo> = map.try_into().context("Group meta")?;
        map.remove(&gid)?;
        Ok(())
    }

    fn insert_group<K: aya::Pod>(
        &self,
        map_name: &str,
        ep: &K,
        beg: &BEGroup,
    ) -> Result<(), anyhow::Error> {
        let map = self.group_mapdata(map_name)?;
        let mut gmap: HashMap<_, K, BEGroup> = map.try_into().context(map_name.to_string())?;
        gmap.insert(ep, beg, MUFlags::NOEXIST.bits())?;
        Ok(())
    }

    pub fn add(&self, ep: &EndPoint) -> Result<u64, anyhow::Error> {
        let ginfo = ep.as_group_info(&self.ifname)?;
        let gid = self.allocate_group(&ginfo)?;
        let mut beg = BEGroup::new(gid);

        beg.flags = ginfo.flags;

        match &ginfo.key {
            EPX::V4(ep4) => self.insert_group("ZLB_LB4", ep4, &beg),
            EPX::V6(ep6) => self.insert_group("ZLB_LB6", ep6, &beg),
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
        let mut table = InfoTable::new(vec!["gid", "endpoint", "netdev", "flags", "be_count"]);
        let map = self.group_mapdata("ZLBX_GMETA")?;
        let map: HashMap<_, u64, GroupInfo> = map.try_into().context("Groups meta")?;

        for (gid, ginfo) in map.iter().filter_map(|pair| pair.ok()) {
            let ep = match ginfo.key {
                EPX::V4(ep4) => ToEndPoint::as_endpoint(&ep4),
                EPX::V6(ep6) => ToEndPoint::as_endpoint(&ep6),
            };

            table.push_row(vec![
                gid.to_string(),
                ep.to_string(),
                if_index_to_name(ginfo.ifindex).unwrap_or(ginfo.ifindex.to_string()),
                format!("{:x}", ginfo.flags),
                format!("{}", ginfo.becount),
            ]);
        }

        table.print("Backend groups");

        table.reset();
        Ok(())
    }

    pub fn remove(&self, gid: u64) -> Result<Vec<EndPoint>, anyhow::Error> {
        let mut rem_eps = vec![];
        let mut search = |ep: &EndPoint, g: &BEGroup| {
            if g.gid == gid {
                rem_eps.push(*ep);
            }
        };
        self.iterate_mut::<EP4, _>("ZLB_LB4", &mut search)
            .context("IPv4 group")?;
        self.iterate_mut::<EP6, _>("ZLB_LB6", &mut search)
            .context("IPv6 group")?;

        if rem_eps.len() == 0 {
            return Err(anyhow!("Can't find group with id {}", gid));
        }

        for ep in &rem_eps {
            self.remove_group(ep)?;
        }

        self.free_group(gid)?;

        Ok(rem_eps)
    }

    fn remove_group(&self, ep: &EndPoint) -> Result<(), anyhow::Error> {
        match ep.ep_key() {
            EPIp::EPIpV4(ep4) => self.remove_group_from_map::<EP4>("ZLB_LB4", &ep4),
            EPIp::EPIpV6(ep6) => self.remove_group_from_map::<EP6>("ZLB_LB6", &ep6),
        }
    }

    fn remove_group_from_map<K>(&self, map_name: &str, ep: &K) -> Result<(), anyhow::Error>
    where
        K: aya::Pod,
    {
        let map = self.group_mapdata(map_name)?;
        let mut map: HashMap<_, K, BEGroup> = map.try_into()?;
        map.remove(ep)?;
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
