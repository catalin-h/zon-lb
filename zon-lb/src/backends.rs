use crate::helpers::{
    self, if_index_to_name, mapdata_from_pinned_map, BpfMapUpdateFlags as MUFlags,
};
use crate::info::InfoTable;
use crate::protocols::Protocol;
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, Map, MapData};
use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
use zon_lb_common::{BEGroup, BEKey, EPFlags, GroupInfo, BE, EP4, EP6, EPX};

/// Little endian
#[derive(Copy, Clone)]
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

impl ToEndPoint for EPX {
    fn as_endpoint(&self) -> EndPoint {
        match &self {
            EPX::V4(ep4) => ep4.as_endpoint(),
            EPX::V6(ep6) => ep6.as_endpoint(),
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

    fn ep_key(&self) -> EPX {
        match &self.ipaddr {
            IpAddr::V4(ip) => EPX::V4(EP4 {
                address: ip.octets(),
                port: self.port,
                proto: self.proto as u16,
            }),
            IpAddr::V6(ip) => EPX::V6(EP6 {
                address: ip.octets(),
                port: self.port,
                proto: self.proto as u16,
            }),
        }
    }

    fn as_group_info(&self, ifname: &str) -> Result<GroupInfo, anyhow::Error> {
        let key = self.ep_key();
        let flags = match key {
            EPX::V4(_) => EPFlags::IPV4,
            EPX::V6(_) => EPFlags::IPV6,
        };
        let ifindex = helpers::ifindex(ifname)?;

        Ok(GroupInfo {
            becount: 0,
            flags,
            ifindex,
            key: self.ep_key(),
        })
    }

    fn as_backend(&self, gid: u64) -> BE {
        BE {
            address: match &self.ipaddr {
                IpAddr::V4(ip) => {
                    let mut v6: [u8; 16] = [0; 16];
                    v6[..4].clone_from_slice(&ip.octets()[..]);
                    v6
                }
                IpAddr::V6(ip) => ip.octets(),
            },
            port: self.port,
            gid: gid as u16,
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

    fn group_meta() -> Result<HashMap<MapData, u64, GroupInfo>, anyhow::Error> {
        let map = mapdata_from_pinned_map("", "ZLBX_GMETA").context("Group meta")?;
        let map = Map::HashMap(map);
        map.try_into().context("Groups meta")
    }

    fn allocate_group(&self, ginfo: &GroupInfo) -> Result<u64, anyhow::Error> {
        let mut map = Self::group_meta()?;
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
        let mut map = Self::group_meta()?;
        map.remove(&gid).context("Remove group meta")?;
        Ok(())
    }

    fn insert_group<K: aya::Pod>(
        &self,
        map_name: &str,
        ep: &K,
        beg: &BEGroup,
        flags: MUFlags,
    ) -> Result<(), anyhow::Error> {
        let map = self.group_mapdata(map_name)?;
        let mut gmap: HashMap<_, K, BEGroup> = map.try_into().context(map_name.to_string())?;
        gmap.insert(ep, beg, flags.bits())?;
        Ok(())
    }

    pub fn add(&self, ep: &EndPoint) -> Result<u64, anyhow::Error> {
        let ginfo = ep.as_group_info(&self.ifname)?;
        let gid = self.allocate_group(&ginfo)?;
        let mut beg = BEGroup::new(gid);

        beg.flags = ginfo.flags;

        match &ginfo.key {
            EPX::V4(ep4) => self.insert_group("ZLB_LB4", ep4, &beg, MUFlags::NOEXIST),
            EPX::V6(ep6) => self.insert_group("ZLB_LB6", ep6, &beg, MUFlags::NOEXIST),
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
        let map = Self::group_meta()?;

        for (gid, ginfo) in map.iter().filter_map(|pair| pair.ok()) {
            table.push_row(vec![
                gid.to_string(),
                ginfo.key.as_endpoint().to_string(),
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
        let gmap = Self::group_meta()?;

        if let Ok(ginfo) = gmap.get(&gid, 0) {
            rem_eps.push(ginfo.key.as_endpoint());
        } else {
            let mut search = |ep: &EndPoint, g: &BEGroup| {
                if g.gid == gid {
                    rem_eps.push(*ep);
                }
            };
            self.iterate_mut::<EP4, _>("ZLB_LB4", &mut search)
                .context("IPv4 group")?;
            self.iterate_mut::<EP6, _>("ZLB_LB6", &mut search)
                .context("IPv6 group")?;
        }

        if rem_eps.len() == 0 {
            return Err(anyhow!("Can't find group with id {}", gid));
        }

        for ep in &rem_eps {
            if let Err(e) = self.remove_group(ep) {
                log::warn!("[{}] failed to remove group for {}, {}", self.ifname, ep, e);
            }
        }

        if let Err(e) = self.free_group(gid) {
            log::warn!(
                "[{}] failed to remove group for {}, {}",
                self.ifname,
                gid,
                e
            );
        }

        Ok(rem_eps)
    }

    fn remove_group(&self, ep: &EndPoint) -> Result<(), anyhow::Error> {
        match ep.ep_key() {
            EPX::V4(ep4) => self.remove_group_from_map::<EP4>("ZLB_LB4", &ep4),
            EPX::V6(ep6) => self.remove_group_from_map::<EP6>("ZLB_LB6", &ep6),
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

pub struct Backend {
    pub gid: u64,
    pub group: Group,
}

impl Backend {
    pub fn new(gid: u64) -> Result<Backend, anyhow::Error> {
        let gmap = Group::group_meta()?;
        let ginfo = gmap.get(&gid, 0).context("No group in metadata")?;
        let ifname = if_index_to_name(ginfo.ifindex).ok_or(anyhow!("Can't get netdev name"))?;
        Ok(Self {
            gid,
            group: Group::new(&ifname)?,
        })
    }

    fn backends() -> Result<HashMap<MapData, BEKey, BE>, anyhow::Error> {
        let map =
            mapdata_from_pinned_map("", "ZLBX_BACKENDS").context("Get pinned backends map")?;
        let map = Map::HashMap(map);
        map.try_into().context("Diff data size for backends map")
    }

    pub fn add(&self, ep: &EndPoint) -> Result<(), anyhow::Error> {
        let mut backends = Self::backends()?;
        let mut gmap = Group::group_meta()?;
        let mut ginfo = gmap.get(&self.gid, 0)?;
        let index = ginfo.becount as u16;
        let iflags = MUFlags::EXIST;

        let be = ep.as_backend(self.gid);
        let key = BEKey {
            gid: self.gid as u16,
            index,
        };
        backends
            .insert(key, be, MUFlags::ANY.bits())
            .context("Insert backend")?;

        ginfo.becount += 1;
        gmap.insert(self.gid, ginfo, iflags.bits())
            .context("Update group meta")?;

        let beg = BEGroup {
            gid: self.gid,
            becount: index + 1,
            flags: ginfo.flags,
        };

        match &ginfo.key {
            EPX::V4(ep4) => self
                .group
                .insert_group("ZLB_LB4", ep4, &beg, iflags)
                .context("Update v4 group")?,
            EPX::V6(ep6) => self
                .group
                .insert_group("ZLB_LB6", ep6, &beg, iflags)
                .context("Update v6 group")?,
        }

        Ok(())
    }

    pub fn list(gid: Option<u64>) -> Result<(), anyhow::Error> {
        let mut gtable = InfoTable::new(vec!["gid", "id", "endpoint", "backend"]);
        let mut btable = InfoTable::new(vec!["id", "backend"]);
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
