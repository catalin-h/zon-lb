use crate::helpers::{
    if_index_to_name, ifindex, mapdata_from_pinned_map, stou64, BpfMapUpdateFlags as MUFlags,
};
use crate::info::InfoTable;
use crate::protocols::Protocol;
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, Map, MapData};
use std::collections::HashMap as StdHashMap;
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

pub trait BackendInfo {
    fn ipv4(&self) -> IpAddr;
    fn ipv6(&self) -> IpAddr;
    fn port(&self) -> u16;
}

impl BackendInfo for BE {
    fn ipv4(&self) -> IpAddr {
        IpAddr::from([
            self.address[0],
            self.address[1],
            self.address[2],
            self.address[3],
        ])
    }
    fn ipv6(&self) -> IpAddr {
        IpAddr::from(self.address)
    }
    fn port(&self) -> u16 {
        self.port
    }
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

impl ToEndPoint for BE {
    fn as_endpoint(&self) -> EndPoint {
        let ipaddr = if self.flags.contains(EPFlags::IPV4) {
            self.ipv4()
        } else if self.flags.contains(EPFlags::IPV6) {
            self.ipv6()
        } else {
            IpAddr::from(self.address)
        };

        EndPoint {
            ipaddr,
            proto: self.proto.into(),
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
        let proto = match self.proto {
            Protocol::None => "".to_string(),
            _ => format!("{:?}: ", self.proto),
        };
        if self.port == 0 {
            write!(f, "{}{}", proto, &self.ipaddr)
        } else {
            write!(f, "{}[{}]:{}", proto, &self.ipaddr, &self.port)
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
        let ifindex = ifindex(ifname)?;

        Ok(GroupInfo {
            becount: 0,
            flags,
            ifindex,
            key: self.ep_key(),
        })
    }

    fn as_backend(&self, gid: u64) -> BE {
        let (address, flags) = match &self.ipaddr {
            IpAddr::V4(ip) => {
                let mut v6: [u8; 16] = [0; 16];
                v6[..4].clone_from_slice(&ip.octets()[..]);
                (v6, EPFlags::IPV4)
            }
            IpAddr::V6(ip) => (ip.octets(), EPFlags::IPV6),
        };

        BE {
            address,
            port: self.port,
            gid: gid as u16,
            proto: self.proto as u8,
            flags,
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

    pub fn group_meta() -> Result<HashMap<MapData, u64, GroupInfo>, anyhow::Error> {
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

    fn get<K: aya::Pod>(&self, map_name: &str, ep: &K) -> Result<BEGroup, anyhow::Error> {
        let map = self.group_mapdata(map_name)?;
        let gmap: HashMap<_, K, BEGroup> = map.try_into().context(map_name.to_string())?;
        gmap.get(ep, 0).context("get backend group")
    }

    fn get_by_ep(&self, ep: &EndPoint) -> Result<BEGroup, anyhow::Error> {
        match ep.ep_key() {
            EPX::V4(ep4) => self.get("ZLB_LB4", &ep4),
            EPX::V6(ep6) => self.get("ZLB_LB6", &ep6),
        }
    }

    pub fn add(&self, ep: &EndPoint) -> Result<u64, anyhow::Error> {
        match self.get_by_ep(ep) {
            Ok(beg) => {
                return Err(anyhow!(
                    "Backend group {} already exists, gid: {}",
                    ep,
                    beg.gid
                ))
            }
            Err(_) => {}
        }

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
        table.sort_by_key(0, Some(&|s: &String| stou64(&s, 10)));
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
}

struct GroupMap {
    group: Group,
    info: GroupInfo,
    meta: HashMap<MapData, u64, GroupInfo>,
}

impl GroupMap {
    fn new(gid: u64) -> Result<GroupMap, anyhow::Error> {
        let meta = Group::group_meta()?;
        let info = meta.get(&gid, 0).context("No group in metadata")?;
        let ifname = if_index_to_name(info.ifindex).ok_or(anyhow!("Can't get netdev name"))?;
        let group = Group::new(&ifname)?;
        Ok(Self { group, meta, info })
    }

    fn check_compat(&self, ep: &EndPoint) -> Result<(), anyhow::Error> {
        match ep.ipaddr {
            IpAddr::V4(_) => {
                if !self.info.flags.contains(EPFlags::IPV4) {
                    return Err(anyhow!(
                        "Incompatible IPv4 backend {} with target IPv6 group {}",
                        ep,
                        self.info.key.as_endpoint()
                    ));
                }
            }
            IpAddr::V6(_) => {
                if !self.info.flags.contains(EPFlags::IPV6) {
                    return Err(anyhow!(
                        "Incompatible IPv6 backend {} with target IPv4 group {}",
                        ep,
                        self.info.key.as_endpoint()
                    ));
                }
            }
        }

        if ep.proto != Protocol::None && ep.proto != self.info.key.proto().into() {
            return Err(anyhow!(
                "Incompatible backend protocol {} with target group protocol {}",
                ep,
                self.info.key.as_endpoint()
            ));
        }

        Ok(())
    }

    fn begroup(&self) -> Result<BEGroup, anyhow::Error> {
        self.group.get_by_ep(&self.info.key.as_endpoint())
    }
}

impl Backend {
    pub fn new(gid: u64) -> Result<Backend, anyhow::Error> {
        Ok(Self { gid })
    }

    pub fn backends() -> Result<HashMap<MapData, BEKey, BE>, anyhow::Error> {
        let map =
            mapdata_from_pinned_map("", "ZLBX_BACKENDS").context("Get pinned backends map")?;
        let map = Map::HashMap(map);
        map.try_into().context("Diff data size for backends map")
    }

    pub fn add(&self, ep: &EndPoint) -> Result<Group, anyhow::Error> {
        let mut backends = Self::backends()?;
        let mut gmap = GroupMap::new(self.gid)?;
        let index = gmap.info.becount as u16;
        let iflags = MUFlags::EXIST;

        gmap.check_compat(ep)?;

        let be = ep.as_backend(self.gid);
        let key = BEKey {
            gid: self.gid as u16,
            index,
        };
        backends
            .insert(key, be, MUFlags::ANY.bits())
            .context("Insert backend")?;

        gmap.info.becount += 1;
        gmap.meta
            .insert(self.gid, gmap.info, iflags.bits())
            .context("Update group meta")?;

        let beg = BEGroup {
            gid: self.gid,
            becount: index + 1,
            flags: gmap.info.flags,
        };

        match &gmap.info.key {
            EPX::V4(ep4) => gmap
                .group
                .insert_group("ZLB_LB4", ep4, &beg, iflags)
                .context("Update v4 group")?,
            EPX::V6(ep6) => gmap
                .group
                .insert_group("ZLB_LB6", ep6, &beg, iflags)
                .context("Update v6 group")?,
        }

        Ok(gmap.group)
    }

    fn build_backend_list(gid: u16, ginfo: &GroupInfo) -> Result<InfoTable, anyhow::Error> {
        let mut table = InfoTable::new(vec!["id", "endpoint"]);
        let backends = Self::backends()?;

        for index in 0..ginfo.becount as u16 {
            let key = BEKey { gid, index };
            match backends.get(&key, 0) {
                Ok(be) => {
                    table.push_row(vec![index.to_string(), be.as_endpoint().to_string()]);
                }
                _ => {}
            }
        }

        Ok(table)
    }

    fn list_all() -> Result<(), anyhow::Error> {
        let mut table = InfoTable::new(vec!["gid:id", "backend", "", "if / lb_endpoint"]);
        let backends = Self::backends()?;
        let gmap = Group::group_meta()?;
        let mut cache: StdHashMap<u64, String> = StdHashMap::new();
        let mut fetch = |gid: &u64| {
            if let Some(ginfo) = cache.get(gid) {
                return ginfo.clone();
            }
            let value = match gmap.get(gid, 0) {
                Ok(ginfo) => {
                    let ifname = if_index_to_name(ginfo.ifindex)
                        .unwrap_or_else(|| format!("if#{}", ginfo.ifindex.to_string()));
                    let out = format!("{} / {}", ifname, ginfo.key.as_endpoint());
                    out
                }
                Err(_) => "n/a".to_string(),
            };
            cache.insert(*gid, value.clone());
            value
        };

        for (key, be) in backends.iter().filter_map(|x| x.ok()) {
            let gid = key.gid as u64;
            let ep_str = fetch(&gid);
            table.push_row(vec![
                format!("{}:{}", key.gid, key.index),
                be.as_endpoint().to_string(),
                "<->".to_string(),
                ep_str,
            ]);
        }
        let extract_key = |ids: &String| -> u64 {
            match ids.split_once(':') {
                Some((gid, id)) => stou64(&gid, 10).pow(16) + stou64(&id, 10),
                None => 0_u64,
            }
        };
        table.sort_by_key(0, Some(extract_key));
        table.print("Backends list:");
        Ok(())
    }

    pub fn list(gid: u64) -> Result<(), anyhow::Error> {
        if gid == 0 {
            return Self::list_all();
        }

        let mut table = InfoTable::new(vec!["gid", "endpoint", "netdev", "flags", "be_count"]);
        let to_row = |gid: u16, ginfo: &GroupInfo| {
            vec![
                gid.to_string(),
                ginfo.key.as_endpoint().to_string(),
                if_index_to_name(ginfo.ifindex).unwrap_or(ginfo.ifindex.to_string()),
                format!("{:x}", ginfo.flags),
                format!("{}", ginfo.becount),
            ]
        };

        let gmap = Group::group_meta()?;
        let ginfo = gmap
            .get(&gid, 0)
            .context("Failed to retrieve group for id")?;
        let bt = Self::build_backend_list(gid as u16, &ginfo)?;
        table.push_row(to_row(gid as u16, &ginfo));
        table.print("Backend group info:");
        bt.print("Backends list:");

        Ok(())
    }

    fn replace(&self, src: u16, dst: u16) -> Result<(), anyhow::Error> {
        if dst == src {
            return Ok(());
        }

        let mut backends = Self::backends()?;

        let dkey = BEKey {
            gid: self.gid as u16,
            index: dst,
        };
        let skey = BEKey {
            gid: self.gid as u16,
            index: src,
        };
        let sbe = backends
            .get(&skey, 0)
            .context("replace: get source backend")?;
        backends
            .insert(&dkey, &sbe, MUFlags::EXIST.bits())
            .context("replace: update destination backend")
    }

    fn remove_from_group(&self, index: u16) -> Result<u16, anyhow::Error> {
        let mut gmap = GroupMap::new(self.gid)?;
        let mut begroup = gmap.begroup()?;
        let mut rem_index = index;
        let iflags = MUFlags::EXIST;
        let mut count = begroup.becount.min(gmap.info.becount as u16);

        if count > 0 && index < count {
            self.replace(count - 1, index)?;
            count -= 1;
            rem_index = count;
        }

        if count != begroup.becount {
            begroup.becount = count;
            let res = match &gmap.info.key {
                EPX::V4(ep4) => gmap.group.insert_group("ZLB_LB4", ep4, &begroup, iflags),
                EPX::V6(ep6) => gmap.group.insert_group("ZLB_LB6", ep6, &begroup, iflags),
            };
            if let Err(_) = res {
                log::warn!("Can't update group {}", gmap.info.key.as_endpoint());
            }
        }

        let count: u64 = count.into();
        if count != gmap.info.becount {
            gmap.info.becount = count;
            if let Err(_) = gmap.meta.insert(self.gid, gmap.info, iflags.bits()) {
                log::warn!("Can't update group meta for group {}", self.gid);
            }
        }

        Ok(rem_index)
    }

    pub fn remove(&self, index: u16) -> Result<BE, anyhow::Error> {
        let mut backends = Self::backends()?;
        let rem_index = self.remove_from_group(index).unwrap_or(index);
        let key = BEKey {
            gid: self.gid as u16,
            index: rem_index,
        };

        let be = backends.get(&key, 0).context(format!(
            "Remove: can't find backend: {} : {}",
            key.gid, key.index
        ))?;
        backends.remove(&key).context("Failed to remove backend")?;

        Ok(be)
    }

    pub fn clear(&self) -> Result<Vec<BE>, anyhow::Error> {
        let backends = Self::backends()?;
        let mut rem_eps = Vec::new();

        for (key, _) in backends
            .iter()
            .filter_map(|x| x.ok())
            .filter(|(k, _)| self.gid == k.gid as u64)
        {
            match self.remove(key.index) {
                Ok(be) => rem_eps.push(be),
                Err(_) => {}
            }
        }

        Ok(rem_eps)
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
