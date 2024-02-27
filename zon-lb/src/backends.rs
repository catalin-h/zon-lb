use crate::helpers::{
    if_index_to_name, if_name_or_default, ifindex, mapdata_from_pinned_map, stou64,
    BpfMapUpdateFlags as MUFlags,
};
use crate::info::InfoTable;
use crate::protocols::Protocol;
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, Map, MapData};
use log::{error, info, warn};
use std::collections::{BTreeSet, HashMap as StdHashMap};
use std::fs::remove_file;
use std::path::PathBuf;
use std::{fmt, net::IpAddr};
use zon_lb_common::{BEGroup, BEKey, EPFlags, GroupInfo, BE, EP4, EP6, EPX, INET};

pub trait ToMapName {
    fn map_name() -> &'static str;
}

impl ToMapName for EP4 {
    fn map_name() -> &'static str {
        "ZLB_LB4"
    }
}

impl ToMapName for EP6 {
    fn map_name() -> &'static str {
        "ZLB_LB6"
    }
}

impl ToMapName for GroupInfo {
    fn map_name() -> &'static str {
        "ZLBX_GMETA"
    }
}

impl ToMapName for BE {
    fn map_name() -> &'static str {
        "ZLB_BACKENDS"
    }
}

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
            ipaddr: IpAddr::from(value.address.to_le_bytes()),
            proto: Protocol::from(value.proto.to_le() as u8),
            port: value.port.to_le(),
        }
    }
}

impl From<&EP6> for EndPoint {
    fn from(value: &EP6) -> Self {
        Self {
            ipaddr: IpAddr::from(value.address),
            proto: Protocol::from(value.proto.to_le() as u8),
            port: value.port.to_le(),
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
        IpAddr::from(unsafe { self.address.v4.to_le_bytes() })
    }
    fn ipv6(&self) -> IpAddr {
        IpAddr::from(unsafe { self.address.v6 })
    }
    fn port(&self) -> u16 {
        self.port.to_le()
    }
}

impl ToEndPoint for EP4 {
    fn as_endpoint(&self) -> EndPoint {
        EndPoint {
            ipaddr: IpAddr::from(self.address.to_le_bytes()),
            // protocol is a single byte and the value is not byte-swapped
            proto: Protocol::from(self.proto as u8),
            port: u16::from_be(self.port),
        }
    }
}

impl ToEndPoint for EP6 {
    fn as_endpoint(&self) -> EndPoint {
        EndPoint {
            ipaddr: IpAddr::from(self.address),
            // protocol is a single byte and the value is not byte-swapped
            proto: Protocol::from(self.proto as u8),
            port: u16::from_be(self.port),
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
        } else {
            self.ipv6()
        };

        EndPoint {
            ipaddr,
            proto: self.proto.into(),
            port: u16::from_be(self.port),
        }
    }
}

impl Default for EndPoint {
    fn default() -> Self {
        Self {
            ipaddr: IpAddr::from([0; 4]),
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

    /// Convert to EP4/6 using network endianess (big-endian).
    /// Note that the endpoint stores fields in little endian format.
    fn ep_key(&self) -> EPX {
        let port = self.port.to_be();
        let proto = self.proto as u16;
        match &self.ipaddr {
            IpAddr::V4(ip) => EPX::V4(EP4 {
                address: u32::from_le_bytes(ip.octets()),
                port,
                proto,
            }),
            IpAddr::V6(ip) => EPX::V6(EP6 {
                address: ip.octets(),
                port,
                proto,
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
            key,
        })
    }

    fn as_backend(&self, gid: u64) -> BE {
        let (address, flags) = match &self.ipaddr {
            IpAddr::V4(ip) => (INET::from(u32::from(*ip).to_be()), EPFlags::IPV4),
            IpAddr::V6(ip) => (INET::from(ip.octets()), EPFlags::IPV6),
        };

        BE {
            address,
            port: self.port.to_be(),
            proto: self.proto as u8,
            flags,
            gid: gid as u16,
        }
    }
}

pub struct Group {
    pub ifname: String,
    pub ifindex: u32,
}

impl Group {
    pub fn new(ifname: &str) -> Result<Self, anyhow::Error> {
        Ok(Self {
            ifname: ifname.to_string(),
            ifindex: ifindex(ifname)?,
        })
    }

    fn group_mapdata<K>() -> Result<HashMap<MapData, K, BEGroup>, anyhow::Error>
    where
        K: aya::Pod + ToMapName,
    {
        let map = mapdata_from_pinned_map("", K::map_name())
            .ok_or(anyhow!("Failed to find map: {} in bpffs", K::map_name()))?;
        let map = Map::HashMap(map);
        let map: HashMap<_, K, BEGroup> = map.try_into()?;
        Ok(map)
    }

    pub fn group_meta() -> Result<HashMap<MapData, u64, GroupInfo>, anyhow::Error> {
        let map = mapdata_from_pinned_map("", GroupInfo::map_name()).context("Group meta fetch")?;
        let map = Map::HashMap(map);
        map.try_into().context("Groups meta size change")
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

    fn insert_group<K: aya::Pod + ToMapName>(
        &self,
        ep: &K,
        beg: &BEGroup,
        flags: MUFlags,
    ) -> Result<(), anyhow::Error> {
        let mut gmap = Self::group_mapdata::<K>()?;
        gmap.insert(ep, beg, flags.bits())?;
        Ok(())
    }

    fn get<K: aya::Pod + ToMapName>(&self, ep: &K) -> Result<BEGroup, anyhow::Error> {
        let gmap = Self::group_mapdata::<K>()?;
        gmap.get(ep, 0).context("get backend group")
    }

    fn get_by_ep(&self, ep: &EndPoint) -> Result<BEGroup, anyhow::Error> {
        match ep.ep_key() {
            EPX::V4(ep4) => self.get(&ep4),
            EPX::V6(ep6) => self.get(&ep6),
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
        beg.ifindex = self.ifindex;

        match &ginfo.key {
            EPX::V4(ep4) => self.insert_group(ep4, &beg, MUFlags::NOEXIST),
            EPX::V6(ep6) => self.insert_group(ep6, &beg, MUFlags::NOEXIST),
        }?;

        Ok(beg.gid)
    }

    fn iterate_mut<K, F>(mut apply: F) -> Result<(), anyhow::Error>
    where
        K: aya::Pod + ToEndPoint + ToMapName,
        F: FnMut(&K, &BEGroup),
    {
        let gmap = Self::group_mapdata::<K>()?;

        for (ep, g) in gmap.iter().filter_map(|res| res.ok()) {
            apply(&ep, &g);
        }
        Ok(())
    }

    pub fn iterate_all<F>(mut apply: F) -> Result<(), anyhow::Error>
    where
        F: FnMut(EndPoint, &BEGroup),
    {
        Self::iterate_mut::<EP4, _>(|ep, g| apply(ep.as_endpoint(), g))?;
        Self::iterate_mut::<EP6, _>(|ep, g| apply(ep.as_endpoint(), g))?;
        Ok(())
    }

    pub fn list() -> Result<(), anyhow::Error> {
        let mut table = InfoTable::new(vec!["gid", "endpoint", "netdev", "flags", "be_count"]);
        let search = |ep: EndPoint, g: &BEGroup| {
            table.push_row(vec![
                g.gid.to_string(),
                ep.to_string(),
                if_index_to_name(g.ifindex).unwrap_or(g.ifindex.to_string()),
                format!("{:x}", g.flags),
                format!("{}", g.becount),
            ])
        };

        Self::iterate_all(search)?;

        table.sort_by_key(0, Some(&|s: &String| stou64(&s, 10)));
        table.print("Backend groups");

        table.reset();
        Ok(())
    }

    pub fn remove(&self, gid: u64) -> Result<(), anyhow::Error> {
        self.remove_all_by_id::<EP4>(gid)?;
        self.remove_all_by_id::<EP6>(gid)?;

        match Backend::new(gid).clear() {
            Ok(v) => info!("[{}/{}] Removed backends: {}", self.ifname, gid, v.len()),
            Err(e) => error!("[{}/{}] Error on freeing backends,{}", self.ifname, gid, e),
        };

        if let Err(e) = self.free_group(gid) {
            error!("[{}/{}] Error on info freeing,{}", self.ifname, gid, e);
        }

        Ok(())
    }

    fn remove_all_by_id<K>(&self, gid: u64) -> Result<(), anyhow::Error>
    where
        K: aya::Pod + ToMapName + ToEndPoint,
    {
        let mut map = Self::group_mapdata::<K>()?;
        let mut eps = vec![];

        for (ep, _) in map
            .iter()
            .filter_map(|item| item.ok())
            .filter(|(_, g)| g.gid == gid)
        {
            eps.push(ep);
        }

        for ep in eps {
            let endp = ep.as_endpoint();
            match map.remove(&ep) {
                Ok(()) => info!("[{}/{}] Group {} was removed", self.ifname, gid, endp),
                Err(e) => warn!("[{}/{}] Group {} not removed,{}", self.ifname, gid, endp, e),
            }
        }

        Ok(())
    }

    pub fn remove_all(&self) -> Result<(), anyhow::Error> {
        let mut gids = BTreeSet::new();
        Self::iterate_all(|_, g| {
            if g.ifindex == self.ifindex {
                gids.insert(g.gid);
            }
        })?;

        info!("[{}] Removing groups {:?}", &self.ifname, gids);

        let mut i = 0;
        let n = gids.len();
        for gid in &gids {
            match self.remove(*gid) {
                Ok(()) => i += 1,
                Err(e) => error!("Group {} not removed from {}, {}", gid, self.ifname, e),
            }
        }

        info!("[{}] Group remove summary: {}/{}", self.ifname, i, n);

        Ok(())
    }

    pub fn _copy<K: aya::Pod + ToMapName + ToEndPoint>(
        &self,
        dst_map: &mut Map,
    ) -> Result<(), anyhow::Error> {
        let mut map: HashMap<_, K, BEGroup> = dst_map.try_into()?;

        Self::iterate_mut::<K, _>(|&ep, &beg| match map.insert(ep, beg, 0) {
            Ok(()) => log::info!("[{}] {} copied to map", &self.ifname, ep.as_endpoint(),),
            Err(e) => log::error!(
                "[{}] Failed to copy {} to map, {}",
                &self.ifname,
                ep.as_endpoint(),
                e
            ),
        })?;
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
    pub fn new(gid: u64) -> Self {
        Self { gid }
    }

    pub fn backends() -> Result<HashMap<MapData, BEKey, BE>, anyhow::Error> {
        let map = mapdata_from_pinned_map("", BE::map_name()).context("Get pinned backends map")?;
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
            ifindex: gmap.info.ifindex,
        };

        match &gmap.info.key {
            EPX::V4(ep4) => gmap
                .group
                .insert_group(ep4, &beg, iflags)
                .context("Update v4 group")?,
            EPX::V6(ep6) => gmap
                .group
                .insert_group(ep6, &beg, iflags)
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
        let mut cache: StdHashMap<u64, String> = StdHashMap::new();

        Group::iterate_all(|ep, group| {
            if group.becount > 0 {
                let out = format!("{} / {}", if_name_or_default(group.ifindex), ep);
                cache.insert(group.gid, out);
            }
        })?;

        for (key, be) in backends.iter().filter_map(|x| x.ok()) {
            let gid = key.gid as u64;
            let ep_str = cache.get(&gid).map_or("n/a", |v| v.as_str());
            table.push_row(vec![
                format!("{}:{}", key.gid, key.index),
                be.as_endpoint().to_string(),
                "<->".to_string(),
                ep_str.to_string(),
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
                EPX::V4(ep4) => gmap.group.insert_group(ep4, &begroup, iflags),
                EPX::V6(ep6) => gmap.group.insert_group(ep6, &begroup, iflags),
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

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    for map_name in [
        GroupInfo::map_name(),
        EP4::map_name(),
        EP6::map_name(),
        BE::map_name(),
    ] {
        let path = PathBuf::from(crate::BPFFS).join(map_name);
        match path.try_exists() {
            Ok(false) => continue,
            Ok(true) => {}
            Err(e) => {
                log::error!("Can't check the file status for map {}, {}", map_name, e);
                continue;
            }
        }
        match remove_file(path) {
            Ok(()) => log::info!("Map {} bpffs successfully deleted", map_name),
            Err(e) => log::error!("Failed to delete map {} bpffs, {}", map_name, e),
        }
    }
    Ok(())
}
