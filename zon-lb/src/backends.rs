use crate::helpers::{
    if_index_to_name, if_name_or_default, ifindex, mapdata_from_pinned_map, stou64, teardown_maps,
    BpfMapUpdateFlags as MUFlags,
};
use crate::info::InfoTable;
use crate::protocols::Protocol;
use crate::{EpOptions, ToMapName};
use anyhow::{anyhow, Context, Result};
use aya::maps::{HashMap, Map, MapData};
use log::{error, info, warn};
use std::collections::{BTreeMap, BTreeSet, HashMap as StdHashMap};
use std::ops::Shl;
use std::{fmt, net::IpAddr};
use zon_lb_common::{BEGroup, BEKey, EPFlags, GroupInfo, BE, EP4, EP6, EPX, INET};

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
#[derive(Clone)]
pub struct EndPoint {
    pub ipaddr: IpAddr,
    pub proto: Protocol,
    pub port: u16,
    pub options: EpOptions,
}

impl From<&EP4> for EndPoint {
    fn from(value: &EP4) -> Self {
        Self {
            ipaddr: IpAddr::from(value.address.to_le_bytes()),
            proto: Protocol::from(value.proto.to_le() as u8),
            port: value.port.to_le(),
            ..Default::default()
        }
    }
}

impl From<&EP6> for EndPoint {
    fn from(value: &EP6) -> Self {
        Self {
            ipaddr: IpAddr::from(value.address),
            proto: Protocol::from(value.proto.to_le() as u8),
            port: value.port.to_le(),
            ..Default::default()
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
        IpAddr::from(self.address.v4.to_le_bytes())
    }
    fn ipv6(&self) -> IpAddr {
        IpAddr::from(self.address.v6)
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
            ..Default::default()
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
            ..Default::default()
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
            options: EpOptions {
                flags: self.flags,
                props: BTreeMap::from([]),
            },
        }
    }
}

impl Default for EndPoint {
    fn default() -> Self {
        Self {
            ipaddr: IpAddr::from([0; 4]),
            proto: Protocol::None,
            port: 0,
            options: EpOptions::default(),
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
        options: Option<EpOptions>,
    ) -> Result<Self, anyhow::Error> {
        Ok(Self {
            ipaddr: ip_address.parse().map_err(|e| e)?,
            proto: proto.clone(),
            port: port.unwrap_or_default(),
            options: options.unwrap_or_default(),
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
        let ifindex = ifindex(ifname)?;

        Ok(GroupInfo { ifindex, key })
    }

    fn as_backend(&self, gid: u16) -> BE {
        let (address, flags) = match &self.ipaddr {
            IpAddr::V4(ip) => (INET::from(u32::from(*ip).to_be()), EPFlags::IPV4),
            IpAddr::V6(ip) => (INET::from(ip.octets()), EPFlags::IPV6),
        };
        let flags = flags | self.options.flags;
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

    fn allocate_group(&self, ginfo: &GroupInfo) -> Result<u16, anyhow::Error> {
        let mut map = Self::group_meta()?;
        let max_id = map.keys().filter_map(|x| x.ok()).max().unwrap_or_default();
        let mut id = max_id + 1;
        while id != max_id {
            if let Ok(_) = map.insert(id, ginfo, MUFlags::NOEXIST.bits()) {
                return Ok(id as u16);
            }
            id = (id + 1) % (u16::MAX as u64 + 1);
        }

        Err(anyhow!(
            "Failed to allocate backend group, try reload application!"
        ))
    }

    fn free_group(&self, gid: u16) -> Result<(), anyhow::Error> {
        let mut map = Self::group_meta()?;
        map.remove(&(gid as u64)).context("Remove group meta")?;
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

    pub fn add(&self, ep: &EndPoint) -> Result<u16, anyhow::Error> {
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

        beg.flags = match ginfo.key {
            EPX::V4(_) => EPFlags::IPV4,
            EPX::V6(_) => EPFlags::IPV6,
        } | ep.options.flags;
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
                EpOptions::new(g.flags).to_string(),
                g.becount.to_string(),
            ])
        };

        Self::iterate_all(search)?;

        table.sort_by_key(0, Some(&|s: &String| stou64(&s, 10)));
        table.print("Backend groups");

        table.reset();
        Ok(())
    }

    pub fn remove(&self, gid: u16) -> Result<(), anyhow::Error> {
        match Backend::new(gid).clear() {
            Ok(v) => info!("[{}/{}] Removed backends: {}", self.ifname, gid, v.len()),
            Err(e) => error!("[{}/{}] Error on freeing backends,{}", self.ifname, gid, e),
        };

        self.remove_all_by_id::<EP4>(gid)?;
        self.remove_all_by_id::<EP6>(gid)?;

        if let Err(e) = self.free_group(gid) {
            error!("[{}/{}] Error on info freeing,{}", self.ifname, gid, e);
        }

        Ok(())
    }

    fn remove_all_by_id<K>(&self, gid: u16) -> Result<(), anyhow::Error>
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
    pub gid: u16,
}

struct GroupMap {
    group: Group,
    info: GroupInfo,
}

impl GroupMap {
    fn new(gid: u16) -> Result<GroupMap, anyhow::Error> {
        let meta = Group::group_meta()?;
        let info = meta.get(&(gid as u64), 0).context("No group in metadata")?;
        // TODO: need ifname?
        let ifname = if_index_to_name(info.ifindex).ok_or(anyhow!("Can't get netdev name"))?;
        let group = Group::new(&ifname)?;
        Ok(Self { group, info })
    }

    fn check_compat(&self, ep: &EndPoint) -> Result<(), anyhow::Error> {
        let (flags, epx) = match self.info.key {
            EPX::V4(ep4) => (EPFlags::IPV4, ep4.as_endpoint()),
            EPX::V6(ep6) => (EPFlags::IPV6, ep6.as_endpoint()),
        };
        match ep.ipaddr {
            IpAddr::V4(_) => {
                if !flags.contains(EPFlags::IPV4) {
                    return Err(anyhow!(
                        "Incompatible IPv4 backend {} with target IPv6 group {}",
                        ep,
                        epx
                    ));
                }
            }
            IpAddr::V6(_) => {
                if !flags.contains(EPFlags::IPV6) {
                    return Err(anyhow!(
                        "Incompatible IPv6 backend {} with target IPv4 group {}",
                        ep,
                        epx,
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
    pub fn new(gid: u16) -> Self {
        Self { gid }
    }

    pub fn backends() -> Result<HashMap<MapData, BEKey, BE>, anyhow::Error> {
        let map = mapdata_from_pinned_map("", BE::map_name()).context("Get pinned backends map")?;
        let map = Map::HashMap(map);
        map.try_into().context("Diff data size for backends map")
    }

    pub fn add(&self, ep: &EndPoint) -> Result<Group, anyhow::Error> {
        let mut backends = Self::backends()?;
        let gmap = GroupMap::new(self.gid)?;

        gmap.check_compat(ep)?;

        // TODO: enforce constraints:
        // TODO: run bfs to check for cycles

        let mut beg = gmap.begroup()?;
        let index = beg.becount;
        let iflags = MUFlags::EXIST;

        let be = ep.as_backend(self.gid);
        let key = BEKey {
            gid: beg.gid as u16,
            index,
        };
        backends
            .insert(key, be, MUFlags::ANY.bits())
            .context("Insert backend")?;

        beg.becount += 1;

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

    fn build_backend_list(gid: u16, becount: u16) -> Result<InfoTable, anyhow::Error> {
        let mut table = InfoTable::new(vec!["id", "endpoint", "options"]);
        let backends = Self::backends()?;

        for index in 0..becount {
            let key = BEKey { gid, index };
            match backends.get(&key, 0) {
                Ok(be) => {
                    let ep = be.as_endpoint();
                    table.push_row(vec![
                        index.to_string(),
                        ep.to_string(),
                        ep.options.to_string(),
                    ]);
                }
                _ => {}
            }
        }

        Ok(table)
    }

    fn list_all() -> Result<(), anyhow::Error> {
        let mut table =
            InfoTable::new(vec!["gid:id", "if / lb_endpoint", "", "backend", "options"]);
        let backends = Self::backends()?;
        let mut cache: StdHashMap<u16, String> = StdHashMap::new();

        Group::iterate_all(|ep, group| {
            if group.becount > 0 {
                let out = format!("{} / {}", if_name_or_default(group.ifindex), ep);
                cache.insert(group.gid, out);
            }
        })?;

        for (key, be) in backends.iter().filter_map(|x| x.ok()) {
            let ep_str = cache.get(&key.gid).map_or("n/a", |v| v.as_str());
            let bep = be.as_endpoint();
            table.push_row(vec![
                format!("{}:{}", key.gid, key.index),
                ep_str.to_string(),
                "<->".to_string(),
                bep.to_string(),
                bep.options.to_string(),
            ]);
        }

        let extract_key = |ids: &String| -> u64 {
            match ids.split_once(':') {
                Some((gid, id)) => stou64(&gid, 10).shl(16) + stou64(&id, 10),
                None => 0_u64,
            }
        };
        table.sort_by_key(0, Some(extract_key));
        table.print("Backends list:");
        Ok(())
    }

    pub fn list(gid: u16) -> Result<(), anyhow::Error> {
        if gid == 0 {
            return Self::list_all();
        }

        let mut table = InfoTable::new(vec!["gid", "endpoint", "netdev", "flags", "be_count"]);
        let gmap = GroupMap::new(gid)?;
        let beg = gmap.begroup()?;
        let bt = Self::build_backend_list(gid as u16, beg.becount)?;

        table.push_row(vec![
            gid.to_string(),
            gmap.info.key.as_endpoint().to_string(),
            if_name_or_default(beg.ifindex),
            EpOptions::new(beg.flags).to_string(),
            beg.becount.to_string(),
        ]);
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
        let gmap = GroupMap::new(self.gid)?;
        let mut begroup = gmap.begroup()?;
        let mut rem_index = index;
        let iflags = MUFlags::EXIST;
        let mut count = begroup.becount;

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

        Ok(rem_index)
    }

    pub fn remove(&self, index: u16) -> Result<BE, anyhow::Error> {
        let mut backends = Self::backends()?;
        let key = BEKey {
            gid: self.gid as u16,
            index,
        };
        let be = backends.get(&key, 0).context(format!(
            "Remove: can't find backend: {} : {}",
            self.gid, index
        ))?;
        let rem_index = self.remove_from_group(index)?;
        let key = BEKey {
            gid: self.gid as u16,
            index: rem_index,
        };
        backends.remove(&key).context("Failed to remove backend")?;

        Ok(be)
    }

    pub fn clear(&self) -> Result<Vec<BE>, anyhow::Error> {
        let backends = Self::backends()?;
        let mut rem_eps = Vec::new();

        for (_, _) in backends
            .iter()
            .filter_map(|x| x.ok())
            .filter(|(k, _)| self.gid == k.gid)
        {
            match self.remove(0) {
                Ok(be) => rem_eps.push(be),
                Err(_) => {}
            }
        }

        Ok(rem_eps)
    }

    pub fn clear_stray() -> Result<Vec<BE>, anyhow::Error> {
        let mut group_ids = BTreeSet::new();
        let mut group_no_be = BTreeSet::new();
        Group::iterate_all(|_, beg| {
            group_ids.insert(beg.gid);
            if beg.becount == 0 {
                group_no_be.insert(beg.gid);
            }
        })?;
        let mut backends = Self::backends()?;
        let mut rb = BTreeMap::<BEKey, BE>::new();
        for (key, be) in backends
            .iter()
            .filter_map(|x| x.ok())
            .filter(|(k, _)| !group_ids.contains(&k.gid) || group_no_be.contains(&k.gid))
        {
            rb.insert(key, be);
        }

        let mut rem_eps = Vec::<BE>::new();
        for (key, be) in rb {
            match backends.remove(&key) {
                Ok(()) => rem_eps.push(be),
                Err(e) => error!(
                    "can't delete {}:{} => {}, {}",
                    key.gid,
                    key.index,
                    be.as_endpoint(),
                    e
                ),
            }
        }

        Ok(rem_eps)
    }
}

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    teardown_maps(&[
        GroupInfo::map_name(),
        EP4::map_name(),
        EP6::map_name(),
        BE::map_name(),
    ])
}
