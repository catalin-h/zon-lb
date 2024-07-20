use crate::ToMapName;
use anyhow::{anyhow, Context, Result};
use aya::maps::MapInfo;
use aya::{maps::HashMap as AyaHashMap, maps::Map, maps::MapData, Ebpf};
use aya_obj::generated::{bpf_link_type, BPF_ANY, BPF_EXIST, BPF_F_LOCK, BPF_NOEXIST};
use bitflags;
use libc::{clock_gettime, sockaddr_in, sockaddr_in6, sockaddr_ll, timespec, CLOCK_MONOTONIC};
use log::{info, warn};
use std::collections::HashMap;
use std::fs::remove_file;
use std::net::IpAddr;
use std::ops::BitAnd;
use std::path::{Path, PathBuf};

bitflags::bitflags! {
/// Flags for BPF_MAP_UPDATE_ELEM command
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfMapUpdateFlags: u64 {
/// 0, create new element or update existing
const ANY = BPF_ANY as u64;
/// 1, create new element if it didn't exist
const NOEXIST = BPF_NOEXIST as u64;
/// 2, update existing element
const EXIST = BPF_EXIST as u64;
/// 4, spin_lock-ed map_lookup/map_update
const F_LOCK = BPF_F_LOCK as u64;
}
}

//
// Pinned link naming scheme used by the loading user app
//  program: <bpffs>/zlb_<ifname>
//  prog maps: <bpffs>/ZLB_<map-name>
//  common maps: <bpffs>/ZLBX_<map-name>
//
pub(crate) fn pinned_link_name(ifname: &str, map_name: &str) -> Option<String> {
    if map_name.is_empty() {
        Some(format!("zlb_{}", ifname))
    } else if map_name.starts_with("ZLB") {
        Some(map_name.to_string())
    } else {
        None
    }
}

pub(crate) fn pinned_link_bpffs_path(ifname: &str, map_name: &str) -> Option<PathBuf> {
    pinned_link_name(ifname, map_name).map(|rel_link| Path::new(crate::BPFFS).join(rel_link))
}

// TODO: maybe return result instead of options in order to pass the error
pub(crate) fn mapdata_from_pinned_map(ifname: &str, map_name: &str) -> Option<MapData> {
    pinned_link_bpffs_path(ifname, map_name).map_or(None, |path| match MapData::from_pin(&path) {
        Err(_) => None,
        Ok(m) => Some(m),
    })
}

/// TODO: search and get maps by iterating over the loaded programs and the used maps
pub(crate) fn _mapdata_by_name(_ifname: &str, _map_name: &str) -> Result<MapData, anyhow::Error> {
    Ok(MapData::from_id(0)?)
}

pub(crate) fn _create_pinned_links_for_maps(
    bpf: &mut Ebpf,
    ifname: &str,
) -> Result<(), anyhow::Error> {
    for (name, map) in bpf.maps() {
        if let Some(path) = pinned_link_bpffs_path(ifname, name) {
            let path_str = path.to_str().unwrap_or_default();
            match path.try_exists() {
                Ok(false) => {
                    map.pin(&path)
                        .context("Failed to create pinned link for map")?;
                    info!("Pinned link created for map {} at {}", name, path_str);
                }
                Ok(true) => {
                    info!("Map {} already pinned at {}", name, path_str);
                }
                Err(e) => {
                    warn!(
                        "Failed to check if pinned link exists for map {} at {}, {}",
                        name,
                        path_str,
                        e.to_string()
                    );
                }
            }
        } else {
            info!("Skip non zon-lb map: {}", name);
        }
    }
    Ok(())
}

pub fn hashmap_mapdata<K, V>() -> Result<AyaHashMap<MapData, K, V>, anyhow::Error>
where
    K: aya::Pod + ToMapName,
    V: aya::Pod,
{
    // TODO: maybe return result instead of options in order to pass the error
    let map = mapdata_from_pinned_map("", K::map_name())
        .ok_or(anyhow!("Failed to find map: {} in bpffs", K::map_name()))?;
    let map = Map::HashMap(map);
    let map: AyaHashMap<_, K, V> = map.try_into()?;
    Ok(map)
}

pub struct MapOpResult {
    pub count: u32,
    pub errors: u32,
    pub total: u32,
}

impl MapOpResult {
    fn new() -> Self {
        MapOpResult {
            count: 0,
            errors: 0,
            total: 0,
        }
    }

    pub fn matches_total(&self) -> bool {
        self.errors + self.count >= self.total
    }
}

pub fn hashmap_remove_by_key<K, V>(key: &K) -> Result<(), anyhow::Error>
where
    K: aya::Pod + ToMapName,
    V: aya::Pod,
{
    let mut map = hashmap_mapdata::<K, V>()?;

    map.remove(key).map_err(|e| {
        anyhow!(
            "can't remove key from map {}, {}",
            K::map_name(),
            e.to_string()
        )
    })
}

pub fn hashmap_remove_if<K, V, F>(predicate: F) -> Result<MapOpResult, anyhow::Error>
where
    K: aya::Pod + ToMapName,
    V: aya::Pod,
    F: Fn(&K, &V) -> bool,
{
    let mut map = hashmap_mapdata::<K, V>()?;
    let mut result = MapOpResult::new();

    result.total = map.iter().count() as u32;

    loop {
        let keys = map
            .iter()
            .filter_map(|pair| pair.ok())
            .filter_map(|(k, v)| if predicate(&k, &v) { Some(k) } else { None })
            .take(10)
            .collect::<Vec<_>>();

        if keys.is_empty() || result.matches_total() {
            break;
        }

        for key in keys {
            if result.matches_total() {
                return Ok(result);
            }
            match map.remove(&key) {
                Ok(_) => result.count += 1,
                Err(_) => result.errors += 1,
            }
        }
    }

    Ok(result)
}

pub(crate) fn if_index_to_name(index: u32) -> Option<String> {
    let mut name = [0_i8; libc::IF_NAMESIZE];
    let iname = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };

    if iname.is_null() {
        None
    } else {
        let str = unsafe { std::ffi::CStr::from_ptr(iname) };
        let str = str.to_string_lossy();
        Some(str.to_string())
    }
}

pub(crate) fn if_name_or_default(index: u32) -> String {
    let mut name = [0_i8; libc::IF_NAMESIZE];
    let iname = unsafe { libc::if_indextoname(index, name.as_mut_ptr()) };

    if iname.is_null() {
        format!("if#{}", index)
    } else {
        let str = unsafe { std::ffi::CStr::from_ptr(iname) };
        let str = str.to_string_lossy();
        str.to_string()
    }
}
pub fn ifindex(ifname: &str) -> Result<u32, anyhow::Error> {
    if ifname.starts_with("if#") && ifname.len() > 3 {
        if let Ok(index) = ifname[3..].parse::<u32>() {
            return Ok(index);
        }
    }

    let c_interface = std::ffi::CString::new(ifname)?;
    let if_index = unsafe { libc::if_nametoindex(c_interface.as_ptr()) };
    if if_index == 0 {
        Err(anyhow!("No interface named {}", ifname))
    } else {
        Ok(if_index)
    }
}

pub fn _increase_memlocked() -> Result<(), anyhow::Error> {
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        Err(anyhow!(
            "remove limit on locked memory failed, ret is: {}",
            ret
        ))
    } else {
        Ok(())
    }
}

/// Return the pinned link path for the program attached to the `ifname` interface.

pub fn prog_bpffs(ifname: &str) -> Result<(PathBuf, bool), anyhow::Error> {
    prog_and_map_bpffs(ifname, "")
}

pub fn prog_and_map_bpffs(ifname: &str, map_name: &str) -> Result<(PathBuf, bool), anyhow::Error> {
    // Check if name exists
    ifindex(ifname)?;

    // Default location for bpffs
    let zdpath = pinned_link_bpffs_path(ifname, map_name).unwrap();

    let zlblink_exists = zdpath
        .try_exists()
        .context("Can't verify if zon-lb bpffs exists")?;

    Ok((zdpath, zlblink_exists))
}

pub fn stou64(number: &str, base: u32) -> u64 {
    u64::from_str_radix(number, base).unwrap_or_default()
}

pub struct XdpLinkInfo {
    pub id: u32,
    pub program_id: u32,
    pub ifindex: u32,
}

pub fn get_xdp_link_info(ifname: &str) -> Option<XdpLinkInfo> {
    let ifindex = ifindex(ifname).ok()?;
    for link in aya::programs::loaded_links().filter_map(|link| link.ok()) {
        if link.type_ == bpf_link_type::BPF_LINK_TYPE_XDP as u32
            && unsafe { link.__bindgen_anon_1.xdp.ifindex as u32 } == ifindex
        {
            return Some(XdpLinkInfo {
                id: link.id,
                program_id: link.prog_id,
                ifindex,
            });
        }
    }

    None
}

pub fn teardown_maps(map_list: &[&str]) -> Result<(), anyhow::Error> {
    for map_name in map_list {
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

pub(crate) fn get_mapdata_by_name(ifname: &str, map_name: &str) -> Option<MapData> {
    let program_info = crate::get_program_info_by_ifname(ifname).ok()?;
    let map = program_info
        .map_ids()
        .ok()?
        .iter()
        .filter_map(|id| MapInfo::from_id(*id).ok())
        .find(|map_info| match map_info.name_as_str() {
            Some(name) => name == map_name,
            None => false,
        })?;
    MapData::from_id(map.id()).ok()
}

pub struct IfCache {
    cache: HashMap<u32, String>,
    def_name: String,
}

impl IfCache {
    pub fn new<T: AsRef<str>>(def_name: T) -> Self {
        Self {
            cache: HashMap::new(),
            def_name: String::from(def_name.as_ref()),
        }
    }
    pub fn name(&mut self, ifindex: u32) -> String {
        if let Some(name) = self.cache.get(&ifindex) {
            return name.clone();
        }

        let name = match if_index_to_name(ifindex) {
            None => format!("{}:{}", &self.def_name, ifindex),
            Some(name) => format!("{}:{}", name, ifindex),
        };

        self.cache.insert(ifindex, name.clone());
        name
    }
}

pub fn mac_to_str(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub struct ComboHwAddr<'a> {
    pub combo: &'a [u32; 3],
}

impl<'a> ComboHwAddr<'a> {
    pub fn new(combo: &'a [u32; 3usize]) -> Self {
        Self { combo }
    }

    fn at(&self, index: usize) -> &[u8; 6] {
        let split = self.combo.as_ptr() as *const [u8; 6];
        unsafe { &*split.add(index) }
    }

    pub fn first_string(&self) -> String {
        mac_to_str(self.at(0))
    }

    pub fn second_string(&self) -> String {
        mac_to_str(self.at(1))
    }
}

pub fn get_monotonic_clock_time() -> i64 {
    let mut tp = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let ptp = &mut tp as *mut timespec;

    if 0 != unsafe { clock_gettime(CLOCK_MONOTONIC, ptp) } {
        return 0;
    }

    tp.tv_sec
}

pub struct PrintTimeStatus {
    now: i64,
    expiry_interval: i64,
}

impl PrintTimeStatus {
    pub fn new(expiry_interval: u32) -> Self {
        Self {
            now: get_monotonic_clock_time(),
            expiry_interval: expiry_interval as i64,
        }
    }

    pub fn status(&self, expiry: u32) -> String {
        if self.now == 0 {
            return "unknown".to_string();
        }

        if self.now - expiry as i64 >= self.expiry_interval {
            "stale".to_string()
        } else {
            "active".to_string()
        }
    }
}

pub fn parse_mac<T: AsRef<str>>(input: T) -> Result<[u8; 6], anyhow::Error> {
    let mut mac = [0; 6];
    let bytes: Vec<&str> = input.as_ref().split(":").collect();
    if bytes.len() == 6 {
        for (i, b) in bytes.iter().enumerate() {
            mac[i] = u8::from_str_radix(b, 16)?;
        }
        return Ok(mac);
    }

    let bytes: Vec<&str> = input.as_ref().split("-").collect();
    if bytes.len() == 6 {
        for (i, b) in bytes.iter().enumerate() {
            mac[i] = u8::from_str_radix(b, 16)?;
        }
        return Ok(mac);
    }

    for (i, c) in input.as_ref().char_indices() {
        if i >= 12 {
            return Err(anyhow!(
                "invalid lenth for mac address '{}'",
                input.as_ref()
            ));
        }
        let hexd = c.to_digit(16).ok_or(anyhow!("non hex digit '{}'", c))? as u8;
        mac[i / 2] |= hexd << 4 * (1 - (i & 1));
    }

    Ok(mac)
}

pub fn is_unicast_mac(mac: &[u8; 6]) -> bool {
    *mac != [0_u8; 6] && (mac[0] & 0x1) == 0_u8
}

pub fn parse_unicast_mac<T: AsRef<str>>(input: T) -> Result<[u8; 6], anyhow::Error> {
    let mac = parse_mac(input)?;
    if is_unicast_mac(&mac) {
        return Ok(mac);
    }

    Err(anyhow!("Not a unicast address, {}", mac_to_str(&mac)))
}

fn cstr_to_string(cstr_buff: *const i8) -> String {
    let str = unsafe { std::ffi::CStr::from_ptr(cstr_buff) };
    let str = str.to_string_lossy();
    str.to_string()
}

pub fn str_error(err: i32) -> String {
    let mut buff = [0_i8; 256];
    let rc = unsafe { libc::strerror_r(err, buff.as_mut_ptr(), buff.len()) };

    if rc != 0 {
        format!("errno={}, unknown", err)
    } else {
        cstr_to_string(buff.as_ptr())
    }
}

pub fn str_errno() -> String {
    let errno = unsafe { *libc::__errno_location() };
    str_error(errno)
}

#[derive(Default, Clone)]
pub struct NetIf {
    pub ifindex: u32,
    pub mac: [u8; 6],
    pub ips: Vec<IpAddr>,
}

pub fn get_netifs() -> Result<HashMap<String, NetIf>, anyhow::Error> {
    let mut ifs = HashMap::new();
    let mut ifaddrs: *mut libc::ifaddrs = core::ptr::null_mut();
    let rc = unsafe { libc::getifaddrs(&mut ifaddrs) };

    if rc != 0 {
        return Err(anyhow!("failed to get net interfaces, {}", str_errno()));
    }

    let mut next_ifa = ifaddrs;

    // TODO add:
    // 1. MTU: use iotcl(SIOCGIFMTU) or read /sys/class/net/veth0/mtu
    // 2. state: read /sys/class/net/veth0/operstate or read iotcl SIOCSIFFLAGS/IFF_UP
    // see: https://www.kernel.org/doc/Documentation/ABI/testing/sysfs-class-net

    loop {
        if next_ifa.is_null() {
            break;
        }

        let ifa = unsafe { (*next_ifa).ifa_addr };

        if ifa.is_null() {
            next_ifa = unsafe { (*next_ifa).ifa_next };
            continue;
        }

        let ifname = cstr_to_string(unsafe { (*next_ifa).ifa_name });
        let netif = ifs.entry(ifname).or_insert_with(|| NetIf::default());

        match unsafe { (*ifa).sa_family } as i32 {
            libc::AF_PACKET => {
                let lladdr = ifa as *const sockaddr_ll;
                netif.mac = unsafe { *((*lladdr).sll_addr.as_ptr() as *const [u8; 6]) };
                netif.ifindex = unsafe { (*lladdr).sll_ifindex } as u32;
            }
            libc::AF_INET => {
                let sa = ifa as *const sockaddr_in;
                let addr = unsafe { (*sa).sin_addr.s_addr };
                netif.ips.push(IpAddr::from(addr.to_le_bytes()));
            }
            libc::AF_INET6 => {
                let sa = ifa as *const sockaddr_in6;
                let ip = IpAddr::from(unsafe { (*sa).sin6_addr.s6_addr });
                netif.ips.push(ip);
            }
            _ => {}
        }

        next_ifa = unsafe { (*next_ifa).ifa_next };
    }

    unsafe { libc::freeifaddrs(ifaddrs) };

    Ok(ifs)
}

pub fn netmask_matches(netmask: &IpAddr, ipaddr: &IpAddr) -> bool {
    match netmask {
        IpAddr::V4(mask) => {
            if let IpAddr::V4(addr) = ipaddr {
                mask.bitand(addr).eq(mask)
            } else {
                false
            }
        }
        IpAddr::V6(mask) => {
            if let IpAddr::V6(addr) = ipaddr {
                mask.bitand(addr).eq(mask)
            } else {
                false
            }
        }
    }
}
