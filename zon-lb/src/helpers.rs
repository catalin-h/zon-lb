use anyhow::{anyhow, Context, Result};
use aya::maps::MapInfo;
use aya::{maps::MapData, Ebpf};
use aya_obj::generated::{bpf_link_type, BPF_ANY, BPF_EXIST, BPF_F_LOCK, BPF_NOEXIST};
use bitflags;
use log::{info, warn};
use std::fs::remove_file;
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
