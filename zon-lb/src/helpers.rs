use anyhow::{anyhow, Context, Result};
use aya::{maps::MapData, Bpf};
use aya_obj::generated::{BPF_ANY, BPF_EXIST, BPF_F_LOCK, BPF_NOEXIST};
use bitflags;
use log::{info, warn};
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
//  program: zlb_<ifname>
//  prog maps: zlb_<ifname>_<map-name>
//  common maps: zlbx_<lowcase_name>
//
pub(crate) fn pinned_link_name(ifname: &str, map_name: &str) -> Option<String> {
    if map_name.is_empty() {
        Some(format!("zlb_{}", ifname))
    } else if map_name.starts_with("ZLBX") {
        Some(map_name.to_ascii_lowercase())
    } else if !ifname.is_empty() && map_name.starts_with("ZLB") && map_name.len() >= 5 {
        let mut name = map_name.to_ascii_lowercase();
        if map_name.starts_with("ZLB_") {
            name.insert(3, '_');
        } else {
            name.insert_str(3, "__");
        }
        name.insert_str(4, ifname);
        Some(name)
    } else {
        None
    }
}

pub(crate) fn pinned_link_bpffs_path(ifname: &str, map_name: &str) -> Option<PathBuf> {
    pinned_link_name(ifname, map_name).map(|pname| Path::new("/sys/fs/bpf").join(pname))
}

pub(crate) fn mapdata_from_pinned_map(ifname: &str, map_name: &str) -> Option<MapData> {
    pinned_link_bpffs_path(ifname, map_name).map_or(None, |path| match MapData::from_pin(&path) {
        Err(_) => None,
        Ok(m) => Some(m),
    })
}

pub(crate) fn _teardown_maps(prefix: &str) -> Result<(), anyhow::Error> {
    let iter = std::fs::read_dir("/sys/fs/bpf/").context("Failed to iterate bpffs")?;

    for path in iter
        .into_iter()
        .filter_map(|entry| entry.map_or(None, |p| Some(p.path())))
        .filter_map(|path| if path.is_file() { Some(path) } else { None })
        .filter_map(|path| {
            if path
                .file_name()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                .starts_with(prefix)
            {
                Some(path)
            } else {
                None
            }
        })
    {
        match std::fs::remove_file(&path) {
            Ok(_) => {
                info!(
                    "Pinned link removed: {}",
                    &path.to_str().unwrap_or_default()
                );
            }
            Err(e) => {
                warn!(
                    "Failed to remove pinned link: {}, e: {}",
                    &path.to_str().unwrap_or_default(),
                    e.to_string()
                );
            }
        };
    }

    Ok(())
}

pub(crate) fn _create_pinned_links_for_maps(
    bpf: &mut Bpf,
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
pub fn ifindex(ifname: &str) -> Result<u32, anyhow::Error> {
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
    // Check if name exists
    ifindex(ifname)?;

    // Default location for bpffs
    let zdpath = pinned_link_bpffs_path(ifname, "").unwrap();

    let zlblink_exists = zdpath
        .try_exists()
        .context("Can't verify if zon-lb bpffs exists")?;

    Ok((zdpath, zlblink_exists))
}

pub fn stou64(number: &str, base: u32) -> u64 {
    u64::from_str_radix(number, base).unwrap_or_default()
}
