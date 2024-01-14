use crate::helpers::*;

use anyhow::anyhow;
use aya::{
    maps::{Array, Map, MapData, MapInfo},
    programs::{loaded_links, loaded_programs, ProgramInfo},
};
use aya_obj::generated::bpf_prog_type;
use chrono::{DateTime, Local};
use log::warn;
use std::collections::HashMap as StdHashMap;
use zon_lb_common::ZonInfo;

// TODO: add struct to set/get ZLB_INFO data
pub(crate) fn get_zon_info(ifname: &str) -> Result<Array<MapData, ZonInfo>, anyhow::Error> {
    match mapdata_from_pinned_map(ifname, "ZLB_INFO") {
        Some(map) => {
            let map = Map::Array(map);
            let map: Array<_, ZonInfo> = map.try_into()?;
            Ok(map)
        }
        _ => Err(anyhow!("No ZLB_INFO map")),
    }
}

/// List formatting
pub(crate) fn list_info() -> Result<(), anyhow::Error> {
    struct ZLBInfo {
        prog: ProgramInfo,
        link_id: u32,
        ifindex: u32,
    }
    let mut pmap: StdHashMap<u32, ZLBInfo> = StdHashMap::new();

    let header = "Loaded zon-lb programs";
    println!("\r\n{0:-<1$}\r\n{header}\r\n{0:-<1$}", "-", header.len());

    for p in loaded_programs().filter_map(|p| match p {
        Ok(prog) => {
            if prog.program_type() == bpf_prog_type::BPF_PROG_TYPE_XDP as u32
                && prog
                    .name_as_str()
                    .unwrap_or_default()
                    .eq_ignore_ascii_case(crate::PROG_NAME)
            {
                Some(prog)
            } else {
                None
            }
        }
        Err(e) => {
            warn!("Failed to get program info, {}", e.to_string());
            None
        }
    }) {
        pmap.insert(
            p.id(),
            ZLBInfo {
                prog: p,
                link_id: 0,
                ifindex: 0,
            },
        );
    }

    // NOTE: since the zon-lb programs are attached to interface via links,
    // the if index is from aya_obj::generated::bpf_prog_info is invalid (0).
    // To get the actual attached interface must iterate over all links and match
    // the program id that the link refers.
    for l in loaded_links() {
        match l {
            Ok(link) => {
                if let Some(pinfo) = pmap.get_mut(&(link.prog_id as u32)) {
                    pinfo.link_id = link.id as u32;
                    pinfo.ifindex = unsafe { link.__bindgen_anon_1.xdp.ifindex as u32 };
                }
            }
            Err(e) => {
                warn!("Failed to get link info, {}", e.to_string());
            }
        }
    }

    // NOTE: use if_indextoname to get the interface name from index
    // NOTE: the maps must be used inside the program in order to be
    // present in the program info id list

    for (id, info) in pmap.iter() {
        println!("\r\nprogram_id: {}", id);
        println!("tag: {:>x}", info.prog.tag());
        let dt: DateTime<Local> = info.prog.loaded_at().into();
        println!("loaded_at: {}", dt.format("%H:%M:%S %d-%m-%Y"));
        let ifname = if_index_to_name(info.ifindex);
        match &ifname {
            Some(name) => {
                println!("ifname: {}", name);
                if let Some(pb) = pinned_link_bpffs_path(&name, "") {
                    match pb.try_exists() {
                        Ok(true) => println!("pin: {}", pb.to_string_lossy()),
                        _ => {}
                    }
                }
                match get_zon_info(&name) {
                    Ok(map) => match map.get(&0, 0) {
                        Ok(info) => {
                            println!("version: {}", info.version);
                        }
                        _ => {}
                    },
                    _ => {}
                }
            }
            None => {
                println!("ifindex: {}", info.ifindex);
            }
        }
        if info.link_id != 0 {
            println!("link_id: {}", info.link_id);
        }

        let mut ids = info.prog.map_ids().unwrap_or_default();
        ids.sort();

        println!(
            "maps_ids: {}",
            ids.iter()
                .map(|id| id.to_string() + " ")
                .collect::<String>()
        );

        let mut tab: Vec<Vec<String>> = vec![vec![
            "name".to_string(),
            "id".to_string(),
            "type".to_string(),
            "max".to_string(),
            "flags".to_string(),
            "pin".to_string(),
        ]];
        let mut sizes = tab[0].iter().map(|s| s.len()).collect::<Vec<_>>();
        for (name, map) in ids.iter().filter_map(|&id| {
            MapInfo::from_id(id).map_or(None, |map| match map.name_as_str() {
                Some(name) => Some((name.to_string(), map)),
                _ => None,
            })
        }) {
            let pin = match &ifname {
                Some(iname) => {
                    if let Some(pb) = pinned_link_bpffs_path(iname, &name) {
                        match pb.try_exists() {
                            Ok(true) => pb.to_string_lossy().to_string(),
                            Ok(false) => "n/a".to_string(),
                            Err(e) => e.to_string(),
                        }
                    } else {
                        "n/a".to_string()
                    }
                }
                _ => "err".to_string(),
            };
            let row = vec![
                name,
                map.id().to_string(),
                map.map_type().to_string(),
                map.max_entries().to_string(),
                format!("{:x}h", map.map_flags()),
                pin,
            ];
            for (i, s) in row.iter().enumerate() {
                sizes[i] = sizes[i].max(s.len());
            }
            tab.push(row);
        }

        let mut hdr_len = 0_usize;
        for (i, row) in tab.iter().enumerate() {
            let line = format!(
                "{}",
                sizes
                    .iter()
                    .enumerate()
                    .map(|(i, &size)| format!("{0:<1$}", row[i], size + 1))
                    .collect::<String>()
            );
            println!("{}", line);
            if i == 0 {
                hdr_len = line.len() - sizes[row.len() - 1] + row[row.len() - 1].len() - 1;
                println!("{0:-<1$}", '-', hdr_len);
            } else if i == tab.len() - 1 {
                println!("{0:-<1$}", '-', hdr_len);
            }
        }
    }

    Ok(())
}
