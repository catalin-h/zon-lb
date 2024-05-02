use crate::{helpers::*, runvars::RunVars};

use anyhow::anyhow;
use aya::{
    maps::MapInfo,
    programs::{loaded_links, loaded_programs, ProgramInfo},
};
use aya_obj::generated::bpf_prog_type;
use chrono::{DateTime, Local};
use log::warn;
use std::collections::BTreeMap;

pub struct InfoTable {
    header: Vec<String>,
    table: Vec<Vec<String>>,
    align: Vec<usize>,
}

impl InfoTable {
    fn to_sizes(row: &Vec<String>) -> Vec<usize> {
        row.iter().map(|x| x.len()).collect()
    }

    pub fn new<T: AsRef<str>>(hdr: Vec<T>) -> Self {
        let header: Vec<_> = hdr.into_iter().map(|s| String::from(s.as_ref())).collect();
        let align = Self::to_sizes(&header);
        Self {
            header,
            table: vec![],
            align,
        }
    }
    pub fn push_row<T: AsRef<str>>(&mut self, row: Vec<T>) {
        let mut trow = vec![String::from(""); self.align.len()];
        for (i, s) in row.into_iter().enumerate() {
            trow[i] = s.as_ref().to_string();
            self.align[i] = self.align[i].max(trow[i].len());
        }
        self.table.push(trow);
    }

    fn to_aligned_column(&self, row: &Vec<String>) -> String {
        row.iter()
            .enumerate()
            .map(|(i, s)| format!("{0:<1$}", s, self.align[i] + 1))
            .collect()
    }

    pub fn print(&self, description: &str) {
        let hdr = self.to_aligned_column(&self.header);
        println!("{description}\r\n{hdr}");
        println!("{0:-<1$}", '-', hdr.len());
        for row in &self.table {
            println!("{}", self.to_aligned_column(row));
        }
        println!("{0:-<1$}", '-', hdr.len());
    }
    pub fn reset(&mut self) {
        self.table.clear();
        self.align = Self::to_sizes(&self.header);
    }
    pub fn sort(&mut self) {
        self.table.sort();
    }
    pub fn sort_by_key(&mut self, index: usize, extract_key: Option<impl Fn(&String) -> u64>) {
        match extract_key {
            Some(extfun) => self.table.sort_by_cached_key(|v| extfun(&v[index])),
            None => self.table.sort_by(|a, b| a[index].cmp(&b[index])),
        };
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}

struct ZLBInfo {
    prog: ProgramInfo,
    link_id: u32,
    ifindex: u32,
}

fn build_prog_info(ifindex: Option<u32>) -> Result<BTreeMap<u32, ZLBInfo>, anyhow::Error> {
    let mut pmap = BTreeMap::new();

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

    pmap.retain(|_, info| {
        if let Some(index) = ifindex {
            index == info.ifindex
        } else {
            true
        }
    });

    Ok(pmap)
}

pub fn get_program_info_by_ifname(ifname: &str) -> Result<ProgramInfo, anyhow::Error> {
    let ifindex = ifindex(ifname)?;
    let (_, info) = build_prog_info(Some(ifindex))?
        .pop_first()
        .ok_or(anyhow!("No program loaded for interface: {}", ifname))?;
    Ok(info.prog)
}

/// List formatting
pub(crate) fn list_info() -> Result<(), anyhow::Error> {
    let pmap = build_prog_info(None)?;

    if pmap.is_empty() {
        println!("No zon-lb programs loaded");
        return Ok(());
    }

    let header = "Loaded zon-lb programs";
    println!("\r\n{0:-<1$}\r\n{header}\r\n{0:-<1$}", "-", header.len());

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
                match RunVars::new(&name) {
                    Ok(rv) => println!("version: {}", rv.version()),
                    _ => println!("version: n/a"),
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

        let mut tab = InfoTable::new(vec!["name", "id", "type", "max", "flags", "pin"]);
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
            tab.push_row(vec![
                name,
                map.id().to_string(),
                map.map_type().to_string(),
                map.max_entries().to_string(),
                format!("{:x}h", map.map_flags()),
                pin,
            ]);
        }
        tab.sort();
        tab.print(&format!(
            "maps_ids: {}",
            ids.iter()
                .map(|id| id.to_string() + " ")
                .collect::<String>()
        ));
    }

    Ok(())
}
