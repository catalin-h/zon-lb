use crate::{
    backends::EndPoint,
    helpers::{mapdata_from_pinned_map, teardown_maps},
    info::InfoTable,
    protocols::Protocol,
    ToMapName,
};
use anyhow::anyhow;
use aya::maps::{HashMap, Map, MapData};
use log::info;
use std::net::IpAddr;
use zon_lb_common::NAT4Key;

impl ToMapName for NAT4Key {
    fn map_name() -> &'static str {
        "ZLB_CONNTRACK4"
    }
}

fn conntrack_mapdata<K, V>() -> Result<HashMap<MapData, K, V>, anyhow::Error>
where
    K: aya::Pod + ToMapName,
    V: aya::Pod,
{
    let map = mapdata_from_pinned_map("", K::map_name())
        .ok_or(anyhow!("Failed to find map: {} in bpffs", K::map_name()))?;
    let map = Map::HashMap(map);
    let map: HashMap<_, K, V> = map.try_into()?;
    Ok(map)
}

pub fn conntrack_list(_gid: u32) -> Result<(), anyhow::Error> {
    let ctm = conntrack_mapdata::<NAT4Key, u32>()?;
    let mut tab = InfoTable::new(vec!["proto", "src", "lb", "backend"]);
    for (key, ip_src) in ctm.iter().filter_map(|f| f.ok()) {
        let src = EndPoint {
            ipaddr: IpAddr::from(ip_src.to_le_bytes()),
            port: u16::from_be(key.port_lb_dst),
            proto: Protocol::None,
        };
        let lb = EndPoint {
            ipaddr: IpAddr::from(key.ip_lb_dst.to_le_bytes()),
            port: u16::from_be(key.port_lb_dst),
            proto: Protocol::None,
        };
        let be = EndPoint {
            ipaddr: IpAddr::from(key.ip_be_src.to_le_bytes()),
            port: u16::from_be(key.port_be_src),
            proto: Protocol::None,
        };
        tab.push_row(vec![
            format!("{:?}", Protocol::from(key.proto as u8)),
            src.to_string(),
            lb.to_string(),
            be.to_string(),
        ]);
    }

    tab.print("Connection tracking and NAT IPv4 table");
    Ok(())
}

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    teardown_maps(&[NAT4Key::map_name()])
}

pub fn remove_all() -> Result<(), anyhow::Error> {
    let mut ctm = conntrack_mapdata::<NAT4Key, u32>()?;
    let mut error_no = 0;
    let mut count = 0;
    loop {
        let keys = ctm
            .keys()
            .filter_map(|k| k.ok())
            .take(10)
            .collect::<Vec<_>>();
        if keys.is_empty() {
            break;
        }
        for key in keys {
            match ctm.remove(&key) {
                Ok(()) => count += 1,
                Err(_) => error_no += 1,
            };
        }
    }

    info!("[ct] Remove summary, count/errors: {}/{}", count, error_no);

    Ok(())
}
