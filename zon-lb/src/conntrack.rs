use crate::{
    backends::EndPoint,
    helpers::{hashmap_mapdata, teardown_maps, IfCache},
    info::InfoTable,
    protocols::Protocol,
    ToMapName,
};
use log::info;
use std::net::IpAddr;
use zon_lb_common::{NAT4Key, NAT4Value, NAT6Key, NAT6Value};

impl ToMapName for NAT4Key {
    fn map_name() -> &'static str {
        "ZLB_CONNTRACK4"
    }
}

impl ToMapName for NAT6Key {
    fn map_name() -> &'static str {
        "ZLB_CONNTRACK6"
    }
}

pub fn conntrack_list(_gid: u32) -> Result<(), anyhow::Error> {
    let ctm4 = hashmap_mapdata::<NAT4Key, NAT4Value>()?;
    let mut ifc = IfCache::new();
    let mut tab = InfoTable::new(vec!["proto", "src", "lb", "backend", "if", "vlan"]);

    for (key, value) in ctm4.iter().filter_map(|f| f.ok()) {
        let src = EndPoint {
            ipaddr: IpAddr::from(value.ip_src.to_le_bytes()),
            port: u16::from_be(key.port_lb_dst),
            proto: Protocol::None,
            ..Default::default()
        };
        let lb = EndPoint {
            ipaddr: IpAddr::from(key.ip_lb_dst.to_le_bytes()),
            port: u16::from_be(value.port_lb as u16),
            proto: Protocol::None,
            ..Default::default()
        };
        let be = EndPoint {
            ipaddr: IpAddr::from(key.ip_be_src.to_le_bytes()),
            port: u16::from_be(key.port_be_src),
            proto: Protocol::None,
            ..Default::default()
        };
        tab.push_row(vec![
            format!("{:?}", Protocol::from(key.proto as u8)),
            src.to_string(),
            lb.to_string(),
            be.to_string(),
            format!("{}:{}", ifc.name(value.ifindex, "na"), value.ifindex),
            format!("{:x}", value.vlan_hdr.to_be() & 0xFFF),
        ]);
    }

    let ctm6 = hashmap_mapdata::<NAT6Key, NAT6Value>()?;

    for (key, value) in ctm6.iter().filter_map(|f| f.ok()) {
        let src = EndPoint {
            ipaddr: IpAddr::from(unsafe { value.ip_src.addr8 }),
            port: u16::from_be(key.port_lb_dst as u16) as u16,
            proto: Protocol::None,
            ..Default::default()
        };
        let lb = EndPoint {
            ipaddr: IpAddr::from(unsafe { key.ip_lb_dst.addr8 }),
            port: u16::from_be(value.port_lb as u16),
            proto: Protocol::None,
            ..Default::default()
        };
        let be = EndPoint {
            ipaddr: IpAddr::from(unsafe { key.ip_be_src.addr8 }),
            port: u16::from_be(key.port_be_src as u16),
            proto: Protocol::None,
            ..Default::default()
        };
        tab.push_row(vec![
            format!("{:?}", Protocol::from(key.next_hdr as u8)),
            src.to_string(),
            lb.to_string(),
            be.to_string(),
            format!("{}:{}", ifc.name(value.ifindex, "na"), value.ifindex),
            format!("{:x}", value.vlan_hdr.to_be() & 0xFFF),
        ]);
    }

    tab.print("Connection tracking");
    Ok(())
}

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    teardown_maps(&[NAT4Key::map_name(), NAT6Key::map_name()])
}

pub fn remove_all() -> Result<(), anyhow::Error> {
    let mut ctm = hashmap_mapdata::<NAT4Key, NAT4Value>()?;
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
