use crate::{
    helpers::{
        hashmap_mapdata, hashmap_remove_if, if_index_to_name, mac_to_str, teardown_maps, IfCache,
        PrintTimeStatus,
    },
    info::InfoTable,
    options::{self, Options},
    ToMapName,
};
use anyhow::anyhow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use zon_lb_common::{ArpEntry, ArpKey, EPFlags, Inet6U, NDKey};

impl ToMapName for ArpKey {
    fn map_name() -> &'static str {
        "ZLB_ARP"
    }
}

impl ToMapName for NDKey {
    fn map_name() -> &'static str {
        "ZLB_ND"
    }
}

pub fn list(filter_opts: &Vec<String>) -> Result<(), anyhow::Error> {
    let mut ifc = IfCache::new("(na)");
    let mut tab = InfoTable::new(vec!["ip", "mac", "if", "if_mac", "vlan", "status"]);
    let options = Options::from_option_args_with_keys(
        filter_opts,
        &vec![options::FLAG_ALL, options::FLAG_IPV4, options::FLAG_IPV6],
    );
    let mut hidden = 0;
    let pts = PrintTimeStatus::new(0);
    if options.flags.contains(EPFlags::IPV4) || !options.flags.contains(EPFlags::IPV6) {
        let arp = hashmap_mapdata::<ArpKey, ArpEntry>()?;
        for (key, value) in arp.iter().filter_map(|f| f.ok()) {
            let name = ifc.name(value.ifindex);
            if !options.props.contains_key(options::FLAG_ALL) && name.contains("(na)") {
                hidden += 1;
                continue;
            }

            tab.push_row(vec![
                Ipv4Addr::from(key.addr.to_be()).to_string(),
                mac_to_str(&value.mac),
                name,
                mac_to_str(&value.if_mac),
                format!("{:x}", value.vlan_id.to_be() & 0xFFF),
                pts.status(value.expiry),
            ]);
        }
    }

    if options.flags.contains(EPFlags::IPV6) || !options.flags.contains(EPFlags::IPV4) {
        let nd = hashmap_mapdata::<NDKey, ArpEntry>()?;
        for (key, value) in nd.iter().filter_map(|f| f.ok()) {
            let name = ifc.name(value.ifindex);
            if !options.props.contains_key(options::FLAG_ALL) && name.contains("(na)") {
                hidden += 1;
                continue;
            }
            tab.push_row(vec![
                Ipv6Addr::from(unsafe { Inet6U::from(&key.addr32).addr8 }).to_string(),
                mac_to_str(&value.mac),
                name,
                mac_to_str(&value.if_mac),
                format!("{:x}", value.vlan_id.to_be() & 0xFFF),
                pts.status(value.expiry),
            ]);
        }
    }

    tab.print(&format!(
        "Neighbors cache (hidden: {}, filter: {})",
        hidden,
        options.to_options().join(", ")
    ));

    Ok(())
}

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    teardown_maps(&[ArpKey::map_name(), NDKey::map_name()])
}

pub fn remove(filter_opts: &Vec<String>) -> Result<(), anyhow::Error> {
    let rem_all = Options::from_option_args_with_keys(filter_opts, &vec![options::FLAG_ALL])
        .props
        .contains_key(options::FLAG_ALL);
    let result = hashmap_remove_if::<ArpKey, ArpEntry, _>(|_, e| {
        rem_all || if_index_to_name(e.ifindex).is_none()
    })?;
    log::info!(
        "remove arp (ipv4) entries, count/errors: {}/{}",
        result.count,
        result.errors
    );

    let result = hashmap_remove_if::<NDKey, ArpEntry, _>(|_, e| {
        rem_all || if_index_to_name(e.ifindex).is_none()
    })?;
    log::info!(
        "remove ND (ipv6) entries, count/errors: {}/{}",
        result.count,
        result.errors
    );

    Ok(())
}

const NEIGH_OPTIONS: [&str; 4] = [
    options::IF_NAME,
    options::IF_MAC_ADDR,
    options::MAC_ADDR,
    options::VLAN,
];

fn fill_neigh_entry(entry: &mut ArpEntry, opts: &Options) -> bool {
    let mut updated = false;

    if let Ok(mac) = opts.get_mac(options::MAC_ADDR) {
        if mac != entry.mac {
            log::info!(
                "[nd] update mac: {} -> {}",
                mac_to_str(&entry.mac),
                mac_to_str(&mac)
            );
            entry.mac = mac;
            updated = true;
        }
    }

    if let Ok(mac) = opts.get_mac(options::IF_MAC_ADDR) {
        if entry.if_mac != mac {
            log::info!(
                "[nd] update if_mac: {} -> {}",
                mac_to_str(&entry.if_mac),
                mac_to_str(&mac)
            );
            entry.if_mac = mac;
            updated = true;
        }
    }

    if let Ok(if_index) = opts.get_u32(options::IF_INDEX) {
        if if_index != entry.ifindex {
            let mut ifc = IfCache::new("na");
            log::info!(
                "[nd] update if: {} -> {}",
                ifc.name(entry.ifindex),
                ifc.name(if_index)
            );
            entry.ifindex = if_index;
            updated = true;
        }
    }

    if let Ok(vlan) = opts.get_u32(options::VLAN) {
        if vlan != entry.vlan_id {
            log::info!("[nd] update vlan id: {} -> {}", entry.vlan_id, vlan);
            entry.vlan_id = vlan;
            updated = true;
        }
    }

    updated
}

fn insert_ipv4(ip: &Ipv4Addr, opts: &Options) -> Result<(), anyhow::Error> {
    let mut arp = hashmap_mapdata::<ArpKey, ArpEntry>()?;
    let key = ArpKey {
        addr: u32::from_le_bytes(ip.octets()),
    };
    let mut entry = match arp.get(&key, 0) {
        Ok(entry) => entry,
        Err(_) => ArpEntry::default(),
    };

    if !fill_neigh_entry(&mut entry, opts) {
        log::info!("[nd] no updates!");
        return Ok(());
    }

    arp.insert(&key, entry, 0).map_err(|e| {
        anyhow!(
            "can't update arp neigh {}, {}",
            ip.to_string(),
            e.to_string()
        )
    })
}

fn insert_ipv6(ip: &Ipv6Addr, opts: &Options) -> Result<(), anyhow::Error> {
    Ok(())
}

/// Launch a TCP connection to trigger ND discovery
pub fn trigger_nd(ip: &str) -> Result<(), anyhow::Error> {
    let ip = ip.parse::<IpAddr>()?;
    Ok(())
}

pub fn insert(ip: &str, in_opts: &Vec<String>) -> Result<(), anyhow::Error> {
    let opts = Options::from_option_args_with_keys(in_opts, &NEIGH_OPTIONS);

    if opts.props_empty() {
        return trigger_nd(&ip);
    }

    let ipaddr = ip.parse::<IpAddr>()?;

    log::info!("[nd] updating {} ...", ipaddr.to_string());
    match ipaddr {
        IpAddr::V4(v4) => insert_ipv4(&v4, &opts),
        IpAddr::V6(v6) => insert_ipv6(&v6, &opts),
    }?;

    Ok(())
}
