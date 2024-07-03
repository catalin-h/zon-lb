use crate::{
    helpers::{hashmap_mapdata, hashmap_remove_if, mac_to_str, teardown_maps, IfCache},
    info::InfoTable,
    options::{self, Options},
    ToMapName,
};
use std::net::{Ipv4Addr, Ipv6Addr};
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
    let mut ifc = IfCache::new();
    let mut tab = InfoTable::new(vec!["ip", "mac", "if", "if_mac", "vlan", "expiry"]);
    let options = Options::from_option_args_with_keys(
        filter_opts,
        &vec![options::FLAG_ALL, options::FLAG_IPV4, options::FLAG_IPV6],
    );
    let mut hidden = 0;
    if options.flags.contains(EPFlags::IPV4) || !options.flags.contains(EPFlags::IPV6) {
        let arp = hashmap_mapdata::<ArpKey, ArpEntry>()?;
        for (key, value) in arp.iter().filter_map(|f| f.ok()) {
            let name = ifc.name(value.ifindex, "(na)");
            if !options.props.contains_key(options::FLAG_ALL) && name.contains("(na)") {
                hidden += 1;
                continue;
            }
            tab.push_row(vec![
                Ipv4Addr::from(key.addr.to_be()).to_string(),
                mac_to_str(&value.mac),
                format!("{}:{}", name, value.ifindex),
                mac_to_str(&value.if_mac),
                format!("{:x}", value.vlan_id.to_be() & 0xFFF),
                value.expiry.to_string(),
            ]);
        }
    }

    if options.flags.contains(EPFlags::IPV6) || !options.flags.contains(EPFlags::IPV4) {
        let nd = hashmap_mapdata::<NDKey, ArpEntry>()?;
        for (key, value) in nd.iter().filter_map(|f| f.ok()) {
            let name = ifc.name(value.ifindex, "(na)");
            if !options.props.contains_key(options::FLAG_ALL) && name.contains("(na)") {
                hidden += 1;
                continue;
            }
            tab.push_row(vec![
                Ipv6Addr::from(unsafe { Inet6U::from(&key.addr32).addr8 }).to_string(),
                mac_to_str(&value.mac),
                format!("{}:{}", ifc.name(value.ifindex, "na"), value.ifindex),
                mac_to_str(&value.if_mac),
                format!("{:x}", value.vlan_id.to_be() & 0xFFF),
                value.expiry.to_string(),
            ]);
        }
    }

    tab.print(&format!("Neighbors cache ({} hidden)", hidden));

    Ok(())
}

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    teardown_maps(&[ArpKey::map_name(), NDKey::map_name()])
}

pub fn remove_all() -> Result<(), anyhow::Error> {
    let result = hashmap_remove_if::<ArpKey, ArpEntry, _>(|_, _| true)?;
    log::info!(
        "[nd] remove arp (ipv4) summary, count/errors: {}/{}",
        result.count,
        result.errors
    );

    let result = hashmap_remove_if::<NDKey, ArpEntry, _>(|_, _| true)?;
    log::info!(
        "[nd] remove ND (ipv6) summary, count/errors: {}/{}",
        result.count,
        result.errors
    );

    Ok(())
}
