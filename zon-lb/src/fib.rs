use crate::{
    helpers::{
        hashmap_mapdata, hashmap_remove_if, if_index_to_name, teardown_maps, ComboHwAddr, IfCache,
        PrintTimeStatus,
    },
    info::InfoTable,
    options::{self, Options},
    ToMapName,
};
use std::net::{Ipv4Addr, Ipv6Addr};
use zon_lb_common::{EPFlags, Fib4Key, Fib6Key, FibEntry, Inet6U};

impl ToMapName for Fib4Key {
    fn map_name() -> &'static str {
        "ZLB_FIB4"
    }
}

impl ToMapName for Fib6Key {
    fn map_name() -> &'static str {
        "ZLB_FIB6"
    }
}

pub fn list(filter_opts: &Vec<String>) -> Result<(), anyhow::Error> {
    let mut ifc = IfCache::new("(na)");
    let mut tab = InfoTable::new(vec![
        "dst", "src", "mac dst", "", "mac src", "if", "mtu", "expiry",
    ]);
    let options = Options::from_option_args_with_keys(
        filter_opts,
        &vec![options::FLAG_ALL, options::FLAG_IPV4, options::FLAG_IPV6],
    );
    let mut hidden = 0;
    let pts = PrintTimeStatus::new(0);

    if options.flags.contains(EPFlags::IPV4) || !options.flags.contains(EPFlags::IPV6) {
        let arp = hashmap_mapdata::<Fib4Key, FibEntry>()?;
        for (key, value) in arp.iter().filter_map(|f| f.ok()) {
            let name = ifc.name(value.ifindex);
            if !options.props.contains_key(options::FLAG_ALL) && name.contains("(na)") {
                hidden += 1;
                continue;
            }
            let cwa = ComboHwAddr::new(&value.macs);
            tab.push_row(vec![
                Ipv4Addr::from(key.addr.to_be()).to_string(),
                Ipv4Addr::from(value.ip_src[0].to_be()).to_string(),
                cwa.first_string(),
                String::from("<"),
                cwa.second_string(),
                name,
                value.mtu.to_string(),
                pts.status(value.expiry),
            ]);
        }
    }

    if options.flags.contains(EPFlags::IPV6) || !options.flags.contains(EPFlags::IPV4) {
        let nd = hashmap_mapdata::<Fib6Key, FibEntry>()?;
        for (key, value) in nd.iter().filter_map(|f| f.ok()) {
            let name = ifc.name(value.ifindex);
            if !options.props.contains_key(options::FLAG_ALL) && name.contains("(na)") {
                hidden += 1;
                continue;
            }
            let cwa = ComboHwAddr::new(&value.macs);
            let dst = Ipv6Addr::from(unsafe { Inet6U::from(&key.addr32).addr8 });
            let src = Ipv6Addr::from(unsafe { Inet6U::from(&value.ip_src).addr8 });
            tab.push_row(vec![
                dst.to_string(),
                src.to_string(),
                cwa.first_string(),
                String::from("<"),
                cwa.second_string(),
                name,
                value.mtu.to_string(),
                pts.status(value.expiry),
            ]);
        }
    }

    tab.print(&format!(
        "Fib cache (hidden: {}, filter: {})",
        hidden,
        options.to_options().join(", ")
    ));

    Ok(())
}

pub fn teardown_all_maps() -> Result<(), anyhow::Error> {
    teardown_maps(&[Fib4Key::map_name(), Fib6Key::map_name()])
}

pub fn remove(filter_opts: &Vec<String>) -> Result<(), anyhow::Error> {
    let rem_all = Options::from_option_args_with_keys(filter_opts, &vec![options::FLAG_ALL])
        .props
        .contains_key(options::FLAG_ALL);
    let result = hashmap_remove_if::<Fib4Key, FibEntry, _>(|_, e| {
        rem_all || if_index_to_name(e.ifindex).is_none()
    })?;
    log::info!(
        "remove ipv4 fib entries, count/errors: {}/{}",
        result.count,
        result.errors
    );

    let result = hashmap_remove_if::<Fib6Key, FibEntry, _>(|_, e| {
        rem_all || if_index_to_name(e.ifindex).is_none()
    })?;
    log::info!(
        "remove ipv6 fib entries, count/errors: {}/{}",
        result.count,
        result.errors
    );

    Ok(())
}
