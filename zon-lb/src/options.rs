use crate::helpers::{self, ifindex, mac_to_str, parse_unicast_mac};
use anyhow::anyhow;
use std::{collections::BTreeMap, fmt, net::IpAddr, str::FromStr};
use zon_lb_common::EPFlags;

pub const DISABLE: &str = "disable";
pub const REDIRECT: &str = "redirect";
pub const TX: &str = "tx";
pub const NO_NAT: &str = "no_nat";
pub const SRC_IP: &str = "src_ip";
pub const REPLACE: &str = "replace";
pub const LOG_FILTER: &str = "log_filter";
pub const FLAG_ALL: &str = "all";
pub const FLAG_IPV4: &str = "ipv4";
pub const FLAG_IPV6: &str = "ipv6";
pub const MAC_ADDR: &str = "mac";
pub const IF_MAC_ADDR: &str = "if_mac";
pub const IF_NAME: &str = "if";
pub const IF_INDEX: &str = "ifidx";
pub const VLAN: &str = "vlan";

#[derive(Clone)]
pub struct Options {
    pub props: BTreeMap<String, String>,
    pub flags: EPFlags,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            props: BTreeMap::default(),
            flags: EPFlags::default(),
        }
    }
}

impl fmt::Display for Options {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for opt in self.to_options() {
            write!(f, "{} ", opt)?
        }
        Ok(())
    }
}

impl Options {
    pub fn to_options(&self) -> Vec<String> {
        let mut opt = vec![];
        for flag in self.flags {
            let name = match flag {
                EPFlags::DISABLE => DISABLE,
                EPFlags::XDP_TX => TX,
                EPFlags::XDP_REDIRECT => REDIRECT,
                EPFlags::NO_CONNTRACK => NO_NAT,
                EPFlags::IPV4 => FLAG_IPV4,
                EPFlags::IPV6 => FLAG_IPV6,
                _ => continue,
            };
            opt.push(name.to_string());
        }
        for (k, v) in &self.props {
            if v.is_empty() {
                opt.push(k.clone());
            } else {
                opt.push(format!("{}={}", k, v));
            }
        }
        opt
    }

    pub fn new(flags: EPFlags) -> Self {
        Self {
            props: BTreeMap::new(),
            flags,
        }
    }

    pub fn from_option_args(args: &Vec<String>) -> Self {
        Self::from_option_args_with_keys(args, &vec![])
    }

    pub fn from_option_args_with_keys(args: &Vec<String>, allowed_keys: &[&str]) -> Self {
        let mut props = BTreeMap::new();
        let mut flags = EPFlags::empty();

        for arg in args {
            let kv = arg.split_once('=');
            let (key, value) = match kv {
                None => {
                    let f = arg.to_lowercase();
                    if !allowed_keys.is_empty() && !allowed_keys.contains(&f.as_str()) {
                        log::warn!("Unknown flag '{}' for current context", arg);
                        continue;
                    }
                    match f.as_str() {
                        DISABLE => flags.insert(EPFlags::DISABLE),
                        TX => flags.insert(EPFlags::XDP_TX),
                        NO_NAT | "no_conntrack" | "no_ct" => flags.insert(EPFlags::NO_CONNTRACK),
                        REDIRECT => flags.insert(EPFlags::XDP_REDIRECT),
                        FLAG_IPV4 => flags.insert(EPFlags::IPV4),
                        FLAG_IPV6 => flags.insert(EPFlags::IPV6),
                        // Flags not used by EPFlags but allowed for some commands
                        REPLACE | FLAG_ALL => {
                            props.insert(arg.to_string(), String::new());
                        }
                        _ => log::error!("Unknown flag '{}' ", arg),
                    }
                    continue;
                }
                Some(kv) => kv,
            };

            let key = key.to_lowercase();
            if !allowed_keys.is_empty() && !allowed_keys.iter().any(|a| *a == key) {
                log::warn!("Unknown key '{}' for current context", key);
                continue;
            }
            match key.as_str() {
                REDIRECT => match helpers::ifindex(value) {
                    Ok(_) => {
                        flags.insert(EPFlags::XDP_REDIRECT);
                        props.insert(key.to_string(), value.to_string());
                    }
                    Err(_) => {
                        log::error!("No '{}' interface, see option '{}'", value, arg)
                    }
                },
                SRC_IP => match value.parse::<IpAddr>() {
                    Ok(_) => {
                        props.insert(key.to_string(), value.to_string());
                    }
                    Err(e) => log::error!("Invalid src_ip '{}', {}", value, e),
                },
                LOG_FILTER => {
                    props.insert(key.to_string(), value.to_string());
                }
                MAC_ADDR | IF_MAC_ADDR => match parse_unicast_mac(&value) {
                    Ok(mac) => {
                        log::info!(
                            "Using {} mac: {}",
                            if key == MAC_ADDR { "neighbor" } else { "if" },
                            mac_to_str(&mac)
                        );
                        props.insert(key.to_string(), mac_to_str(&mac));
                    }
                    Err(e) => log::error!("{} parse error, {}", key, e),
                },
                VLAN => match u16::from_str_radix(&value, 10) {
                    Ok(_) => {
                        props.insert(key.to_string(), value.to_string());
                    }
                    Err(e) => log::error!("{} parse error, {}", key, e),
                },
                IF_NAME => match ifindex(value) {
                    Ok(index) => {
                        props.insert(key.to_string(), value.to_string());
                        props.insert(IF_INDEX.to_string(), index.to_string());
                    }
                    Err(e) => log::error!("{} parse error, {}", key, e),
                },
                _ => log::error!("Unknown key '{}' in option '{}'", key, arg),
            };
        }
        Self { props, flags }
    }

    pub fn get_and_parse<V, T>(&self, key: T) -> Result<V, anyhow::Error>
    where
        T: AsRef<str>,
        V: FromStr,
    {
        let value = self.props.get(key.as_ref()).ok_or(anyhow!(""))?;
        value
            .parse::<V>()
            .map_err(|_| anyhow!("{}: parse error '{}'", key.as_ref(), value))
    }

    pub fn get_mac<T: AsRef<str>>(&self, key: T) -> Result<[u8; 6], anyhow::Error> {
        let mac: String = self.get_and_parse(key)?;
        parse_unicast_mac(mac)
    }

    pub fn get_u32<T: AsRef<str>>(&self, key: T) -> Result<u32, anyhow::Error> {
        let num: u32 = self.get_and_parse(key)?;
        Ok(num)
    }

    pub fn props_empty(&self) -> bool {
        self.props.is_empty()
    }
}
