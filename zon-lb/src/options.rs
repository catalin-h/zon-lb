use crate::helpers;
use std::{collections::BTreeMap, fmt, net::IpAddr};
use zon_lb_common::EPFlags;

pub const DISABLE: &str = "disable";
pub const REDIRECT: &str = "redirect";
pub const TX: &str = "tx";
pub const NO_NAT: &str = "no_nat";
pub const SRC_IP: &str = "src_ip";
pub const REPLACE: &str = "replace";
pub const LOG_FILTER: &str = "log_filter";

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
                _ => continue,
            };
            opt.push(name.to_string());
        }
        for (k, v) in &self.props {
            opt.push(format!("{}={}", k, v));
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
        let mut props = BTreeMap::new();
        let mut flags = EPFlags::empty();

        for arg in args {
            let kv = arg.split_once('=');
            let (key, value) = match kv {
                None => {
                    match arg.as_str() {
                        DISABLE => flags.insert(EPFlags::DISABLE),
                        TX => flags.insert(EPFlags::XDP_TX),
                        NO_NAT | "no_conntrack" | "no_ct" => flags.insert(EPFlags::NO_CONNTRACK),
                        REDIRECT => flags.insert(EPFlags::XDP_REDIRECT),
                        REPLACE => {
                            props.insert(arg.to_string(), String::new());
                        }
                        _ => log::error!("Unknown flag '{}' ", arg),
                    }
                    continue;
                }
                Some(kv) => kv,
            };
            match key {
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
                _ => log::error!("Unknown key '{}' in option '{}'", key, arg),
            };
        }
        Self { props, flags }
    }
}
