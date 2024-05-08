use crate::{helpers::*, options::Options, InfoTable, ToMapName};
use anyhow::anyhow;
use aya::maps::{Array, Map, MapData};
use log::LevelFilter;
use std::str::FromStr;
use zon_lb_common::{runvars, VERSION};

static VAR_NAMES: [&str; runvars::MAX as usize] = ["version", "features", "log_filter"];

pub struct RunVars {
    ifname: String,
    rvmap: Array<MapData, u64>,
}

impl ToMapName for RunVars {
    fn map_name() -> &'static str {
        "ZLB_RUNVAR"
    }
}

impl RunVars {
    pub fn new(ifname: &str) -> Result<Self, anyhow::Error> {
        let map = get_mapdata_by_name(ifname, RunVars::map_name())
            .ok_or(anyhow!("Can't find map {}", RunVars::map_name()))?;
        let map = Map::Array(map);
        let rvmap: Array<_, u64> = map.try_into()?;
        Ok(Self {
            ifname: ifname.to_string(),
            rvmap,
        })
    }

    pub fn set(&mut self, rv_idx: u32, value: u64) -> bool {
        match self.rvmap.set(rv_idx, &value, 0) {
            Ok(()) => true,
            Err(e) => {
                log::error!("Failed to set {} to {}, {}", rv_idx, value, e);
                false
            }
        }
    }

    pub fn set_str(&mut self, rv_idx: u32, value: &str) -> bool {
        match rv_idx {
            runvars::VERSION => false,
            runvars::FEATURES => false,
            runvars::LOG_FILTER => match LevelFilter::from_str(value) {
                Ok(lf) => self.set_log_filter(lf),
                Err(e) => {
                    log::error!("Unknown log filter value '{}', {}", value, e);
                    false
                }
            },
            _ => false,
        }
    }

    pub fn get(&self, rv_idx: u32, def_val: u64) -> u64 {
        match self.rvmap.get(&rv_idx, 0) {
            Ok(value) => value,
            Err(e) => {
                log::error!("Failed to get {}, {}", rv_idx, e);
                def_val
            }
        }
    }

    pub fn get_str(&self, rv_idx: u32, def_val: u64) -> String {
        let value = self.get(rv_idx, def_val);
        match rv_idx {
            runvars::LOG_FILTER => {
                for (index, lf) in LevelFilter::iter().enumerate() {
                    if index == value as usize {
                        return lf.to_string();
                    }
                }
                format!("unknown:{}", value)
            }
            _ => value.to_string(),
        }
    }

    // TODO: set feature flags

    pub fn print_all(&self, pattern: Option<&str>) {
        let mut sinfo = InfoTable::new(vec![format!(
            "{} {}variables",
            self.ifname,
            if let Some(p) = pattern {
                format!("*{}* ", p)
            } else {
                String::new()
            }
        )
        .as_str()]);

        for (idx, name) in VAR_NAMES.iter().enumerate() {
            if let Some(p) = pattern {
                if !name.contains(p) {
                    continue;
                }
            }

            sinfo.push_row(vec![format!(
                "{}: {}",
                name.to_string(),
                self.get_str(idx as u32, 0)
            )]);
        }

        sinfo.print("");
    }

    pub fn bulk_set(&mut self, pairs: &Vec<String>) -> Result<(), anyhow::Error> {
        let opt = Options::from_option_args(pairs);
        let mut count = 0;

        for (index, name) in VAR_NAMES.iter().enumerate() {
            if let Some(v) = opt.props.get(&name.to_string()) {
                if self.set_str(index as u32, v.as_str()) {
                    count += 1;
                }
            }
        }

        // TODO: handle feature flags
        log::info!(
            "[{}] Set summary: {}/{}",
            self.ifname,
            count,
            opt.props.len()
        );

        Ok(())
    }

    pub fn set_defaults(&mut self) {
        self.set(runvars::VERSION, VERSION as u64);
        self.set_log_filter(log::max_level());
    }

    pub fn set_log_filter(&mut self, level: LevelFilter) -> bool {
        if !self.set(runvars::LOG_FILTER, level as u64) {
            eprintln!("Failed to set log level to {}", level);
            false
        } else {
            true
        }
    }

    pub fn get_log_filter(&self) -> LevelFilter {
        let lf = self.get(runvars::LOG_FILTER, LevelFilter::Info as u64);
        for filter in LevelFilter::iter() {
            if filter as u64 == lf {
                return filter;
            }
        }
        LevelFilter::Off
    }

    pub fn version(&self) -> u64 {
        self.get(runvars::VERSION, 0)
    }
}
