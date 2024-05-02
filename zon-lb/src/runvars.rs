use crate::{helpers::*, ToMapName};
use anyhow::anyhow;
use aya::maps::{Array, Map, MapData};
use log::LevelFilter;
use zon_lb_common::{
    runvars::{FUSED_VERSION_IDX, LOG_LEVEL_IDX},
    VERSION,
};

pub struct RunVars {
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
        Ok(Self { rvmap })
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

    pub fn get(&self, rv_idx: u32, def_val: u64) -> u64 {
        match self.rvmap.get(&rv_idx, 0) {
            Ok(value) => value,
            Err(e) => {
                log::error!("Failed to get {}, {}", rv_idx, e);
                def_val
            }
        }
    }

    // TODO: set feature flags

    pub fn set_defaults(&mut self) {
        self.set(FUSED_VERSION_IDX, VERSION as u64);
        self.set_logging_level(log::max_level());
    }

    fn set_logging_level(&mut self, level: LevelFilter) {
        if !self.set(LOG_LEVEL_IDX, level as u64) {
            eprintln!("Failed to set log level to {}", level);
        }
    }

    pub fn version(&self) -> u64 {
        self.get(FUSED_VERSION_IDX, 0)
    }
}
