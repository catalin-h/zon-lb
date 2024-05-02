use crate::{helpers::*, ToMapName};
use anyhow::anyhow;
use aya::maps::{Array, Map, MapData};
use log::LevelFilter;
use zon_lb_common::runvars::LOG_LEVEL_IDX;

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

    pub fn _get(&mut self, rv_idx: u32) -> Result<u64, anyhow::Error> {
        let value = self.rvmap.get(&rv_idx, 0)?;
        Ok(value)
    }

    pub fn set_defaults(&mut self) {
        self.set_logging_level(log::max_level());
    }

    fn set_logging_level(&mut self, level: LevelFilter) {
        if !self.set(LOG_LEVEL_IDX, level as u64) {
            eprintln!("Failed to set log level to {}", level);
        }
    }
}
