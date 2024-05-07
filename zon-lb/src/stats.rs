use crate::{helpers::get_mapdata_by_name, InfoTable, ToMapName};
use anyhow::anyhow;
use aya::maps::{Map, MapData, PerCpuArray};
use zon_lb_common::stats;

static STATS_NAMES: [&str; stats::MAX as usize] = [
    "packets",
    "xdp_pass",
    "xdp_redirect",
    "xdp_redirect_map",
    "xdp_redirect_full_nat",
    "xdp_redirect_errors",
    "xdp_tx",
    "xdp_drop",
    "fib_lookups",
    "fib_lookup_fails",
    "runtime_errors",
    "lb_error_no_backends",
    "lb_error_bad_backend",
    "conntrack_error_update",
    "arp_error_update",
];

pub struct Stats {
    ifname: String,
    smap: PerCpuArray<MapData, u64>,
}

impl ToMapName for Stats {
    fn map_name() -> &'static str {
        "ZLB_STATS"
    }
}

impl Stats {
    pub fn new(ifname: &str) -> Result<Self, anyhow::Error> {
        let map = get_mapdata_by_name(ifname, Stats::map_name())
            .ok_or(anyhow!("Can't find map {}", Stats::map_name()))?;
        let map = Map::PerCpuArray(map);
        let smap: PerCpuArray<_, u64> = map.try_into()?;
        Ok(Self {
            ifname: String::from(ifname),
            smap,
        })
    }

    fn get(&self, stat_idx: u32) -> u64 {
        match self.smap.get(&stat_idx, 0) {
            Err(e) => {
                log::error!("Failed to get {}, {}", Self::as_str(stat_idx), e);
                0
            }
            Ok(pcv) => pcv.iter().map(|cv| *cv).sum(),
        }
    }

    pub fn as_str(stat_idx: u32) -> &'static str {
        STATS_NAMES[stat_idx as usize]
    }

    pub fn print_all(&self) {
        let mut sinfo = InfoTable::new(vec![format!("{} stat", self.ifname).as_str(), "count"]);

        for (idx, name) in STATS_NAMES.iter().enumerate() {
            sinfo.push_row(vec![name.to_string(), self.get(idx as u32).to_string()]);
        }

        sinfo.print("");
    }
}
