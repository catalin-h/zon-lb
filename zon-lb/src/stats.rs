use crate::{helpers::get_mapdata_by_name, InfoTable, ToMapName};
use anyhow::anyhow;
use aya::maps::{Map, MapData, PerCpuArray, PerCpuValues};
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
    "ip_fragments",
    "ipv6_fragments",
    "ip_fragment_errors",
    "ipv6_fragment_errors",
    "arp_reply",
    "icmpv6_ptb",
    "icmpv6_nd_advertisement",
    "icmp_dest_unreach_frag_rq",
    "ip6tnl_packets",
    "ipv6_unknown_fragments",
    "ipv4_unknown_fragments",
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
        let map = get_mapdata_by_name(ifname, Stats::map_name()).ok_or(anyhow!(
            "[{}] can't find map {}",
            ifname,
            Stats::map_name()
        ))?;
        let map = Map::PerCpuArray(map);
        let smap: PerCpuArray<_, u64> = map.try_into()?;
        Ok(Self {
            ifname: String::from(ifname),
            smap,
        })
    }

    fn reset(&mut self, stat_idx: u32) {
        let pcv = match self.smap.get(&stat_idx, 0) {
            Err(e) => {
                log::error!(
                    "[{}] Failed to get {}, {}",
                    self.ifname,
                    Self::as_str(stat_idx),
                    e
                );
                return;
            }
            Ok(pcv) => pcv,
        };
        let pcv = match PerCpuValues::try_from(vec![0; pcv.len()]) {
            Err(e) => {
                log::error!("[{}] Failed to create per cpu value, {}", self.ifname, e);
                return;
            }
            Ok(v) => v,
        };
        if let Err(e) = self.smap.set(stat_idx, pcv, 0) {
            log::error!(
                "[{}] Failed to reset counter: {}, {}",
                self.ifname,
                Self::as_str(stat_idx),
                e
            );
        }
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

    pub fn print_all(&self, pattern: Option<&str>) {
        let mut sinfo = InfoTable::new(vec![format!(
            "{} stats {}counters",
            self.ifname,
            if let Some(p) = pattern {
                format!("*{}* ", p)
            } else {
                String::new()
            }
        )
        .as_str()]);

        for (idx, name) in STATS_NAMES.iter().enumerate() {
            if let Some(p) = pattern {
                if !name.contains(p) {
                    continue;
                }
            }

            sinfo.push_row(vec![format!(
                "{}: {}",
                name.to_string(),
                self.get(idx as u32)
            )]);
        }

        sinfo.print("");
    }

    pub fn reset_counter(&mut self, ctr_name: Option<&str>) {
        match ctr_name {
            Some(name) => {
                for (index, id) in STATS_NAMES.iter().enumerate() {
                    if id.eq_ignore_ascii_case(name) {
                        log::info!("[{}] Resetting counter: {} ..", self.ifname, id);
                        self.reset(index as u32);
                        return;
                    }
                }
                log::error!("No counter {}", name)
            }
            None => {
                log::info!("[{}] Resetting all counters ..", self.ifname);
                (0..stats::MAX).for_each(|idx| self.reset(idx as u32))
            }
        };
    }
}
