use crate::helpers::get_xdp_link_info;
use crate::info;
use anyhow::anyhow;
use aya_log::EbpfLogger;

/// Enables the xdp program logging by attaching the default logger
/// to the log map loaded along the ebpf program.
pub fn init_log(ifname: &str) -> Result<(), anyhow::Error> {
    match get_xdp_link_info(ifname) {
        Some(info) => {
            log::info!(
                "Attaching log to program id: {} binded to {}",
                info.program_id,
                ifname
            );
            EbpfLogger::init_from_id(info.program_id)?;
            Ok(())
        }
        None => {
            return Err(anyhow!(
                "No program pinned link binded to {}, try load program",
                ifname
            ))
        }
    }
}

/// Enables the ebpf program logging by loading and replacing the program
/// and using this instance to attach the default logger to.
/// This is a workaround until aya-log support attaching by program id.
pub fn init_log_with_replace(ifname: &str) -> Result<(), anyhow::Error> {
    use crate::Prog;
    info::get_program_info_by_ifname(ifname)?;
    let mut bpf = crate::bpf_instance()?;
    let prg = Prog::new(ifname)?;
    log::info!("Replacing program to attach the logger");
    prg.replace(&mut bpf)
}
