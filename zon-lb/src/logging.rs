use crate::info;
use anyhow;

#[cfg(init_log_by_prog_id)]
/// Enables the xdp program logging by attaching the default logger
/// to the log map loaded along the ebpf program.
pub fn init_log(ifname: &str) -> Result<(), anyhow::Error> {
    use aya_log::BpfLogger;
    let program_info = info::get_program_info_by_ifname(ifname)?;
    let _logger = BpfLogger::init_from_id(program_info.id())?;
    Ok(())
}

#[cfg(not(init_log_by_prog_id))]
/// Enables the ebpf program logging by loading and replacing the program
/// and using this instance to attach the default logger to.
/// This is a workaround until aya-log support attaching by program id.
pub fn init_log(ifname: &str) -> Result<(), anyhow::Error> {
    use crate::Prog;
    info::get_program_info_by_ifname(ifname)?;
    let mut bpf = crate::bpf_instance(ifname)?;
    let prg = Prog::new(ifname)?;
    log::info!("Replacing program to attach the logger");
    prg.replace(&mut bpf)
}
