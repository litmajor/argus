use anyhow::Result;

pub fn kill_process(pid: u32) -> Result<()> {
    crate::runtime::collectors::process_actions::kill_process(pid)
}
