use anyhow::Result;

pub fn suspend_process(pid: u32) -> Result<()> {
    crate::runtime::collectors::process_actions::suspend_process(pid)
}

pub fn resume_process(pid: u32) -> Result<()> {
    crate::runtime::collectors::process_actions::resume_process(pid)
}
