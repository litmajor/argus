use crate::domains::process::state::ProcessState;
use std::fs::File;
use std::io::Write;

pub fn export_snapshot(state: &ProcessState, path: &str) -> std::io::Result<()> {
    let mut f = File::create(path)?;
    for info in state.processes.values() {
        writeln!(f, "PID:{} NAME:{} CPU:{:.1} MEM:{:.1} PARENT:{}", info.pid, info.name, info.cpu_percent, info.memory_mb, info.parent_pid)?;
    }
    Ok(())
}
