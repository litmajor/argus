use anyhow::Result;

/// High-level action API facade. Surfaces should call these, not call low-level Win32 directly.
pub fn kill(pid: u32) -> Result<()> {
    // Pre-flight: basic sanity and permission checks
    println!("[Action] kill preflight pid={}", pid);
    if pid == 0 {
        return Err(anyhow::anyhow!("invalid pid"));
    }

    // Emit attempt event
    crate::actions::bus::publish(&crate::actions::events::ActionEvent::KillAttempt { _pid: pid });

    // Try to perform kill
    let res = crate::actions::kill_process::kill_process(pid);

    let success = res.is_ok();
    crate::actions::bus::publish(&crate::actions::events::ActionEvent::KillResult { _pid: pid, _success: success });
    if success {
        println!("[Action] kill succeeded pid={}", pid);
        Ok(())
    } else {
        println!("[Action] kill failed pid={}", pid);
        res
    }
}

pub fn suspend(pid: u32) -> Result<()> {
    println!("[Action] suspend preflight pid={}", pid);
    crate::actions::bus::publish(&crate::actions::events::ActionEvent::SuspendAttempt { _pid: pid });
    let res = crate::actions::suspend_process::suspend_process(pid);
    let success = res.is_ok();
    crate::actions::bus::publish(&crate::actions::events::ActionEvent::SuspendResult { _pid: pid, _success: success });
    res
}

pub fn resume(pid: u32) -> Result<()> {
    crate::actions::suspend_process::resume_process(pid)
}

pub fn export_snapshot(state: &crate::domains::process::ProcessState, path: &str) -> std::io::Result<()> {
    let res = crate::actions::export_snapshot::export_snapshot(state, path);
    if res.is_ok() {
        crate::actions::bus::publish(&crate::actions::events::ActionEvent::ExportSnapshot { _path: path.to_string() });
    }
    res
}
