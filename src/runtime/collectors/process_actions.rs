use anyhow::Result;
use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, Thread32First, Thread32Next, THREADENTRY32, TH32CS_SNAPTHREAD};
use windows::Win32::System::Threading::{OpenThread, SuspendThread, ResumeThread, THREAD_SUSPEND_RESUME, OpenProcess, TerminateProcess, PROCESS_TERMINATE};
use windows::Win32::Foundation::CloseHandle;

pub fn kill_process(pid: u32) -> Result<()> {
    unsafe {
        if let Ok(handle) = OpenProcess(PROCESS_TERMINATE, false, pid) {
            if !handle.is_invalid() {
                let res = TerminateProcess(handle, 1);
                let _ = CloseHandle(handle);
                if res.is_ok() {
                    return Ok(());
                }
            }
        }
    }
    Err(anyhow::anyhow!("Failed to terminate process {}", pid))
}

pub fn suspend_process(pid: u32) -> Result<()> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        let mut entry = THREADENTRY32::default();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            return Err(anyhow::anyhow!("Thread32First failed"));
        }

        loop {
            if entry.th32OwnerProcessID == pid {
                if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                    if !h.is_invalid() {
                        let _ = SuspendThread(h);
                        let _ = CloseHandle(h);
                    }
                }
            }

            if Thread32Next(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
    }
    Ok(())
}

pub fn resume_process(pid: u32) -> Result<()> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)?;
        let mut entry = THREADENTRY32::default();
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        if Thread32First(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            return Err(anyhow::anyhow!("Thread32First failed"));
        }

        loop {
            if entry.th32OwnerProcessID == pid {
                if let Ok(h) = OpenThread(THREAD_SUSPEND_RESUME, false, entry.th32ThreadID) {
                    if !h.is_invalid() {
                        // ResumeThread returns previous suspend count; call until zero
                        let mut _res = ResumeThread(h);
                        let _ = CloseHandle(h);
                    }
                }
            }

            if Thread32Next(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
    }
    Ok(())
}
