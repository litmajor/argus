use anyhow::Result;
use crate::core::process::Process;
use crate::runtime::event_bus;
use crate::domains::process::events::ProcessEvent;
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::{collections::{HashMap, HashSet}, sync::Mutex, time::Instant};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
    TH32CS_SNAPPROCESS,
};
use windows::Win32::Foundation::{CloseHandle, FILETIME};
use windows::Win32::System::Threading::{
    OpenProcess, GetProcessTimes, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
};
use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};

static LAST: Lazy<Mutex<HashMap<u32, (u64, Instant)>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn filetime_to_u64(ft: FILETIME) -> u64 {
    ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
}

pub fn collect_processes() -> Result<Vec<Process>> {
    // Phase 1: enumerate on a single thread (ToolHelp32 is not thread-safe)
    let mut entries: Vec<(u32, String, u32, u32)> = Vec::new();

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            .map_err(|e| anyhow::anyhow!(e))?;

        let mut entry = PROCESSENTRY32W::default();
        entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

        if Process32FirstW(snapshot, &mut entry).is_err() {
            let _ = CloseHandle(snapshot);
            return Err(anyhow::anyhow!("Process32FirstW failed"));
        }

        loop {
            let name_w = &entry.szExeFile;
            let len = name_w.iter().position(|&c| c == 0).unwrap_or(name_w.len());
            let name = String::from_utf16_lossy(&name_w[..len]);
            entries.push((entry.th32ProcessID, name, entry.cntThreads, entry.th32ParentProcessID));

            if Process32NextW(snapshot, &mut entry).is_err() {
                break;
            }
        }

        let _ = CloseHandle(snapshot);
    }

    // Phase 2: query CPU/memory in parallel, minimizing mutex contention
    let now = Instant::now();
    // Obtain system total memory once per collection cycle (expensive to refresh)
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    let total_mb = sys.total_memory() as f32 / 1024.0;

    // Snapshot the previous state once under a single lock acquisition
    let prev_snapshot: HashMap<u32, (u64, Instant)> = {
        let map = LAST.lock().unwrap();
        map.clone()
    };

    let sampled: Vec<(u32, u64, f32, f32, Option<u64>)> = entries
        .par_iter()
        .map(|(pid, _name, _threads, _parent)| {
            let pid = *pid;
            let mut cpu_total: u64 = 0;
            let mut cpu_percent: f32 = 0.0;
            let mut memory_mb: f32 = 0.0;
            let mut start_time: Option<u64> = None;

            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
                    if !handle.is_invalid() {
                        let mut creation = FILETIME::default();
                        let mut exit = FILETIME::default();
                        let mut kernel = FILETIME::default();
                        let mut user = FILETIME::default();

                        if GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok() {
                            let total = filetime_to_u64(kernel) + filetime_to_u64(user);
                            cpu_total = total;
                            // capture creation time (FILETIME as u64)
                            start_time = Some(filetime_to_u64(creation));
                            if let Some((prev_total, prev_time)) = prev_snapshot.get(&pid) {
                                let delta_100ns = total.saturating_sub(*prev_total);
                                let delta_sec = delta_100ns as f64 * 1e-7;
                                let mut elapsed = now.duration_since(*prev_time).as_secs_f64();
                                if elapsed <= 0.0 { elapsed = 1e-6; }
                                let cpu_count = num_cpus::get() as f64;
                                let mut pct = (delta_sec / elapsed * 100.0 / cpu_count) as f32;
                                if pct.is_nan() || pct.is_infinite() { pct = 0.0; }
                                pct = pct.clamp(0.0, 100.0);
                                cpu_percent = pct;
                            }
                        }

                        let mut pmc = PROCESS_MEMORY_COUNTERS { cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32, ..Default::default() };
                        if K32GetProcessMemoryInfo(handle, &mut pmc, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).as_bool() {
                            let raw_mb = (pmc.WorkingSetSize as f64 / 1024.0 / 1024.0) as f32;
                            if total_mb > 0.0 && raw_mb > total_mb * 10.0 {
                                memory_mb = f32::NAN;
                            } else {
                                memory_mb = raw_mb;
                            }
                        }

                        if let Err(e) = CloseHandle(handle) {
                            eprintln!("Warning: CloseHandle(process {}) failed: {:?}", pid, e);
                        }
                    }
                }
            }

            (pid, cpu_total, cpu_percent, memory_mb, start_time)
        })
        .collect();

    // Write updated CPU totals back under a single lock acquisition
    {
        let mut map = LAST.lock().unwrap();
        for &(pid, cpu_total, _, _, _) in &sampled {
            if cpu_total > 0 {
                map.insert(pid, (cpu_total, now));
            }
        }
        // Evict any PIDs that are no longer present in the current enumeration
        let current_pids: HashSet<u32> = entries.iter().map(|(pid, _name, _threads, _parent)| *pid).collect();
        map.retain(|pid, _| current_pids.contains(pid));
    }

    // Assemble final output
    let pid_to_sample: HashMap<u32, (f32, f32, Option<u64>)> = sampled
        .into_iter()
        .map(|(pid, _, cpu, mem, start)| (pid, (cpu, mem, start)))
        .collect();

    let processes: Vec<Process> = entries
        .into_iter()
        .map(|(pid, name, threads, parent_pid)| {
            let (cpu_percent, memory_mb, start_time) = pid_to_sample.get(&pid).copied().unwrap_or((0.0, 0.0, None));
            Process {
                pid,
                name,
                cpu_percent,
                memory_mb,
                threads,
                parent_pid,
                start_time,
            }
        })
        .collect();

    // Publish started/terminated events by comparing previous snapshot with current
    let prev_pids: HashSet<u32> = prev_snapshot.keys().copied().collect();
    let current_pids: HashSet<u32> = processes.iter().map(|p: &Process| p.pid).collect();

    // New processes -> Started
    for p in processes.iter() {
        if !prev_pids.contains(&p.pid) {
            // Convert core::process::Process -> domains::process::state::ProcessInfo via From impl
            let info: crate::domains::process::state::ProcessInfo = p.clone().into();
            event_bus::publish(ProcessEvent::Started(info));
        }
    }

    // Terminated processes -> Terminated(pid)
    for pid in prev_pids.difference(&current_pids) {
        event_bus::publish(ProcessEvent::Terminated(*pid));
    }

    Ok(processes)
}
