use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::prelude::*;
use serde::{Serialize, Deserialize};

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));
static FILE_HANDLE: Lazy<Mutex<Option<std::fs::File>>> = Lazy::new(|| Mutex::new(None));

#[derive(Debug, Serialize, Deserialize)]
pub struct EventRecord {
    ts: i64,
    kind: String,
    pid: Option<u32>,
    msg: String,
}

fn ensure_handle() {
    let mut h = FILE_HANDLE.lock().unwrap();
    if h.is_some() { return; }
    if let Err(e) = std::fs::create_dir_all("timelines") {
        eprintln!("Failed to create timelines dir: {:?}", e);
        return;
    }
    let fname = format!("timelines/timeline_{}.jsonl", Local::now().format("%Y_%m_%d"));
    match OpenOptions::new().create(true).append(true).open(&fname) {
        Ok(f) => { *h = Some(f); }
        Err(e) => { eprintln!("Failed to open timeline file {}: {:?}", fname, e); }
    }
}

fn write_record(rec: &EventRecord) {
    ensure_handle();
    if let Some(f) = FILE_HANDLE.lock().unwrap().as_mut() {
        if let Ok(s) = serde_json::to_string(rec) {
            if let Err(e) = writeln!(f, "{}", s) {
                eprintln!("Failed to write timeline record: {:?}", e);
            }
            let _ = f.flush();
        }
    }
}

pub fn register() {
    ensure_handle();

    // Subscribe to process events
    let sub_p = crate::runtime::events::subscribe_to_process_events(Box::new(|ev| match ev {
        crate::domains::process::events::ProcessEvent::Started(info) => {
            let rec = EventRecord { ts: Local::now().timestamp(), kind: "process_started".to_string(), pid: Some(info.pid), msg: format!("Started {}", info.name) };
            write_record(&rec);
        }
        crate::domains::process::events::ProcessEvent::Terminated(pid) => {
            let rec = EventRecord { ts: Local::now().timestamp(), kind: "process_terminated".to_string(), pid: Some(*pid), msg: format!("Terminated pid {}", pid) };
            write_record(&rec);
        }
        crate::domains::process::events::ProcessEvent::CpuSpike { pid, cpu } => {
            let rec = EventRecord { ts: Local::now().timestamp(), kind: "process_cpu_spike".to_string(), pid: Some(*pid), msg: format!("CPU spike: {:.1}%", cpu) };
            write_record(&rec);
        }
        crate::domains::process::events::ProcessEvent::FamilyCpuSpike { family, cpu } => {
            let rec = EventRecord { ts: Local::now().timestamp(), kind: "family_cpu_spike".to_string(), pid: None, msg: format!("Family {} CPU {:.1}%", family, cpu) };
            write_record(&rec);
        }
        crate::domains::process::events::ProcessEvent::FamilyNormalized { family } => {
            let rec = EventRecord { ts: Local::now().timestamp(), kind: "family_normalized".to_string(), pid: None, msg: format!("Family {} normalized", family) };
            write_record(&rec);
        }
    }));
    SUBS.lock().unwrap().push(sub_p);

    // Subscribe to rule findings
    let sub_f = crate::runtime::events::subscribe_to_rules_findings(Box::new(|f: &crate::domains::rules::Finding| {
        let rec = EventRecord { ts: Local::now().timestamp(), kind: "finding".to_string(), pid: None, msg: format!("{} risk={} severity={:?}", f.title, f.risk, f.severity) };
        write_record(&rec);
    }));
    SUBS.lock().unwrap().push(sub_f);

    // Subscribe to UI messages (e.g., snapshot saved)
    let sub_u = crate::runtime::events::subscribe_to_ui_messages(Box::new(|m| {
        let rec = EventRecord { ts: Local::now().timestamp(), kind: format!("ui:{}", m.topic), pid: None, msg: m.body.clone() };
        write_record(&rec);
    }));
    SUBS.lock().unwrap().push(sub_u);
}

pub fn unregister() {
    // Dropping the subscriptions will unsubscribe via Drop impl
    let mut v = SUBS.lock().unwrap();
    let old = std::mem::take(&mut *v);
    drop(old);
    // Close file handle
    let mut fh = FILE_HANDLE.lock().unwrap();
    if let Some(mut f) = fh.take() {
        let _ = f.flush();
    }
}

/// Read today's timeline and return records matching a pid (if provided)
pub fn query_pid(pid: u32) -> Vec<EventRecord> {
    use std::fs;
    let fname = format!("timelines/timeline_{}.jsonl", Local::now().format("%Y_%m_%d"));
    let mut out = Vec::new();
    if let Ok(s) = fs::read_to_string(&fname) {
        for line in s.lines() {
            if let Ok(r) = serde_json::from_str::<EventRecord>(line) {
                if r.pid == Some(pid) {
                    out.push(r);
                }
            }
        }
    }
    out
}
