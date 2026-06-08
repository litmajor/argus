use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use std::sync::Mutex;
use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use chrono::prelude::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableProcessIdentity {
    pub path: Option<String>,
    pub signer: Option<String>,
    pub company: Option<String>,
    pub category: Option<String>,
    pub start_time: Option<u64>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f32,
    pub threads: u32,
    pub parent_pid: u32,
    pub identity: Option<SerializableProcessIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableFinding {
    pub title: String,
    pub description: String,
    pub risk: u8,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub ts: i64,
    pub processes: Vec<SerializableProcessInfo>,
    pub graph: crate::domains::graph::Graph,
    pub findings: Vec<SerializableFinding>,
    pub risk: Vec<(u32, u8)>,
}

static LATEST_SNAPSHOT: Lazy<Mutex<Option<Snapshot>>> = Lazy::new(|| Mutex::new(None));

fn severity_to_string(s: &crate::domains::rules::Severity) -> String {
    match s {
        crate::domains::rules::Severity::Low => "Low".to_string(),
        crate::domains::rules::Severity::Medium => "Medium".to_string(),
        crate::domains::rules::Severity::High => "High".to_string(),
        crate::domains::rules::Severity::Critical => "Critical".to_string(),
    }
}

pub fn save_snapshot() {
    // gather processes
    let mut procs: Vec<SerializableProcessInfo> = Vec::new();
    if let Some(state) = crate::runtime::get_latest_state() {
        for p in state.processes.values() {
            let identity = p.identity.as_ref().map(|id| SerializableProcessIdentity {
                path: id.path.clone(),
                signer: id.signer.clone(),
                company: id.company.clone(),
                category: id.category.clone(),
                start_time: id.start_time,
                risk_score: id.risk_score,
            });
            procs.push(SerializableProcessInfo {
                pid: p.pid,
                name: p.name.clone(),
                cpu_percent: p.cpu_percent,
                memory_mb: p.memory_mb,
                threads: p.threads,
                parent_pid: p.parent_pid,
                identity,
            });
        }
    }

    // graph
    let g = crate::domains::graph::get_graph();

    // findings: gather current (evaluate_all may publish, but we want last cycle findings)
    let mut findings_ser: Vec<SerializableFinding> = Vec::new();
    // We can call evaluate_all() to compute findings now
    let findings = crate::domains::rules::evaluate_all();
    for f in findings.iter() {
        findings_ser.push(SerializableFinding { title: f.title.clone(), description: f.description.clone(), risk: f.risk, severity: severity_to_string(&f.severity) });
    }

    // risk map
    let mut risk_vec: Vec<(u32,u8)> = Vec::new();
    if let Some(state) = crate::runtime::get_latest_state() {
        for pid in state.processes.keys() {
            let sc = crate::domains::security::state::get_process_score(*pid);
            risk_vec.push((*pid, sc));
        }
    }

    let now = Local::now();
    let ts = now.timestamp();
    let snap = Snapshot { ts, processes: procs, graph: g, findings: findings_ser, risk: risk_vec };

    // ensure snapshots dir
    if let Err(e) = create_dir_all("snapshots") {
        eprintln!("Failed to create snapshots dir: {:?}", e);
        return;
    }

    let fname = format!("snapshots/snapshot_{}.json", now.format("%Y_%m_%d"));
    if let Ok(f) = File::create(&fname) {
        let w = BufWriter::new(f);
        if let Err(e) = serde_json::to_writer_pretty(w, &snap) {
            eprintln!("Failed to write snapshot {}: {:?}", fname, e);
        } else {
            let mut g = LATEST_SNAPSHOT.lock().unwrap();
            *g = Some(snap);
            println!("Saved snapshot: {}", fname);
            // publish a UI message so other surfaces (and timeline) can react
            crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "snapshot_saved".to_string(), body: fname.clone() });
        }
    } else {
        eprintln!("Failed to create snapshot file: {}", fname);
    }
}

pub fn load_latest_snapshot() -> Option<Snapshot> {
    use std::fs;
    // look for files matching snapshots/snapshot_YYYY_MM_DD.json and pick the latest by name
    if let Ok(entries) = fs::read_dir("snapshots") {
        let mut files: Vec<String> = Vec::new();
        for e in entries.flatten() {
            let p = e.path();
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("snapshot_") && name.ends_with(".json") {
                    files.push(p.to_string_lossy().to_string());
                }
            }
        }
        files.sort();
        if let Some(last) = files.last() {
            if let Ok(s) = fs::read_to_string(last) {
                if let Ok(snap) = serde_json::from_str::<Snapshot>(&s) {
                    let mut g = LATEST_SNAPSHOT.lock().unwrap();
                    *g = Some(snap.clone());
                    return Some(snap);
                }
            }
        }
    }
    None
}

pub fn get_loaded_snapshot() -> Option<Snapshot> {
    let g = LATEST_SNAPSHOT.lock().unwrap();
    g.clone()
}

pub fn compare_with_loaded(current: &Snapshot) -> String {
    // compare processes and findings and risk counts; return a human readable diff
    let mut out = String::new();
    if let Some(prev) = get_loaded_snapshot() {
        // processes: by pid
        let prev_pids: std::collections::HashSet<u32> = prev.processes.iter().map(|p| p.pid).collect();
        let cur_pids: std::collections::HashSet<u32> = current.processes.iter().map(|p| p.pid).collect();
        let added: Vec<u32> = cur_pids.difference(&prev_pids).cloned().collect();
        let removed: Vec<u32> = prev_pids.difference(&cur_pids).cloned().collect();
        out.push_str(&format!("Processes added: {:?}\n", added));
        out.push_str(&format!("Processes removed: {:?}\n", removed));

        // findings: compare titles
        let prev_find: std::collections::HashSet<String> = prev.findings.iter().map(|f| f.title.clone()).collect();
        let cur_find: std::collections::HashSet<String> = current.findings.iter().map(|f| f.title.clone()).collect();
        let new_findings: Vec<String> = cur_find.difference(&prev_find).cloned().collect();
        out.push_str(&format!("New findings: {:?}\n", new_findings));

        // risk changes
        let prev_map: std::collections::HashMap<u32,u8> = prev.risk.into_iter().collect();
        let cur_map: std::collections::HashMap<u32,u8> = current.risk.clone().into_iter().collect();
        let mut deltas: Vec<String> = Vec::new();
        for (pid, cur_score) in cur_map.iter() {
            let prev_score = prev_map.get(pid).cloned().unwrap_or(0);
            if cur_score != &prev_score {
                deltas.push(format!("pid {}: {} -> {}", pid, prev_score, cur_score));
            }
        }
        out.push_str(&format!("Risk changes: {:?}\n", deltas));

        // graph changes: node/edge counts
        out.push_str(&format!("Graph nodes: prev={} cur={} edges: prev={} cur={}\n", prev.graph.nodes.len(), current.graph.nodes.len(), prev.graph.edges.len(), current.graph.edges.len()));
    } else {
        out.push_str("No previously loaded snapshot for comparison.\n");
    }
    out
}
