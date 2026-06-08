use crate::domains::graph;
use crate::domains::process;
use once_cell::sync::Lazy;
use std::sync::Mutex;

#[derive(Debug, Clone)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub title: String,
    pub description: String,
    pub risk: u8,
    pub severity: Severity,
}

pub trait Rule: Send + Sync {
    fn evaluate(&self, graph: &graph::Graph, state: &process::ProcessState) -> Vec<Finding>;
}

// Registry of rules
static RULES: Lazy<Mutex<Vec<Box<dyn Rule>>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register_rule(r: Box<dyn Rule>) {
    RULES.lock().unwrap().push(r);
}

pub fn evaluate_all() -> Vec<Finding> {
    let g = graph::get_graph();
    let state = match crate::runtime::get_latest_state() {
        Some(s) => s,
        None => process::ProcessState::default(),
    };
    let rules = RULES.lock().unwrap();
    let mut out: Vec<Finding> = Vec::new();
    for r in rules.iter() {
        let mut fs = r.evaluate(&g, &state);
        out.append(&mut fs);
    }

    // Publish findings to the event bus so surfaces and other components can subscribe
    for f in out.iter() {
        // publish a clone of the finding
        crate::runtime::event_bus::publish(f.clone());
    }
    out
}

// Helpers
fn risk_to_severity(r: u8) -> Severity {
    if r >= 90 { Severity::Critical }
    else if r >= 70 { Severity::High }
    else if r >= 40 { Severity::Medium }
    else { Severity::Low }
}

// Sample rule: PowerShellSpawnRule: powershell -> cmd
pub struct PowerShellSpawnRule;
impl Rule for PowerShellSpawnRule {
    fn evaluate(&self, graph: &graph::Graph, _state: &process::ProcessState) -> Vec<Finding> {
        let mut out = Vec::new();
        for e in graph.edges.iter() {
            if matches!(e.kind, graph::EdgeKind::Spawned | graph::EdgeKind::ParentOf) {
                let src = graph.nodes.get(&e.src);
                let dst = graph.nodes.get(&e.dst);
                if let (Some(s), Some(d)) = (src, dst) {
                    let sname = s.name.to_lowercase();
                    let dname = d.name.to_lowercase();
                    if sname.contains("powershell") && dname.contains("cmd") {
                        let risk = 20u8;
                        out.push(Finding {
                            title: "PowerShell spawned cmd".to_string(),
                            description: format!("{} spawned {}", s.name, d.name),
                            risk,
                            severity: risk_to_severity(risk),
                        });
                    }
                }
            }
        }
        out
    }
}

// UnknownExecutableRule: matches nodes named "unknown.exe"
pub struct UnknownExecutableRule;
impl Rule for UnknownExecutableRule {
    fn evaluate(&self, graph: &graph::Graph, _state: &process::ProcessState) -> Vec<Finding> {
        let mut out = Vec::new();
        for n in graph.nodes.values() {
            if n.name.to_lowercase().contains("unknown") {
                let risk = 40u8;
                out.push(Finding {
                    title: "Unknown executable observed".to_string(),
                    description: format!("Unknown executable: {}", n.name),
                    risk,
                    severity: risk_to_severity(risk),
                });
            }
        }
        out
    }
}

// OfficeChildProcessRule: winword -> powershell
pub struct OfficeChildProcessRule;
impl Rule for OfficeChildProcessRule {
    fn evaluate(&self, graph: &graph::Graph, _state: &process::ProcessState) -> Vec<Finding> {
        let mut out = Vec::new();
        for e in graph.edges.iter() {
            if matches!(e.kind, graph::EdgeKind::Spawned | graph::EdgeKind::ParentOf) {
                let src = graph.nodes.get(&e.src);
                let dst = graph.nodes.get(&e.dst);
                if let (Some(s), Some(d)) = (src, dst) {
                    let sname = s.name.to_lowercase();
                    let dname = d.name.to_lowercase();
                    if sname.contains("winword") && dname.contains("powershell") {
                        let risk = 70u8;
                        out.push(Finding {
                            title: "Office spawned PowerShell".to_string(),
                            description: format!("{} spawned {}", s.name, d.name),
                            risk,
                            severity: risk_to_severity(risk),
                        });
                    }
                }
            }
        }
        out
    }
}

// MassProcessSpawnRule: detect parent spawning >= threshold children
pub struct MassProcessSpawnRule {
    pub threshold: usize,
}
impl Rule for MassProcessSpawnRule {
    fn evaluate(&self, _graph: &graph::Graph, state: &process::ProcessState) -> Vec<Finding> {
        use std::collections::HashMap;
        let mut out = Vec::new();
        let mut counts: HashMap<u32, usize> = HashMap::new();
        for (_pid, info) in state.processes.iter() {
            counts.entry(info.parent_pid).and_modify(|c| *c += 1).or_insert(1);
        }
        // compute statistics for a relative baseline
        let vals: Vec<f64> = counts.iter().filter(|(p,_)| **p != 0).map(|(_,c)| *c as f64).collect();
        if !vals.is_empty() {
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            let var = vals.iter().map(|v| (v - mean)*(v - mean)).sum::<f64>() / vals.len() as f64;
            let std = var.sqrt();
            let cutoff = (mean + 3.0 * std).ceil() as usize;
            for (parent, cnt) in counts.iter() {
                if *parent == 0 { continue; }
                // flag if above absolute threshold OR above relative cutoff
                if *cnt >= self.threshold || *cnt >= cutoff {
                    let pname = state.processes.get(parent).map(|p| p.name.clone()).unwrap_or_else(|| format!("pid:{}", parent));
                    let risk = 50u8;
                    out.push(Finding {
                        title: "Mass process spawn detected".to_string(),
                        description: format!("{} spawned {} children (threshold {} / cutoff {})", pname, cnt, self.threshold, cutoff),
                        risk,
                        severity: risk_to_severity(risk),
                    });
                }
            }
        }
        out
    }
}

// PowerShellBehaviorRule: detect powershell processes that both create files and touch registry
pub struct PowerShellBehaviorRule;
impl Rule for PowerShellBehaviorRule {
    fn evaluate(&self, graph: &graph::Graph, _state: &process::ProcessState) -> Vec<Finding> {
        let mut out: Vec<Finding> = Vec::new();
        for n in graph.nodes.values() {
            let name = n.name.to_lowercase();
            if name.contains("powershell") {
                // check incident edges for CreatedFiles and TouchesRegistry
                let mut created = 0usize;
                let mut touches_registry = false;
                for e in graph.edges.iter() {
                    if e.src == n.id || e.dst == n.id {
                        if matches!(e.kind, graph::EdgeKind::CreatedFiles) { created += 1; }
                        if matches!(e.kind, graph::EdgeKind::TouchesRegistry) { touches_registry = true; }
                    }
                }
                if created > 0 && touches_registry {
                    let risk = 30u8;
                    out.push(Finding {
                        title: "PowerShell created files and touched registry".to_string(),
                        description: format!("{} ({}) created files={} and touched registry", n.name, n.id, created),
                        risk,
                        severity: risk_to_severity(risk),
                    });
                }
            }
        }
        out
    }
}

// Register default rules
pub fn register_defaults() {
    register_rule(Box::new(PowerShellSpawnRule));
    register_rule(Box::new(UnknownExecutableRule));
    register_rule(Box::new(OfficeChildProcessRule));
    register_rule(Box::new(PowerShellBehaviorRule));
    register_rule(Box::new(MassProcessSpawnRule { threshold: 100 }));
    // Behavioral detection rules
    register_rule(Box::new(SustainedCpuSpikeRule {}));
    register_rule(Box::new(RapidSpawnTerminateRule {}));
    register_rule(Box::new(SuspiciousRegistryAccessRule {}));
    register_rule(Box::new(PeriodicProcessCycleRule {}));
}

// Sustained CPU spike: repeated CpuSpike events for same PID within window
pub struct SustainedCpuSpikeRule;
impl Rule for SustainedCpuSpikeRule {
    fn evaluate(&self, _graph: &graph::Graph, state: &process::ProcessState) -> Vec<Finding> {
        use chrono::Local;
        let mut out = Vec::new();
        let events = crate::domains::process::storage::get_events();
        let now = Local::now().timestamp();
        // map pid -> recent cpu spike timestamps
        let mut spikes: std::collections::HashMap<u32, Vec<i64>> = std::collections::HashMap::new();
        for (ts, ev) in events.into_iter().rev() {
            if now - ts > 300 { break; } // only look 5 minutes back
            if let crate::domains::process::events::ProcessEvent::CpuSpike { pid, cpu: _ } = ev {
                spikes.entry(pid).or_default().push(ts);
            }
        }
        for (pid, v) in spikes.iter() {
            if v.len() >= 3 {
                let pname = state.processes.get(pid).map(|p| p.name.clone()).unwrap_or_else(|| format!("pid:{}", pid));
                let risk = 60u8;
                out.push(Finding { title: "Sustained CPU spikes".to_string(), description: format!("{} (PID {}) had {} CPU spike events in last 5m", pname, pid, v.len()), risk, severity: risk_to_severity(risk) });
            }
        }
        out
    }
}

// Rapid spawn/terminate: many Started events from same parent in a short window
pub struct RapidSpawnTerminateRule;
impl Rule for RapidSpawnTerminateRule {
    fn evaluate(&self, _graph: &graph::Graph, state: &process::ProcessState) -> Vec<Finding> {
        use chrono::Local;
        let mut out = Vec::new();
        let events = crate::domains::process::storage::get_events();
        let now = Local::now().timestamp();
        let mut starts_by_parent: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
        for (ts, ev) in events.into_iter().rev() {
            if now - ts > 120 { break; } // last 2 minutes
            if let crate::domains::process::events::ProcessEvent::Started(info) = ev {
                starts_by_parent.entry(info.parent_pid).and_modify(|c| *c += 1).or_insert(1);
            }
        }
        for (parent, cnt) in starts_by_parent.iter() {
            if *parent == 0 { continue; }
            if *cnt >= 10 {
                let pname = state.processes.get(parent).map(|p| p.name.clone()).unwrap_or_else(|| format!("pid:{}", parent));
                let risk = 70u8;
                out.push(Finding { title: "Rapid spawn/terminate churn".to_string(), description: format!("{} (PID {}) spawned {} processes in last 2m", pname, parent, cnt), risk, severity: risk_to_severity(risk) });
            }
        }
        out
    }
}

// Suspicious registry access: non-standard executables touching HKCU/HKLM
pub struct SuspiciousRegistryAccessRule;
impl Rule for SuspiciousRegistryAccessRule {
    fn evaluate(&self, graph: &graph::Graph, _state: &process::ProcessState) -> Vec<Finding> {
        let mut out = Vec::new();
        for e in graph.edges.iter() {
            if matches!(e.kind, graph::EdgeKind::TouchesRegistry) {
                // determine process node id
                let proc_id = if e.src.starts_with("proc:") { &e.src } else if e.dst.starts_with("proc:") { &e.dst } else { continue };
                if let Some(n) = graph.nodes.get(proc_id) {
                    let pname = n.name.clone();
                    let family = process::state::family_for_name(&pname);
                    if family != "svchost" && family != "services" && !family.to_lowercase().contains("explorer") {
                        let pid = n.pid.unwrap_or(0);
                        if pid != 0 {
                            let risk = 50u8;
                            out.push(Finding { title: "Suspicious registry access".to_string(), description: format!("{} (PID {}) touched registry (edge {})", pname, pid, e.ts), risk, severity: risk_to_severity(risk) });
                        }
                    }
                }
            }
        }
        out
    }
}

// Periodic short-lived process cycles (e.g., webview instances)
pub struct PeriodicProcessCycleRule;
impl Rule for PeriodicProcessCycleRule {
    fn evaluate(&self, _graph: &graph::Graph, _state: &process::ProcessState) -> Vec<Finding> {
        use chrono::Local;
        let mut out = Vec::new();
        let events = crate::domains::process::storage::get_events();
        let now = Local::now().timestamp();
        // gather recent starts by name with short lifetimes
        let mut starts: std::collections::HashMap<String, Vec<i64>> = std::collections::HashMap::new();
        let mut term_times: std::collections::HashMap<u32, i64> = std::collections::HashMap::new();
        // collect term times
        for (ts, ev) in events.iter().rev() {
            if now - *ts > 900 { break; } // 15 minutes window
            if let crate::domains::process::events::ProcessEvent::Terminated(pid) = ev {
                term_times.insert(*pid, *ts);
            }
        }
        for (ts, ev) in events.into_iter().rev() {
            if now - ts > 900 { break; }
            if let crate::domains::process::events::ProcessEvent::Started(info) = ev {
                // check if terminated soon after
                if let Some(tend) = term_times.get(&info.pid) {
                    if *tend - ts <= 5 {
                        starts.entry(info.name.clone()).or_default().push(ts);
                    }
                }
            }
        }
        for (name, times) in starts.iter() {
            if times.len() >= 3 {
                // compute median interval
                let mut diffs: Vec<i64> = Vec::new();
                for w in times.windows(2) { diffs.push(w[1] - w[0]); }
                if diffs.is_empty() { continue; }
                let avg = diffs.iter().sum::<i64>() as f64 / diffs.len() as f64;
                // if avg interval ~ 90s (1.5m) within tolerance 60s
                if (avg - 90.0).abs() <= 60.0 {
                    let risk = 30u8;
                    out.push(Finding { title: "Periodic short-lived process cycle".to_string(), description: format!("Process {} started {} times with short lifetimes and avg interval {:.0}s", name, times.len(), avg), risk, severity: risk_to_severity(risk) });
                }
            }
        }
        out
    }
}
