use crate::domains::process::state::{ProcessInfo, ProcessState};
use crate::domains::process::events::ProcessEvent;
use crate::runtime::event_bus;
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;

pub struct Engine {
    prev: ProcessState,
    cpu_spike_threshold: f32,
}

impl Engine {
    pub fn new(cpu_spike_threshold: f32) -> Self {
        Self {
            prev: ProcessState::default(),
            cpu_spike_threshold,
        }
    }

    pub fn diff_and_emit(&mut self, new: ProcessState) {
        let mut events: Vec<ProcessEvent> = Vec::new();

        // Fast access maps
        let old_map: &HashMap<u32, ProcessInfo> = &self.prev.processes;
        let new_map: &HashMap<u32, ProcessInfo> = &new.processes;

        // Added
        for (pid, info) in new_map.iter() {
            if !old_map.contains_key(pid) {
                events.push(ProcessEvent::Started(info.clone()));
            }
        }

        // Removed
        for pid in old_map.keys() {
            if !new_map.contains_key(pid) {
                events.push(ProcessEvent::Terminated(*pid));
            }
        }

        // Changed: CPU spike
        for (pid, new_info) in new_map.iter() {
            if let Some(old_info) = old_map.get(pid) {
                // Emit if new CPU exceeds threshold and increased meaningfully
                if new_info.cpu_percent > self.cpu_spike_threshold
                    && (new_info.cpu_percent - old_info.cpu_percent) > 5.0
                {
                    events.push(ProcessEvent::CpuSpike { pid: *pid, cpu: new_info.cpu_percent });
                }
            }
        }

        // Update previous snapshot
        // Publish events to runtime event bus
        for ev in &events {
            // publish event
            event_bus::publish(ev.clone());
            // apply incremental graph/state updates for start/terminate events
            match ev {
                ProcessEvent::Started(info) => {
                    // add node and parent edge
                    crate::domains::graph::apply_process_started(info.pid, &info.name, info.parent_pid);
                    // increment parent's child counter
                    if info.parent_pid != 0 {
                        crate::domains::security::state::incr_child_spawn(info.parent_pid, 1);
                    }
                }
                ProcessEvent::Terminated(pid) => {
                    crate::domains::graph::apply_process_terminated(*pid);
                }
                _ => {}
            }
        }

        // Run family-level observation using previous (self.prev) and the new snapshot
        let old_snapshot = self.prev.clone();
        self.prev = new;
        {
            let mut fe = GLOBAL_FAMILY_ENGINE.lock().unwrap();
            fe.observe(&old_snapshot, &self.prev);
        }
    }
}

static GLOBAL_ENGINE: Lazy<Mutex<Engine>> = Lazy::new(|| Mutex::new(Engine::new(20.0)));

pub fn diff_and_emit(new: ProcessState) {
    let mut g = GLOBAL_ENGINE.lock().unwrap();
    g.diff_and_emit(new)
}

/// Populate identity metadata (path, signer, company, category, risk_score)
/// for processes in the provided `ProcessState` using sysinfo and security policies.
pub fn populate_identities(state: &mut ProcessState) {
    use sysinfo::{System, ProcessesToUpdate};
    let mut sys = System::new_all();
    sys.refresh_processes(ProcessesToUpdate::All, false);

    // Precompute parent family for each pid to avoid mutable/immutable borrow conflicts
    use std::collections::HashMap as StdHashMap;
    let mut parent_family: StdHashMap<u32, Option<String>> = StdHashMap::new();
    for (pid, info) in state.processes.iter() {
        let pf = state.processes.get(&info.parent_pid).map(|p| crate::domains::process::state::family_for_name(&p.name));
        parent_family.insert(*pid, pf);
    }

    for (pid, info) in state.processes.iter_mut() {
        let pid_sys = sysinfo::Pid::from(*pid as usize);
        if let Some(proc) = sys.process(pid_sys) {
            // exe path
            let path_str = proc.exe().and_then(|p| p.to_str()).map(|s| s.to_string());
            if let Some(identity) = &mut info.identity {
                identity.path = path_str;
                // evaluate signature heuristics
                let ver = crate::domains::security::policies::evaluate_process_signature(*pid, &info.name);
                match ver {
                    crate::domains::security::policies::SignatureVerification::Signed => {
                        identity.signer = Some("signed".to_string());
                        identity.category = Some("trusted".to_string());
                        identity.risk_score = 0;
                        crate::domains::security::state::set_process_score(*pid, 0);
                    }
                    crate::domains::security::policies::SignatureVerification::Unsigned => {
                        identity.signer = Some("unsigned".to_string());
                        identity.category = Some("untrusted".to_string());
                        // Default unsigned penalty
                        let mut score: u8 = 80;
                        // Parent-context weighting: if parent family is vscode, reduce penalty
                        if let Some(Some(pfam)) = parent_family.get(pid) {
                            if pfam == "vscode" {
                                score = 30; // integrated terminal scenario
                            }
                        }
                        identity.risk_score = score;
                        crate::domains::security::state::set_process_score(*pid, score);
                    }
                    crate::domains::security::policies::SignatureVerification::VerificationFailed => {
                        identity.signer = Some("verification_failed".to_string());
                        identity.category = Some("unknown".to_string());
                        let mut score: u8 = 50;
                        if let Some(Some(pfam)) = parent_family.get(pid) {
                            if pfam == "vscode" {
                                score = 20;
                            }
                        }
                        identity.risk_score = score;
                        crate::domains::security::state::set_process_score(*pid, score);
                    }
                    crate::domains::security::policies::SignatureVerification::Unknown => {
                        // leave signer/company empty; no score change
                        identity.signer = None;
                    }
                }
            }
        }
    }
}

// Family-aware engine for detecting family-level CPU spikes using simple
// hysteresis (consecutive observations) to avoid flapping.
struct FamilyEngine {
    spike_threshold: f64,
    consecutive_required: usize,
    state: HashMap<String, (usize, usize, bool)>, // family -> (consec_spikes, consec_normals, active_spike)
}

impl FamilyEngine {
    fn new(spike_threshold: f64, consecutive_required: usize) -> Self {
        Self { spike_threshold, consecutive_required, state: HashMap::new() }
    }

    fn observe(&mut self, old: &ProcessState, new: &ProcessState) {
        // consider families present in either snapshot
        let mut families = std::collections::BTreeSet::new();
        for k in old.families.keys() { families.insert(k.clone()); }
        for k in new.families.keys() { families.insert(k.clone()); }

        for fam in families.into_iter() {
            let old_cpu = old.families.get(&fam).map(|f| f.total_cpu).unwrap_or(0.0);
            let new_cpu = new.families.get(&fam).map(|f| f.total_cpu).unwrap_or(0.0);
            let entry = self.state.entry(fam.clone()).or_insert((0usize, 0usize, false));

            if new_cpu > self.spike_threshold && (new_cpu - old_cpu) > 5.0 {
                entry.0 += 1; // consec_spikes
                entry.1 = 0; // reset normals
            } else {
                entry.1 += 1; // consec_normals
                entry.0 = 0; // reset spikes
            }

            if !entry.2 && entry.0 >= self.consecutive_required {
                // raise family spike
                entry.2 = true;
                event_bus::publish(ProcessEvent::FamilyCpuSpike { family: fam.clone(), cpu: new_cpu });
            } else if entry.2 && entry.1 >= self.consecutive_required {
                // normalized
                entry.2 = false;
                event_bus::publish(ProcessEvent::FamilyNormalized { family: fam.clone() });
            }
        }
    }
}

static GLOBAL_FAMILY_ENGINE: Lazy<Mutex<FamilyEngine>> = Lazy::new(|| Mutex::new(FamilyEngine::new(50.0, 2)));


/// Compute family-level metrics from a `ProcessState` and return a sorted
/// vector of `(family_name, ProcessFamily)` ordered by total_cpu desc.
pub fn compute_family_metrics(state: &ProcessState) -> Vec<(String, crate::domains::process::state::ProcessFamily)> {
    let mut v: Vec<(String, crate::domains::process::state::ProcessFamily)> = state.families.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    v.sort_by(|a, b| b.1.total_cpu.partial_cmp(&a.1.total_cpu).unwrap_or(std::cmp::Ordering::Equal));
    v
}
