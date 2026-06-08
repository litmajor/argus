use std::cmp::Ordering;

pub mod collectors;
pub mod events;
pub mod event_bus;
use crate::domains::process;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::Instant;
use std::sync::Mutex as SyncMutex;

// Shared latest process snapshot (updated each runtime cycle). Surfaces or
// external threads can read a clone via `get_latest_state()`.
static LATEST_STATE: Lazy<Mutex<Option<process::ProcessState>>> = Lazy::new(|| Mutex::new(None));

static UI_ACTIVE: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));

pub fn set_latest_state(s: process::ProcessState) {
    let mut guard = LATEST_STATE.lock().unwrap();
    *guard = Some(s);
}

pub fn get_latest_state() -> Option<process::ProcessState> {
    let guard = LATEST_STATE.lock().unwrap();
    guard.clone()
}

pub fn set_ui_active(v: bool) {
    UI_ACTIVE.store(v, AtomicOrdering::SeqCst);
}

pub fn is_ui_active() -> bool {
    UI_ACTIVE.load(AtomicOrdering::SeqCst)
}

pub fn start(silent: bool) {
    if !silent { println!("Runtime starting collectors..."); }

    match collectors::process_collector::collect_processes() {
        Ok(mut procs) => {
            // sort by CPU desc
            procs.sort_by(|a, b| b.cpu_percent.partial_cmp(&a.cpu_percent).unwrap_or(Ordering::Equal));
                if !silent {
                    println!("{:<6}  {:<25}  {:>6}  {:>8}  {:>7}", "PID", "NAME", "CPU%", "MEM(MB)", "THREADS");
                }
            for p in procs.iter().take(20) {
                let score = crate::domains::security::state::get_process_score(p.pid);
                let status = crate::domains::security::state::status_for_pid(p.pid);
                    if !silent {
                        println!("{:6}  {:25.25}  {:6.1}  {:8.1}  {:7}  SCORE:{:3}% {:?}", p.pid, p.name, p.cpu_percent, p.memory_mb, p.threads, score, status);
                    }
            }

            // Collect CPU and memory domains (they publish events to their buses)
            let _ = collectors::cpu_collector::collect_cpu();
            let _ = collectors::memory_collector::collect_memory();

            // Build process snapshot and run diff engine to emit events
            let state = process::ProcessState::from_vec(procs);
            // Heuristic instrumentation moved to domain engines (collectors/runtime should not contain heuristics)
            // Populate identity metadata (paths/signers) before rebuilding the graph
            let mut state_mut = state.clone();
            crate::domains::process::engine::populate_identities(&mut state_mut);
            // Rebuild system knowledge graph for the snapshot periodically
            // to reconcile with occasional missed incremental events.
            const RECONCILE_INTERVAL_SECS: u64 = 30;
            static LAST_RECONCILE: Lazy<SyncMutex<Option<Instant>>> = Lazy::new(|| SyncMutex::new(None));
            let now = Instant::now();
            let mut last = LAST_RECONCILE.lock().unwrap();
            let do_rebuild = match *last {
                Some(ts) => now.duration_since(ts).as_secs() >= RECONCILE_INTERVAL_SECS,
                None => true,
            };
            if do_rebuild {
                crate::domains::graph::rebuild_from_state(state_mut.clone());
                *last = Some(now);
            }
            // Use the graph API to fetch current graph and print basic counts
            let g = crate::domains::graph::get_graph();
                if !silent { println!("Graph nodes: {} edges: {}", g.nodes.len(), g.edges.len()); }
            // Compute and print top families for quick inspection (uses compute_family_metrics)
            let fams = crate::domains::process::engine::compute_family_metrics(&state_mut);
            if !fams.is_empty() {
                    if !silent { println!("Top families by CPU:"); }
                for (i, (_name, fam)) in fams.into_iter().take(5).enumerate() {
                    // Use the stored `ProcessFamily.name` field to exercise its usage
                        if !silent { println!("  {}. {} -> {:.1} CPU across {} procs", i + 1, fam.name, fam.total_cpu, fam.count); }
                }
            }
            // Engine now publishes events to the bus
            process::diff_and_emit(state_mut.clone());

            // Update the shared latest snapshot for other threads (REPL/export)
            set_latest_state(state_mut.clone());

            // Evaluate rules against the current graph/state and print findings
            let findings = crate::domains::rules::evaluate_all();
            if !findings.is_empty() {
                    if !silent { println!("Findings:"); }
                for f in findings {
                        if !silent { println!(" - {} | risk={} severity={:?}\n   {}", f.title, f.risk, f.severity, f.description); }
                }
            }

            // Publish raw per-process memory samples as observations for the memory domain
            for (pid, info) in state.processes.iter() {
                crate::runtime::event_bus::publish(crate::domains::memory::events::MemoryEvent::ProcessMemorySample { pid: *pid, memory_mb: info.memory_mb });
            }

            // Render a simple ASCII process tree
            use std::collections::{HashMap, HashSet};

            let proc_map: HashMap<u32, process::state::ProcessInfo> = state.processes.clone();
            let mut children: HashMap<u32, Vec<process::state::ProcessInfo>> = HashMap::new();
            for info in proc_map.values() {
                children.entry(info.parent_pid).or_default().push(info.clone());
            }

            for vec in children.values_mut() {
                vec.sort_by(|a, b| a.name.cmp(&b.name));
            }

            let roots: Vec<process::state::ProcessInfo> = proc_map
                .values()
                .filter(|info| info.parent_pid == 0 || !proc_map.contains_key(&info.parent_pid))
                .cloned()
                .collect();

            fn print_node(
                info: &process::state::ProcessInfo,
                children: &HashMap<u32, Vec<process::state::ProcessInfo>>,
                prefix: &str,
                is_last: bool,
                visited: &mut HashSet<u32>,
                silent: bool,
            ) {
                if visited.contains(&info.pid) {
                    if !silent { println!("{}{} (cycle)", prefix, info.name); }
                    return;
                }
                visited.insert(info.pid);
                let branch = if prefix.is_empty() { "" } else if is_last { "└── " } else { "├── " };
                let score = crate::domains::security::state::get_process_score(info.pid);
                let status = crate::domains::security::state::status_for_pid(info.pid);
                if !silent { println!("{}{}{} ({})  SCORE:{:3}% {:?}", prefix, branch, info.name, info.pid, score, status); }
                let child_list = children.get(&info.pid);
                if let Some(cl) = child_list {
                    // Group children by family for entity resolution
                    use std::collections::BTreeMap;
                    let mut groups: BTreeMap<String, Vec<process::state::ProcessInfo>> = BTreeMap::new();
                    for child in cl.iter() {
                        let fam = crate::domains::process::state::family_for_name(&child.name);
                        groups.entry(fam).or_default().push(child.clone());
                    }

                    let group_count = groups.len();
                    for (gi, (fam, procs)) in groups.into_iter().enumerate() {
                        let group_is_last = gi + 1 == group_count;
                        let group_branch = if prefix.is_empty() { "" } else if group_is_last { "└── " } else { "├── " };
                                if !silent { println!("{}{}{} ({})", prefix, group_branch, fam, procs.len()); }

                        // print processes inside the family group
                        let proc_count = procs.len();
                        for (pi, p) in procs.into_iter().enumerate() {
                            let proc_is_last = pi + 1 == proc_count;
                            let _proc_branch = if proc_is_last { "└── " } else { "├── " };
                            let new_prefix = format!("{}{}", prefix, if prefix.is_empty() { "" } else if group_is_last { "    " } else { "│   " });
                                // recurse to print this process and its descendants
                                print_node(&p, children, &new_prefix, proc_is_last, visited, silent);
                        }
                    }
                }
            }

                if !silent { println!("\nProcess Tree:"); }
            let mut visited = HashSet::new();
            for (i, root) in roots.iter().enumerate() {
                let last = i + 1 == roots.len();
                print_node(root, &children, "", last, &mut visited, silent);
            }
            // If there's a high scoring PID, print its lineage to help investigation
            let mut highest_pid: Option<u32> = None;
            let mut highest_score: u8 = 0;
            for (pid, _) in proc_map.iter() {
                let sc = crate::domains::security::state::get_process_score(*pid);
                if sc > highest_score {
                    highest_score = sc;
                    highest_pid = Some(*pid);
                }
            }
            if let Some(pid) = highest_pid {
                if highest_score > 0 {
                        if !silent { println!("\nHighest security score: {}% for PID {} - showing lineage:", highest_score, pid); }
                    crate::surfaces::process::show_lineage(pid);
                    crate::surfaces::process::show_graph(pid);
                }
            }
        }
        Err(e) => {
            eprintln!("Error collecting processes: {:?}", e);
        }
    }
}
