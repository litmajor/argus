use once_cell::sync::Lazy;
use std::sync::Mutex;

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register() {
    // Process surface can react to process events; for now we print counts via overview
    let sub = crate::runtime::events::subscribe_to_process_events(Box::new(|ev| match ev {
        crate::domains::process::events::ProcessEvent::Started(info) => {
            // Build a multi-line message describing the started process
            let mut body_lines: Vec<String> = Vec::new();
            body_lines.push(format!("[ProcessSurface] Started: {} ({})", info.name, info.pid));
            if let Some(identity) = &info.identity {
                if let Some(st) = identity.start_time {
                    body_lines.push(format!("  Identity start_time: {}", st));
                }
                body_lines.push(format!("  Identity risk_score: {}", identity.risk_score));
                if let Some(p) = &identity.path {
                    body_lines.push(format!("  Identity path: {}", p));
                }
                if let Some(signer) = &identity.signer {
                    body_lines.push(format!("  Identity signer: {}", signer));
                }
                if let Some(company) = &identity.company {
                    body_lines.push(format!("  Identity company: {}", company));
                }
                if let Some(category) = &identity.category {
                    body_lines.push(format!("  Identity category: {}", category));
                }
            }

            // Print lineage and family aggregation for the started process
            if let Some(state) = crate::runtime::get_latest_state() {
                // ancestors
                let ancestors = state.lineage.get_ancestors(info.pid);
                if !ancestors.is_empty() {
                    let mut s = format!("[ProcessSurface] Ancestors for {}: ", info.pid);
                    for a in ancestors.iter().rev() {
                        if let Some(p) = state.processes.get(a) {
                            s.push_str(&format!("{}({}) ", p.name, p.pid));
                        }
                    }
                    body_lines.push(s);
                }

                // direct children
                let children = state.lineage.get_children(info.pid);
                if !children.is_empty() {
                    body_lines.push(format!("[ProcessSurface] Children of {}: {}", info.pid, children.len()));
                    for c in children.iter() {
                        if let Some(p) = state.processes.get(c) {
                            body_lines.push(format!("  - {} ({}) CPU:{:.1}% MEM:{:.1}", p.name, p.pid, p.cpu_percent, p.memory_mb));
                        }
                    }
                }
            }

            // If UI is active, publish as UiMessage; otherwise print to stdout
            let body = body_lines.join("\n");
            if crate::runtime::is_ui_active() {
                crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "process".to_string(), body });
            } else {
                println!("{}", body);
            }
        }
        crate::domains::process::events::ProcessEvent::Terminated(pid) => {
            if crate::runtime::is_ui_active() {
                crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "process".to_string(), body: format!("[ProcessSurface] Terminated: {}", pid) });
            } else {
                println!("[ProcessSurface] Terminated: {}", pid);
            }
        }
        crate::domains::process::events::ProcessEvent::CpuSpike { pid, cpu } => {
            if crate::runtime::is_ui_active() {
                crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "process".to_string(), body: format!("[ProcessSurface] CPU spike: {} -> {:.1}%", pid, cpu) });
            } else {
                println!("[ProcessSurface] CPU spike: {} -> {:.1}%", pid, cpu);
            }
        }
        crate::domains::process::events::ProcessEvent::FamilyCpuSpike { family, cpu } => {
            if crate::runtime::is_ui_active() {
                crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "process".to_string(), body: format!("[ProcessSurface] Family CPU spike: {} -> {:.1}%", family, cpu) });
            } else {
                println!("[ProcessSurface] Family CPU spike: {} -> {:.1}%", family, cpu);
            }
        }
        crate::domains::process::events::ProcessEvent::FamilyNormalized { family } => {
            if crate::runtime::is_ui_active() {
                crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "process".to_string(), body: format!("[ProcessSurface] Family normalized: {}", family) });
            } else {
                println!("[ProcessSurface] Family normalized: {}", family);
            }
        }
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn unregister() {
    let mut v = SUBS.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_process_events(sub.id);
    }
}

/// Programmatic helper: print lineage for a given PID using latest state snapshot.
pub fn show_lineage(pid: u32) {
    if let Some(state) = crate::runtime::get_latest_state() {
        println!("Process Lineage for PID {}:", pid);
        // ancestors
        let ancestors = state.lineage.get_ancestors(pid);
        if ancestors.is_empty() {
            println!("  Ancestors: <none>");
        } else {
            print!("  Ancestors: ");
            for a in ancestors.iter().rev() {
                if let Some(p) = state.processes.get(a) {
                    print!("{}({}) ", p.name, p.pid);
                }
            }
            println!("");
        }

        // descendants (direct children)
        let children = state.lineage.get_children(pid);
        // direct parent
        if let Some(parent_pid) = state.lineage.get_parent(pid) {
            if let Some(p) = state.processes.get(&parent_pid) {
                println!("  Parent: {} ({})", p.name, p.pid);
            }
        }
        if children.is_empty() {
            println!("  Children: <none>");
        } else {
            println!("  Children:");
            for c in children.iter() {
                if let Some(p) = state.processes.get(c) {
                    println!("    - {} ({}) CPU:{:.1}% MEM:{:.1}", p.name, p.pid, p.cpu_percent, p.memory_mb);
                }
            }
        }
    } else {
        println!("No latest state available");
    }
}

pub fn show_graph(pid: u32) {
    println!("Graph neighbors for PID {}:", pid);
    let neigh = crate::domains::graph::get_neighbors_for_pid(pid);
    if neigh.is_empty() {
        println!("  <none>");
    } else {
        for n in neigh.iter() {
            let pid_info = n.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
            println!("  - {} [{}] pid={} id={}", n.name, match n.node_type {
                crate::domains::graph::NodeType::Process => "process",
                crate::domains::graph::NodeType::File => "file",
                crate::domains::graph::NodeType::Socket => "socket",
                crate::domains::graph::NodeType::User => "user",
                crate::domains::graph::NodeType::Service => "service",
                crate::domains::graph::NodeType::Registry => "registry",
                crate::domains::graph::NodeType::Other => "other",
            }, pid_info, n.id);
        }
    }
}

/// Show neighbors up to `depth` edges away (BFS). Depth 1 behaves like `show_graph`.
pub fn show_graph_depth(pid: u32, depth: usize) {
    println!("Graph neighbors for PID {} (depth={}):", pid, depth);
    if depth == 0 {
        println!("  <none> (depth 0)");
        return;
    }
    let neigh = crate::domains::graph::get_neighbors_for_pid_depth(pid, depth);
    if neigh.is_empty() {
        println!("  <none>");
    } else {
        for n in neigh.iter() {
            let pid_info = n.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
            println!("  - {} [{}] pid={} id={}", n.name, match n.node_type {
                crate::domains::graph::NodeType::Process => "process",
                crate::domains::graph::NodeType::File => "file",
                crate::domains::graph::NodeType::Socket => "socket",
                crate::domains::graph::NodeType::User => "user",
                crate::domains::graph::NodeType::Service => "service",
                crate::domains::graph::NodeType::Registry => "registry",
                crate::domains::graph::NodeType::Other => "other",
            }, pid_info, n.id);
        }
    }
    // also publish to UI
    let mut body = String::new();
    for n in neigh.iter() {
        let pid_info = n.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".to_string());
        body.push_str(&format!("- {} [{}] pid={} id={}\n", n.name, match n.node_type { crate::domains::graph::NodeType::Process => "process", crate::domains::graph::NodeType::File => "file", crate::domains::graph::NodeType::Socket => "socket", crate::domains::graph::NodeType::User => "user", crate::domains::graph::NodeType::Service => "service", crate::domains::graph::NodeType::Registry => "registry", crate::domains::graph::NodeType::Other => "other", }, pid_info, n.id));
    }
    crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "graph-depth".to_string(), body });
}
