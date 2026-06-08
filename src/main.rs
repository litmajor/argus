mod core;
mod runtime;
mod domains;
mod actions;
mod surfaces;
mod persistence;
mod timeline;
mod bridge;
mod ui;

use std::{sync::{Arc, atomic::{AtomicBool, Ordering}}};
use chrono::{Local, Utc, TimeZone};

fn main() {
    println!("Argus SSA Process Monitor — live");

    let running = Arc::new(AtomicBool::new(true));
    {
        let r = running.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);
        }).expect("Error setting Ctrl-C handler");
    }

    // Register surfaces and engines
    surfaces::console::register();
    surfaces::overview::register();
    surfaces::process::register();
    surfaces::findings::register();
    surfaces::security::register();

    crate::domains::security::engine::register();
    crate::domains::rules::register_defaults();
    crate::domains::memory::engine::register();
    crate::domains::cpu::engine::register();

    // Register persistence subscribers and load latest snapshot
    crate::domains::process::subscribers::register_file_logger("events.log");
    crate::domains::process::subscribers::register_persistence();
    crate::domains::process::subscribers::register_udp_publisher("127.0.0.1:9000");
    if let Some(s) = crate::persistence::load_latest_snapshot() {
        println!("Loaded snapshot from ts={}", s.ts);
    }

    // Timeline recorder: stores timestamped events to daily JSONL
    crate::timeline::register();

    // Start the HTTP + WebSocket IPC bridge on localhost:3000
    crate::bridge::start("127.0.0.1:3000");

    // Spawn REPL thread for commands
    {
        let running = running.clone();
        std::thread::spawn(move || {
            use std::io::{self, BufRead};
            let stdin = io::stdin();
            let mut handle = stdin.lock();
            let mut line = String::new();
            println!("Action REPL ready. Commands: why <pid>, show <graph|findings|timeline> ..., diff yesterday, kill/suspend/resume/export, quit");
            while running.load(Ordering::SeqCst) {
                line.clear();
                if handle.read_line(&mut line).is_err() { break; }
                let input = line.trim();
                if input.is_empty() { continue; }
                let mut parts = input.split_whitespace();
                match parts.next().unwrap_or("") {
                    "why" => {
                        if let Some(pid_s) = parts.next() {
                            if let Ok(pid) = pid_s.parse::<u32>() {
                                let path = crate::domains::graph::reason_structured_for_pid(pid);
                                if path.is_empty() { println!("No graph path found for pid {}", pid); }
                                else {
                                    let graph = crate::domains::graph::get_graph();
                                    println!("Reason trace for pid {}:", pid);
                                    for (node, edges) in path {
                                        println!(" - {} ({:?})", node.name, node.node_type);
                                        for e in edges { let dst = graph.nodes.get(&e.dst).map(|n| n.name.clone()).unwrap_or(e.dst.clone()); println!("    -> {:?} -> {} (count={} ts={})", e.kind, dst, e.count, e.ts); }
                                    }
                                    let names = crate::domains::graph::reason_for_pid(pid);
                                    if !names.is_empty() { println!("Ancestry: {}", names.join(" -> ")); }
                                    // publish to UI
                                    let mut body = String::new();
                                    body.push_str(&format!("Ancestry: {}\n", names.join(" -> ")));
                                    for e in crate::domains::graph::reason_edges_for_pid(pid).iter() { let src = crate::domains::graph::get_graph().nodes.get(&e.src).map(|n| n.name.clone()).unwrap_or(e.src.clone()); let dst = crate::domains::graph::get_graph().nodes.get(&e.dst).map(|n| n.name.clone()).unwrap_or(e.dst.clone()); body.push_str(&format!("{} --{:?}--> {}\n", src, e.kind, dst)); }
                                    crate::runtime::event_bus::publish(crate::runtime::events::UiMessage { topic: "why".to_string(), body });
                                }
                            } else { println!("Invalid pid: {}", pid_s); }
                        } else { println!("Usage: why <pid>"); }
                    }
                    "show" => {
                        if let Some(sub) = parts.next() {
                            match sub {
                                "graph" => {
                                    if let Some(pid_s) = parts.next() {
                                        if let Ok(pid) = pid_s.parse::<u32>() {
                                            if let Some(depth_s) = parts.next() {
                                                if let Ok(depth) = depth_s.parse::<usize>() { crate::surfaces::process::show_graph_depth(pid, depth); }
                                                else { println!("Invalid depth: {}", depth_s); }
                                            } else {
                                                crate::surfaces::process::show_graph(pid);
                                            }
                                        } else { println!("Invalid pid: {}", pid_s); }
                                    } else { println!("Usage: show graph <pid>"); }
                                }
                                "findings" => { if let Some(n_s) = parts.next() { if let Ok(n) = n_s.parse::<usize>() { crate::surfaces::findings::show_recent(n); } else { println!("Invalid number: {}", n_s); } } else { crate::surfaces::findings::show_recent(10); } }
                                "timeline" => { if let Some(arg) = parts.next() { if arg == "pid" { if let Some(pid_s) = parts.next() { if let Ok(pid) = pid_s.parse::<u32>() { for r in crate::timeline::query_pid(pid) { println!("{:?}", r); } } else { println!("Invalid pid: {}", pid_s); } } else { println!("Usage: show timeline pid <pid>"); } } else { println!("Unknown timeline arg: {}", arg); } } else { println!("Usage: show timeline pid <pid>"); } }
                                other => { println!("Unknown show subcommand: {}", other); }
                            }
                        } else { println!("Usage: show <graph|findings|timeline>"); }
                    }
                    "diff" => {
                        if let Some(sub) = parts.next() {
                            match sub {
                                "yesterday" => {
                                    use crate::persistence::{Snapshot, SerializableProcessInfo, SerializableProcessIdentity, SerializableFinding};
                                    let mut procs: Vec<SerializableProcessInfo> = Vec::new();
                                    if let Some(state) = crate::runtime::get_latest_state() { for p in state.processes.values() { let identity = p.identity.as_ref().map(|id| SerializableProcessIdentity { path: id.path.clone(), signer: id.signer.clone(), company: id.company.clone(), category: id.category.clone(), start_time: id.start_time, risk_score: id.risk_score }); procs.push(SerializableProcessInfo { pid: p.pid, name: p.name.clone(), cpu_percent: p.cpu_percent, memory_mb: p.memory_mb, threads: p.threads, parent_pid: p.parent_pid, identity }); } }
                                    let g = crate::domains::graph::get_graph();
                                    let findings = crate::domains::rules::evaluate_all();
                                    let mut findings_ser: Vec<SerializableFinding> = Vec::new();
                                    for f in findings.iter() { findings_ser.push(SerializableFinding { title: f.title.clone(), description: f.description.clone(), risk: f.risk, severity: format!("{:?}", f.severity) }); }
                                    let mut risk_vec: Vec<(u32,u8)> = Vec::new();
                                    if let Some(state) = crate::runtime::get_latest_state() { for pid in state.processes.keys() { let sc = crate::domains::security::state::get_process_score(*pid); risk_vec.push((*pid, sc)); } }
                                    let current = Snapshot { ts: chrono::Local::now().timestamp(), processes: procs, graph: g, findings: findings_ser, risk: risk_vec };
                                    let diff = crate::persistence::compare_with_loaded(&current);
                                    println!("{}", diff);
                                }
                                other => { println!("Unknown diff target: {}", other); }
                            }
                        } else { println!("Usage: diff yesterday"); }
                    }
                    "kill" => { if let Some(pid_s) = parts.next() { if let Ok(pid) = pid_s.parse::<u32>() { if pid <= 4 { println!("Refusing to kill reserved/system pid {}", pid); } else { println!("Confirm kill pid {}? Type 'yes' to confirm:", pid); line.clear(); if handle.read_line(&mut line).is_ok() && line.trim() == "yes" { let _ = crate::actions::kill(pid); } } } else { println!("Invalid pid: {}", pid_s); } } else { println!("Usage: kill <pid>"); } }
                    "suspend" => { if let Some(pid_s) = parts.next() { if let Ok(pid) = pid_s.parse::<u32>() { if pid <= 4 { println!("Refusing to suspend reserved/system pid {}", pid); } else { println!("Confirm suspend pid {}? Type 'yes' to confirm:", pid); line.clear(); if handle.read_line(&mut line).is_ok() && line.trim() == "yes" { let _ = crate::actions::suspend(pid); } } } else { println!("Invalid pid: {}", pid_s); } } else { println!("Usage: suspend <pid>"); } }
                    "resume" => { if let Some(pid_s) = parts.next() { if let Ok(pid) = pid_s.parse::<u32>() { println!("Confirm resume pid {}? Type 'yes' to confirm:", pid); line.clear(); if handle.read_line(&mut line).is_ok() && line.trim() == "yes" { let _ = crate::actions::resume(pid); } } else { println!("Invalid pid: {}", pid_s); } } else { println!("Usage: resume <pid>"); } }
                    "export" => { if let Some(path) = parts.next() { match crate::runtime::get_latest_state() { Some(state) => { match crate::actions::export_snapshot(&state, path) { Ok(_) => println!("Exported snapshot to {}", path), Err(e) => println!("Export failed: {}", e), } } None => { println!("No live snapshot available; exporting empty snapshot"); let state = crate::domains::process::ProcessState::default(); match crate::actions::export_snapshot(&state, path) { Ok(_) => println!("Exported snapshot to {}", path), Err(e) => println!("Export failed: {}", e), } } } } else { println!("Usage: export <path>"); } }
                    "quit" | "exit" => { println!("Exiting REPL"); running.store(false, Ordering::SeqCst); break; }
                    other => { println!("Unknown command: {}", other); }
                }
            }
        });
    }

    // Run TUI dashboard (blocks until quit or Ctrl-C)
    crate::ui::run(running.clone());

    // shutdown
    surfaces::console::unregister();
    surfaces::process::unregister();
    surfaces::security::unregister();
    surfaces::overview::unregister();
    surfaces::findings::unregister();
    crate::timeline::unregister();
    crate::domains::process::subscribers::unregister_all();
    crate::domains::security::engine::unregister();
    crate::domains::memory::engine::unregister();

    // persisted events
    let events = crate::domains::process::storage::get_events();
    if !events.is_empty() {
        println!("\nPersisted Events ({}):", events.len());
        for (ts, ev) in events {
            let t = match Utc.timestamp_opt(ts, 0).single() {
                Some(dt) => dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string(),
                None => Utc.timestamp_opt(0, 0).single().unwrap().with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string(),
            };
            println!("[{}] {}", t, ev);
        }
    }

    crate::persistence::save_snapshot();

    println!("Exiting.");
}
