use crate::domains::security::SecurityEvent;
use crate::domains::security::{policies, state};
use crate::runtime::events;
use crate::runtime::event_bus;
use once_cell::sync::Lazy;
use std::sync::Mutex;

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register() {
    // subscribe via the runtime event facade to avoid direct domain imports
    let sub = events::subscribe_to_process_events(Box::new(|ev| match ev {
        crate::domains::process::events::ProcessEvent::Started(info) => {
            if info.name.to_lowercase().contains("powershell") {
                event_bus::publish(SecurityEvent::PowershellSpawned { pid: info.pid });
            }

            // Heuristic observations moved from runtime: attribute basic file/socket counts
            let lname = info.name.to_lowercase();
            if lname.contains("powershell") {
                state::incr_file_create(info.pid, 1);
                state::evaluate_behavior(info.pid);
            }
            if lname.contains("chrome") || lname.contains("brave") || lname.contains("edge") {
                state::incr_socket_open(info.pid, 1);
                state::evaluate_behavior(info.pid);
            }

            // Update behavior counters: attribute child spawn to parent and evaluate
            // Attribute to direct parent (if available)
            if info.parent_pid != 0 {
                state::incr_child_spawn(info.parent_pid, 1);
                state::evaluate_behavior(info.parent_pid);
                // If parent's behavior evaluation reached a critical status, emit a handle-hijack signal
                let status = state::status_for_pid(info.parent_pid);
                if let crate::domains::security::SecurityStatus::Critical = status {
                    event_bus::publish(SecurityEvent::HandleHijackDetected { pid: info.parent_pid });
                }
            }

            // Publish relationship/origin information when we have a latest snapshot
            if let Some(state) = crate::runtime::get_latest_state() {
                let ancestors = state.lineage.get_ancestors(info.pid);
                if !ancestors.is_empty() {
                    // top-most ancestor (closest to root) is last in the chain
                    let origin_pid = *ancestors.last().unwrap();
                    let origin_name = state.processes.get(&origin_pid).map(|p| p.name.clone()).unwrap_or_else(|| "<unknown>".to_string());
                    // build readable lineage names (ancestor -> ... -> parent)
                    let mut lineage: Vec<String> = Vec::new();
                    for a in ancestors.iter().rev() {
                        if let Some(p) = state.processes.get(a) {
                            lineage.push(format!("{}({})", p.name, p.pid));
                        }
                    }
                    event_bus::publish(SecurityEvent::ProcessSpawnedBy { pid: info.pid, origin_pid, origin_name, lineage });
                }
            }

            let ver = policies::evaluate_process_signature(info.pid, &info.name);
            match ver {
                crate::domains::security::policies::SignatureVerification::Signed => {
                    // signed -> lower any existing score
                    state::set_process_score(info.pid, 0);
                    // record contributor
                    state::record_contribution(info.pid, "signed", 0);
                }
                crate::domains::security::policies::SignatureVerification::Unsigned => {
                    event_bus::publish(SecurityEvent::UnsignedProcessStarted { pid: info.pid, name: info.name.clone() });
                    // strong signal -> mark high score
                    state::record_contribution(info.pid, "unsigned", 90);
                }
                other => {
                    // Emit an informational verification result so surfaces can decide.
                    event_bus::publish(SecurityEvent::ProcessSignatureVerification { pid: info.pid, name: info.name.clone(), result: other.clone() });
                    // Adjust score conservatively based on result. Treat Unknown as informational (no score),
                    // and only increase score for explicit verification failures.
                    match other {
                        crate::domains::security::policies::SignatureVerification::VerificationFailed => {
                            state::record_contribution(info.pid, "verification_failed", 20);
                        }
                        crate::domains::security::policies::SignatureVerification::Unknown => {
                            // intentionally no score change for Unknown to avoid noisy alerts
                        }
                        _ => {}
                    }
                }
            }
            // Additional heuristics: decompose power-shell/script signals into explainable contributions
            let lname = info.name.to_lowercase();
            if lname.contains("powershell") || lname.contains("pwsh") || lname.contains("cscript") || lname.contains("wscript") {
                // generic script engine signal
                state::record_contribution(info.pid, "script_engine", 20);
                // specific powershell signal
                if lname.contains("powershell") || lname.contains("pwsh") {
                    state::record_contribution(info.pid, "powershell", 20);
                }

                // interactive console detection: parent is conhost/cmd/powershell
                if let Some(state_snap) = crate::runtime::get_latest_state() {
                    if let Some(parent) = state_snap.processes.get(&info.parent_pid) {
                        let parent_name = parent.name.to_lowercase();
                        if parent_name.contains("conhost") || parent_name.contains("cmd") || parent_name.contains("powershell") {
                            state::record_contribution(info.pid, "interactive_console", 10);
                        }
                    }

                    // spawned from dev tools: check ancestry for vscode/code
                    let ancestors = state_snap.lineage.get_ancestors(info.pid);
                    for a in ancestors.iter() {
                        if let Some(p) = state_snap.processes.get(a) {
                            let pn = p.name.to_lowercase();
                            if pn.contains("code") || pn.contains("vscode") {
                                state::record_contribution(info.pid, "spawned_from_devtool", 10);
                                break;
                            }
                        }
                    }
                }
            }
        }
        _ => {}
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn unregister() {
    let mut v = SUBS.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_process_events(sub.id);
    }
}
