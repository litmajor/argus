use std::thread;
use std::sync::Arc;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use tokio::runtime::Runtime;
use tokio::sync::broadcast::{self, Sender};
use axum::{Router, routing::get, extract::Query, response::Json, http::StatusCode, extract::ws::{WebSocketUpgrade, Message, WebSocket}};
use serde_json::json;
use chrono::Utc;
use tower_http::cors::{CorsLayer, Any};
use futures::{StreamExt, SinkExt};

#[derive(Clone)]
struct AppState {
    tx: Sender<String>,
}

// Keep subscriptions so they unsubscribe on bridge drop/restart
static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Start the bridge in a background thread and return immediately.
pub fn start(listen_addr: &str) {
    // Clear stale subscriptions if bridge restarted
    SUBS.lock().unwrap().clear();

    let addr = listen_addr.to_string();
    thread::spawn(move || {
        // Build a multi-threaded Tokio runtime for the server
        let rt = Runtime::new().expect("Failed to create Tokio runtime for bridge");
        rt.block_on(async move {
            // broadcast channel for websocket clients
            let (tx, _rx) = broadcast::channel::<String>(1024);
            let state = AppState { tx: tx.clone() };

            // Subscribe to runtime event bus and forward events into broadcast channel
            // Process events
            let tx_p = tx.clone();
            let sub_p = crate::runtime::events::subscribe_to_process_events(Box::new(move |ev| {
                let tx = tx_p.clone();
                match ev {
                    crate::domains::process::events::ProcessEvent::Started(info) => {
                        // Build serializable process info
                        let ser = crate::persistence::SerializableProcessInfo {
                            pid: info.pid,
                            name: info.name.clone(),
                            cpu_percent: info.cpu_percent,
                            memory_mb: info.memory_mb,
                            threads: info.threads,
                            parent_pid: info.parent_pid,
                            identity: info.identity.as_ref().map(|id| crate::persistence::SerializableProcessIdentity {
                                path: id.path.clone(), signer: id.signer.clone(), company: id.company.clone(), category: id.category.clone(), start_time: id.start_time, risk_score: id.risk_score
                            }),
                        };
                        if let Ok(p) = serde_json::to_value(&ser) {
                            let we = json!({"kind": "process.started", "payload": p, "ts": Utc::now().timestamp_millis()});
                            let _ = tx.send(we.to_string());
                        }
                    }
                    crate::domains::process::events::ProcessEvent::Terminated(pid) => {
                        let we = json!({"kind": "process.terminated", "payload": {"pid": pid}, "ts": Utc::now().timestamp_millis()});
                        let _ = tx.send(we.to_string());
                    }
                    crate::domains::process::events::ProcessEvent::CpuSpike { pid, cpu } => {
                        let we = json!({"kind": "process.cpuspike", "payload": {"pid": pid, "cpu": cpu}, "ts": Utc::now().timestamp_millis()});
                        let _ = tx.send(we.to_string());
                    }
                    _ => {}
                }
            }));
            SUBS.lock().unwrap().push(sub_p);

            // Memory events
            let tx_mem = tx.clone();
            let sub_m = crate::runtime::events::subscribe_to_memory_events(Box::new(move |ev| match ev {
                crate::domains::memory::events::MemoryEvent::UsedSample { used_mb } => {
                    let we = json!({"kind": "memory.used", "payload": {"used_mb": used_mb}, "ts": Utc::now().timestamp_millis()});
                    let _ = tx_mem.send(we.to_string());
                }
                crate::domains::memory::events::MemoryEvent::PressureHigh { used_mb } => {
                    let we = json!({"kind": "memory.pressure", "payload": {"used_mb": used_mb}, "ts": Utc::now().timestamp_millis()});
                    let _ = tx_mem.send(we.to_string());
                }
                crate::domains::memory::events::MemoryEvent::ProcessMemorySample { pid, memory_mb } => {
                    let we = json!({"kind": "memory.process", "payload": {"pid": pid, "memory_mb": memory_mb}, "ts": Utc::now().timestamp_millis()});
                    let _ = tx_mem.send(we.to_string());
                }
                _ => {}
            }));
            SUBS.lock().unwrap().push(sub_m);

            // Security events
            let tx_sec = tx.clone();
            let sub_s = crate::runtime::events::subscribe_to_security_events(Box::new(move |ev| match ev {
                crate::domains::security::events::SecurityEvent::PowershellSpawned { pid } => {
                    let we = json!({"kind": "security.powershell_spawned", "payload": {"pid": pid}, "ts": Utc::now().timestamp_millis()});
                    let _ = tx_sec.send(we.to_string());
                }
                crate::domains::security::events::SecurityEvent::UnsignedProcessStarted { pid, name } => {
                    let we = json!({"kind": "security.unsigned", "payload": {"pid": pid, "name": name}, "ts": Utc::now().timestamp_millis()});
                    let _ = tx_sec.send(we.to_string());
                }
                _ => {}
            }));
            SUBS.lock().unwrap().push(sub_s);

            // Rule findings
            let tx_find = tx.clone();
            let sub_f = crate::runtime::events::subscribe_to_rules_findings(Box::new(move |f| {
                let ser = crate::persistence::SerializableFinding { title: f.title.clone(), description: f.description.clone(), risk: f.risk, severity: format!("{:?}", f.severity) };
                if let Ok(p) = serde_json::to_value(&ser) {
                    let we = json!({"kind": "finding", "payload": p, "ts": Utc::now().timestamp_millis()});
                    let _ = tx_find.send(we.to_string());
                }
            }));
            SUBS.lock().unwrap().push(sub_f);

            // UI messages
            let tx_ui = tx.clone();
            let sub_u = crate::runtime::events::subscribe_to_ui_messages(Box::new(move |m| {
                let we = json!({"kind": format!("ui.{}", m.topic), "payload": {"body": m.body}, "ts": Utc::now().timestamp_millis()});
                let _ = tx_ui.send(we.to_string());
            }));
            SUBS.lock().unwrap().push(sub_u);

            // Build routes
            let app_state = Arc::new(state);
            let cors = CorsLayer::new().allow_origin(Any).allow_methods(Any).allow_headers(Any);
            let app = Router::new()
                .route("/", get(root))
                .route("/processes", get(processes_handler))
                .route("/findings", get(findings_handler))
                .route("/graph", get(graph_handler))
                .route("/timeline", get(timeline_handler))
                .route("/metrics", get(metrics_handler))
                .route("/ws", get(ws_handler))
                .with_state(app_state)
                .layer(cors);

            // Run server using TcpListener + axum::serve and support Ctrl-C shutdown
            let socket_addr: std::net::SocketAddr = addr.parse().expect("Invalid listen address");
            println!("Bridge listening on http://{}", socket_addr);
            // Bind a std TcpListener and run axum Server with graceful shutdown
            let std_listener = std::net::TcpListener::bind(socket_addr).expect("Failed to bind listener");
            std_listener.set_nonblocking(true).expect("set_nonblocking");
            let server = axum::Server::from_tcp(std_listener).expect("from_tcp").serve(app.into_make_service());
            let shutdown = async {
                let _ = tokio::signal::ctrl_c().await;
                println!("Bridge received shutdown signal");
            };
            server.with_graceful_shutdown(shutdown).await.expect("Bridge server failed");
        });
    });
}

async fn root() -> &'static str { "Argus IPC bridge" }

async fn processes_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Build serializable process list from latest state
    let mut procs: Vec<crate::persistence::SerializableProcessInfo> = Vec::new();
    if let Some(state) = crate::runtime::get_latest_state() {
        for p in state.processes.values() {
            let identity = p.identity.as_ref().map(|id| crate::persistence::SerializableProcessIdentity { path: id.path.clone(), signer: id.signer.clone(), company: id.company.clone(), category: id.category.clone(), start_time: id.start_time, risk_score: id.risk_score });
            procs.push(crate::persistence::SerializableProcessInfo { pid: p.pid, name: p.name.clone(), cpu_percent: p.cpu_percent, memory_mb: p.memory_mb, threads: p.threads, parent_pid: p.parent_pid, identity });
        }
    }
    Ok(Json(json!({"processes": procs})))
}

async fn findings_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // evaluate_all may be blocking/expensive -> run in blocking thread
    let findings = tokio::task::spawn_blocking(|| crate::domains::rules::evaluate_all())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("task join error: {}", e)))?;
    let mut out: Vec<crate::persistence::SerializableFinding> = Vec::new();
    for f in findings.iter() {
        out.push(crate::persistence::SerializableFinding { title: f.title.clone(), description: f.description.clone(), risk: f.risk, severity: format!("{:?}", f.severity) });
    }
    Ok(Json(json!({"findings": out})))
}

async fn graph_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let g = crate::domains::graph::get_graph();
    Ok(Json(json!({"graph": g})))
}

async fn timeline_handler(Query(params): Query<std::collections::HashMap<String, String>>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    if let Some(pid_s) = params.get("pid") {
        if let Ok(pid) = pid_s.parse::<u32>() {
            let recs = crate::timeline::query_pid(pid);
            return Ok(Json(json!({"timeline": recs}))); 
        }
        return Err((StatusCode::BAD_REQUEST, "invalid pid".to_string()));
    }
    Err((StatusCode::BAD_REQUEST, "missing pid param".to_string()))
}

async fn metrics_handler() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Build lightweight system metrics from latest snapshot and collectors
    // This may be called frequently; keep it fast.
    // Use sysinfo to fetch total memory
    let total_mb = match sysinfo::System::new().total_memory() {
        0 => 0.0,
        v => v as f32 / 1024.0 / 1024.0,
    };

    if let Some(state) = crate::runtime::get_latest_state() {
        let mut cpu_sum: f32 = 0.0;
        let mut mem_sum: f32 = 0.0;
        for info in state.processes.values() {
            cpu_sum += info.cpu_percent;
            mem_sum += info.memory_mb;
        }
        // Cap CPU at 100 for UI convenience
        let cpu_pct = if cpu_sum.is_finite() { cpu_sum.min(100.0) } else { 0.0 };
        let process_count = state.processes.len();

        // Determine threat level from current findings
        let findings = crate::domains::rules::evaluate_all();
        let mut threat = "Normal".to_string();
        if findings.iter().any(|f| matches!(f.severity, crate::domains::rules::Severity::Critical)) {
            threat = "Critical".to_string();
        } else if findings.iter().any(|f| matches!(f.severity, crate::domains::rules::Severity::High)) {
            threat = "Suspicious".to_string();
        } else if findings.iter().any(|f| matches!(f.severity, crate::domains::rules::Severity::Medium)) {
            threat = "Elevated".to_string();
        }

        let we = json!({
            "cpuPercent": cpu_pct,
            "memoryUsedMb": mem_sum,
            "memoryTotalMb": total_mb,
            "processCount": process_count,
            "threatLevel": threat,
        });
        return Ok(Json(we));
    }

    // No state available
    let we = json!({"cpuPercent": 0.0, "memoryUsedMb": 0.0, "memoryTotalMb": total_mb, "processCount": 0, "threatLevel": "Normal"});
    Ok(Json(we))
}

async fn ws_handler(ws: WebSocketUpgrade, state: axum::extract::State<Arc<AppState>>) -> impl axum::response::IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state.tx.clone()))
}

async fn handle_socket(socket: WebSocket, tx: Sender<String>) {
    // split into sender/receiver
    let (mut ws_tx, mut ws_rx) = socket.split();

    println!("[bridge] New websocket client connected");

    // Create an mpsc channel to receive broadcast messages (forwarded by a task)
    let (mpsc_tx, mut mpsc_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let mut b_rx = tx.subscribe();
    // spawn a task to forward broadcast -> mpsc channel
    let forward_bridge = tokio::spawn(async move {
        while let Ok(msg) = b_rx.recv().await {
            // best-effort, ignore if receiver closed
            if mpsc_tx.send(msg).is_err() {
                eprintln!("[bridge] mpsc receiver closed while forwarding broadcast");
                break;
            }
        }
    });

    // Read inbound messages and forward broadcast messages to the websocket sender
    loop {
        tokio::select! {
            biased;
            // inbound websocket messages
            msg = ws_rx.next() => {
                match msg {
                    Some(Ok(m)) => match m {
                        Message::Text(t) => {
                            // echo client text back (preserve existing behavior)
                            if let Err(e) = ws_tx.send(Message::Text(t)).await {
                                eprintln!("[bridge] failed to send text to ws client: {:?}", e);
                                break;
                            }
                        }
                        Message::Ping(p) => {
                            if let Err(e) = ws_tx.send(Message::Pong(p)).await {
                                eprintln!("[bridge] failed to send pong: {:?}", e);
                                break;
                            }
                        }
                        Message::Close(_) => {
                            println!("[bridge] ws client closed connection");
                            break;
                        }
                        _ => {}
                    },
                    Some(Err(e)) => {
                        eprintln!("[bridge] websocket receive error: {:?}", e);
                        break;
                    }
                    None => {
                        println!("[bridge] websocket stream ended");
                        break;
                    }
                }
            }
            // broadcast -> websocket
            Some(bmsg) = mpsc_rx.recv() => {
                if let Err(e) = ws_tx.send(Message::Text(bmsg)).await {
                    eprintln!("[bridge] failed to forward broadcast to ws client: {:?}", e);
                    break;
                }
            }
        }
    }

    forward_bridge.abort();
    println!("[bridge] websocket handler exiting for client");
}
