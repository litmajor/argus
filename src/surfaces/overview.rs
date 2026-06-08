use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{Instant, Duration};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

static SUBS_CPU: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));
static SUBS_MEM: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));
static SUBS_PROC: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));
static SUBS_SEC: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));
static SUBS_UI: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

// Split overview state into domain-specific locks to reduce contention
#[derive(Default)]
struct MetricState {
    cpu: crate::domains::cpu::CpuState,
    mem: crate::domains::memory::MemoryState,
}

#[derive(Default)]
struct ProcState {
    pid_families: HashMap<u32, String>,
    pid_classes: HashMap<u32, ProcessClass>,
    class_counts: HashMap<ProcessClass, usize>,
    active_families: HashMap<String, usize>,
    fam_count: usize,
}

#[derive(Default)]
struct MetaState {
    sec: crate::domains::security::SecurityStatus,
    last_ui: Option<String>,
    last_suspicion: Option<Instant>,
}

static STATE_METRICS: Lazy<Mutex<MetricState>> = Lazy::new(|| Mutex::new(MetricState::default()));
static STATE_PROC: Lazy<Mutex<ProcState>> = Lazy::new(|| Mutex::new(ProcState::default()));
static STATE_META: Lazy<Mutex<MetaState>> = Lazy::new(|| Mutex::new(MetaState::default()));
static LAST_PRINTED: Lazy<Mutex<Instant>> = Lazy::new(|| Mutex::new(Instant::now()));
static THROTTLE_MS: Lazy<u64> = Lazy::new(|| std::env::var("OVERVIEW_THROTTLE_MS").ok().and_then(|v| v.parse().ok()).unwrap_or(250));
static PENDING_PRINT: Lazy<AtomicBool> = Lazy::new(|| AtomicBool::new(false));
const SUSPICION_TTL_SECS: u64 = 60;


pub fn register() {
    // Subscribe to cpu and memory events and update overview state
    let sub_cpu = crate::runtime::events::subscribe_to_cpu_events(Box::new(|ev| match ev {
        crate::domains::cpu::CpuEvent::Spike { percent } => {
            {
                let mut m = STATE_METRICS.lock().unwrap();
                m.cpu.usage_percent = *percent;
            }
            print_overview();
        }
        crate::domains::cpu::CpuEvent::RawSample { percent } => {
            let mut m = STATE_METRICS.lock().unwrap();
            m.cpu.usage_percent = *percent;
            // raw samples are high-frequency; throttle printing but request an update
            print_overview();
        }
        crate::domains::cpu::CpuEvent::Normalized => {
            {
                let mut m = STATE_METRICS.lock().unwrap();
                m.cpu.usage_percent = 0.0;
            }
            print_overview();
            }
    }));
    SUBS_CPU.lock().unwrap().push(sub_cpu);

    let sub_mem = crate::runtime::events::subscribe_to_memory_events(Box::new(|ev| match ev {
        crate::domains::memory::MemoryEvent::UsedSample { used_mb } => {
            {
                let mut m = STATE_METRICS.lock().unwrap();
                m.mem.used_mb = *used_mb;
            }
            print_overview();
        }
        crate::domains::memory::MemoryEvent::PressureHigh { used_mb } => {
            {
                let mut m = STATE_METRICS.lock().unwrap();
                m.mem.used_mb = *used_mb;
            }
            print_overview();
        }
        crate::domains::memory::MemoryEvent::LeakSuspected { pid } => {
            println!("[Overview] Leak suspected in PID {}", pid);
        }
        // Per-process ProcessMemorySample events are published by the runtime; do not treat them as system usage.
        crate::domains::memory::MemoryEvent::ProcessMemorySample { pid: _, memory_mb: _ } => {
            // ignore here; surfaces that need per-process memory can subscribe to process events or read latest state
        }
    }));
    SUBS_MEM.lock().unwrap().push(sub_mem);

    // Track process count via process events
    // Track processes by family to avoid inflated "many independent processes" counts
    let sub_proc = crate::runtime::events::subscribe_to_process_events(Box::new(|ev| match ev {
        crate::domains::process::events::ProcessEvent::Started(info) => {
            {
                let mut p = STATE_PROC.lock().unwrap();
                let fam = crate::domains::process::state::family_for_name(&info.name);
                p.pid_families.insert(info.pid, fam.clone());
                // update active_families and fam_count incrementally
                match p.active_families.get_mut(&fam) {
                    Some(cnt) => { *cnt = cnt.saturating_add(1); }
                    None => { p.active_families.insert(fam.clone(), 1); p.fam_count = p.fam_count.saturating_add(1); }
                }
                let class = classify_name(&info.name);
                p.pid_classes.insert(info.pid, class.clone());
                *p.class_counts.entry(class).or_insert(0) += 1;
            }
            print_overview();
        }
        crate::domains::process::events::ProcessEvent::Terminated(pid) => {
            {
                let mut p = STATE_PROC.lock().unwrap();
                if let Some(fam) = p.pid_families.remove(pid) {
                    if let Some(cnt) = p.active_families.get_mut(&fam) {
                        if *cnt > 1 {
                            *cnt -= 1;
                        } else {
                            p.active_families.remove(&fam);
                            p.fam_count = p.fam_count.saturating_sub(1);
                        }
                    }
                }
                if let Some(class) = p.pid_classes.remove(pid) {
                    if let Some(cnt) = p.class_counts.get_mut(&class) {
                        if *cnt > 1 {
                            *cnt -= 1;
                        } else {
                            p.class_counts.remove(&class);
                        }
                    }
                }
            }
            print_overview();
        }
        _ => {}
    }));
    SUBS_PROC.lock().unwrap().push(sub_proc);

    // Subscribe to security events to reflect SecurityStatus in overview
    let sub_sec = crate::runtime::events::subscribe_to_security_events(Box::new(|ev| match ev {
        crate::domains::security::SecurityEvent::PowershellSpawned { pid: _ } => {
            {
                let mut m = STATE_META.lock().unwrap();
                m.sec = crate::domains::security::SecurityStatus::Suspicious;
                m.last_suspicion = Some(Instant::now());
            }
            print_overview();
        }
        crate::domains::security::SecurityEvent::UnsignedProcessStarted { pid: _, name: _ } => {
            {
                let mut m = STATE_META.lock().unwrap();
                m.sec = crate::domains::security::SecurityStatus::Suspicious;
                m.last_suspicion = Some(Instant::now());
            }
            print_overview();
        }
        crate::domains::security::SecurityEvent::ProcessSignatureVerification { pid: _, name: _, result } => {
            // Only escalate to Suspicious for explicit Unsigned results. Treat
            // Unknown/VerificationFailed as informational so they don't make the
            // security signal useless.
            use crate::domains::security::policies::SignatureVerification;
                if *result == SignatureVerification::Unsigned {
                {
                    let mut m = STATE_META.lock().unwrap();
                    m.sec = crate::domains::security::SecurityStatus::Suspicious;
                    m.last_suspicion = Some(Instant::now());
                }
                print_overview();
            }
        }
        _ => {}
    }));
    SUBS_SEC.lock().unwrap().push(sub_sec);

    // Subscribe to UI messages (from REPL commands) to show last message in overview
    let sub_ui = crate::runtime::events::subscribe_to_ui_messages(Box::new(|m| {
        {
            let mut meta = STATE_META.lock().unwrap();
            meta.last_ui = Some(format!("{}: {}", m.topic, m.body));
        }
        print_overview();
    }));
    SUBS_UI.lock().unwrap().push(sub_ui);
}

pub fn unregister() {
    let mut v = SUBS_CPU.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_cpu_events(sub.id);
    }
    let mut v = SUBS_MEM.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_memory_events(sub.id);
    }
    let mut v = SUBS_PROC.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_process_events(sub.id);
    }
    let mut v = SUBS_SEC.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_security_events(sub.id);
    }
    let mut v = SUBS_UI.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_ui_messages(sub.id);
    }
}

fn print_overview() {
    // Throttle prints using configurable threshold
    let throttle = *THROTTLE_MS; // ms
    {
        let mut last = LAST_PRINTED.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*last).as_millis() < throttle as u128 {
            // schedule a pending print if not already scheduled
            if !PENDING_PRINT.load(Ordering::SeqCst) {
                if PENDING_PRINT.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                    let th = throttle;
                    thread::spawn(move || {
                        thread::sleep(Duration::from_millis(th));
                        // clear pending then invoke print once
                        PENDING_PRINT.store(false, Ordering::SeqCst);
                        // best-effort: call print_overview (ignores its own scheduling)
                        crate::surfaces::overview::print_overview();
                    });
                }
            }
            return;
        }
        *last = now;
    }

    // Lock ordering: metrics -> proc -> meta
    let m = STATE_METRICS.lock().unwrap();
    let p = STATE_PROC.lock().unwrap();
    let mut meta = STATE_META.lock().unwrap();

    // expire suspicious status after TTL
    if let crate::domains::security::SecurityStatus::Suspicious = meta.sec {
        if let Some(ts) = meta.last_suspicion {
            if Instant::now().duration_since(ts).as_secs() > SUSPICION_TTL_SECS {
                meta.sec = crate::domains::security::SecurityStatus::Normal;
                meta.last_suspicion = None;
            }
        }
    }

    let proc_count = p.pid_families.len();
    let fam_count = p.fam_count;
    let browsers = p.class_counts.get(&ProcessClass::Browser).cloned().unwrap_or(0);
    let devtools = p.class_counts.get(&ProcessClass::DevTools).cloned().unwrap_or(0);
    let unknown = p.class_counts.get(&ProcessClass::Unknown).cloned().unwrap_or(0);
    let max_score = crate::domains::security::state::max_score();
    println!("[Overview] CPU:{:.1}% MEM(MB):{:.1} PROCS:{} FAM:{} BROWSER:{} DEV:{} UNKNOWN:{} SEC:{:?} SCORE_MAX:{}%", m.cpu.usage_percent, m.mem.used_mb, proc_count, fam_count, browsers, devtools, unknown, meta.sec, max_score);
    if let Some(u) = &meta.last_ui {
        println!("[Overview UI] {}", u);
    }
}

// family resolution moved to `domains::process::state::family_for_name`

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum ProcessClass {
    System,
    Shell,
    UserInteractive,
    DevTools,
    Browser,
    VmWsl,
    Social,
    Unknown,
}

fn classify_name(name: &str) -> ProcessClass {
    let lower = name.to_lowercase();
    if lower == "system" || lower == "[system process]" || lower == "smss.exe" || lower == "csrss.exe" || lower == "wininit.exe" {
        return ProcessClass::System;
    }
    if lower.contains("code") || lower.contains("cargo") || lower.contains("clion") || lower.contains("rust") || lower.contains("golang") {
        return ProcessClass::DevTools;
    }
    if lower.contains("brave") || lower.contains("chrome") || lower.contains("edge") || lower.contains("msedgewebview2") || lower.contains("firefox") {
        return ProcessClass::Browser;
    }
    // shell/console hosts
    if lower.contains("powershell") || lower.contains("pwsh") || lower.contains("cmd") || lower.contains("conhost") {
        return ProcessClass::Shell;
    }
    // system service hosts
    if lower.contains("wsl") || lower.contains("vm") || lower.contains("vmms") || lower.contains("vmcompute") {
        return ProcessClass::VmWsl;
    }
    if lower.contains("svchost") || lower.contains("dllhost") || lower.contains("runtimebroker") {
        return ProcessClass::System;
    }
    if lower.contains("whatsapp") || lower.contains("teams") || lower.contains("discord") || lower.contains("slack") {
        return ProcessClass::Social;
    }
    // heuristics for interactive user apps
    if lower.contains("explorer") || lower.contains("startmenu") || lower.contains("shell") || lower.contains("openconsole") {
        return ProcessClass::UserInteractive;
    }
    ProcessClass::Unknown
}
