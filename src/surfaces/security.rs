use once_cell::sync::Lazy;
use std::sync::Mutex;

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register() {
    // Subscribe to security domain events and render them
    let sub = crate::runtime::events::subscribe_to_security_events(Box::new(|ev| match ev {
        crate::domains::security::SecurityEvent::PowershellSpawned { pid } => {
            println!("[SecuritySurface] Powershell spawned PID:{}", pid);
        }
        crate::domains::security::SecurityEvent::ProcessSpawnedBy { pid, origin_pid, origin_name, lineage } => {
            println!("[SecuritySurface] Process {} was spawned by {}({})", pid, origin_name, origin_pid);
            if !lineage.is_empty() {
                println!("[SecuritySurface] Lineage: {}", lineage.join(" -> "));
            }
            // Print behavior counters for quick triage
            let b = crate::domains::security::state::get_behavior(*origin_pid);
            println!("[SecuritySurface] Origin behavior: files={} sockets={} children={} (last_updated={})", b.files_created, b.sockets_opened, b.children_spawned, b.last_updated);
        }
        crate::domains::security::SecurityEvent::UnsignedProcessStarted { pid, name } => {
            println!("[SecuritySurface] Unsigned process started: {} ({})", name, pid);
        }
        crate::domains::security::SecurityEvent::ProcessSignatureVerification { pid, name, result } => {
            println!("[SecuritySurface] Signature check {} (pid={}): {:?}", name, pid, result);
        }
        crate::domains::security::SecurityEvent::HandleHijackDetected { pid } => {
            println!("[SecuritySurface] Handle hijack suspected PID:{}", pid);
        }
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn unregister() {
    let mut v = SUBS.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_security_events(sub.id);
    }
}
