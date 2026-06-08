use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::collections::HashMap;
use crate::domains::memory::events::MemoryEvent;
use crate::runtime::event_bus;

static LAST: Lazy<Mutex<HashMap<u32, f32>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn register() {
    // Subscribe to raw memory samples and evaluate for leaks
    let _sub = crate::runtime::events::subscribe_to_memory_events(Box::new(|ev| match ev {
        MemoryEvent::ProcessMemorySample { pid, memory_mb } => {
            let mut last = LAST.lock().unwrap();
            let prev = last.get(pid).cloned().unwrap_or(0.0);
            let curr = *memory_mb;
            // If process has grown by >100 MB and is large (>500MB), suspect leak
            if curr > 500.0 && (curr - prev) > 100.0 {
                event_bus::publish(MemoryEvent::LeakSuspected { pid: *pid });
            }
            last.insert(*pid, curr);
            // prune entries for processes that disappear will be handled elsewhere periodically
        }
        _ => {}
    }));
    // keep subscription alive by storing it in a module static (RAII elsewhere)
}

pub fn unregister() {
    // No-op: relying on runtime shutdown to drop subscriptions held by surfaces/subscribers
}
