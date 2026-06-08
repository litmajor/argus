use once_cell::sync::Lazy;
use std::sync::Mutex;

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register() {
    // subscribe to process events and print only terminations and cpu spikes
    // (avoid duplicating the full process list printed by the runtime)
    let sub = crate::runtime::events::subscribe_to_process_events(Box::new(|ev: &crate::domains::process::events::ProcessEvent| {
        match ev {
            crate::domains::process::events::ProcessEvent::Terminated(pid) => {
                println!("[PROCESS_TERMINATED] PID:{}", pid);
            }
            crate::domains::process::events::ProcessEvent::CpuSpike { pid, cpu } => {
                println!("[PROCESS_CPU_SPIKE] PID:{} CPU:{:.1}%", pid, cpu);
            }
            _ => {}
        }
    }));
    SUBS.lock().unwrap().push(sub);

    // Subscribe to rule findings to print them in the console surface
    let sub_f = crate::runtime::events::subscribe_to_rules_findings(Box::new(|f: &crate::domains::rules::Finding| {
        println!("[FINDING] {} risk={} severity={:?}\n  {}", f.title, f.risk, f.severity, f.description);
    }));
    SUBS.lock().unwrap().push(sub_f);
}

pub fn unregister() {
    let mut v = SUBS.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_process_events(sub.id);
    }
}
