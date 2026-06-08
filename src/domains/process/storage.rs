use crate::domains::process::events::ProcessEvent;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use chrono::Local;

// Store timestamped events so the UI can display when they occurred
static STORE: Lazy<Mutex<Vec<(i64, ProcessEvent)>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn store_event(ev: &ProcessEvent) {
    let mut s = STORE.lock().unwrap();
    let ts = Local::now().timestamp();
    s.push((ts, ev.clone()));
}

pub fn get_events() -> Vec<(i64, ProcessEvent)> {
    let s = STORE.lock().unwrap();
    s.clone()
}
