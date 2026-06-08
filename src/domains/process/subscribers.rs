use crate::domains::process::events::ProcessEvent;
use crate::domains::process::storage;
use std::fs::{OpenOptions};
use std::io::Write;
use std::net::UdpSocket;
use once_cell::sync::Lazy;
use std::sync::Mutex;

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub fn register_file_logger(path: &str) {
    let path = path.to_string();
    let sub = crate::runtime::events::subscribe_to_process_events(Box::new(move |ev: &ProcessEvent| {
        if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(&path) {
            let ts = chrono::Local::now().format("%H:%M:%S").to_string();
            let _ = writeln!(f, "[{}] {}", ts, ev);
        }
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn register_udp_publisher(addr: &str) {
    let addr = addr.to_string();
    // Best-effort: create socket per event to avoid sync issues across platforms
    let sub = crate::runtime::events::subscribe_to_process_events(Box::new(move |ev: &ProcessEvent| {
        let _ = std::thread::spawn({
            let addr = addr.clone();
            let evs = ev.to_string();
            move || {
                if let Ok(sock) = UdpSocket::bind("0.0.0.0:0") {
                    let _ = sock.send_to(evs.as_bytes(), &addr);
                }
            }
        });
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn register_persistence() {
    let sub = crate::runtime::events::subscribe_to_process_events(Box::new(|ev: &ProcessEvent| {
        storage::store_event(ev);
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn unregister_all() {
    let mut v = SUBS.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_process_events(sub.id);
    }
}
