use crate::actions::events::ActionEvent;
use once_cell::sync::Lazy;
use std::sync::Mutex;

type Handler = Box<dyn Fn(&ActionEvent) + Send + Sync + 'static>;

static BUS: Lazy<Mutex<Vec<Handler>>> = Lazy::new(|| Mutex::new(Vec::new()));

#[allow(dead_code)]
pub fn subscribe(h: Handler) {
    let mut v = BUS.lock().unwrap();
    v.push(h);
}

pub fn publish(ev: &ActionEvent) {
    let v = BUS.lock().unwrap();
    for h in v.iter() {
        h(ev);
    }
}
