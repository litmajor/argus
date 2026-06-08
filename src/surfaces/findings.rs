use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::collections::VecDeque;

use ratatui::widgets::ListItem;

static SUBS: Lazy<Mutex<Vec<crate::runtime::events::Subscription>>> = Lazy::new(|| Mutex::new(Vec::new()));
static HISTORY: Lazy<Mutex<VecDeque<crate::domains::rules::Finding>>> = Lazy::new(|| Mutex::new(VecDeque::with_capacity(200)));

pub fn register() {
    let sub = crate::runtime::events::subscribe_to_rules_findings(Box::new(|f: &crate::domains::rules::Finding| {
        let mut h = HISTORY.lock().unwrap();
        if h.len() == 200 { h.pop_front(); }
        h.push_back(f.clone());
    }));
    SUBS.lock().unwrap().push(sub);
}

pub fn unregister() {
    let mut v = SUBS.lock().unwrap();
    while let Some(sub) = v.pop() {
        crate::runtime::events::unsubscribe_from_rules_findings(sub.id);
    }
}

/// Draw a simple ratatui panel showing recent Findings. Safe to call from the UI render loop.
/// Return a list of `ListItem`s for the most recent findings. The UI code
/// can call `List::new(items)` and render it into a `Frame`.
pub fn recent_list_items() -> Vec<ListItem<'static>> {
    use ratatui::widgets::ListItem as LI;

    let h = HISTORY.lock().unwrap();
    let mut items: Vec<ListItem<'static>> = Vec::new();
    for fi in h.iter().rev().take(20) {
        let mut text = format!("{} [risk={} severity={:?}]", fi.title, fi.risk, fi.severity);
        if !fi.description.is_empty() {
            text.push_str("\n");
            text.push_str(&fi.description);
        }
        items.push(LI::new(text));
    }
    items
}

/// Convenience CLI helper retained for non-UI use.
pub fn show_recent(n: usize) {
    let h = HISTORY.lock().unwrap();
    println!("Recent Findings (most recent last):");
    let start = if h.len() > n { h.len() - n } else { 0 };
    for f in h.iter().skip(start) {
        println!(" - {} | risk={} severity={:?}\n   {}", f.title, f.risk, f.severity, f.description);
    }
}
