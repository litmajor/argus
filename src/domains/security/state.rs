#[derive(Debug, Clone)]
pub enum SecurityStatus {
    Normal,
    Elevated,
    Suspicious,
    Critical,
}

impl Default for SecurityStatus {
    fn default() -> Self {
        SecurityStatus::Normal
    }
}

use once_cell::sync::Lazy;
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Simple numeric security scoring manager. Scores range 0..=100.
pub struct SecurityScores {
    inner: HashMap<u32, u8>,
}

impl SecurityScores {
    pub fn new() -> Self { SecurityScores { inner: HashMap::new() } }

    pub fn set_score(&mut self, pid: u32, score: u8) {
        self.inner.insert(pid, score.min(100));
    }

    pub fn add_score(&mut self, pid: u32, delta: i32) {
        let cur = *self.inner.get(&pid).unwrap_or(&0) as i32;
        let mut next = cur + delta;
        if next < 0 { next = 0 }
        if next > 100 { next = 100 }
        self.inner.insert(pid, next as u8);
    }

    pub fn get_score(&self, pid: u32) -> u8 {
        *self.inner.get(&pid).unwrap_or(&0)
    }

    pub fn max_score(&self) -> u8 {
        self.inner.values().cloned().max().unwrap_or(0)
    }

    pub fn map_score_to_status(score: u8) -> SecurityStatus {
        match score {
            0..=24 => SecurityStatus::Normal,
            25..=49 => SecurityStatus::Elevated,
            50..=74 => SecurityStatus::Suspicious,
            _ => SecurityStatus::Critical,
        }
    }
}

static GLOBAL_SCORES: Lazy<Mutex<SecurityScores>> = Lazy::new(|| Mutex::new(SecurityScores::new()));

pub fn set_process_score(pid: u32, score: u8) {
    let mut g = GLOBAL_SCORES.lock().unwrap();
    g.set_score(pid, score);
}

// Per-pid explanation contributors: list of (label, delta)
static GLOBAL_CONTRIB: Lazy<Mutex<HashMap<u32, Vec<(String,i32)>>>> = Lazy::new(|| Mutex::new(HashMap::new()));

pub fn record_contribution(pid: u32, label: &str, delta: i32) {
    // update numeric score
    // prefer using helper to update score
    add_process_score(pid, delta);
    // append contributor
    let mut c = GLOBAL_CONTRIB.lock().unwrap();
    let entry = c.entry(pid).or_insert_with(Vec::new);
    entry.push((label.to_string(), delta));
}

pub fn get_contributions(pid: u32) -> Vec<(String,i32)> {
    let c = GLOBAL_CONTRIB.lock().unwrap();
    c.get(&pid).cloned().unwrap_or_default()
}

pub fn add_process_score(pid: u32, delta: i32) {
    let mut g = GLOBAL_SCORES.lock().unwrap();
    g.add_score(pid, delta);
}

pub fn get_process_score(pid: u32) -> u8 {
    let g = GLOBAL_SCORES.lock().unwrap();
    g.get_score(pid)
}

pub fn max_score() -> u8 {
    let g = GLOBAL_SCORES.lock().unwrap();
    g.max_score()
}

pub fn status_for_pid(pid: u32) -> SecurityStatus {
    let g = GLOBAL_SCORES.lock().unwrap();
    SecurityScores::map_score_to_status(g.get_score(pid))
}

/// Simple behavior counters per PID for tracking actions (files, sockets, child spawns)
#[derive(Debug, Clone, Default)]
pub struct BehaviorCounters {
    pub files_created: u32,
    pub sockets_opened: u32,
    pub children_spawned: u32,
    pub last_updated: u64,
}

static GLOBAL_BEHAVIOR: Lazy<Mutex<HashMap<u32, BehaviorCounters>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn now_ts() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn incr_file_create(pid: u32, delta: u32) {
    let mut g = GLOBAL_BEHAVIOR.lock().unwrap();
    let entry = g.entry(pid).or_insert_with(BehaviorCounters::default);
    entry.files_created = entry.files_created.saturating_add(delta);
    entry.last_updated = now_ts();
}

pub fn incr_socket_open(pid: u32, delta: u32) {
    let mut g = GLOBAL_BEHAVIOR.lock().unwrap();
    let entry = g.entry(pid).or_insert_with(BehaviorCounters::default);
    let prev = entry.sockets_opened;
    entry.sockets_opened = entry.sockets_opened.saturating_add(delta);
    entry.last_updated = now_ts();
    // If crossing a network activity threshold, record a contributor
    if prev < 20 && entry.sockets_opened >= 20 {
        record_contribution(pid, "network_activity", 30);
    }
}

pub fn incr_child_spawn(pid: u32, delta: u32) {
    let mut g = GLOBAL_BEHAVIOR.lock().unwrap();
    let entry = g.entry(pid).or_insert_with(BehaviorCounters::default);
    entry.children_spawned = entry.children_spawned.saturating_add(delta);
    entry.last_updated = now_ts();
}

pub fn get_behavior(pid: u32) -> BehaviorCounters {
    let g = GLOBAL_BEHAVIOR.lock().unwrap();
    g.get(&pid).cloned().unwrap_or_default()
}

/// Evaluate simple behavior heuristics and update security score accordingly.
pub fn evaluate_behavior(pid: u32) {
    let b = get_behavior(pid);
    // Simple thresholds
    if b.children_spawned >= 50 || b.files_created >= 1000 {
        record_contribution(pid, "behavior_threshold_severe", 100);
    } else if b.children_spawned >= 10 || b.files_created >= 200 || b.sockets_opened >= 100 {
        record_contribution(pid, "behavior_threshold_high", 60);
    } else if b.children_spawned >= 5 || b.files_created >= 50 || b.sockets_opened >= 20 {
        record_contribution(pid, "behavior_threshold_medium", 40);
    }
}
