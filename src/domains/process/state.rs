use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f32,
    pub threads: u32,
    pub parent_pid: u32,
    // Identity metadata (optional until collectors populate)
    pub identity: Option<ProcessIdentity>,
}

impl From<crate::core::process::Process> for ProcessInfo {
    fn from(p: crate::core::process::Process) -> Self {
        Self {
            pid: p.pid,
            name: p.name,
            cpu_percent: p.cpu_percent,
            memory_mb: p.memory_mb,
            threads: p.threads,
            parent_pid: p.parent_pid,
            identity: Some(ProcessIdentity { path: None, signer: None, company: None, category: None, start_time: p.start_time, risk_score: 0 }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ProcessIdentity {
    pub path: Option<String>,
    pub signer: Option<String>,
    pub company: Option<String>,
    pub category: Option<String>,
    pub start_time: Option<u64>,
    pub risk_score: u8,
}

#[derive(Debug, Clone, Default)]
pub struct ProcessState {
    pub processes: HashMap<u32, ProcessInfo>,
    // Aggregated families for entity resolution: family name -> aggregated info
    pub families: HashMap<String, ProcessFamily>,
    // Lineage: parent -> children mapping and ancestor chains
    pub lineage: ProcessLineage,
}

impl ProcessState {
    pub fn from_vec(vec: Vec<crate::core::process::Process>) -> Self {
        let mut processes = HashMap::with_capacity(vec.len());
        for p in vec.into_iter() {
            let info: ProcessInfo = p.into();
            processes.insert(info.pid, info);
        }
        let mut state = Self { processes, families: HashMap::new(), lineage: ProcessLineage::default() };
        state.recompute_families();
        state.recompute_lineage();
        state
    }

    pub fn recompute_families(&mut self) {
        self.families.clear();
        for info in self.processes.values() {
            let fam = family_for_name(&info.name);
            let entry = self.families.entry(fam.clone()).or_insert_with(|| ProcessFamily::new(fam.clone()));
            entry.count += 1;
            entry.pids.push(info.pid);
            entry.total_cpu += info.cpu_percent as f64;
            entry.total_memory += info.memory_mb as f64;
        }
    }

    pub fn recompute_lineage(&mut self) {
        let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
        let mut parent: HashMap<u32, u32> = HashMap::new();
        for info in self.processes.values() {
            parent.insert(info.pid, info.parent_pid);
            children.entry(info.parent_pid).or_default().push(info.pid);
        }

        // Build ancestor chains for each PID
        let mut ancestors: HashMap<u32, Vec<u32>> = HashMap::new();
        for pid in self.processes.keys() {
            let mut chain: Vec<u32> = Vec::new();
            let mut current = *pid;
            let mut visited = std::collections::HashSet::new();
            while let Some(p) = parent.get(&current) {
                if *p == 0 || visited.contains(p) {
                    break;
                }
                chain.push(*p);
                visited.insert(*p);
                current = *p;
            }
            ancestors.insert(*pid, chain);
        }

        self.lineage = ProcessLineage { parent, children, ancestors };
    }
}

#[derive(Debug, Clone)]
pub struct ProcessFamily {
    pub name: String,
    pub count: usize,
    pub pids: Vec<u32>,
    pub total_cpu: f64,
    pub total_memory: f64,
}

impl ProcessFamily {
    pub fn new(name: String) -> Self {
        Self { name, count: 0, pids: Vec::new(), total_cpu: 0.0, total_memory: 0.0 }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ProcessLineage {
    pub parent: HashMap<u32, u32>,
    pub children: HashMap<u32, Vec<u32>>,
    pub ancestors: HashMap<u32, Vec<u32>>,
}

impl ProcessLineage {
    pub fn get_children(&self, pid: u32) -> Vec<u32> {
        self.children.get(&pid).cloned().unwrap_or_default()
    }

    pub fn get_ancestors(&self, pid: u32) -> Vec<u32> {
        self.ancestors.get(&pid).cloned().unwrap_or_default()
    }

    pub fn get_parent(&self, pid: u32) -> Option<u32> {
        self.parent.get(&pid).cloned().and_then(|p| if p == 0 { None } else { Some(p) })
    }
}

/// Derive a canonical family name for a process executable name.
/// This is used for simple entity resolution/grouping (e.g. `Code.exe` -> `vscode`).
pub fn family_for_name(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("code") || lower.contains("vscode") {
        return "vscode".to_string();
    }
    if lower.contains("brave") || lower.contains("chrome") || lower.contains("chromium") {
        return "chromium".to_string();
    }
    if lower.contains("msedgewebview2") || lower.contains("msedge") || lower.contains("webview") {
        return "webview2".to_string();
    }
    if lower.contains("svchost") {
        return "svchost".to_string();
    }
    if lower.contains("dllhost") {
        return "dllhost".to_string();
    }
    if lower.contains("conhost") {
        return "conhost".to_string();
    }
    // default family is the executable name itself
    name.to_string()
}
