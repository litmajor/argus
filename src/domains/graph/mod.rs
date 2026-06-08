use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::fs::{create_dir_all, File};
use std::io::BufWriter;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeType {
    Process,
    File,
    Socket,
    User,
    Service,
    Registry,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    pub id: String,
    pub node_type: NodeType,
    pub name: String,
    pub pid: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EdgeKind {
    ParentOf,
    ChildOf,
    Spawned,
    Opened,
    UsesNetwork,
    UsesFile,
    RelatedTo,
    MemberOfFamily,
    Owns,
    Provides,
    TouchesRegistry,
    CreatedFiles,
    OpenedSockets,
    SpawnedChildrenMetric,
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub src: String,
    pub dst: String,
    pub kind: EdgeKind,
    pub ts: u64,
    pub count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Graph {
    pub nodes: HashMap<String, Node>,
    pub edges: Vec<GraphEdge>,
}

impl Graph {
    pub fn add_node(&mut self, n: Node) {
        self.nodes.insert(n.id.clone(), n);
    }

    pub fn add_edge(&mut self, src: &str, dst: &str, kind: EdgeKind) {
        let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        // If an identical edge exists, increment its count and update timestamp
        if let Some(e) = self.edges.iter_mut().find(|e| e.src == src && e.dst == dst && e.kind == kind) {
            e.count = e.count.saturating_add(1);
            e.ts = ts;
        } else {
            self.edges.push(GraphEdge { src: src.to_string(), dst: dst.to_string(), kind, ts, count: 1 });
        }
    }

    pub fn neighbors(&self, id: &str) -> Vec<&Node> {
        let mut out: Vec<&Node> = Vec::new();
        for e in &self.edges {
            if e.src == id {
                if let Some(n) = self.nodes.get(&e.dst) {
                    out.push(n);
                }
            }
            if e.dst == id {
                if let Some(n) = self.nodes.get(&e.src) {
                    out.push(n);
                }
            }
        }
        out
    }
}

use once_cell::sync::Lazy;
use std::sync::Mutex;

static LAST_SNAPSHOT_TS: Lazy<Mutex<u64>> = Lazy::new(|| Mutex::new(0));
const SNAPSHOT_INTERVAL_SECS: u64 = 300; // 5 minutes

static GLOBAL_GRAPH: Lazy<Mutex<Graph>> = Lazy::new(|| Mutex::new(Graph::default()));

/// Rebuild the graph from the process state snapshot. This creates process nodes and
/// parent-child edges, and attaches aggregated file/socket nodes derived from security behavior counters.
pub fn rebuild_from_state(state: crate::domains::process::ProcessState) {
    let mut g = Graph::default();
    // create process nodes
    for (pid, info) in state.processes.iter() {
        let id = format!("proc:{}", pid);
        let node = Node { id: id.clone(), node_type: NodeType::Process, name: info.name.clone(), pid: Some(*pid) };
        g.add_node(node);
    }

    // parent-child edges
    for (pid, info) in state.processes.iter() {
        if info.parent_pid != 0 {
            let parent_id = format!("proc:{}", info.parent_pid);
            let child_id = format!("proc:{}", pid);
            if g.nodes.contains_key(&parent_id) {
                g.add_edge(&parent_id, &child_id, EdgeKind::ParentOf);
            }
        }
    }

    // attach aggregated behavior nodes (files/sockets) per process if counters > 0
    for (pid, _) in state.processes.iter() {
        let b = crate::domains::security::state::get_behavior(*pid);
        let proc_id = format!("proc:{}", pid);
        if b.files_created > 0 {
            let file_node_id = format!("files:{}", pid);
            let file_node = Node { id: file_node_id.clone(), node_type: NodeType::File, name: format!("created:{}", b.files_created), pid: Some(*pid) };
            g.add_node(file_node);
            g.add_edge(&proc_id, &file_node_id, EdgeKind::CreatedFiles);
        }
        if b.sockets_opened > 0 {
            let sock_id = format!("sockets:{}", pid);
            let sock_node = Node { id: sock_id.clone(), node_type: NodeType::Socket, name: format!("opened:{}", b.sockets_opened), pid: Some(*pid) };
            g.add_node(sock_node);
            g.add_edge(&proc_id, &sock_id, EdgeKind::OpenedSockets);
        }
        // children_spawned is already encoded via parent_of edges; optionally add metric node
        if b.children_spawned > 0 {
            let c_id = format!("children_metric:{}", pid);
            let c_node = Node { id: c_id.clone(), node_type: NodeType::Other, name: format!("spawned:{}", b.children_spawned), pid: Some(*pid) };
            g.add_node(c_node);
            g.add_edge(&proc_id, &c_id, EdgeKind::SpawnedChildrenMetric);
        }
    }

    // Add User nodes (best-effort): use current environment user as owner for all processes
    let username = std::env::var("USERNAME").unwrap_or_else(|_| "unknown".to_string());
    let user_id = format!("user:{}", username);
    if !g.nodes.contains_key(&user_id) {
        let u = Node { id: user_id.clone(), node_type: NodeType::User, name: username.clone(), pid: None };
        g.add_node(u);
    }
    for (pid, _) in state.processes.iter() {
        let proc_id = format!("proc:{}", pid);
        g.add_edge(&user_id, &proc_id, EdgeKind::Owns);
    }

    // Add Service nodes heuristically for processes that look like services
    for (pid, info) in state.processes.iter() {
        let name = info.name.to_lowercase();
        if name.contains("svchost") || name.contains("service") || info.parent_pid == 0 {
            let svc_id = format!("service:{}", name);
            if !g.nodes.contains_key(&svc_id) {
                let s = Node { id: svc_id.clone(), node_type: NodeType::Service, name: name.clone(), pid: None };
                g.add_node(s);
            }
            let proc_id = format!("proc:{}", pid);
            g.add_edge(&svc_id, &proc_id, EdgeKind::Provides);
        }
    }

    // Add Registry nodes and link to processes that commonly interact with the registry
    let hkcu_id = "registry:HKCU".to_string();
    let hklm_id = "registry:HKLM".to_string();
    if !g.nodes.contains_key(&hkcu_id) {
        g.add_node(Node { id: hkcu_id.clone(), node_type: NodeType::Registry, name: "HKCU".to_string(), pid: None });
    }
    if !g.nodes.contains_key(&hklm_id) {
        g.add_node(Node { id: hklm_id.clone(), node_type: NodeType::Registry, name: "HKLM".to_string(), pid: None });
    }
    for (pid, info) in state.processes.iter() {
        let name = info.name.to_lowercase();
        let proc_id = format!("proc:{}", pid);
        if name.contains("regedit") || name.contains("powershell") || name.contains("cmd") || name.contains("explorer") {
            g.add_edge(&proc_id, &hkcu_id, EdgeKind::TouchesRegistry);
        }
        // some system processes may touch HKLM
        if info.parent_pid == 0 || name.contains("svchost") {
            g.add_edge(&proc_id, &hklm_id, EdgeKind::TouchesRegistry);
        }
    }

    // Persist snapshot to disk no more often than SNAPSHOT_INTERVAL_SECS
    if let Ok(ts) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let secs = ts.as_secs();
        let mut last = LAST_SNAPSHOT_TS.lock().unwrap();
        if secs.saturating_sub(*last) >= SNAPSHOT_INTERVAL_SECS {
            if let Err(e) = create_dir_all("graph_snapshots") {
                eprintln!("Failed to create graph_snapshots dir: {:?}", e);
            } else {
                let path = format!("graph_snapshots/graph_{}.json", secs);
                if let Ok(f) = File::create(&path) {
                    let w = BufWriter::new(f);
                    if let Err(e) = serde_json::to_writer_pretty(w, &g) {
                        eprintln!("Failed to write graph snapshot: {:?}", e);
                    } else {
                        *last = secs;
                    }
                }
            }
        }
    }

    let mut guard = GLOBAL_GRAPH.lock().unwrap();
    *guard = g;
}

pub fn get_graph() -> Graph {
    let g = GLOBAL_GRAPH.lock().unwrap();
    g.clone()
}

pub fn get_neighbors_for_pid(pid: u32) -> Vec<crate::domains::graph::Node> {
    let id = format!("proc:{}", pid);
    let g = GLOBAL_GRAPH.lock().unwrap();
    g.neighbors(&id).into_iter().cloned().collect()
}

/// Return neighbors for `pid` up to `depth` edges away (BFS). The start node is excluded.
pub fn get_neighbors_for_pid_depth(pid: u32, depth: usize) -> Vec<crate::domains::graph::Node> {
    use std::collections::{VecDeque, HashSet};
    let start = format!("proc:{}", pid);
    let g = GLOBAL_GRAPH.lock().unwrap();

    let mut out: Vec<crate::domains::graph::Node> = Vec::new();
    if depth == 0 {
        return out;
    }

    let mut q: VecDeque<(String, usize)> = VecDeque::new();
    let mut visited: HashSet<String> = HashSet::new();

    visited.insert(start.clone());
    q.push_back((start.clone(), 0));

    while let Some((cur, dist)) = q.pop_front() {
        if dist >= depth {
            continue;
        }

        // explore incident neighbors
        for e in &g.edges {
            let neighbor = if e.src == cur {
                Some(e.dst.clone())
            } else if e.dst == cur {
                Some(e.src.clone())
            } else {
                None
            };

            if let Some(nb) = neighbor {
                if visited.contains(&nb) {
                    continue;
                }
                visited.insert(nb.clone());
                // collect node if present
                if let Some(n) = g.nodes.get(&nb) {
                    out.push(n.clone());
                }
                q.push_back((nb, dist + 1));
            }
        }
    }

    out
}

/// Incrementally add a process node to the global graph and link to its parent if present.
pub fn apply_process_started(pid: u32, name: &str, parent_pid: u32) {
    let mut g = GLOBAL_GRAPH.lock().unwrap();
    let id = format!("proc:{}", pid);
    if !g.nodes.contains_key(&id) {
        let node = Node { id: id.clone(), node_type: NodeType::Process, name: name.to_string(), pid: Some(pid) };
        g.add_node(node);
    }
    if parent_pid != 0 {
        let parent_id = format!("proc:{}", parent_pid);
        if g.nodes.contains_key(&parent_id) {
            g.add_edge(&parent_id, &id, EdgeKind::ParentOf);
        }
    }
}

/// Incrementally remove a process node and its incident edges from the global graph.
pub fn apply_process_terminated(pid: u32) {
    let mut g = GLOBAL_GRAPH.lock().unwrap();
    let id = format!("proc:{}", pid);
    // remove node
    g.nodes.remove(&id);
    // remove incident edges
    g.edges.retain(|e| e.src != id && e.dst != id);
}

/// Return a human-readable ancestry chain (root -> ... -> pid) by following
/// `ParentOf` and `Spawned` edges backwards from the process node.
pub fn reason_for_pid(pid: u32) -> Vec<String> {
    use std::collections::HashSet;
    let start = format!("proc:{}", pid);
    let g = GLOBAL_GRAPH.lock().unwrap();

    let mut path: Vec<String> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut cur = start.clone();
    let mut depth = 0usize;
    while depth < 50 && !visited.contains(&cur) {
        visited.insert(cur.clone());
        if let Some(n) = g.nodes.get(&cur) {
            path.push(n.name.clone());
        } else {
            path.push(cur.clone());
        }

        // find a direct parent (edge.src -> edge.dst == cur) using ParentOf or Spawned
        if let Some(e) = g.edges.iter().find(|e| e.dst == cur && matches!(e.kind, EdgeKind::ParentOf | EdgeKind::Spawned)) {
            cur = e.src.clone();
            depth += 1;
            continue;
        }

        // no parent, stop
        break;
    }

    path.reverse();
    path
}

/// Return a structured path: for each node in the ancestry chain, include the node
/// and any incident behavior/service edges (e.g., CreatedFiles, OpenedSockets, Provides, Owns).
pub fn reason_structured_for_pid(pid: u32) -> Vec<(crate::domains::graph::Node, Vec<crate::domains::graph::GraphEdge>)> {
    let start = format!("proc:{}", pid);
    let g = GLOBAL_GRAPH.lock().unwrap();
    let mut visited = std::collections::HashSet::new();
    let mut cur = start.clone();
    let mut depth = 0usize;
    let mut out: Vec<(crate::domains::graph::Node, Vec<crate::domains::graph::GraphEdge>)> = Vec::new();

    while depth < 50 && !visited.contains(&cur) {
        visited.insert(cur.clone());
        let node = if let Some(n) = g.nodes.get(&cur) { n.clone() } else { crate::domains::graph::Node { id: cur.clone(), node_type: crate::domains::graph::NodeType::Other, name: cur.clone(), pid: None } };

        // collect incident edges of interest originating from this node
        let incident: Vec<crate::domains::graph::GraphEdge> = g.edges.iter()
            .filter(|e| e.src == cur && matches!(e.kind, EdgeKind::CreatedFiles | EdgeKind::OpenedSockets | EdgeKind::Provides | EdgeKind::Owns | EdgeKind::TouchesRegistry | EdgeKind::SpawnedChildrenMetric))
            .cloned()
            .collect();

        out.push((node, incident));

        // step to parent if available
        if let Some(e) = g.edges.iter().find(|e| e.dst == cur && matches!(e.kind, EdgeKind::ParentOf | EdgeKind::Spawned)) {
            cur = e.src.clone();
            depth += 1;
            continue;
        }
        break;
    }

    out.reverse();
    out
}

/// Return a chain of `GraphEdge` records representing the ancestry and incident
/// behavior edges for `pid`. The returned vector is ordered root -> ... -> pid.
pub fn reason_edges_for_pid(pid: u32) -> Vec<crate::domains::graph::GraphEdge> {
    let start = format!("proc:{}", pid);
    let g = GLOBAL_GRAPH.lock().unwrap();
    let mut visited = std::collections::HashSet::new();
    let mut cur = start.clone();
    let mut depth = 0usize;
    let mut edges_collected: Vec<crate::domains::graph::GraphEdge> = Vec::new();

    while depth < 50 && !visited.contains(&cur) {
        visited.insert(cur.clone());

        // collect incident behavior/service edges originating from this node
        let incident: Vec<crate::domains::graph::GraphEdge> = g.edges.iter()
            .filter(|e| e.src == cur && matches!(e.kind, EdgeKind::CreatedFiles | EdgeKind::OpenedSockets | EdgeKind::Provides | EdgeKind::Owns | EdgeKind::TouchesRegistry | EdgeKind::SpawnedChildrenMetric))
            .cloned()
            .collect();

        // append incident edges first (they relate to this node)
        for e in incident {
            edges_collected.push(e);
        }

        // then add the parent/spawn edge (if any) to walk upwards
        if let Some(parent_edge) = g.edges.iter().find(|e| e.dst == cur && matches!(e.kind, EdgeKind::ParentOf | EdgeKind::Spawned)) {
            edges_collected.push(parent_edge.clone());
            cur = parent_edge.src.clone();
            depth += 1;
            continue;
        }

        break;
    }

    // currently edges_collected is target->root order; reverse to get root->target
    edges_collected.reverse();
    edges_collected
}
