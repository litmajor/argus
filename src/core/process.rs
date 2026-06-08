#[derive(Debug, Clone)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub cpu_percent: f32,
    pub memory_mb: f32,
    pub threads: u32,
    pub parent_pid: u32,
    pub start_time: Option<u64>,
}
