#[derive(Debug, Clone)]
pub enum MemoryEvent {
    PressureHigh { used_mb: f32 },
    LeakSuspected { pid: u32 },
    // Raw per-process memory sample observation (collectors/runtime publish)
    ProcessMemorySample { pid: u32, memory_mb: f32 },
    // System-level memory usage sample (collectors publish)
    UsedSample { used_mb: f32 },
}
