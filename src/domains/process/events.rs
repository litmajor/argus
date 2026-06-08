use crate::domains::process::state::ProcessInfo;
use std::fmt;

#[derive(Debug, Clone)]
pub enum ProcessEvent {
    Started(ProcessInfo),
    Terminated(u32),
    CpuSpike { pid: u32, cpu: f32 },
    FamilyCpuSpike { family: String, cpu: f64 },
    FamilyNormalized { family: String },
}

impl fmt::Display for ProcessEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProcessEvent::Started(info) => write!(f, "[PROCESS_STARTED] PID:{} NAME:{} MEM(MB):{:.1} THREADS:{}", info.pid, info.name, info.memory_mb, info.threads),
            ProcessEvent::Terminated(pid) => write!(f, "[PROCESS_TERMINATED] PID:{}", pid),
            ProcessEvent::CpuSpike { pid, cpu } => write!(f, "[PROCESS_CPU_SPIKE] PID:{} CPU:{:.1}%", pid, cpu),
            ProcessEvent::FamilyCpuSpike { family, cpu } => write!(f, "[FAMILY_CPU_SPIKE] {} CPU:{:.1}%", family, cpu),
            ProcessEvent::FamilyNormalized { family } => write!(f, "[FAMILY_NORMALIZED] {}", family),
        }
    }
}
