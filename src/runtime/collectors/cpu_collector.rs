use anyhow::Result;
use crate::domains::cpu::events::CpuEvent;
use crate::runtime::event_bus;
use sysinfo::System;

pub fn collect_cpu() -> Result<()> {
    // Use lightweight constructor and refresh CPU info only
    let mut sys = System::new();
    sys.refresh_cpu_all();
    // use the global cpu usage accessor in sysinfo v0.39 (returns a f32)
    let usage = sys.global_cpu_usage();
    // Emit raw sample; cpu engine will perform hysteresis and emit Spike/Normalized
    event_bus::publish(CpuEvent::RawSample { percent: usage });
    Ok(())
}
