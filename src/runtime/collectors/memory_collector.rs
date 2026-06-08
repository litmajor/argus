use anyhow::Result;
use crate::domains::memory::events::MemoryEvent;
use crate::runtime::event_bus;
use sysinfo::System;

pub fn collect_memory() -> Result<()> {
    // Use lightweight constructor and refresh only memory data
    let mut sys = System::new();
    sys.refresh_memory();
    // sysinfo returns values in bytes; convert to MB using 1024*1024
    let total = sys.total_memory() as f32 / 1024.0 / 1024.0; // MB
    let used = sys.used_memory() as f32 / 1024.0 / 1024.0; // MB
    let used_pct = if total > 0.0 { used / total * 100.0 } else { 0.0 };

    // Publish a system-level memory usage sample every tick so overview stays current
    event_bus::publish(MemoryEvent::UsedSample { used_mb: used });

    // Also publish pressure alerts when above threshold
    if used_pct > 80.0 {
        event_bus::publish(MemoryEvent::PressureHigh { used_mb: used });
    }

    Ok(())
}
