use crate::domains::cpu::CpuEvent;
use once_cell::sync::Lazy;
use std::sync::Mutex;
use crate::runtime::event_bus;

struct Engine {
    spike_threshold: f32,
    consecutive_required: usize,
    consecutive_spikes: usize,
    consecutive_normals: usize,
    active_spike: bool,
}

impl Engine {
    fn new(spike_threshold: f32, consecutive_required: usize) -> Self {
        Self {
            spike_threshold,
            consecutive_required,
            consecutive_spikes: 0,
            consecutive_normals: 0,
            active_spike: false,
        }
    }

    fn observe(&mut self, pct: f32) {
        if pct > self.spike_threshold {
            self.consecutive_spikes += 1;
            self.consecutive_normals = 0;
        } else {
            self.consecutive_normals += 1;
            self.consecutive_spikes = 0;
        }

        if !self.active_spike && self.consecutive_spikes >= self.consecutive_required {
            self.active_spike = true;
            // publish stabilized spike
            event_bus::publish(CpuEvent::Spike { percent: pct });
        } else if self.active_spike && self.consecutive_normals >= self.consecutive_required {
            self.active_spike = false;
            event_bus::publish(CpuEvent::Normalized);
        }
    }
}

static CPU_ENGINE: Lazy<Mutex<Engine>> = Lazy::new(|| Mutex::new(Engine::new(80.0, 3)));

pub fn register() {
    // subscribe to raw cpu samples on the cpu bus and apply hysteresis
    let sub = crate::runtime::events::subscribe_to_cpu_events(Box::new(|ev| match ev {
        CpuEvent::RawSample { percent } => {
            let mut g = CPU_ENGINE.lock().unwrap();
            g.observe(*percent);
        }
        _ => {}
    }));
    // keep the subscription alive for the lifetime of the engine
    let _ = sub;
}
