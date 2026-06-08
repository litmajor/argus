#[derive(Debug, Clone)]
pub enum CpuEvent {
    /// Raw sample emitted by collector (consumed by cpu engine)
    RawSample { percent: f32 },
    Spike { percent: f32 },
    Normalized,
}
