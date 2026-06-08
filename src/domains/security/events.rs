#[derive(Debug, Clone)]
pub enum SecurityEvent {
    PowershellSpawned { pid: u32 },
    /// Emitted when a process start can be attributed to an originator (who spawned it).
    ProcessSpawnedBy { pid: u32, origin_pid: u32, origin_name: String, lineage: Vec<String> },
    UnsignedProcessStarted { pid: u32, name: String },
    /// Emitted when the verification result is informational (Signed/Unknown/VerificationFailed)
    ProcessSignatureVerification { pid: u32, name: String, result: crate::domains::security::policies::SignatureVerification },
    HandleHijackDetected { pid: u32 },
}
