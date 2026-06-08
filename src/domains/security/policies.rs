use sysinfo::{System, ProcessesToUpdate};

/// Result of signature verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureVerification {
    Signed,
    Unsigned,
    Unknown,
    VerificationFailed,
}

/// Evaluate the digital signature of the process executable.
/// Returns a `SignatureVerification` indicating the result. Current
/// implementation uses heuristics (whitelist and path checks). A future
/// improvement will integrate WinVerifyTrust. Importantly, this function
/// distinguishes between `Unknown` and `VerificationFailed` so callers
/// can avoid treating inability to verify as a definite unsigned result.
pub fn evaluate_process_signature(pid: u32, _name: &str) -> SignatureVerification {
    let mut sys = System::new_all();
    // Refresh processes to ensure we can query the target PID
    sys.refresh_processes(ProcessesToUpdate::All, false);
    let pid_sys = sysinfo::Pid::from(pid as usize);
    let exe_path = match sys.process(pid_sys).and_then(|p| p.exe()).map(|p| p.to_path_buf()) {
        Some(p) => p,
        None => return SignatureVerification::Unknown,
    };

    // Quick family/name whitelist to avoid flagging large multi-process apps
    if let Some(fname) = exe_path.file_name().and_then(|s| s.to_str()) {
        let lower = fname.to_lowercase();
        let allowed = [
            "code.exe",
            "brave.exe",
            "msedgewebview2.exe",
            "svchost.exe",
            "dllhost.exe",
            "conhost.exe",
            "explorer.exe",
            "system",
        ];
        if allowed.iter().any(|a| *a == lower) {
            return SignatureVerification::Signed;
        }
    }

    // Heuristic: treat executables under Program Files or Windows\System32 as signed/trusted.
    if let Some(path_str) = exe_path.to_str() {
        let lower = path_str.to_lowercase();
        if lower.contains("program files") || lower.contains("windows\\system32") {
            return SignatureVerification::Signed;
        }
    }

    // No definitive check available yet — treat as verification failed (not necessarily unsigned).
    SignatureVerification::VerificationFailed
}
