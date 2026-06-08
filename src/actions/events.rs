#[derive(Debug, Clone)]
pub enum ActionEvent {
    KillAttempt { _pid: u32 },
    KillResult { _pid: u32, _success: bool },
    SuspendAttempt { _pid: u32 },
    SuspendResult { _pid: u32, _success: bool },
    ExportSnapshot { _path: String },
}
