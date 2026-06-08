# Argus Developer Guide

Welcome to the Argus development guide. This document covers setup, development workflow, and common tasks.

## 🛠️ Development Environment Setup

### Prerequisites

- **Rust 1.70+** — [Install here](https://www.rust-lang.org/tools/install)
- **Windows 10+** — Currently Windows-specific (Win32 API)
- **PowerShell 5.0+** or Command Prompt
- **Git** — For version control
- **Visual Studio Code** (optional but recommended)

### Verify Installation

```powershell
rustc --version
cargo --version
```

### Project Setup

1. **Clone the repository**:
   ```powershell
   git clone <argus project link will be here>
   cd argus
   ```

2. **Build the project**:
   ```powershell
   cargo build
   ```

3. **Run tests**:
   ```powershell
   cargo test
   ```

4. **Run the application**:
   ```powershell
   cargo run
   ```

## 📝 Project Layout

**Key directories and their purposes**:

| Directory | Purpose |
|-----------|---------|
| `src/core/` | State models — the single source of truth |
| `src/domains/` | Observable domains (cpu, memory, security, etc.) |
| `src/actions/` | Event definitions and dispatcher |
| `src/surfaces/` | Presentation layers (TUI, HTTP, console) |
| `src/runtime/` | Async runtime and orchestration |
| `src/bridge/` | HTTP/WebSocket IPC server |
| `src/persistence.rs` | Snapshot and state management |
| `src/timeline.rs` | Event timeline recording (JSONL) |
| `ui/` | TypeScript frontend (separate build) |
| `Cargo.toml` | Rust dependencies and configuration |

## 🚀 Development Workflow

### 1. Adding a New Feature

**Scenario**: Add memory pressure threshold alerts

#### Step A: Identify the Domain

- Is this part of an existing domain (memory, process, etc.)?
- Or does it need a new domain?

For memory alerts, we'll extend the `domains/memory` domain.

#### Step B: Update Core State

**File**: `src/core/memory.rs`

Add a new state model:

```rust
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemoryPressure {
    pub usage_percent: f64,
    pub available_bytes: u64,
    pub total_bytes: u64,
    pub pressure_level: PressureLevel,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PressureLevel {
    Healthy,
    Warning,
    Critical,
}
```

#### Step C: Update Domain Actions

**File**: `src/domains/memory/actions.rs`

Add new action:

```rust
#[derive(Clone, Debug, Serialize)]
pub enum MemoryAction {
    // ... existing actions
    MemoryPressureDetected(MemoryPressure),
    CriticalMemoryAlert { 
        usage_percent: f64,
        available_bytes: u64 
    },
}
```

#### Step D: Update Domain Engine

**File**: `src/domains/memory/engine.rs`

Add pressure analysis:

```rust
async fn analyze_memory_pressure(metrics: &MemoryMetrics) -> Vec<Action> {
    let mut actions = vec![];
    
    let usage_percent = (metrics.used as f64 / metrics.total as f64) * 100.0;
    
    let pressure_level = match usage_percent {
        p if p > 90.0 => PressureLevel::Critical,
        p if p > 75.0 => PressureLevel::Warning,
        _ => PressureLevel::Healthy,
    };
    
    if pressure_level == PressureLevel::Critical {
        actions.push(Action::Memory(
            MemoryAction::CriticalMemoryAlert {
                usage_percent,
                available_bytes: metrics.available,
            }
        ));
    }
    
    actions
}
```

#### Step E: Update Surfaces

**File**: `src/surfaces/memory.rs` or a new surface

Subscribe to the new action:

```rust
pub fn handle_action(action: &Action) {
    match action {
        Action::Memory(MemoryAction::CriticalMemoryAlert { usage_percent, .. }) => {
            // Display warning in TUI or alert
            eprintln!("⚠️ CRITICAL: Memory usage at {:.1}%", usage_percent);
        }
        _ => {}
    }
}
```

#### Step F: Test the Feature

Create or update tests:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pressure_detection() {
        let pressure = MemoryPressure {
            usage_percent: 92.5,
            available_bytes: 1024,
            total_bytes: 16384,
            pressure_level: PressureLevel::Critical,
            timestamp: Utc::now(),
        };
        
        assert_eq!(pressure.pressure_level, PressureLevel::Critical);
    }
}
```

Run tests:

```powershell
cargo test
```

### 2. Adding a New Domain

See [ARCHITECTURE.md](ARCHITECTURE.md#adding-new-domains) for detailed steps with example.

**Quick checklist**:

- [ ] Create `src/domains/newdomain/`
- [ ] Define state models in `src/core/newdomain.rs`
- [ ] Implement collector in `domains/newdomain/collector.rs`
- [ ] Implement engine in `domains/newdomain/engine.rs`
- [ ] Define actions in `domains/newdomain/actions.rs`
- [ ] Create surface in `src/surfaces/newdomain.rs`
- [ ] Register in `src/main.rs`
- [ ] Update `src/actions/mod.rs`

### 3. Working with Persistence

The persistence layer handles snapshots and event logs.

**View persisted events**:

```powershell
# Tail the event log
Get-Content -Path "events.log" -Tail 10

# View daily timeline JSONL files
Get-ChildItem -Path "timelines/" -Filter "*.jsonl"
```

**Snapshots**:

```rust
// Save snapshot
use crate::persistence;
let snapshot = persistence::create_snapshot();
persistence::save_snapshot(&snapshot)?;

// Load latest
if let Some(snapshot) = persistence::load_latest_snapshot() {
    println!("Loaded state from {}", snapshot.ts);
}
```

### 4. Debugging

#### Enable Detailed Logging

Add `RUST_LOG` environment variable:

```powershell
$env:RUST_LOG="debug"
cargo run
```

#### Debug a Specific Module

```powershell
$env:RUST_LOG="argus::domains::security=debug"
cargo run
```

#### Common Debug Patterns

```rust
// Print state for debugging
dbg!(&process_data);

// Conditional logging
if usage_percent > 90.0 {
    eprintln!("High memory: {:.1}%", usage_percent);
}

// Use anyhow for context
let result = operation()
    .context("Failed to collect metrics")?;
```

### 5. Performance Profiling

#### Check Build Time

```powershell
cargo build --release -j 1
```

#### Profile Runtime Performance

Use Windows Performance Analyzer or similar profiler.

#### Optimize Async Tasks

- Use `tokio::task::spawn_blocking()` for CPU-intensive work
- Batch I/O operations
- Use channels to avoid lock contention
- Profile with `--profile=release`

## 🔄 Git Workflow

### Branch Strategy

```
main (stable releases)
  ↑
  └─ develop (integration branch)
      ↑
      ├─ feature/cpu-optimizations
      ├─ feature/network-monitoring
      └─ bugfix/memory-leak
```

### Creating a Feature Branch

```powershell
git checkout develop
git pull origin develop
git checkout -b feature/your-feature-name
```

### Committing Changes

```powershell
# Stage changes
git add src/domains/newfeature/

# Commit with clear message
git commit -m "feat: add memory pressure alerts to memory domain"

# Push to remote
git push origin feature/your-feature-name
```

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types**: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

**Example**:

```
feat(memory): add pressure threshold detection

- Detect when memory usage exceeds thresholds
- Emit CriticalMemoryAlert action
- Add pressure_level to MemoryPressure state

Closes #42
```

## 📚 Common Tasks

### Running a Specific Test

```powershell
cargo test test_memory_pressure_detection -- --nocapture
```

### Building for Release

```powershell
cargo build --release
```

### Checking Code Style

```powershell
cargo fmt --check
```

### Auto-Format Code

```powershell
cargo fmt
```

### Lint with Clippy

```powershell
cargo clippy -- -D warnings
```

### Update Dependencies

```powershell
cargo update
```

### Clean Build Artifacts

```powershell
cargo clean
```

## 🧪 Testing

### Unit Tests

Create tests within modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_state_creation() {
        let process = Process {
            pid: 1234,
            name: "chrome.exe".to_string(),
            cpu_usage: 25.5,
            memory_usage: 512000000,
            status: ProcessStatus::Running,
            start_time: Utc::now(),
            updated_at: Utc::now(),
        };
        
        assert_eq!(process.pid, 1234);
    }
}
```

### Integration Tests

Create in `tests/` directory:

```rust
// tests/integration_test.rs
#[test]
fn test_full_workflow() {
    // Set up domains
    // Emit actions
    // Verify surfaces updated
}
```

### Run All Tests

```powershell
cargo test
```

### Run Tests with Output

```powershell
cargo test -- --nocapture
```

## 📖 Code Organization Tips

### Module Structure

Keep modules focused:

```rust
// ✅ Good: Single responsibility
mod collector {
    pub fn collect() -> Vec<Data> { .. }
}

mod analyzer {
    pub fn analyze(data: &Data) -> Analysis { .. }
}

// ❌ Bad: Mixed concerns
mod everything {
    pub fn collect_and_analyze_and_display() { .. }
}
```

### Naming Conventions

- **Modules**: lowercase with underscores (`cpu_monitor`)
- **Types/Structs**: CamelCase (`ProcessMetrics`)
- **Functions**: snake_case (`collect_metrics()`)
- **Constants**: SCREAMING_SNAKE_CASE (`MAX_PROCESSES`)
- **Errors**: end with `Error` (`CollectionError`)

### Documentation

Document public APIs:

```rust
/// Collects memory metrics from the system.
///
/// # Returns
///
/// A `MemoryMetrics` struct containing current memory statistics.
///
/// # Errors
///
/// Returns an error if system APIs are unavailable.
pub fn collect_memory() -> anyhow::Result<MemoryMetrics> {
    // ...
}
```

## 🚨 Troubleshooting

### Compilation Errors

**"cannot find type X in this scope"**
- Check that you've added the import: `use crate::core::x;`
- Verify the module is exported in `mod.rs`

**"async block that must be `Send`"**
- Ensure all types in async blocks implement `Send`
- Use `Arc<Mutex<T>>` instead of `Rc<RefCell<T>>`

### Runtime Issues

**"No matching action handler"**
- Check that surfaces are registered
- Verify domain is emitting actions
- Check action matches in surface handlers

**"Memory grows indefinitely"**
- Check for unbounded channel queues
- Ensure old events are cleaned up
- Profile with task-local storage

### Windows API Errors

**"Access denied" (permission errors)**
- Run with administrator privileges for some APIs
- Check Windows API documentation for required permissions
- Use error context: `context("Failed to open process handle")?`

## 📱 Frontend Development

The `ui/` directory contains the TypeScript frontend.

### Setup

```powershell
cd ui
npm install
npm start
```

### Build

```powershell
npm run build
```

### Connect to Backend

The UI connects to the WebSocket bridge on `ws://127.0.0.1:3000`

See [README-UI.md](README-UI.md) for frontend-specific details.

## 🤝 Contributing

When contributing to Argus:

1. **Follow SSA principles** — Keep domains, surfaces, and state separate
2. **Write tests** — Aim for >80% coverage of domain logic
3. **Document changes** — Update relevant `.md` files
4. **Use type safety** — Prefer strong types over strings
5. **Think long-term** — Consider how this enables future features

## 📚 Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Tokio Documentation](https://tokio.rs/)
- [Windows Win32 API Docs](https://learn.microsoft.com/en-us/windows/win32/api/)
- [Ratatui TUI Guide](https://ratatui.rs/)
- [Serde Serialization](https://serde.rs/)

## ❓ FAQ

**Q: Where do I add a new command-line argument?**
A: Extend the argument parsing in `src/main.rs`. Consider using the `clap` crate for robust CLI.

**Q: How do I connect to a remote database?**
A: Add a persistence backend in `src/persistence.rs`. The current implementation uses local JSONL files.

**Q: Can I run Argus on Linux?**
A: Currently it uses Windows Win32 APIs. Porting would require abstracting the platform layer and implementing Linux equivalents using `/proc` filesystem and system calls.

**Q: How do I disable a domain?**
A: Remove its `register()` call from `main.rs`. Consider using feature flags for compile-time control.

**Q: What's the performance impact of adding more surfaces?**
A: Each surface adds action handling overhead. Surfaces are lightweight and should be sub-millisecond per action.

---

**Need help?** Check [ARCHITECTURE.md](ARCHITECTURE.md) for architectural questions or open an issue with details about what you're trying to accomplish.
