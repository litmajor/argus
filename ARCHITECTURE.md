# Argus Architecture — Surface-State Architecture (SSA)

This document formalizes the **Surface-State Architecture (SSA)** pattern used in Argus. Understanding this pattern is essential for extending the system, adding new domains, and maintaining clean separation of concerns.

## 🎯 Core Principle

**Argus separates concerns across five layers: State, Domains, Actions, Surfaces, and Runtime.**

This separation enables:
- ✅ **Extensibility**: New domains integrate without modifying core logic
- ✅ **Testability**: Each layer can be tested independently
- ✅ **Clarity**: Clear data flow and responsibility boundaries
- ✅ **Reusability**: State models and domains can be consumed by multiple surfaces
- ✅ **Scalability**: Add more collectors, domains, and surfaces without redesign

## 🏗️ The Five Layers

### 1. **State Layer (Core)**

**Responsibility**: Define immutable or thread-safe state models representing system objects.

**Location**: `src/core/`

**Key Principle**: State is the single source of truth. It should:
- Be strongly typed
- Represent a complete snapshot of an observable entity
- Be serializable (Serde)
- Be cloneable or Arc-wrapped for thread safety
- Include timestamps for all observations

**Example**:

```rust
// src/core/process.rs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub cpu_usage: f64,
    pub memory_usage: u64,
    pub status: ProcessStatus,
    pub start_time: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
```

**State Layer Responsibilities**:
- Define core data structures
- Implement serialization/deserialization
- Provide constructors and validation
- **Do NOT**: Perform I/O, make system calls, or emit events

### 2. **Domains Layer**

**Responsibility**: Collect, process, and analyze data within a specific feature area.

**Location**: `src/domains/`

**Each domain contains**:
- **State models** (in `core/`) — The data this domain tracks
- **Collectors** — Routines that gather raw data from the system
- **Engines** — Analysis, transformation, and event emission logic
- **Subscribers** — Listeners that react to domain events
- **Action definitions** — Events emitted by this domain

**Example Structure**:

```
src/domains/
├── cpu/
│   ├── mod.rs              # Domain exports
│   ├── engine.rs           # CPU analysis engine
│   ├── collector.rs        # CPU metrics collection
│   └── actions.rs          # CPU-related events
├── memory/
│   ├── mod.rs
│   ├── engine.rs
│   ├── collector.rs
│   └── actions.rs
└── [other domains]
```

**Domain Lifecycle**:

1. **Registration** (in `main.rs`):
   ```rust
   crate::domains::cpu::engine::register();
   crate::domains::memory::engine::register();
   ```

2. **Collection** (periodic or event-triggered):
   - Collectors gather raw system data
   - Data is wrapped in domain state models

3. **Analysis** (engines process state):
   - Engines apply business logic
   - Thresholds are evaluated
   - Events (actions) are emitted

4. **Event Propagation**:
   - Actions flow through the runtime
   - Subscribers (surfaces, persistence) receive and react

**Domain Responsibilities**:
- Collect data from system APIs
- Maintain domain state models
- Emit actions (events)
- Provide analysis and filtering
- Register themselves with the runtime
- **Do NOT**: Directly modify global state or display data

### 3. **Actions Layer**

**Responsibility**: Define and dispatch events throughout the system.

**Location**: `src/actions/` and within each domain

**Key Concept**: Actions represent state changes and commands flowing through the system.

**Action Types**:

1. **Domain Actions** — Emitted by domains when state changes occur
   ```rust
   // src/domains/cpu/actions.rs
   #[derive(Clone, Debug, Serialize)]
   pub enum CpuAction {
       MetricsUpdated { cpu_data: CpuMetrics },
       HighCpuDetected { process_pid: u32, usage: f64 },
       CorrelationAnalyzed { findings: Vec<String> },
   }
   ```

2. **System Actions** — Global events
   ```rust
   // src/actions/mod.rs
   #[derive(Clone, Debug)]
   pub enum Action {
       Cpu(cpu::actions::CpuAction),
       Memory(memory::actions::MemoryAction),
       Process(process::actions::ProcessAction),
       Security(security::actions::SecurityAction),
       // ...
   }
   ```

**Action Flow**:
```
Domain (Collector/Engine)
    ↓
Emit Action
    ↓
Runtime Dispatcher
    ↓
All Subscribers (Surfaces, Persistence, etc.)
```

**Action Best Practices**:
- Make actions data-rich (include all relevant context)
- Include timestamps
- Use enums for type safety
- Keep actions focused (one concern per action type)
- Make actions serializable for persistence and IPC

### 4. **Surfaces Layer**

**Responsibility**: Present data to users or external systems without modifying core logic.

**Location**: `src/surfaces/`

**Surface Types**:

1. **TUI Surface** (`surfaces/overview/`, `surfaces/process/`)
   - Interactive terminal user interface using Ratatui
   - Receives actions and updates display
   - User-driven, responsive to keypresses

2. **HTTP/WebSocket Bridge** (`src/bridge/`)
   - Exposes metrics and events via HTTP and WebSocket
   - Enables remote dashboards and external tools
   - Real-time streaming of events

3. **Console Surface** (`surfaces/console/`)
   - Simple console output for debugging
   - Can be toggled on/off

4. **Custom Surfaces**
   - Can subscribe to any actions
   - Examples: Slack integration, metrics export, alerts

**Surface Registration** (in `main.rs`):

```rust
surfaces::console::register();
surfaces::overview::register();
surfaces::process::register();
surfaces::findings::register();
surfaces::security::register();
```

**Surface Responsibilities**:
- Subscribe to relevant actions
- Transform domain state for display/export
- Handle user input (if interactive)
- Maintain surface-specific state (UI focus, filters, etc.)
- **Do NOT**: Modify domain state or emit domain actions

**Creating a New Surface**:

```rust
// src/surfaces/custom.rs
pub fn register() {
    // Subscribe to relevant actions
    // Set up UI or external connection
    // Update when actions arrive
}

pub fn handle_action(action: &Action) {
    match action {
        Action::Process(proc_action) => {
            // Update display with process data
        }
        Action::Security(sec_action) => {
            // Update security findings display
        }
        _ => {}
    }
}
```

### 5. **Runtime Layer**

**Responsibility**: Orchestrate and dispatch events, manage lifecycle.

**Location**: `src/runtime/`, `src/main.rs`

**Runtime Responsibilities**:
- Register domains and surfaces
- Provide event dispatch mechanism
- Manage async task scheduling
- Handle signals (Ctrl+C graceful shutdown)
- Coordinate startup and teardown

**Startup Sequence** (see `main.rs`):

```rust
// 1. Register surfaces
surfaces::console::register();
surfaces::overview::register();
// ...

// 2. Register domain engines
domains::cpu::engine::register();
domains::memory::engine::register();
domains::security::engine::register();
// ...

// 3. Register persistence
domains::process::subscribers::register_file_logger("events.log");
domains::process::subscribers::register_persistence();

// 4. Load state
if let Some(s) = persistence::load_latest_snapshot() {
    println!("Loaded snapshot from ts={}", s.ts);
}

// 5. Start services
timeline::register();
bridge::start("127.0.0.1:3000");

// 6. Run runtime
runtime::run(&running);
```

## 📊 Data Flow Diagram

```
System APIs (Win32, sysinfo)
    ↓
Domain Collectors
    ↓
Raw Data → State Models
    ↓
Domain Engines (Analysis)
    ↓
Actions Emitted
    ↓
┌───────────────────────────┐
│   Runtime Dispatcher      │
└───────────────────────────┘
    ↓ ↓ ↓ ↓ ↓ (broadcast)
    ↓ ↓ ↓ ↓ └─→ Persistence Layer
    ↓ ↓ ↓ └───→ HTTP/WebSocket Bridge
    ↓ ↓ └─────→ TUI Surface
    ↓ └───────→ Console Surface
    └─────────→ Custom Surfaces
```

## 🔌 Adding New Domains

To add a new observability domain (e.g., File System Monitoring):

### Step 1: Define Core State Models

**File**: `src/core/filesystem.rs`

```rust
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FileOperation {
    pub path: String,
    pub operation: FileOperationType,
    pub timestamp: DateTime<Utc>,
    pub process_pid: u32,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FileOperationType {
    Created,
    Modified,
    Deleted,
    Accessed,
}
```

Update `src/core/mod.rs`:
```rust
pub mod filesystem;
```

### Step 2: Create Domain Module

**File**: `src/domains/filesystem/mod.rs`

```rust
pub mod collector;
pub mod engine;
pub mod actions;

pub use engine::register;
```

### Step 3: Define Domain Actions

**File**: `src/domains/filesystem/actions.rs`

```rust
use crate::core::filesystem::{FileOperation, FileOperationType};
use serde::{Serialize, Deserialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FilesystemAction {
    FileOperationDetected(FileOperation),
    SuspiciousFileActivityFound {
        path: String,
        reason: String,
        risk_level: String,
    },
    DirectoryTraversalAttempted {
        source_pid: u32,
        target_path: String,
    },
}
```

### Step 4: Implement Data Collection

**File**: `src/domains/filesystem/collector.rs`

```rust
use crate::core::filesystem::{FileOperation, FileOperationType};
use chrono::Utc;

pub struct FilesystemCollector;

impl FilesystemCollector {
    pub async fn collect_file_operations() -> Vec<FileOperation> {
        // Use Windows API or ETW to collect file operations
        // Wrap in FileOperation state models
        // Return collected data
        vec![]
    }
}
```

### Step 5: Implement Domain Engine

**File**: `src/domains/filesystem/engine.rs`

```rust
use crate::actions::{Action, dispatcher};
use super::actions::FilesystemAction;
use super::collector::FilesystemCollector;
use tokio::task;
use std::time::Duration;

pub fn register() {
    task::spawn(async {
        loop {
            // Collect data
            let operations = FilesystemCollector::collect_file_operations().await;

            // Analyze and emit actions
            for op in operations {
                // Analyze operation...
                
                let action = Action::Filesystem(
                    FilesystemAction::FileOperationDetected(op)
                );
                
                dispatcher::dispatch(action).await;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}
```

### Step 6: Register Domain in Runtime

**File**: `src/main.rs`

```rust
// Add import
mod domains {
    // ... existing
    pub mod filesystem;
}

// In main():
crate::domains::filesystem::engine::register();
```

### Step 7: Update Action Enum

**File**: `src/actions/mod.rs`

```rust
pub enum Action {
    Process(process::actions::ProcessAction),
    Cpu(cpu::actions::CpuAction),
    Memory(memory::actions::MemoryAction),
    Security(security::actions::SecurityAction),
    Filesystem(filesystem::actions::FilesystemAction),  // NEW
}
```

### Step 8: Create Surfaces to Display Data

**File**: `src/surfaces/filesystem.rs`

```rust
use crate::actions::Action;

pub fn register() {
    // Set up subscription and UI
}

pub fn handle_action(action: &Action) {
    match action {
        Action::Filesystem(fs_action) => {
            // Update filesystem view
        }
        _ => {}
    }
}
```

Register in `main.rs`:
```rust
surfaces::filesystem::register();
```

## 🔄 Integration Patterns

### Pattern 1: Domain-to-Surface Flow

**Use Case**: Display real-time metrics in TUI

```
CPU Domain → Emits CpuAction
        ↓
    Runtime Dispatcher
        ↓
    CPU Surface → Updates TUI display
```

### Pattern 2: Domain-to-Persistence Flow

**Use Case**: Log all security events to disk

```
Security Domain → Emits SecurityAction
        ↓
    Runtime Dispatcher
        ↓
    Persistence Subscriber → Writes to events.log
```

### Pattern 3: Domain-to-Domain Flow

**Use Case**: Process domain analysis triggers security checks

```
Process Domain → Emits ProcessAction
        ↓
    Runtime Dispatcher
        ↓
    Security Domain → Analyzes for threats → Emits SecurityAction
        ↓
    Runtime Dispatcher
        ↓
    Security Surface & Persistence
```

### Pattern 4: External Integration

**Use Case**: Send critical alerts to external systems

```
Security Domain → Emits SecurityAction
        ↓
    Runtime Dispatcher
        ↓
    Custom Alert Surface → Sends to Slack/PagerDuty
```

## 🎯 Best Practices

### 1. **State Management**
- Keep state models simple and focused
- Use `Arc<Mutex<T>>` or `Arc<RwLock<T>>` for shared mutable state
- Immutable-first approach when possible
- Always include timestamps

### 2. **Domain Isolation**
- Each domain should be independently deployable
- Minimize inter-domain dependencies
- Communicate via actions, not direct function calls
- Use feature flags for optional domains

### 3. **Action Design**
- Actions should be self-contained (include all context)
- Use strong typing (enums, not strings)
- Make actions serializable
- Keep action hierarchy flat within a domain

### 4. **Error Handling**
- Use `anyhow::Result` for fallible operations
- Log errors but don't panic in domain logic
- Emit error actions if recovery is needed
- Let surfaces decide how to display errors

### 5. **Performance**
- Use async/await for I/O operations
- Batch operations when collecting data
- Cache state when appropriate
- Use channels for inter-task communication

### 6. **Testing**
- Test state models independently
- Mock system APIs in domain tests
- Test action emission logic
- Test surface reaction to actions

## 📋 Checklist for Adding New Features

- [ ] Define core state models
- [ ] Create domain module structure
- [ ] Implement data collectors
- [ ] Implement domain engine with analysis
- [ ] Define domain actions
- [ ] Register domain in runtime
- [ ] Update main action enum
- [ ] Create surfaces to display data
- [ ] Add persistence subscribers if needed
- [ ] Write tests for domain logic
- [ ] Document domain in this file
- [ ] Update README with new capability

## 🔮 Future Extensibility

The SSA pattern enables these future capabilities:

1. **Distributed Observability**: Multiple Argus instances emit actions to a central dispatcher
2. **Rule Engine Integration**: Custom rules trigger actions based on complex conditions
3. **ML Integration**: Anomaly detection engines consume actions and emit alerts
4. **Fleet Management**: Aggregate actions from multiple hosts
5. **Custom Plugins**: Third-party domains integrate via action streams

---

**Next Steps**: See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for setup and development workflow.
