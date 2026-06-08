# Argus — Host Observability Platform

A Rust-based host observability runtime currently focused on process monitoring, with a roadmap to evolve into a comprehensive system observability platform. Argus is built using **Surface-State Architecture (SSA)** to enable extensible, maintainable monitoring and threat detection across the entire system stack.

> **Note**: This project was created to solidify low-level system programming skills while building a production-ready observability product.

## 🎯 Project Vision

Argus is not just a process monitor—it's the foundation for a complete host observability platform. While we start with process monitoring, the architecture is designed to support:

- **Process Monitoring** (current)
- File System Monitoring
- Network Monitoring
- Security Monitoring & Threat Detection
- Event Correlation
- Telemetry Collection
- Policy Engine
- Fleet Monitoring

Every architectural decision is made with this long-term vision in mind.

## 🛠️ Tech Stack

### Backend
- **Language**: Rust (2021 edition)
- **Async Runtime**: Tokio (multi-threaded)
- **TUI Framework**: Ratatui + Crossterm
- **System APIs**: Windows Win32 API, sysinfo
- **IPC/Networking**: Axum web framework, WebSocket support
- **Data Serialization**: Serde + JSON

### Frontend
- **UI**: TypeScript/JavaScript-based web dashboard
- **Protocol**: WebSocket for real-time communication

### Architecture Pattern
- **SSA (Surface-State Architecture)**: Decoupled event-driven architecture for extensibility

## 📋 Quick Start

### Prerequisites
- Rust 1.70+
- Windows OS (currently Windows-specific due to Win32 API usage)
- PowerShell or Command Prompt

### Running the Application

```powershell
cd c:\Users\RYZEN\repos\litmajor\argus
cargo run
```

The application will:
1. Start the core runtime and register all domains
2. Initialize all surfaces (console, TUI, HTTP bridge)
3. Begin collecting system metrics and process data
4. Expose WebSocket bridge on `ws://127.0.0.1:3000`

Press `Ctrl+C` to gracefully shutdown.

## 📁 Project Structure

```
argus/
├── src/
│   ├── main.rs                 # Entry point, runtime initialization
│   ├── core/                   # Core domain models and state
│   │   ├── process.rs         # Process model definition
│   │   └── mod.rs
│   ├── domains/                # Feature domains (pluggable)
│   │   ├── process/           # Process monitoring domain
│   │   ├── cpu/               # CPU metrics domain
│   │   ├── memory/            # Memory metrics domain
│   │   ├── security/          # Security scanning domain
│   │   ├── graph/             # Graph analysis
│   │   ├── rules/             # Rule engine
│   │   └── mod.rs
│   ├── actions/                # Domain actions (events, commands)
│   ├── surfaces/               # Output interfaces (TUI, HTTP, console)
│   │   ├── console/           # Console/CLI surface
│   │   ├── overview/          # Overview display
│   │   ├── process/           # Process-specific UI
│   │   ├── findings/          # Security findings display
│   │   ├── security/          # Security surface
│   │   └── mod.rs
│   ├── runtime/                # Async runtime orchestration
│   ├── bridge/                 # HTTP + WebSocket IPC
│   ├── persistence.rs          # Snapshot and state persistence
│   ├── timeline.rs             # Event timeline recording (JSONL)
│   ├── ui.rs                   # UI integrations
│   └── [other modules]
├── ui/                         # TypeScript frontend
│   ├── src/
│   ├── package.json
│   └── tsconfig.json
├── Cargo.toml                  # Rust dependencies
├── Architect_prompt.md         # Architecture vision document
└── README.md                   # This file
```

## 🏗️ Architecture Overview

Argus uses **Surface-State Architecture (SSA)**, a pattern that cleanly separates concerns:

### Key Components

1. **State (Core)**: Immutable or synchronized state models representing system objects
   - `core::process::Process` — process state representation
   - Domain-specific state models

2. **Domains**: Feature areas that collect, process, and analyze data
   - Each domain is self-contained and pluggable
   - Domains emit events through the action system
   - Register engines for collection and analysis

3. **Actions**: The event flow system
   - Domains emit actions (events) representing state changes
   - Actions are dispatched through a central runtime
   - Subscribers (surfaces, persistence, bridges) receive and react to actions

4. **Surfaces**: Presentation and IPC layers
   - TUI surface for interactive monitoring
   - HTTP/WebSocket bridge for remote access
   - Console output for debugging
   - Custom surfaces can be added without modifying core logic

5. **Persistence**: State snapshot and event logging
   - Daily JSONL timeline recording
   - Snapshot serialization
   - UDP event publishing for external systems

For an in-depth explanation of SSA, integration patterns, and how to extend Argus, see [ARCHITECTURE.md](ARCHITECTURE.md).

## 📚 Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — SSA architecture deep dive, domain integration, and extension patterns
- **[DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md)** — Development setup, workflow, and how to add new features
- **[README-UI.md](README-UI.md)** — Frontend-specific documentation

## 🚀 Current Status

- ✅ SSA architecture implemented
- ✅ Process monitoring domain
- ✅ CPU and memory metrics collection
- ✅ Security scanning baseline
- ✅ TUI surface with multiple views
- ✅ WebSocket bridge for remote access
- ✅ Event persistence (timeline + snapshots)
- 🔄 Active development on domain expansion

## 🔌 Extending Argus

To add a new monitoring domain:

1. Create a new domain module in `src/domains/`
2. Define state models in `core/`
3. Register event actions in the domain's action module
4. Implement collectors and engines
5. Register with the runtime in `main.rs`
6. Add surfaces to display the data

See [ARCHITECTURE.md](ARCHITECTURE.md#adding-new-domains) for detailed integration steps.

## 🤝 Contributing

This project emphasizes architectural clarity and domain-driven design. When contributing:

- Follow the SSA pattern—keep concerns separated
- Use strong typing and immutable state
- Document domain responsibilities
- Ensure new domains can be integrated without modifying core runtime

See [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for setup and development workflow.

## 📖 Learning Resources

This project demonstrates:
- **Low-level system programming** with Windows Win32 API
- **Async Rust** patterns with Tokio
- **Event-driven architecture** design
- **Terminal UI** development with Ratatui
- **System observability** techniques

## 📄 License
This project is under MIT License

## 👤 Author

Created as a learning project to solidify low-level system skills while building a production observability platform.

---

**Questions?** Refer to [ARCHITECTURE.md](ARCHITECTURE.md) for deep dives or [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md) for development help.
