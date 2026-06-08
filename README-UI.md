Scaffold for `ui/` React + Vite app and `src-tauri/` Tauri wrapper.

To run the UI locally (dev):

1. cd ui
2. npm i
3. npm run dev

To build UI for Tauri:

1. cd ui
2. npm run build
3. cd ..
4. cargo tauri build

Note: Tauri integration assumes the Rust crate exposes `bridge::start()`; adjust `src-tauri/src/main.rs` if needed.
