#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // Start the backend IPC bridge (non-blocking)
    // The `argus` crate should expose a `bridge::start` function as implemented in the repo.
    // If building the tauri wrapper, ensure `src/main.rs` of the main crate exposes bridge::start.
    std::thread::spawn(|| {
        // call into the existing binary crate to start the bridge
        // Note: this requires `argus` to be a library crate or the bridge function to be reachable.
        let _ = std::panic::catch_unwind(|| {
            if let Err(e) = std::panic::AssertUnwindSafe(|| {
                // best-effort: call the bridge start if available
                // If `argus::bridge::start` is not accessible, adapt this file to spawn the binary instead.
                #[allow(unused_imports)]
                use argus::runtime;
                use argus::bridge;
                // start core runtime
                let _ = std::panic::catch_unwind(|| { runtime::start(); });
                // start bridge on port 9000
                bridge::start("127.0.0.1:9000");
            }) {
                eprintln!("bridge start panicked: {:?}", e);
            }
        });
    });

    // Launch Tauri
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
