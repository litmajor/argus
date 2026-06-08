// Minimal Tauri IPC wrapper with WebSocket fallback
export async function invoke<T = unknown>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  // If running inside Tauri, use the global `window.__TAURI__` bridge
  // otherwise, reject and let callers fallback to WS.
  // Keep this minimal to avoid hard dependency on @tauri-apps/api in the UI.
  // Consumers should handle fallback logic.
  // Example usage: invoke('runtime.do_something', { pid: 123 })
  // Note: this is intentionally lightweight and returns a rejected promise
  // when Tauri is not available so the caller can fallback.
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  if (typeof window !== 'undefined' && (window as any).__TAURI__ && (window as any).invoke) {
    // @ts-ignore
    return (window as any).invoke(cmd, args)
  }
  return Promise.reject(new Error('Tauri not available'))
}
