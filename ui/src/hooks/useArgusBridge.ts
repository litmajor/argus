// hooks/useArgusBridge.ts
import { useEffect } from 'react'
import { useSsaStore } from '../state/ssa.store'
import { Alert } from '../models/Alert'
import { TimelineEvent } from '../models/TimelineEvent'

let wsInstance: WebSocket | null = null
let reconnectTimer: number | null = null
let pollingTimer: number | null = null

function connect(url: string) {
  if (wsInstance?.readyState === WebSocket.OPEN) return

  const ws = new WebSocket(url)
  wsInstance = ws

  ws.onopen = () => console.log('[Argus] Bridge connected')
  ws.onopen = () => {
    console.log('[Argus] Bridge connected')
    stopPolling()
  }

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data)
      const store = useSsaStore.getState()

      switch (msg.kind) {
        case 'memory.used':
          store.setMetrics({
            memoryUsedMb: msg.payload.used_mb,
            memoryTotalMb: msg.payload.total_mb,
          })
          break

        case 'cpu.sample':
        case 'cpu.spike':
          store.setMetrics({ cpuPercent: msg.payload.percent })
          break

        case 'process.started':
          store.upsertProcess({
            pid: msg.payload.pid,
            name: msg.payload.name,
            parentPid: msg.payload.parent_pid ?? 0,
            cpuPercent: msg.payload.cpu_percent ?? 0,
            memoryMb: msg.payload.memory_mb ?? 0,
            threads: msg.payload.threads ?? 0,
            riskScore: msg.payload.identity?.risk_score ?? 0,
            identity: msg.payload.identity,
            children: [],
            startTime: Date.now(),
          })
          break

        case 'process.terminated':
          store.removeProcess(msg.payload.pid)
          break

        case 'process.cpuspike':
          store.upsertProcess({
            pid: msg.payload.pid,
            name: '',
            parentPid: 0,
            cpuPercent: msg.payload.cpu,
            memoryMb: 0,
            threads: 0,
            riskScore: 0,
            children: [],
            startTime: Date.now(),
          })
          break

        case 'security.powershell_spawned':
        case 'security.unsigned': {
          const alert: Alert = {
            id: `${msg.kind}-${msg.payload.pid}-${Date.now()}`,
            title: msg.kind === 'security.powershell_spawned' ? 'PowerShell Spawned' : 'Unsigned Process',
            description: `PID ${msg.payload.pid}${msg.payload.name ? ` (${msg.payload.name})` : ''}`,
            risk: msg.kind === 'security.powershell_spawned' ? 70 : 50,
            severity: msg.kind === 'security.powershell_spawned' ? 'High' : 'Medium',
            pid: msg.payload.pid,
            timestamp: msg.ts ?? Date.now(),
            kind: 'security',
          }
          store.addAlert(alert)
          break
        }

        case 'finding': {
          const alert: Alert = {
            id: `finding-${Date.now()}`,
            title: msg.payload.title,
            description: msg.payload.description,
            risk: msg.payload.risk,
            severity: msg.payload.severity,
            timestamp: msg.ts ?? Date.now(),
            kind: 'finding',
          }
          store.addAlert(alert)
          break
        }

        default: {
          const event: TimelineEvent = {
            id: `${msg.kind}-${Date.now()}`,
            kind: msg.kind,
            timestamp: msg.ts ?? Date.now(),
            payload: msg.payload,
            summary: eventSummary(msg),
          }
          store.addEvent(event)
        }
      }
    } catch (e) {
      console.error('[Argus] Invalid message:', event.data)
    }
  }

  ws.onclose = () => {
    console.log('[Argus] Bridge disconnected, reconnecting...')
    wsInstance = null
    reconnectTimer = setTimeout(() => connect(url), 3000)
    // start HTTP polling fallback
    startPolling(url)
  }

  ws.onerror = (err) => {
    console.error('[Argus] WebSocket error:', err)
    ws.close()
  }
}

function startPolling(url: string) {
  if (pollingTimer) return
  const base = url.replace(/^ws:/, 'http:').replace(/\/ws$/, '')
  const poll = async () => {
    try {
      const store = useSsaStore.getState()
      // processes
      const p = await fetch(`${base}/processes`)
      if (p.ok) {
        const j = await p.json()
        const seen = new Set<number>()
        let cpuSum = 0
        let memSum = 0
        for (const proc of j.processes || []) {
          const pi = {
            pid: proc.pid,
            name: proc.name || '',
            parentPid: proc.parent_pid || 0,
            cpuPercent: proc.cpu_percent || 0,
            memoryMb: proc.memory_mb || 0,
            threads: proc.threads || 0,
            identity: proc.identity,
            children: [],
            startTime: Date.now(),
            riskScore: proc.identity?.risk_score ?? 0,
          }
          cpuSum += pi.cpuPercent || 0
          memSum += pi.memoryMb || 0
          store.upsertProcess(pi)
          seen.add(proc.pid)
        }
        // remove stale processes
        for (const pid of Array.from(store.processes.keys())) {
          if (!seen.has(pid)) store.removeProcess(pid)
        }
        // derive simple metrics from processes when no WS metrics available
        const derivedCpu = Math.min(100, Math.round(cpuSum))
        store.setMetrics({ cpuPercent: derivedCpu, memoryUsedMb: Math.round(memSum) })
      }

      // findings -> alerts
      const f = await fetch(`${base}/findings`)
      if (f.ok) {
        const jf = await f.json()
        for (const fn of jf.findings || []) {
          const alert = {
            id: `finding-${Date.now()}-${Math.random().toString(36).slice(2,8)}`,
            title: fn.title,
            description: fn.description,
            risk: fn.risk ?? 0,
            severity: (fn.severity as any) || 'Low',
            timestamp: Date.now(),
            kind: 'finding',
          }
          store.addAlert(alert)
        }
      }
    } catch (e) {
      // ignore poll errors
      // console.error('[Argus] Poll error', e)
    }
  }
  // poll immediately then every 2s
  poll()
  pollingTimer = window.setInterval(poll, 2000)
}

function stopPolling() {
  if (!pollingTimer) return
  clearInterval(pollingTimer)
  pollingTimer = null
}

function eventSummary(msg: any): string {
  if (msg.kind === 'process.started') return `${msg.payload.name} (pid ${msg.payload.pid})`
  if (msg.kind === 'process.terminated') return `PID ${msg.payload.pid} exited`
  if (msg.kind === 'memory.pressure') return `Memory pressure: ${msg.payload.used_mb.toFixed(0)} MB`
  return JSON.stringify(msg.payload).slice(0, 60)
}

export function useArgusBridge(url: string = 'ws://localhost:3000/ws') {
  useEffect(() => {
    connect(url)
    return () => {
      if (reconnectTimer) clearTimeout(reconnectTimer)
      wsInstance?.close()
      wsInstance = null
    }
  }, [url])
}