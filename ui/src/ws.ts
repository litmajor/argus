import { useSsaStore } from './state/ssa.store'
import { Process } from './models/Process'
import { Alert } from './models/Alert'

const WS_URL = 'ws://localhost:3000/ws'

export function startWs() {
  const ws = new WebSocket(WS_URL)
  const setMetrics = useSsaStore.getState().setMetrics
  const upsertProcess = useSsaStore.getState().upsertProcess
  const removeProcess = useSsaStore.getState().removeProcess
  const addEvent = useSsaStore.getState().addEvent
  const addAlert = useSsaStore.getState().addAlert

  ws.onopen = () => console.log('ws open')
  ws.onmessage = (ev) => {
    try {
      const msg: any = JSON.parse(ev.data)
      addEvent(msg)
      switch (msg.kind) {
        case 'memory.used':
          setMetrics({ memoryUsedMb: msg.payload.used_mb, memoryTotalMb: msg.payload.total_mb ?? 0 })
          break
        case 'cpu.sample':
        case 'cpu.spike':
          setMetrics({ cpuPercent: msg.payload.percent })
          break
        case 'process.started': {
          const p: Process = {
            pid: msg.payload.pid,
            name: msg.payload.name,
            parentPid: msg.payload.parent_pid || 0,
            cpuPercent: msg.payload.cpu_percent || 0,
            memoryMb: msg.payload.memory_mb || 0,
            threads: msg.payload.threads || 0,
            identity: msg.payload.identity,
            riskScore: msg.payload.identity?.risk_score ?? 0,
            startTime: msg.payload.identity?.start_time ?? Date.now(),
            children: [],
          }
          upsertProcess(p)
          break
        }
        case 'process.terminated':
          removeProcess(msg.payload.pid)
          break
        case 'process.cpuspike':
          // optional: mark process as spiking
          break
        case 'finding': {
          const a: Alert = {
            id: `finding-${Date.now()}`,
            title: msg.payload.title,
            description: msg.payload.description,
            risk: msg.payload.risk || 0,
            severity: msg.payload.severity || 'Low',
            timestamp: msg.ts ?? Date.now(),
            kind: 'finding',
          }
          addAlert(a)
          break
        }
        default:
          break
      }
    } catch (e) {
      console.error('ws parse error', e)
    }
  }
  ws.onclose = () => setTimeout(startWs, 1000) // reconnect
  ws.onerror = (e) => console.error('ws error', e)
}
