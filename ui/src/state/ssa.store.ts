import { create } from 'zustand'
import { Process } from '../models/Process'
import { Alert } from '../models/Alert'
import { SystemMetrics } from '../models/SystemMetrics'
import { TimelineEvent } from '../models/TimelineEvent'

interface SsaState {
  metrics: SystemMetrics
  processes: Map<number, Process>
  selectedPid: number | null
  expandedPids: Set<number>
  alerts: Alert[]
  alertFilter: Severity | 'all'
  events: TimelineEvent[]
  eventFilter: string
  graphLayout: 'dagre' | 'force' | 'grid'

  setMetrics: (m: Partial<SystemMetrics>) => void
  upsertProcess: (p: Process) => void
  removeProcess: (pid: number) => void
  selectProcess: (pid: number | null) => void
  toggleExpand: (pid: number) => void
  addAlert: (a: Alert) => void
  dismissAlert: (id: string) => void
  setAlertFilter: (f: Severity | 'all') => void
  addEvent: (e: TimelineEvent) => void
  setEventFilter: (f: string) => void
  setGraphLayout: (l: 'dagre' | 'force' | 'grid') => void
}

type Severity = Alert['severity']

let EVENT_ID = 0

export const useSsaStore = create<SsaState>((set, get) => ({
  metrics: {
    cpuPercent: 0,
    memoryUsedMb: 0,
    memoryTotalMb: 0,
    processCount: 0,
    threatLevel: 'Normal',
  },
  processes: new Map(),
  selectedPid: null,
  expandedPids: new Set(),
  alerts: [],
  alertFilter: 'all',
  events: [],
  eventFilter: '',
  graphLayout: 'dagre',

  setMetrics: (m) => set((state) => ({ metrics: { ...state.metrics, ...m } })),

  upsertProcess: (p) => set((state) => {
    const next = new Map(state.processes)
    const existing = next.get(p.pid)
    next.set(p.pid, {
      ...(existing ?? {}),
      ...p,
      children: existing?.children ?? p.children ?? [],
    } as Process)
    if (p.parentPid && p.parentPid !== 0) {
      const parent = next.get(p.parentPid)
      if (parent && !parent.children.includes(p.pid)) {
        parent.children.push(p.pid)
      }
    }
    return { processes: next, metrics: { ...state.metrics, processCount: next.size } }
  }),

  removeProcess: (pid) => set((state) => {
    const next = new Map(state.processes)
    const p = next.get(pid)
    if (p?.parentPid) {
      const parent = next.get(p.parentPid)
      if (parent) parent.children = parent.children.filter(c => c !== pid)
    }
    next.delete(pid)
    return {
      processes: next,
      selectedPid: state.selectedPid === pid ? null : state.selectedPid,
      metrics: { ...state.metrics, processCount: next.size },
    }
  }),

  selectProcess: (pid) => set({ selectedPid: pid }),

  toggleExpand: (pid) => set((state) => {
    const next = new Set(state.expandedPids)
    if (next.has(pid)) next.delete(pid)
    else next.add(pid)
    return { expandedPids: next }
  }),

  addAlert: (a) => set((state) => ({
    alerts: [a, ...state.alerts].slice(0, 200),
    metrics: { ...state.metrics, threatLevel: computeThreatLevel([a, ...state.alerts]) },
  })),

  dismissAlert: (id) => set((state) => {
    const nextAlerts = state.alerts.filter(a => a.id !== id)
    return {
      alerts: nextAlerts,
      metrics: { ...state.metrics, threatLevel: computeThreatLevel(nextAlerts) },
    }
  }),

  // recompute threat level when dismissing alerts
  // ensure threatLevel in metrics stays consistent with alerts
  // NOTE: keep implementation simple and synchronous
  // we update alerts and metrics together
  

  setAlertFilter: (f) => set({ alertFilter: f }),

  addEvent: (e) => set((state) => {
    const id = (e as any).id ?? `evt-${++EVENT_ID}`
    const evt = { ...(e as any), id } as TimelineEvent
    return { events: [evt, ...state.events].slice(0, 500) }
  }),

  setEventFilter: (f) => set({ eventFilter: f }),

  setGraphLayout: (l) => set({ graphLayout: l }),
}))

function computeThreatLevel(alerts: Alert[]): SystemMetrics['threatLevel'] {
  if (alerts.some(a => a.severity === 'Critical')) return 'Critical'
  if (alerts.some(a => a.severity === 'High')) return 'Suspicious'
  if (alerts.some(a => a.severity === 'Medium')) return 'Elevated'
  return 'Normal'
}
