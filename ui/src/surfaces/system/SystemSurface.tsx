import React from 'react'
import { useSsaStore } from '../../state/ssa.store'
import { useMemoryPercent } from '../../state/selectors/system.selectors'

function fmtNum(n: number, digits: number) {
  return Number.isFinite(n) ? n.toFixed(digits) : '—'
}

export function SystemSurface() {
  const metrics = useSsaStore((s) => s.metrics)
  const memPct = useMemoryPercent()
  const processCount = useSsaStore((s) => s.processes.size)

  const cpuAlert = Number.isFinite(metrics.cpuPercent) && metrics.cpuPercent > 80
  const memAlert = memPct > 80

  return (
    <div className="surface system-surface">
      <div className={`metric ${cpuAlert ? 'alert' : ''}`}>
        <span className="metric-label">CPU</span>
        <span className="metric-value">{fmtNum(metrics.cpuPercent, 1)}%</span>
      </div>
      <div className={`metric ${memAlert ? 'alert' : ''}`}>
        <span className="metric-label">RAM</span>
        <span className="metric-value">{fmtNum(metrics.memoryUsedMb, 0)} MB</span>
        <span className="metric-pct">{fmtNum(memPct, 1)}%</span>
      </div>
      <div className="metric">
        <span className="metric-label">Processes</span>
        <span className="metric-value">{processCount}</span>
      </div>
      <div className={`threat-badge threat-${metrics.threatLevel.toLowerCase()}`}>{metrics.threatLevel}</div>
    </div>
  )
}
