import React from 'react'
import { useFilteredAlerts, useAlertStats } from '../../state/selectors/alert.selectors'
import { useSsaStore } from '../../state/ssa.store'

export function AlertSurface() {
  const alerts = useFilteredAlerts()
  const stats = useAlertStats()
  const filter = useSsaStore((s) => s.alertFilter)
  const setFilter = useSsaStore((s) => s.setAlertFilter)
  const dismiss = useSsaStore((s) => s.dismissAlert)

  return (
    <div className="surface alert-surface">
      <header>
        <h3>Alerts</h3>
        <div className="filters">
          {(['all', 'Critical', 'High', 'Medium', 'Low'] as const).map(f => (
            <button key={f} className={filter === f ? 'active' : ''} onClick={() => setFilter(f)}>
              {f === 'all' ? `All (${stats.total})` : `${f} (${(stats as any)[f.toLowerCase()]})`}
            </button>
          ))}
        </div>
      </header>
      <div className="alert-list">
        {alerts.map(a => (
          <div key={a.id} className={`alert severity-${a.severity.toLowerCase()}`}>
            <div className="alert-header">
              <strong>{a.title}</strong>
              <span className="risk">Risk: {a.risk}</span>
              <button onClick={() => dismiss(a.id)}>×</button>
            </div>
            <p>{a.description}</p>
            {a.pid && <span className="pid">PID: {a.pid}</span>}
          </div>
        ))}
      </div>
    </div>
  )
}
