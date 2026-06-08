import React from 'react'
import { useSsaStore } from '../../state/ssa.store'

export function TimelineSurface() {
  const events = useSsaStore((s) => s.events)
  const filter = useSsaStore((s) => s.eventFilter)
  const setFilter = useSsaStore((s) => s.setEventFilter)

  const filtered = filter
    ? events.filter(e => e.kind.toLowerCase().includes(filter.toLowerCase()))
    : events

  return (
    <div className="surface timeline-surface">
      <header>
        <h3>Timeline</h3>
        <input type="text" placeholder="Filter events..." value={filter} onChange={(e) => setFilter(e.target.value)} />
      </header>
      <div className="event-stream">
        {filtered.slice(0,100).map(e => (
          <div key={e.id} className={`event event-${e.kind.split('.')[0]}`}>
            <span className="ts">{new Date(e.timestamp).toLocaleTimeString()}</span>
            <span className="kind">{e.kind}</span>
            <span className="summary">{e.summary}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
