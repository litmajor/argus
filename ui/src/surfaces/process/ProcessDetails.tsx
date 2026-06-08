import React from 'react'
import { useSelectedProcess } from '../../state/selectors/process.selectors'
import { riskClass } from '../../utils/risk'

export function ProcessDetails() {
  const p = useSelectedProcess()

  if (!p) return (
    <div className="surface process-details empty">
      <p>Select a process to inspect</p>
    </div>
  )

  return (
    <div className="surface process-details">
      <header>
        <h3>{p.name}</h3>
        <span className={`risk-badge risk-${riskClass(p.riskScore)}`}>{p.riskScore}</span>
      </header>
      <dl>
        <dt>PID</dt><dd>{p.pid}</dd>
        <dt>Parent</dt><dd>{p.parentPid || 'None'}</dd>
        <dt>CPU</dt><dd>{Number.isFinite(p.cpuPercent) ? p.cpuPercent.toFixed(1) : '—'}%</dd>
        <dt>Memory</dt><dd>{Number.isFinite(p.memoryMb) ? p.memoryMb.toFixed(1) : '—'} MB</dd>
        <dt>Threads</dt><dd>{p.threads}</dd>
        {p.identity && (
          <>
            <dt>Path</dt><dd>{p.identity.path}</dd>
            <dt>Signer</dt><dd>{p.identity.signer}</dd>
            <dt>Company</dt><dd>{p.identity.company}</dd>
            <dt>Category</dt><dd>{p.identity.category}</dd>
          </>
        )}
      </dl>
      {p.children.length > 0 && (
        <div className="children">
          <h4>Children ({p.children.length})</h4>
          <ul>
            {p.children.map(cid => <li key={cid}>{cid}</li>)}
          </ul>
        </div>
      )}
    </div>
  )
}


