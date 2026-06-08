import React from 'react'
import { useProcessList } from '../../state/selectors/process.selectors'
import { useSsaStore } from '../../state/ssa.store'
import { riskClass } from '../../utils/risk'

export function ProcessSurface() {
  const processes = useProcessList()
  const selectedPid = useSsaStore((s) => s.selectedPid)
  const selectProcess = useSsaStore((s) => s.selectProcess)

  return (
    <div className="surface process-surface">
      <header>
        <h3>Processes</h3>
        <span className="count">{processes.length}</span>
      </header>
      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>PID</th>
              <th>Name</th>
              <th>CPU</th>
              <th>Memory</th>
              <th>Score</th>
            </tr>
          </thead>
          <tbody>
            {processes.map(p => (
              <tr
                key={p.pid}
                className={`risk-${riskClass(p.riskScore)} ${selectedPid === p.pid ? 'selected' : ''}`}
                onClick={() => selectProcess(p.pid)}
              >
                <td>{p.pid}</td>
                <td>{p.name}</td>
                <td>{Number.isFinite(p.cpuPercent) ? p.cpuPercent.toFixed(1) : '—'}%</td>
                <td>{Number.isFinite(p.memoryMb) ? p.memoryMb.toFixed(1) : '—'} MB</td>
                <td>{p.riskScore}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}


