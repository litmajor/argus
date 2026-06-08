import React from 'react'
import { SystemSurface } from '../surfaces/system/SystemSurface'
import { ProcessSurface } from '../surfaces/process/ProcessSurface'
import { ProcessDetails } from '../surfaces/process/ProcessDetails'
import { AlertSurface } from '../surfaces/alert/AlertSurface'
import { TimelineSurface } from '../surfaces/timeline/TimelineSurface'
import { GraphSurface } from '../surfaces/graph/GraphSurface'

export function DefaultWorkspace() {
  return (
    <div className="workspace default-workspace">
      <header className="app-header">
        <div className="app-title">Argus</div>
        <div className="app-sub">Observability Dashboard</div>
      </header>
      <SystemSurface />

      <div className="workspace-body">
        <div className="process-pane">
          <div className="grid-cell"><ProcessSurface /></div>
          <div className="grid-cell"><ProcessDetails /></div>
        </div>

        <div className="workspace-grid">
          <div className="grid-cell"><AlertSurface /></div>
          <div className="grid-cell"><TimelineSurface /></div>
          <div className="grid-cell"><GraphSurface /></div>
        </div>
      </div>
    </div>
  )
}
