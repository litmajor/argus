import { useEffect, useRef } from 'react'
import Cytoscape from 'cytoscape'
import dagre from 'cytoscape-dagre'
import { useSsaStore } from '../../state/ssa.store'

;(Cytoscape as any).use(dagre)

export function GraphSurface() {
  const processes = useSsaStore((s) => s.processes)
  const layout = useSsaStore((s) => s.graphLayout)
  const setLayout = useSsaStore((s) => s.setGraphLayout)
  const containerRef = useRef<HTMLDivElement | null>(null)
  const cyRef = useRef<any | null>(null)

  useEffect(() => {
    if (!containerRef.current) return

    const procList = Array.from(processes.values())
    const idSet = new Set(procList.map(p => String(p.pid)))
    const nodes = procList.map(p => ({ data: { id: String(p.pid), label: p.name, score: p.riskScore, parent: (p.parentPid && idSet.has(String(p.parentPid))) ? String(p.parentPid) : undefined } }))
    const nodeIds = new Set(nodes.map(n => n.data.id))
    const edges = Array.from(processes.values())
      .filter(p => p.parentPid && p.parentPid !== 0)
      .map(p => ({ data: { source: String(p.parentPid), target: String(p.pid) } }))
      .filter(e => nodeIds.has(e.data.source) && nodeIds.has(e.data.target))

    if (cyRef.current) { cyRef.current.destroy() }

    cyRef.current = Cytoscape({
      container: containerRef.current,
      elements: [...nodes, ...edges],
      style: [
        { selector: 'node', style: { 'background-color': '#475569', label: 'data(label)', width: 30, height: 30, 'font-size': '10px', color: '#e2e8f0' } },
        { selector: 'node[score >= 80]', style: { 'background-color': '#ef4444' } },
        { selector: 'node[score >= 60]', style: { 'background-color': '#f97316' } },
        { selector: 'node[score >= 30]', style: { 'background-color': '#eab308' } },
        { selector: 'edge', style: { width: 1, 'line-color': '#64748b', 'target-arrow-color': '#64748b', 'target-arrow-shape': 'triangle' } }
      ],
      layout: ({ name: layout, rankDir: 'TB', padding: 10 } as any),
    })

    return () => { cyRef.current?.destroy(); cyRef.current = null }
  }, [processes, layout])

  return (
    <div className="surface graph-surface">
      <header>
        <h3>Process Graph</h3>
        <div className="layout-controls">
          {(['dagre','force','grid'] as const).map(l => (
            <button key={l} className={layout === l ? 'active' : ''} onClick={() => setLayout(l)}>{l}</button>
          ))}
        </div>
      </header>
      <div ref={containerRef} className="graph-container" />
    </div>
  )
}
