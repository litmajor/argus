import { useSsaStore } from '../ssa.store'

export const useProcessList = () => {
  const processes = useSsaStore((s) => s.processes)
  return Array.from(processes.values()).sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0))
}

export const useSelectedProcess = () => {
  const { processes, selectedPid } = useSsaStore()
  return selectedPid ? processes.get(selectedPid) ?? null : null
}

export const useProcessTree = () => {
  const processes = useSsaStore((s) => s.processes)
  const roots: number[] = []
  processes.forEach((p) => {
    if (!p.parentPid || p.parentPid === 0) roots.push(p.pid)
  })
  return roots
}
