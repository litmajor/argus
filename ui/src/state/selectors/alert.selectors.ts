import { useSsaStore } from '../ssa.store'

export const useFilteredAlerts = () => {
  const { alerts, alertFilter } = useSsaStore()
  if (alertFilter === 'all') return alerts
  return alerts.filter(a => a.severity === alertFilter)
}

export const useAlertStats = () => {
  const alerts = useSsaStore((s) => s.alerts)
  return {
    total: alerts.length,
    critical: alerts.filter(a => a.severity === 'Critical').length,
    high: alerts.filter(a => a.severity === 'High').length,
    medium: alerts.filter(a => a.severity === 'Medium').length,
    low: alerts.filter(a => a.severity === 'Low').length,
  }
}
