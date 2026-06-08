export interface SystemMetrics {
  cpuPercent: number
  memoryUsedMb: number
  memoryTotalMb: number
  processCount: number
  threatLevel: 'Normal' | 'Elevated' | 'Suspicious' | 'Critical'
}
