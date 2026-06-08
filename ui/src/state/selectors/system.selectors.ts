import { useSsaStore } from '../ssa.store'

export const useMemoryPercent = () => {
  const { memoryUsedMb, memoryTotalMb } = useSsaStore((s) => s.metrics)
  return memoryTotalMb > 0 ? (memoryUsedMb / memoryTotalMb) * 100 : 0
}
