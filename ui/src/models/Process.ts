export interface ProcessIdentity {
  path: string
  signer: string
  company: string
  category: string
  startTime?: number
  riskScore: number
}

export interface Process {
  pid: number
  name: string
  parentPid: number
  cpuPercent: number
  memoryMb: number
  threads: number
  identity?: ProcessIdentity
  children: number[]
  startTime: number
  riskScore: number
}
