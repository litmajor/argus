export type Severity = 'Low' | 'Medium' | 'High' | 'Critical'

export interface Alert {
  id: string
  title: string
  description: string
  risk: number
  severity: Severity
  pid?: number
  timestamp: number
  kind: string
}
