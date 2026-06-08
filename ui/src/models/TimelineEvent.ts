export interface TimelineEvent {
  id: string
  kind: string
  timestamp: number
  payload: unknown
  summary: string
}
