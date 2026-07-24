export type LogEventSeverity =
  | 'unknown'
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type ParsedLogEvent = {
  id: string
  case_id: string
  evidence_id: string
  ingestion_job_id: string

  event_index: number
  event_time: string | null

  source_type: string
  event_code: string
  severity: LogEventSeverity

  host: string
  username: string
  process_name: string

  source_ip: string
  destination_ip: string

  message: string

  raw_event: Record<string, unknown>
  normalized_event: Record<
    string,
    unknown
  >

  parse_error: string | null
  created_at: string
}

export type ParsedLogEventListResponse = {
  items: ParsedLogEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type ListCaseLogEventsParams = {
  page?: number
  page_size?: number
  search?: string
  severity?: LogEventSeverity
  evidence_id?: string
}