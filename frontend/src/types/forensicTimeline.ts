export type ForensicTimelineEntryType =
  | 'log_event'
  | 'security_finding'
  | 'event_correlation'
  | 'case_audit'
  | 'evidence_custody'

export type ForensicTimelineSortOrder =
  | 'ascending'
  | 'descending'

export type ForensicTimelineSeverity =
  | 'unknown'
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type ForensicTimelineJsonValue =
  | string
  | number
  | boolean
  | null
  | ForensicTimelineJsonValue[]
  | {
      [key: string]:
        ForensicTimelineJsonValue
    }

export type ForensicTimelineEntry = {
  id: string
  case_id: string

  entry_type:
    ForensicTimelineEntryType

  occurred_at: string
  recorded_at: string

  title: string
  description: string

  severity:
    ForensicTimelineSeverity

  confidence: number | null

  source_id: string
  source_type: string

  evidence_id: string | null
  ingestion_job_id: string | null
  parsed_event_id: string | null
  security_finding_id: string | null
  correlation_id: string | null
  custody_event_id: string | null
  audit_event_id: string | null

  event_code: string
  rule_id: string

  host: string
  username: string
  process_name: string
  source_ip: string
  destination_ip: string

  actor_user_id: string | null
  actor_email: string
  actor_full_name: string

  mitre_tactic: string
  mitre_technique_id: string
  mitre_technique_name: string

  correlation_type: string
  correlation_key: string

  details: Record<
    string,
    ForensicTimelineJsonValue
  >
}

export type ForensicTimelineTypeCount = {
  entry_type:
    ForensicTimelineEntryType

  count: number
}

export type ForensicTimelineSeverityCount = {
  severity:
    ForensicTimelineSeverity

  count: number
}

export type ForensicTimelineSummary = {
  total_entries: number

  first_event_at: string | null
  last_event_at: string | null

  log_event_count: number
  security_finding_count: number
  event_correlation_count: number
  case_audit_count: number
  evidence_custody_count: number

  critical_count: number
  high_count: number
  evidence_count: number

  type_counts:
    ForensicTimelineTypeCount[]

  severity_counts:
    ForensicTimelineSeverityCount[]
}

export type ForensicTimelineResponse = {
  items: ForensicTimelineEntry[]
  summary: ForensicTimelineSummary

  total: number
  page: number
  page_size: number
  pages: number

  sort_order:
    ForensicTimelineSortOrder
}

export type ListForensicTimelineParams = {
  page?: number
  page_size?: number

  search?: string

  entry_type?:
    ForensicTimelineEntryType[]

  severity?:
    ForensicTimelineSeverity

  evidence_id?: string

  start_time?: string
  end_time?: string

  sort_order?:
    ForensicTimelineSortOrder
}