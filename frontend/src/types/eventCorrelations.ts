export type EventCorrelationType =
  | 'shared_identity'
  | 'shared_network'
  | 'shared_host'
  | 'shared_process'
  | 'authentication_sequence'
  | 'mitre_technique'
  | 'temporal_cluster'
  | 'multi_indicator'

export type EventCorrelationSeverity =
  | 'unknown'
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type EventCorrelationJsonValue =
  | string
  | number
  | boolean
  | null
  | EventCorrelationJsonValue[]
  | {
      [key: string]: EventCorrelationJsonValue
    }

export type EventCorrelation = {
  id: string
  case_id: string

  correlation_type: EventCorrelationType
  correlation_signature: string

  rule_id: string
  title: string
  description: string

  severity: EventCorrelationSeverity
  confidence: number

  window_start: string | null
  window_end: string | null

  event_count: number
  evidence_count: number

  correlation_key: string

  mitre_tactic: string
  mitre_technique_id: string
  mitre_technique_name: string

  matched_fields: Record<
    string,
    EventCorrelationJsonValue
  >

  created_at: string
  updated_at: string
}

export type EventCorrelationMemberEvent = {
  membership_id: string
  parsed_event_id: string
  evidence_id: string

  event_time: string | null
  position: number
  relationship: string

  source_type: string
  event_code: string
  severity: EventCorrelationSeverity

  host: string
  username: string
  process_name: string

  source_ip: string
  destination_ip: string

  message: string

  matched_values: Record<
    string,
    EventCorrelationJsonValue
  >
}

export type EventCorrelationDetail =
  EventCorrelation & {
    members: EventCorrelationMemberEvent[]
  }

export type EventCorrelationListResponse = {
  items: EventCorrelation[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type EventCorrelationRunResponse = {
  case_id: string
  correlations_created: number
  correlations_updated: number
  correlations_deleted: number
  events_analyzed: number
  evidence_analyzed: number
}

export type ListEventCorrelationsParams = {
  page?: number
  page_size?: number
  search?: string
  severity?: EventCorrelationSeverity
  correlation_type?: EventCorrelationType
  min_confidence?: number
  max_confidence?: number
  evidence_id?: string
  rule_id?: string
  mitre_tactic?: string
  mitre_technique_id?: string
}