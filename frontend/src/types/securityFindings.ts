export type SecurityFindingSeverity =
  | 'unknown'
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type JsonPrimitive =
  | string
  | number
  | boolean
  | null

export type JsonValue =
  | JsonPrimitive
  | JsonValue[]
  | {
      [key: string]: JsonValue
    }

export type SecurityFinding = {
  id: string

  case_id: string
  evidence_id: string
  ingestion_job_id: string
  parsed_event_id: string

  event_index: number

  rule_id: string
  title: string
  description: string

  severity: SecurityFindingSeverity
  confidence: number

  event_time: string | null

  event_code: string
  source_type: string

  mitre_tactic: string
  mitre_technique_id: string
  mitre_technique_name: string

  indicators: Record<
    string,
    JsonValue
  >

  created_at: string
}

export type SecurityFindingListResponse = {
  items: SecurityFinding[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type ListSecurityFindingsParams = {
  page?: number
  page_size?: number
  search?: string
  severity?: SecurityFindingSeverity
  min_confidence?: number
  max_confidence?: number
  evidence_id?: string
  ingestion_job_id?: string
  rule_id?: string
  source_type?: string
  mitre_tactic?: string
  mitre_technique_id?: string
}