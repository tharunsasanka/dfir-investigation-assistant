export type CaseAuditEventType =
  | 'created'
  | 'updated'
  | 'archived'

export type CaseAuditChanges = {
  before?: Record<string, unknown>
  after?: Record<string, unknown>
}

export type CaseAuditEvent = {
  id: string
  case_id: string
  event_type: CaseAuditEventType

  actor_user_id: string | null
  actor_email: string
  actor_full_name: string

  changes: CaseAuditChanges

  ip_address: string | null
  user_agent: string | null
  created_at: string
}

export type CaseAuditEventListResponse = {
  items: CaseAuditEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}