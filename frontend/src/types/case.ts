export type CaseSeverity =
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type CaseStatus =
  | 'open'
  | 'investigating'
  | 'review'
  | 'closed'

export type InvestigationCase = {
  id: string
  title: string
  description: string
  severity: CaseSeverity
  status: CaseStatus
  created_at: string
  updated_at: string
}

export type CaseListResponse = {
  items: InvestigationCase[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type CaseListParameters = {
  page?: number
  page_size?: number
  search?: string
  severity?: CaseSeverity
  status?: CaseStatus
}

export type CaseCreateRequest = {
  title: string
  description: string
  severity: CaseSeverity
}

export type CaseUpdateRequest = {
  title?: string
  description?: string
  severity?: CaseSeverity
  status?: CaseStatus
}