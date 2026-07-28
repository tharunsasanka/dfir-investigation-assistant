export type InvestigationReportFormat =
  | 'pdf'
  | 'json'

export interface InvestigationReportExportRequest {
  summary_id: string
  format: InvestigationReportFormat
  include_traceability: boolean
  include_integrity_verification: boolean
  include_evidence_hashes: boolean
  include_recommendations: boolean
  include_assumptions: boolean
  include_limitations: boolean
}

export interface InvestigationReportDownload {
  content: Blob
  filename: string
  reportId: string | null
  caseId: string | null
  summaryId: string | null
  format: InvestigationReportFormat
  documentSha256: string | null
}