export type SummaryClaimSection =
  | 'executive_summary'
  | 'technical_narrative'
  | 'technical_finding'
  | 'incident_scope'
  | 'mitre_coverage'
  | 'recommended_action'
  | 'verified_fact'
  | 'assumption'
  | 'limitation'

export type SummaryCitationSourceType =
  | 'case'
  | 'evidence'
  | 'parsed_log_event'
  | 'security_finding'
  | 'event_correlation'
  | 'case_audit_event'
  | 'evidence_custody_event'
  | 'incident_scope'
  | 'mitre_mapping'
  | 'deterministic_rule'
  | 'analyst'

export type SummaryClaimSupportLevel =
  | 'direct'
  | 'derived'
  | 'contextual'
  | 'unsupported'

export type SummaryCitationMetadataValue =
  | string
  | number
  | boolean
  | null

export interface SummaryClaimCitation {
  citation_id: string
  source_type: SummaryCitationSourceType
  source_id: string | null
  evidence_id: string | null
  label: string
  relationship: string
  event_time: string | null
  integrity_sha256: string | null
  metadata: Record<string, SummaryCitationMetadataValue>
}

export interface SummaryTraceableClaim {
  claim_id: string
  section: SummaryClaimSection
  ordinal: number
  text: string
  support_level: SummaryClaimSupportLevel
  supported: boolean
  citations: SummaryClaimCitation[]
  unsupported_reason: string
}

export interface InvestigationSummaryTraceability {
  id: string
  investigation_summary_id: string
  case_id: string
  schema_version: string
  claims: SummaryTraceableClaim[]
  total_claim_count: number
  supported_claim_count: number
  unsupported_claim_count: number
  direct_support_count: number
  derived_support_count: number
  contextual_support_count: number
  citation_count: number
  generated_at: string
  report_sha256: string
  source_summary_output_sha256: string
  created_at: string
}

export interface SummaryTraceabilityIntegrity {
  report_id: string
  investigation_summary_id: string
  source_summary_output_sha256: string
  stored_report_sha256: string
  reconstructed_report_sha256: string
  source_hash_matches: boolean
  report_hash_matches: boolean
  integrity_verified: boolean
  verified_at: string
}