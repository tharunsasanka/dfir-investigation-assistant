export type InvestigationSummaryStatus =
  | 'generating'
  | 'pending_review'
  | 'approved'
  | 'rejected'
  | 'failed'

export type InvestigationSummarySource =
  | 'deterministic'
  | 'local_ai'
  | 'hosted_ai'
  | 'analyst'

export type InvestigationSummaryReviewDecision =
  | 'approved'
  | 'rejected'

export type InvestigationActionPriority =
  | 'immediate'
  | 'short_term'
  | 'long_term'

export type InvestigationSummarySeverity =
  | 'unknown'
  | 'informational'
  | 'low'
  | 'medium'
  | 'high'
  | 'critical'

export type InvestigationSummaryJsonValue =
  | string
  | number
  | boolean
  | null
  | InvestigationSummaryJsonValue[]
  | {
      [key: string]:
        InvestigationSummaryJsonValue
    }

export type InvestigationSummaryFinding = {
  title: string
  description: string
  severity: InvestigationSummarySeverity
  confidence: number

  rule_id: string
  event_time: string | null

  evidence_id: string | null
  parsed_event_id: string | null
  security_finding_id: string | null
  correlation_id: string | null

  event_code: string
  source_type: string

  mitre_tactic: string
  mitre_technique_id: string
  mitre_technique_name: string

  indicators: Record<
    string,
    InvestigationSummaryJsonValue
  >
}

export type InvestigationIncidentScope = {
  total_timeline_entries: number

  log_event_count: number
  security_finding_count: number
  event_correlation_count: number
  case_audit_count: number
  evidence_custody_count: number

  evidence_count: number
  critical_count: number
  high_count: number

  first_activity_at: string | null
  last_activity_at: string | null

  affected_hosts: string[]
  affected_usernames: string[]

  observed_source_ips: string[]
  observed_destination_ips: string[]
  observed_processes: string[]

  evidence_ids: string[]
}

export type InvestigationMitreTechnique = {
  tactic: string
  technique_id: string
  technique_name: string

  finding_count: number
  correlation_count: number

  related_rule_ids: string[]
}

export type InvestigationMitreCoverage = {
  tactic_count: number
  technique_count: number

  tactics: string[]

  techniques:
    InvestigationMitreTechnique[]
}

export type InvestigationEvidenceReference = {
  evidence_id: string
  original_filename: string
  evidence_type: string

  sha256: string
  size_bytes: number
  source: string

  collected_at: string | null
  created_at: string | null

  related_event_count: number
  related_finding_count: number
  related_correlation_count: number
}

export type InvestigationRecommendedAction = {
  priority: InvestigationActionPriority

  title: string
  description: string
  rationale: string

  related_rule_ids: string[]
  related_mitre_technique_ids: string[]
  related_evidence_ids: string[]
}

export type InvestigationVerifiedFact = {
  statement: string
  source_type: string
  source_ids: string[]
  confidence: number
}

export type InvestigationAssumption = {
  statement: string
  reason: string
  confidence: number
}

export type InvestigationSummary = {
  id: string
  case_id: string
  parent_summary_id: string | null

  version_number: number
  status: InvestigationSummaryStatus
  generation_source:
    InvestigationSummarySource

  title: string
  executive_summary: string
  technical_narrative: string

  technical_findings:
    InvestigationSummaryFinding[]

  incident_scope:
    InvestigationIncidentScope

  mitre_coverage:
    InvestigationMitreCoverage

  evidence_references:
    InvestigationEvidenceReference[]

  recommended_actions:
    InvestigationRecommendedAction[]

  verified_facts:
    InvestigationVerifiedFact[]

  assumptions:
    InvestigationAssumption[]

  limitations: string[]

  confidence_score: number

  provider_name: string
  model_name: string
  prompt_template_version: string

  generation_parameters: Record<
    string,
    InvestigationSummaryJsonValue
  >

  source_snapshot: Record<
    string,
    InvestigationSummaryJsonValue
  >

  source_snapshot_sha256: string
  output_sha256: string

  requested_by_user_id: string | null
  reviewed_by_user_id: string | null

  review_notes: string
  generation_error: string

  generation_started_at: string | null
  generation_completed_at: string | null
  reviewed_at: string | null

  created_at: string
  updated_at: string
}

export type InvestigationSummaryListResponse = {
  items: InvestigationSummary[]

  total: number
  page: number
  page_size: number
  pages: number
}

export type GenerateInvestigationSummaryRequest = {
  generation_source?:
    InvestigationSummarySource

  provider_name?: string
  model_name?: string

  prompt_template_version?: string

  generation_parameters?: Record<
    string,
    InvestigationSummaryJsonValue
  >
}

export type ListInvestigationSummariesParams = {
  page?: number
  page_size?: number
}

export type ReviewInvestigationSummaryRequest = {
  decision:
    InvestigationSummaryReviewDecision

  review_notes?: string
}

export type CreateInvestigationSummaryRevisionRequest = {
  title: string
  executive_summary: string
  technical_narrative: string

  technical_findings:
    InvestigationSummaryFinding[]

  incident_scope:
    InvestigationIncidentScope

  mitre_coverage:
    InvestigationMitreCoverage

  evidence_references:
    InvestigationEvidenceReference[]

  recommended_actions:
    InvestigationRecommendedAction[]

  verified_facts:
    InvestigationVerifiedFact[]

  assumptions:
    InvestigationAssumption[]

  limitations: string[]

  confidence_score: number
}