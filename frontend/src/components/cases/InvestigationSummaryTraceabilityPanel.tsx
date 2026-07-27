import {
  useCallback,
  useEffect,
  useMemo,
  useState,
} from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileSearch,
  Fingerprint,
  Link2,
  RefreshCw,
  ShieldCheck,
  ShieldX,
} from 'lucide-react'

import {
  getInvestigationSummaryTraceability,
  verifyInvestigationSummaryTraceability,
} from '../../api/summaryTraceability'
import type {
  InvestigationSummaryTraceability,
  SummaryClaimCitation,
  SummaryClaimSupportLevel,
  SummaryTraceabilityIntegrity,
  SummaryTraceableClaim,
} from '../../types/summaryTraceability'

interface InvestigationSummaryTraceabilityPanelProps {
  summaryId: string
  summaryTitle?: string
  summaryVersion?: number
}

function formatLabel(value: string): string {
  return value
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (character) =>
      character.toUpperCase(),
    )
}

function formatDate(value: string | null): string {
  if (!value) {
    return 'Not recorded'
  }

  const parsedDate = new Date(value)

  if (Number.isNaN(parsedDate.getTime())) {
    return value
  }

  return parsedDate.toLocaleString()
}

function shortenHash(value: string): string {
  if (value.length <= 24) {
    return value
  }

  return `${value.slice(0, 12)}...${value.slice(-12)}`
}

function getErrorMessage(error: unknown): string {
  if (
    typeof error === 'object'
    && error !== null
    && 'response' in error
  ) {
    const response = (
      error as {
        response?: {
          data?: {
            detail?: string
          }
        }
      }
    ).response

    if (response?.data?.detail) {
      return response.data.detail
    }
  }

  if (error instanceof Error) {
    return error.message
  }

  return 'Unable to load summary traceability.'
}

function supportBadgeClass(
  supportLevel: SummaryClaimSupportLevel,
): string {
  if (supportLevel === 'direct') {
    return 'border-emerald-500/30 bg-emerald-500/10 text-emerald-300'
  }

  if (supportLevel === 'derived') {
    return 'border-cyan-500/30 bg-cyan-500/10 text-cyan-300'
  }

  if (supportLevel === 'contextual') {
    return 'border-amber-500/30 bg-amber-500/10 text-amber-300'
  }

  return 'border-red-500/30 bg-red-500/10 text-red-300'
}

function CitationCard({
  citation,
}: {
  citation: SummaryClaimCitation
}) {
  const metadataEntries = Object.entries(
    citation.metadata,
  )

  return (
    <div className="rounded-lg border border-slate-700 bg-slate-950/60 p-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="flex items-center gap-2 text-sm font-medium text-slate-100">
            <Link2 className="h-4 w-4 text-cyan-400" />
            <span>{citation.label}</span>
          </div>

          <p className="mt-1 text-xs text-slate-400">
            {citation.relationship}
          </p>
        </div>

        <span className="rounded border border-slate-600 bg-slate-800 px-2 py-1 text-xs text-slate-300">
          {formatLabel(citation.source_type)}
        </span>
      </div>

      <div className="mt-3 grid gap-2 text-xs text-slate-400 sm:grid-cols-2">
        {citation.source_id && (
          <div>
            <span className="text-slate-500">
              Source ID:
            </span>{' '}
            <span className="break-all text-slate-300">
              {citation.source_id}
            </span>
          </div>
        )}

        {citation.evidence_id && (
          <div>
            <span className="text-slate-500">
              Evidence ID:
            </span>{' '}
            <span className="break-all text-slate-300">
              {citation.evidence_id}
            </span>
          </div>
        )}

        {citation.event_time && (
          <div>
            <span className="text-slate-500">
              Event time:
            </span>{' '}
            <span className="text-slate-300">
              {formatDate(citation.event_time)}
            </span>
          </div>
        )}

        {citation.integrity_sha256 && (
          <div>
            <span className="text-slate-500">
              Evidence hash:
            </span>{' '}
            <span
              className="font-mono text-slate-300"
              title={citation.integrity_sha256}
            >
              {shortenHash(
                citation.integrity_sha256,
              )}
            </span>
          </div>
        )}
      </div>

      {metadataEntries.length > 0 && (
        <div className="mt-3 rounded border border-slate-800 bg-slate-900/70 p-2">
          <div className="mb-2 text-xs font-medium uppercase tracking-wide text-slate-500">
            Citation metadata
          </div>

          <div className="grid gap-1 text-xs sm:grid-cols-2">
            {metadataEntries.map(
              ([key, value]) => (
                <div
                  key={key}
                  className="flex gap-2"
                >
                  <span className="text-slate-500">
                    {formatLabel(key)}:
                  </span>

                  <span className="break-all text-slate-300">
                    {String(value)}
                  </span>
                </div>
              ),
            )}
          </div>
        </div>
      )}
    </div>
  )
}

function ClaimCard({
  claim,
  expanded,
  onToggle,
}: {
  claim: SummaryTraceableClaim
  expanded: boolean
  onToggle: () => void
}) {
  return (
    <article className="overflow-hidden rounded-xl border border-slate-700 bg-slate-900/60">
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full items-start gap-3 p-4 text-left transition hover:bg-slate-800/60"
      >
        <div className="mt-0.5 text-slate-400">
          {expanded ? (
            <ChevronDown className="h-5 w-5" />
          ) : (
            <ChevronRight className="h-5 w-5" />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="rounded border border-slate-600 bg-slate-800 px-2 py-1 text-xs text-slate-300">
              {formatLabel(claim.section)}
            </span>

            <span
              className={`rounded border px-2 py-1 text-xs ${supportBadgeClass(
                claim.support_level,
              )}`}
            >
              {formatLabel(claim.support_level)}
            </span>

            <span className="text-xs text-slate-500">
              {claim.citations.length}{' '}
              {claim.citations.length === 1
                ? 'citation'
                : 'citations'}
            </span>
          </div>

          <p className="mt-3 text-sm leading-6 text-slate-200">
            {claim.text}
          </p>
        </div>

        <div className="mt-1">
          {claim.supported ? (
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
          ) : (
            <AlertTriangle className="h-5 w-5 text-red-400" />
          )}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-slate-700 bg-slate-950/40 p-4">
          {!claim.supported
            && claim.unsupported_reason && (
              <div className="mb-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">
                {claim.unsupported_reason}
              </div>
            )}

          {claim.citations.length > 0 ? (
            <div className="space-y-3">
              {claim.citations.map(
                (citation) => (
                  <CitationCard
                    key={citation.citation_id}
                    citation={citation}
                  />
                ),
              )}
            </div>
          ) : (
            <p className="text-sm text-slate-400">
              No supporting citations are linked
              to this claim.
            </p>
          )}
        </div>
      )}
    </article>
  )
}

export function InvestigationSummaryTraceabilityPanel({
  summaryId,
  summaryTitle = 'Investigation Summary',
  summaryVersion,
}: InvestigationSummaryTraceabilityPanelProps) {
  const [report, setReport] =
    useState<InvestigationSummaryTraceability | null>(
      null,
    )

  const [integrity, setIntegrity] =
    useState<SummaryTraceabilityIntegrity | null>(
      null,
    )

  const [expandedClaims, setExpandedClaims] =
    useState<Set<string>>(new Set())

  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] =
    useState(false)
  const [error, setError] = useState('')

  const loadReport = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const loadedReport =
        await getInvestigationSummaryTraceability(
          summaryId,
        )

      setReport(loadedReport)
    } catch (requestError) {
      setReport(null)
      setError(getErrorMessage(requestError))
    } finally {
      setLoading(false)
    }
  }, [summaryId])

  useEffect(() => {
    void loadReport()
  }, [loadReport])

  const verifyIntegrity =
    useCallback(async () => {
      setVerifying(true)
      setError('')

      try {
        const result =
          await verifyInvestigationSummaryTraceability(
            summaryId,
          )

        setIntegrity(result)
      } catch (requestError) {
        setIntegrity(null)
        setError(getErrorMessage(requestError))
      } finally {
        setVerifying(false)
      }
    }, [summaryId])

  const supportPercentage = useMemo(() => {
    if (
      !report
      || report.total_claim_count === 0
    ) {
      return 0
    }

    return Math.round(
      (
        report.supported_claim_count
        / report.total_claim_count
      ) * 100,
    )
  }, [report])

  function toggleClaim(claimId: string) {
    setExpandedClaims((current) => {
      const updated = new Set(current)

      if (updated.has(claimId)) {
        updated.delete(claimId)
      } else {
        updated.add(claimId)
      }

      return updated
    })
  }

  if (loading) {
    return (
      <section className="rounded-xl border border-slate-700 bg-slate-900/70 p-6">
        <div className="flex items-center gap-3 text-slate-300">
          <RefreshCw className="h-5 w-5 animate-spin text-cyan-400" />
          Loading claim-level evidence
          traceability...
        </div>
      </section>
    )
  }

  if (!report) {
    return (
      <section className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="mt-0.5 h-5 w-5 text-amber-300" />

          <div>
            <h3 className="font-semibold text-amber-100">
              Traceability report unavailable
            </h3>

            <p className="mt-2 text-sm text-amber-200/80">
              {error
                || 'No traceability report is stored for this summary version.'}
            </p>

            <button
              type="button"
              onClick={() => void loadReport()}
              className="mt-4 inline-flex items-center gap-2 rounded-lg border border-amber-400/30 bg-amber-400/10 px-3 py-2 text-sm font-medium text-amber-100 transition hover:bg-amber-400/20"
            >
              <RefreshCw className="h-4 w-4" />
              Retry
            </button>
          </div>
        </div>
      </section>
    )
  }

  return (
    <section className="space-y-5 rounded-xl border border-slate-700 bg-slate-900/70 p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileSearch className="h-5 w-5 text-cyan-400" />

            <h3 className="text-lg font-semibold text-slate-100">
              Claim-Level Evidence Traceability
            </h3>
          </div>

          <p className="mt-2 text-sm text-slate-400">
            {summaryTitle}
            {summaryVersion
              ? ` · Version ${summaryVersion}`
              : ''}
          </p>
        </div>

        <button
          type="button"
          onClick={() => void verifyIntegrity()}
          disabled={verifying}
          className="inline-flex items-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 px-3 py-2 text-sm font-medium text-cyan-200 transition hover:bg-cyan-500/20 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {verifying ? (
            <RefreshCw className="h-4 w-4 animate-spin" />
          ) : (
            <Fingerprint className="h-4 w-4" />
          )}

          Verify integrity
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-200">
          {error}
        </div>
      )}

      {integrity && (
        <div
          className={`rounded-xl border p-4 ${
            integrity.integrity_verified
              ? 'border-emerald-500/30 bg-emerald-500/10'
              : 'border-red-500/30 bg-red-500/10'
          }`}
        >
          <div className="flex items-start gap-3">
            {integrity.integrity_verified ? (
              <ShieldCheck className="mt-0.5 h-5 w-5 text-emerald-300" />
            ) : (
              <ShieldX className="mt-0.5 h-5 w-5 text-red-300" />
            )}

            <div>
              <h4
                className={
                  integrity.integrity_verified
                    ? 'font-semibold text-emerald-100'
                    : 'font-semibold text-red-100'
                }
              >
                {integrity.integrity_verified
                  ? 'Traceability integrity verified'
                  : 'Traceability integrity mismatch detected'}
              </h4>

              <p className="mt-1 text-xs text-slate-400">
                Verified{' '}
                {formatDate(
                  integrity.verified_at,
                )}
              </p>

              <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
                <div>
                  Source hash match:{' '}
                  <span className="font-medium text-slate-200">
                    {integrity.source_hash_matches
                      ? 'Yes'
                      : 'No'}
                  </span>
                </div>

                <div>
                  Report hash match:{' '}
                  <span className="font-medium text-slate-200">
                    {integrity.report_hash_matches
                      ? 'Yes'
                      : 'No'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Supported claims
          </div>

          <div className="mt-2 text-2xl font-semibold text-emerald-300">
            {report.supported_claim_count}
          </div>

          <div className="mt-1 text-xs text-slate-400">
            {supportPercentage}% coverage
          </div>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Unsupported claims
          </div>

          <div className="mt-2 text-2xl font-semibold text-red-300">
            {report.unsupported_claim_count}
          </div>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Citations
          </div>

          <div className="mt-2 text-2xl font-semibold text-cyan-300">
            {report.citation_count}
          </div>
        </div>

        <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-4">
          <div className="text-xs uppercase tracking-wide text-slate-500">
            Total claims
          </div>

          <div className="mt-2 text-2xl font-semibold text-slate-100">
            {report.total_claim_count}
          </div>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/5 p-3">
          <div className="text-xs text-emerald-300">
            Direct support
          </div>

          <div className="mt-1 text-xl font-semibold text-emerald-100">
            {report.direct_support_count}
          </div>
        </div>

        <div className="rounded-lg border border-cyan-500/20 bg-cyan-500/5 p-3">
          <div className="text-xs text-cyan-300">
            Derived support
          </div>

          <div className="mt-1 text-xl font-semibold text-cyan-100">
            {report.derived_support_count}
          </div>
        </div>

        <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3">
          <div className="text-xs text-amber-300">
            Contextual support
          </div>

          <div className="mt-1 text-xl font-semibold text-amber-100">
            {report.contextual_support_count}
          </div>
        </div>
      </div>

      <div className="rounded-lg border border-slate-700 bg-slate-950/50 p-4 text-xs text-slate-400">
        <div className="grid gap-2 sm:grid-cols-2">
          <div>
            <span className="text-slate-500">
              Report hash:
            </span>{' '}
            <span
              className="font-mono text-slate-300"
              title={report.report_sha256}
            >
              {shortenHash(report.report_sha256)}
            </span>
          </div>

          <div>
            <span className="text-slate-500">
              Summary output hash:
            </span>{' '}
            <span
              className="font-mono text-slate-300"
              title={
                report.source_summary_output_sha256
              }
            >
              {shortenHash(
                report.source_summary_output_sha256,
              )}
            </span>
          </div>

          <div>
            <span className="text-slate-500">
              Schema:
            </span>{' '}
            <span className="text-slate-300">
              {report.schema_version}
            </span>
          </div>

          <div>
            <span className="text-slate-500">
              Generated:
            </span>{' '}
            <span className="text-slate-300">
              {formatDate(report.generated_at)}
            </span>
          </div>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <h4 className="font-semibold text-slate-100">
            Traceable claims
          </h4>

          <span className="text-xs text-slate-500">
            Select a claim to view its
            supporting sources
          </span>
        </div>

        {report.claims.map((claim) => (
          <ClaimCard
            key={claim.claim_id}
            claim={claim}
            expanded={expandedClaims.has(
              claim.claim_id,
            )}
            onToggle={() =>
              toggleClaim(claim.claim_id)
            }
          />
        ))}
      </div>
    </section>
  )
}