import {
  useState,
} from 'react'
import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Clipboard,
  Download,
  FileJson,
  FileText,
  Loader2,
  ShieldCheck,
} from 'lucide-react'

import {
  exportInvestigationReport,
  saveInvestigationReport,
} from '../../api/investigationReports'
import type {
  InvestigationReportDownload,
  InvestigationReportExportRequest,
  InvestigationReportFormat,
} from '../../types/investigationReport'

interface InvestigationReportExportPanelProps {
  summaryId: string
  summaryTitle?: string
  summaryVersion?: number
}

interface ExportOptions {
  includeTraceability: boolean
  includeIntegrityVerification: boolean
  includeEvidenceHashes: boolean
  includeRecommendations: boolean
  includeAssumptions: boolean
  includeLimitations: boolean
}

const DEFAULT_OPTIONS: ExportOptions = {
  includeTraceability: true,
  includeIntegrityVerification: true,
  includeEvidenceHashes: true,
  includeRecommendations: true,
  includeAssumptions: true,
  includeLimitations: true,
}

async function getErrorMessage(
  error: unknown,
): Promise<string> {
  if (
    typeof error === 'object'
    && error !== null
    && 'response' in error
  ) {
    const response = (
      error as {
        response?: {
          data?: unknown
        }
      }
    ).response

    const responseData =
      response?.data

    if (responseData instanceof Blob) {
      const responseText =
        await responseData.text()

      try {
        const parsed = JSON.parse(
          responseText,
        ) as {
          detail?: string
        }

        if (parsed.detail) {
          return parsed.detail
        }
      } catch {
        if (responseText.trim()) {
          return responseText
        }
      }
    }

    if (
      typeof responseData === 'object'
      && responseData !== null
      && 'detail' in responseData
    ) {
      const detail = (
        responseData as {
          detail?: unknown
        }
      ).detail

      if (typeof detail === 'string') {
        return detail
      }
    }
  }

  if (error instanceof Error) {
    return error.message
  }

  return 'The investigation report could not be exported.'
}

function shortenHash(
  value: string,
): string {
  if (value.length <= 32) {
    return value
  }

  return (
    `${value.slice(0, 16)}`
    + '...'
    + `${value.slice(-16)}`
  )
}

function formatFileSize(
  sizeBytes: number,
): string {
  if (sizeBytes < 1024) {
    return `${sizeBytes} B`
  }

  if (sizeBytes < 1024 * 1024) {
    return `${(
      sizeBytes / 1024
    ).toFixed(1)} KB`
  }

  return `${(
    sizeBytes
    / (1024 * 1024)
  ).toFixed(1)} MB`
}

function OptionToggle({
  id,
  label,
  description,
  checked,
  disabled = false,
  onChange,
}: {
  id: string
  label: string
  description: string
  checked: boolean
  disabled?: boolean
  onChange: (
    checked: boolean,
  ) => void
}) {
  return (
    <label
      htmlFor={id}
      className={`flex gap-3 rounded-lg border p-3 transition ${
        disabled
          ? (
              'cursor-not-allowed '
              + 'border-slate-800 '
              + 'bg-slate-950/30 '
              + 'opacity-60'
            )
          : (
              'cursor-pointer '
              + 'border-slate-700 '
              + 'bg-slate-950/50 '
              + 'hover:border-cyan-500/30 '
              + 'hover:bg-slate-900'
            )
      }`}
    >
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) =>
          onChange(
            event.target.checked,
          )
        }
        className="mt-1 h-4 w-4 rounded border-slate-600 bg-slate-900 text-cyan-500 focus:ring-cyan-500"
      />

      <span>
        <span className="block text-sm font-medium text-slate-200">
          {label}
        </span>

        <span className="mt-1 block text-xs leading-5 text-slate-500">
          {description}
        </span>
      </span>
    </label>
  )
}

export function InvestigationReportExportPanel({
  summaryId,
  summaryTitle = 'Investigation Summary',
  summaryVersion,
}: InvestigationReportExportPanelProps) {
  const [
    reportFormat,
    setReportFormat,
  ] = useState<
    InvestigationReportFormat
  >('pdf')

  const [
    options,
    setOptions,
  ] = useState<ExportOptions>(
    DEFAULT_OPTIONS,
  )

  const [
    exporting,
    setExporting,
  ] = useState(false)

  const [
    error,
    setError,
  ] = useState('')

  const [
    completedDownload,
    setCompletedDownload,
  ] = useState<
    InvestigationReportDownload | null
  >(null)

  const [
    copiedHash,
    setCopiedHash,
  ] = useState(false)

  function updateOption(
    option: keyof ExportOptions,
    checked: boolean,
  ) {
    setOptions((current) => ({
      ...current,
      [option]: checked,
    }))
  }

  function selectFormat(
    format: InvestigationReportFormat,
  ) {
    setReportFormat(format)
    setCompletedDownload(null)
    setError('')
  }

  async function handleExport() {
    setExporting(true)
    setError('')
    setCompletedDownload(null)
    setCopiedHash(false)

    const request:
      InvestigationReportExportRequest = {
        summary_id: summaryId,
        format: reportFormat,
        include_traceability:
          options.includeTraceability,
        include_integrity_verification:
          (
            options
              .includeIntegrityVerification
            && options.includeTraceability
          ),
        include_evidence_hashes:
          options.includeEvidenceHashes,
        include_recommendations:
          options.includeRecommendations,
        include_assumptions:
          options.includeAssumptions,
        include_limitations:
          options.includeLimitations,
      }

    try {
      const download =
        await exportInvestigationReport(
          request,
        )

      saveInvestigationReport(
        download,
      )

      setCompletedDownload(
        download,
      )
    } catch (requestError) {
      setError(
        await getErrorMessage(
          requestError,
        ),
      )
    } finally {
      setExporting(false)
    }
  }

  async function copyDocumentHash() {
    const documentHash =
      completedDownload
        ?.documentSha256

    if (!documentHash) {
      return
    }

    try {
      await navigator.clipboard.writeText(
        documentHash,
      )

      setCopiedHash(true)

      window.setTimeout(() => {
        setCopiedHash(false)
      }, 2000)
    } catch {
      setError(
        'The report hash could not be copied.',
      )
    }
  }

  return (
    <section className="space-y-5 rounded-xl border border-slate-700 bg-slate-900/70 p-5">
      <div>
        <div className="flex items-center gap-2">
          <Download className="h-5 w-5 text-cyan-400" />

          <h3 className="text-lg font-semibold text-slate-100">
            Export Investigation Report
          </h3>
        </div>

        <p className="mt-2 text-sm text-slate-400">
          {summaryTitle}
          {summaryVersion
            ? ` · Version ${summaryVersion}`
            : ''}
        </p>

        <p className="mt-1 text-xs leading-5 text-slate-500">
          Generate an evidence-linked report
          containing the selected investigation
          summary and supporting forensic records.
        </p>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-slate-200">
          Report format
        </h4>

        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <button
            type="button"
            onClick={() =>
              selectFormat('pdf')
            }
            className={`flex items-start gap-3 rounded-xl border p-4 text-left transition ${
              reportFormat === 'pdf'
                ? (
                    'border-cyan-500/50 '
                    + 'bg-cyan-500/10'
                  )
                : (
                    'border-slate-700 '
                    + 'bg-slate-950/50 '
                    + 'hover:border-slate-600'
                  )
            }`}
          >
            <FileText
              className={`mt-0.5 h-5 w-5 ${
                reportFormat === 'pdf'
                  ? 'text-cyan-300'
                  : 'text-slate-500'
              }`}
            />

            <span>
              <span className="block text-sm font-medium text-slate-100">
                Professional PDF
              </span>

              <span className="mt-1 block text-xs leading-5 text-slate-500">
                Multi-page forensic report
                suitable for review, submission
                and presentation.
              </span>
            </span>
          </button>

          <button
            type="button"
            onClick={() =>
              selectFormat('json')
            }
            className={`flex items-start gap-3 rounded-xl border p-4 text-left transition ${
              reportFormat === 'json'
                ? (
                    'border-cyan-500/50 '
                    + 'bg-cyan-500/10'
                  )
                : (
                    'border-slate-700 '
                    + 'bg-slate-950/50 '
                    + 'hover:border-slate-600'
                  )
            }`}
          >
            <FileJson
              className={`mt-0.5 h-5 w-5 ${
                reportFormat === 'json'
                  ? 'text-cyan-300'
                  : 'text-slate-500'
              }`}
            />

            <span>
              <span className="block text-sm font-medium text-slate-100">
                Structured JSON
              </span>

              <span className="mt-1 block text-xs leading-5 text-slate-500">
                Machine-readable report for
                integration, validation and
                archival workflows.
              </span>
            </span>
          </button>
        </div>
      </div>

      <div>
        <h4 className="text-sm font-semibold text-slate-200">
          Included report sections
        </h4>

        <div className="mt-3 grid gap-3 lg:grid-cols-2">
          <OptionToggle
            id="report-traceability"
            label="Claim-level traceability"
            description="Include supported claims, source links and forensic citations."
            checked={
              options.includeTraceability
            }
            onChange={(checked) =>
              updateOption(
                'includeTraceability',
                checked,
              )
            }
          />

          <OptionToggle
            id="report-integrity"
            label="Integrity verification"
            description="Include reconstructed traceability and hash verification results."
            checked={
              options
                .includeIntegrityVerification
            }
            disabled={
              !options.includeTraceability
            }
            onChange={(checked) =>
              updateOption(
                'includeIntegrityVerification',
                checked,
              )
            }
          />

          <OptionToggle
            id="report-evidence-hashes"
            label="Evidence SHA-256 hashes"
            description="Include evidence integrity hashes in references and citations."
            checked={
              options.includeEvidenceHashes
            }
            onChange={(checked) =>
              updateOption(
                'includeEvidenceHashes',
                checked,
              )
            }
          />

          <OptionToggle
            id="report-recommendations"
            label="Recommended actions"
            description="Include containment, investigation and remediation recommendations."
            checked={
              options.includeRecommendations
            }
            onChange={(checked) =>
              updateOption(
                'includeRecommendations',
                checked,
              )
            }
          />

          <OptionToggle
            id="report-assumptions"
            label="Investigation assumptions"
            description="Include clearly labelled assumptions used during automated analysis."
            checked={
              options.includeAssumptions
            }
            onChange={(checked) =>
              updateOption(
                'includeAssumptions',
                checked,
              )
            }
          />

          <OptionToggle
            id="report-limitations"
            label="Analysis limitations"
            description="Include known evidence, coverage and automation limitations."
            checked={
              options.includeLimitations
            }
            onChange={(checked) =>
              updateOption(
                'includeLimitations',
                checked,
              )
            }
          />
        </div>
      </div>

      <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
        <div className="flex items-start gap-3">
          <ShieldCheck className="mt-0.5 h-5 w-5 text-amber-300" />

          <div>
            <h4 className="text-sm font-semibold text-amber-100">
              Analyst review remains required
            </h4>

            <p className="mt-1 text-xs leading-5 text-amber-200/70">
              Exporting a report does not replace
              analyst validation or approval of
              AI-assisted conclusions.
            </p>
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="mt-0.5 h-5 w-5 text-red-300" />

            <div>
              <h4 className="text-sm font-semibold text-red-100">
                Report export failed
              </h4>

              <p className="mt-1 text-sm text-red-200/80">
                {error}
              </p>
            </div>
          </div>
        </div>
      )}

      {completedDownload && (
        <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4">
          <div className="flex items-start gap-3">
            <CheckCircle2 className="mt-0.5 h-5 w-5 text-emerald-300" />

            <div className="min-w-0 flex-1">
              <h4 className="text-sm font-semibold text-emerald-100">
                Report exported successfully
              </h4>

              <div className="mt-3 grid gap-2 text-xs text-slate-300 sm:grid-cols-2">
                <div>
                  <span className="text-slate-500">
                    Filename:
                  </span>{' '}
                  <span className="break-all">
                    {completedDownload.filename}
                  </span>
                </div>

                <div>
                  <span className="text-slate-500">
                    Size:
                  </span>{' '}
                  {formatFileSize(
                    completedDownload
                      .content.size,
                  )}
                </div>

                <div>
                  <span className="text-slate-500">
                    Format:
                  </span>{' '}
                  {completedDownload
                    .format
                    .toUpperCase()}
                </div>

                {completedDownload.reportId && (
                  <div>
                    <span className="text-slate-500">
                      Report ID:
                    </span>{' '}
                    <span className="break-all">
                      {
                        completedDownload
                          .reportId
                      }
                    </span>
                  </div>
                )}
              </div>

              {completedDownload
                .documentSha256 && (
                <div className="mt-3 rounded border border-emerald-500/20 bg-slate-950/40 p-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <div className="text-xs text-slate-500">
                        Exported document SHA-256
                      </div>

                      <div
                        className="mt-1 break-all font-mono text-xs text-slate-200"
                        title={
                          completedDownload
                            .documentSha256
                        }
                      >
                        {shortenHash(
                          completedDownload
                            .documentSha256,
                        )}
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() =>
                        void copyDocumentHash()
                      }
                      className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-800 px-3 py-2 text-xs font-medium text-slate-200 transition hover:bg-slate-700"
                    >
                      {copiedHash ? (
                        <Check className="h-4 w-4 text-emerald-300" />
                      ) : (
                        <Clipboard className="h-4 w-4" />
                      )}

                      {copiedHash
                        ? 'Copied'
                        : 'Copy hash'}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      <button
        type="button"
        onClick={() =>
          void handleExport()
        }
        disabled={exporting}
        className="inline-flex w-full items-center justify-center gap-2 rounded-lg bg-cyan-500 px-4 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-60"
      >
        {exporting ? (
          <Loader2 className="h-5 w-5 animate-spin" />
        ) : (
          <Download className="h-5 w-5" />
        )}

        {exporting
          ? 'Preparing report...'
          : `Export ${reportFormat.toUpperCase()} Report`}
      </button>
    </section>
  )
}