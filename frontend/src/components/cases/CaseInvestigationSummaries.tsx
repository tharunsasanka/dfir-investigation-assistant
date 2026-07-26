import {
  useMutation,
  useQuery,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  AlertCircle,
  BadgeCheck,
  Bot,
  BrainCircuit,
  CalendarClock,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  CircleAlert,
  Clock3,
  Database,
  FileCheck2,
  FileText,
  GitBranch,
  History,
  LoaderCircle,
  PencilLine,
  RefreshCw,
  RotateCcw,
  Save,
  ShieldAlert,
  Target,
  UserCheck,
  X,
  XCircle,
} from 'lucide-react'
import {
  useEffect,
  useMemo,
  useState,
} from 'react'
import type {
  FormEvent,
  ReactNode,
} from 'react'

import {
  createInvestigationSummaryRevision,
  generateCaseInvestigationSummary,
  getInvestigationSummary,
  listCaseInvestigationSummaries,
  reviewInvestigationSummary,
} from '../../api/investigationSummaries'
import { Can } from '../../auth/Can'
import {
  InvestigationSummaryGenerationControls,
} from './InvestigationSummaryGenerationControls'
import type {
  CreateInvestigationSummaryRevisionRequest,
  InvestigationActionPriority,
  InvestigationSummary,
  InvestigationSummarySource,
  InvestigationSummarySeverity,
  InvestigationSummaryStatus,
} from '../../types/investigationSummary'

type CaseInvestigationSummariesProps = {
  caseId: string
}

type RevisionFormState = {
  title: string
  executiveSummary: string
  technicalNarrative: string
  confidenceScore: string
  limitations: string
}

const emptyRevisionForm: RevisionFormState = {
  title: '',
  executiveSummary: '',
  technicalNarrative: '',
  confidenceScore: '0',
  limitations: '',
}

function formatLabel(value: string): string {
  return value
    .replace(/_/g, ' ')
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    )
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Not recorded'
  }

  const parsedDate = new Date(value)

  if (
    Number.isNaN(
      parsedDate.getTime(),
    )
  ) {
    return value
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'medium',
    },
  ).format(parsedDate)
}

function formatFileSize(
  bytes: number,
): string {
  if (bytes < 1024) {
    return `${bytes} B`
  }

  const kilobytes = bytes / 1024

  if (kilobytes < 1024) {
    return `${kilobytes.toFixed(1)} KB`
  }

  const megabytes =
    kilobytes / 1024

  if (megabytes < 1024) {
    return `${megabytes.toFixed(1)} MB`
  }

  const gigabytes =
    megabytes / 1024

  return `${gigabytes.toFixed(1)} GB`
}

function getErrorMessage(
  error: unknown,
): string {
  if (
    isAxiosError(error) &&
    typeof error.response
      ?.data?.detail === 'string'
  ) {
    return error.response.data.detail
  }

  if (
    error instanceof Error &&
    error.message
  ) {
    return error.message
  }

  return (
    'The investigation summary request ' +
    'could not be completed.'
  )
}

function getStatusClasses(
  status: InvestigationSummaryStatus,
): string {
  const classes: Record<
    InvestigationSummaryStatus,
    string
  > = {
    generating:
      'border-sky-400/30 bg-sky-400/10 text-sky-200',
    pending_review:
      'border-amber-400/30 bg-amber-400/10 text-amber-200',
    approved:
      'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
    rejected:
      'border-red-400/30 bg-red-400/10 text-red-200',
    failed:
      'border-rose-500/30 bg-rose-500/10 text-rose-200',
  }

  return classes[status]
}

function getStatusIcon(
  status: InvestigationSummaryStatus,
): ReactNode {
  if (status === 'approved') {
    return <BadgeCheck size={15} />
  }

  if (status === 'rejected') {
    return <XCircle size={15} />
  }

  if (status === 'failed') {
    return <CircleAlert size={15} />
  }

  if (status === 'generating') {
    return (
      <LoaderCircle
        size={15}
        className="animate-spin"
      />
    )
  }

  return <Clock3 size={15} />
}

function getSeverityClasses(
  severity: InvestigationSummarySeverity,
): string {
  const classes: Record<
    InvestigationSummarySeverity,
    string
  > = {
    critical:
      'border-red-400/30 bg-red-400/10 text-red-200',
    high:
      'border-orange-400/30 bg-orange-400/10 text-orange-200',
    medium:
      'border-amber-400/30 bg-amber-400/10 text-amber-200',
    low:
      'border-sky-400/30 bg-sky-400/10 text-sky-200',
    informational:
      'border-emerald-400/30 bg-emerald-400/10 text-emerald-200',
    unknown:
      'border-slate-400/30 bg-slate-400/10 text-slate-300',
  }

  return classes[severity]
}

function getPriorityClasses(
  priority: InvestigationActionPriority,
): string {
  const classes: Record<
    InvestigationActionPriority,
    string
  > = {
    immediate:
      'border-red-400/30 bg-red-400/10 text-red-200',
    short_term:
      'border-amber-400/30 bg-amber-400/10 text-amber-200',
    long_term:
      'border-sky-400/30 bg-sky-400/10 text-sky-200',
  }

  return classes[priority]
}

function SummaryMetric({
  label,
  value,
  icon,
}: {
  label: string
  value: string | number
  icon: ReactNode
}) {
  return (
    <article className="rounded-2xl border border-white/10 bg-white/5 p-4">
      <div className="flex items-center justify-between gap-3">
        <p className="text-xs uppercase tracking-wider text-slate-500">
          {label}
        </p>

        <span className="text-cyan">
          {icon}
        </span>
      </div>

      <p className="mt-3 break-words text-xl font-bold text-slate-100">
        {value}
      </p>
    </article>
  )
}

function SummarySection({
  title,
  description,
  icon,
  children,
}: {
  title: string
  description?: string
  icon: ReactNode
  children: ReactNode
}) {
  return (
    <section className="rounded-2xl border border-white/10 bg-white/5 p-5 sm:p-6">
      <div className="flex items-start gap-3">
        <div className="rounded-xl bg-cyan/10 p-2.5 text-cyan">
          {icon}
        </div>

        <div>
          <h3 className="font-semibold">
            {title}
          </h3>

          {description && (
            <p className="mt-1 text-sm leading-6 text-slate-500">
              {description}
            </p>
          )}
        </div>
      </div>

      <div className="mt-5">
        {children}
      </div>
    </section>
  )
}

export function CaseInvestigationSummaries({
  caseId,
}: CaseInvestigationSummariesProps) {
  const queryClient =
    useQueryClient()

  const [page, setPage] =
    useState(1)

  const [
    selectedSummaryId,
    setSelectedSummaryId,
  ] = useState<string | null>(
    null,
  )

  const [
    reviewNotes,
    setReviewNotes,
  ] = useState('')

  const [
    activeReviewDecision,
    setActiveReviewDecision,
  ] = useState<
    'approved' | 'rejected' | null
  >(null)

  const [
    isRevisionEditorOpen,
    setIsRevisionEditorOpen,
  ] = useState(false)

  const [
    revisionForm,
    setRevisionForm,
  ] = useState<RevisionFormState>(
    emptyRevisionForm,
  )
  const [
    generationSource,
    setGenerationSource,
  ] = useState<InvestigationSummarySource>(
    'deterministic',
  )

  const pageSize = 10

  const summaryListQuery = useQuery({
    queryKey: [
      'investigation-summaries',
      'case',
      caseId,
      page,
      pageSize,
    ],

    queryFn: () =>
      listCaseInvestigationSummaries(
        caseId,
        {
          page,
          page_size: pageSize,
        },
      ),

    enabled: Boolean(caseId),
  })

  const summaries = useMemo(
    () =>
      summaryListQuery.data
        ?.items ?? [],
    [
      summaryListQuery.data
        ?.items,
    ],
  )

  useEffect(() => {
    if (summaries.length === 0) {
      setSelectedSummaryId(null)
      return
    }

    const selectedExists =
      summaries.some(
        (summary) =>
          summary.id ===
          selectedSummaryId,
      )

    if (!selectedExists) {
      setSelectedSummaryId(
        summaries[0].id,
      )
    }
  }, [
    selectedSummaryId,
    summaries,
  ])

  const selectedSummaryQuery =
    useQuery({
      queryKey: [
        'investigation-summary',
        selectedSummaryId,
      ],

      queryFn: () => {
        if (!selectedSummaryId) {
          throw new Error(
            'A summary ID is required.',
          )
        }

        return getInvestigationSummary(
          selectedSummaryId,
        )
      },

      enabled: Boolean(
        selectedSummaryId,
      ),
    })

  const selectedSummary =
    selectedSummaryQuery.data

  useEffect(() => {
    setReviewNotes('')
    setActiveReviewDecision(null)
    setIsRevisionEditorOpen(false)
    setRevisionForm(
      emptyRevisionForm,
    )
  }, [selectedSummaryId])

  const generateMutation =
    useMutation({
      mutationFn: () =>
        generateCaseInvestigationSummary(
          caseId,
          {
            generation_source:
              generationSource,
            provider_name:
              generationSource ===
                'local_ai'
                ? 'ollama'
                : 'deterministic',
            model_name: '',
            prompt_template_version:
              '1.0.0',
            generation_parameters: {},
          },
        ),

      onSuccess: (summary) => {
        queryClient.setQueryData(
          [
            'investigation-summary',
            summary.id,
          ],
          summary,
        )

        setSelectedSummaryId(
          summary.id,
        )

        setPage(1)

        void queryClient.invalidateQueries({
          queryKey: [
            'investigation-summaries',
            'case',
            caseId,
          ],
        })
      },
    })

  const reviewMutation =
    useMutation({
      mutationFn: ({
        summaryId,
        decision,
        notes,
      }: {
        summaryId: string
        decision:
          | 'approved'
          | 'rejected'
        notes: string
      }) =>
        reviewInvestigationSummary(
          summaryId,
          {
            decision,
            review_notes: notes,
          },
        ),

      onSuccess: (summary) => {
        queryClient.setQueryData(
          [
            'investigation-summary',
            summary.id,
          ],
          summary,
        )

        setReviewNotes('')
        setActiveReviewDecision(null)

        void queryClient.invalidateQueries({
          queryKey: [
            'investigation-summaries',
            'case',
            caseId,
          ],
        })
      },
    })

  const revisionMutation =
    useMutation({
      mutationFn: ({
        summaryId,
        payload,
      }: {
        summaryId: string
        payload:
          CreateInvestigationSummaryRevisionRequest
      }) =>
        createInvestigationSummaryRevision(
          summaryId,
          payload,
        ),

      onSuccess: (summary) => {
        queryClient.setQueryData(
          [
            'investigation-summary',
            summary.id,
          ],
          summary,
        )

        setSelectedSummaryId(
          summary.id,
        )

        setPage(1)

        setIsRevisionEditorOpen(
          false,
        )

        setRevisionForm(
          emptyRevisionForm,
        )

        void queryClient.invalidateQueries({
          queryKey: [
            'investigation-summaries',
            'case',
            caseId,
          ],
        })
      },
    })

  function startRevision(
    summary: InvestigationSummary,
  ) {
    setRevisionForm({
      title: summary.title,
      executiveSummary:
        summary.executive_summary,
      technicalNarrative:
        summary.technical_narrative,
      confidenceScore: String(
        summary.confidence_score,
      ),
      limitations:
        summary.limitations.join(
          '\n',
        ),
    })

    setIsRevisionEditorOpen(
      true,
    )
  }

  function submitReview(
    decision:
      | 'approved'
      | 'rejected',
  ) {
    if (!selectedSummary) {
      return
    }

    setActiveReviewDecision(
      decision,
    )

    reviewMutation.mutate({
      summaryId:
        selectedSummary.id,
      decision,
      notes: reviewNotes.trim(),
    })
  }

  function submitRevision(
    event: FormEvent<HTMLFormElement>,
  ) {
    event.preventDefault()

    if (!selectedSummary) {
      return
    }

    const confidenceScore =
      Number(
        revisionForm.confidenceScore,
      )

    if (
      Number.isNaN(
        confidenceScore,
      ) ||
      confidenceScore < 0 ||
      confidenceScore > 100
    ) {
      return
    }

    const payload:
      CreateInvestigationSummaryRevisionRequest =
      {
        title:
          revisionForm.title.trim(),

        executive_summary:
          revisionForm
            .executiveSummary
            .trim(),

        technical_narrative:
          revisionForm
            .technicalNarrative
            .trim(),

        technical_findings:
          selectedSummary
            .technical_findings,

        incident_scope:
          selectedSummary
            .incident_scope,

        mitre_coverage:
          selectedSummary
            .mitre_coverage,

        evidence_references:
          selectedSummary
            .evidence_references,

        recommended_actions:
          selectedSummary
            .recommended_actions,

        verified_facts:
          selectedSummary
            .verified_facts,

        assumptions:
          selectedSummary
            .assumptions,

        limitations:
          revisionForm.limitations
            .split('\n')
            .map((item) =>
              item.trim(),
            )
            .filter(Boolean),

        confidence_score:
          confidenceScore,
      }

    revisionMutation.mutate({
      summaryId:
        selectedSummary.id,
      payload,
    })
  }

  const totalPages =
    summaryListQuery.data
      ?.pages ?? 0

  const currentPage =
    summaryListQuery.data
      ?.page ?? page

  const isAnyMutationPending =
    generateMutation.isPending ||
    reviewMutation.isPending ||
    revisionMutation.isPending

  const mutationError =
    generateMutation.error ||
    reviewMutation.error ||
    revisionMutation.error

  return (
    <section className="glass rounded-3xl p-6 sm:p-8">
      <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
        <div className="flex items-start gap-3">
          <div className="rounded-2xl bg-cyan/10 p-3 text-cyan">
            <BrainCircuit size={26} />
          </div>

          <div>
            <p className="text-sm text-cyan">
              Analyst-controlled reporting
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              AI-Assisted Investigation Summary
            </h2>

            <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-400">
              Generate a traceable case
              summary from stored evidence,
              findings, correlations, MITRE
              mappings, and the unified
              forensic timeline. Every version
              remains subject to analyst
              review.
            </p>
          </div>
        </div>

        <Can permission="cases.update">
          <InvestigationSummaryGenerationControls
            source={generationSource}
            pending={
              generateMutation.isPending
            }
            summary={selectedSummary}
            onSourceChange={
              setGenerationSource
            }
            onGenerate={() => {
              generateMutation.mutate()
            }}
          />
        </Can>
      </div>

      <div className="mt-5 flex items-start gap-3 rounded-2xl border border-amber-400/20 bg-amber-400/5 p-4">
        <CircleAlert
          size={20}
          className="mt-0.5 shrink-0 text-amber-300"
        />

        <p className="text-sm leading-6 text-amber-100/80">
          Generated content is not a final
          forensic conclusion. An authorised
          analyst must validate the source
          evidence, assumptions, MITRE
          mappings, and recommended actions.
        </p>
      </div>

      {mutationError && (
        <div
          role="alert"
          className="mt-5 flex items-start gap-3 rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200"
        >
          <AlertCircle
            size={21}
            className="mt-0.5 shrink-0"
          />

          <div>
            <p className="font-semibold">
              Summary action failed
            </p>

            <p className="mt-1 text-sm text-red-200/80">
              {getErrorMessage(
                mutationError,
              )}
            </p>
          </div>
        </div>
      )}

      <div className="mt-7 grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="rounded-2xl border border-white/10 bg-white/5 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="font-semibold">
                Version history
              </p>

              <p className="mt-1 text-xs text-slate-500">
                {
                  summaryListQuery.data
                    ?.total ?? 0
                }{' '}
                saved version
                {summaryListQuery.data
                  ?.total === 1
                  ? ''
                  : 's'}
              </p>
            </div>

            <button
              type="button"
              disabled={
                summaryListQuery
                  .isFetching
              }
              onClick={() => {
                void summaryListQuery
                  .refetch()
              }}
              className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:border-cyan/30 hover:text-cyan disabled:opacity-40"
              aria-label="Refresh summary versions"
            >
              <RefreshCw
                size={17}
                className={
                  summaryListQuery
                    .isFetching
                    ? 'animate-spin'
                    : ''
                }
              />
            </button>
          </div>

          {summaryListQuery.isPending && (
            <div className="grid min-h-52 place-items-center">
              <LoaderCircle
                size={27}
                className="animate-spin text-cyan"
              />
            </div>
          )}

          {summaryListQuery.isError && (
            <div className="mt-4 rounded-xl border border-red-400/20 bg-red-400/10 p-4">
              <p className="text-sm text-red-200">
                {getErrorMessage(
                  summaryListQuery.error,
                )}
              </p>
            </div>
          )}

          {!summaryListQuery.isPending &&
            !summaryListQuery.isError &&
            summaries.length === 0 && (
              <div className="grid min-h-52 place-items-center text-center">
                <div>
                  <Bot
                    size={34}
                    className="mx-auto text-slate-600"
                  />

                  <p className="mt-3 text-sm font-semibold">
                    No summaries generated
                  </p>

                  <p className="mt-2 text-xs leading-5 text-slate-500">
                    Generate the first
                    deterministic summary for
                    this investigation.
                  </p>
                </div>
              </div>
            )}

          {summaries.length > 0 && (
            <div className="mt-4 space-y-3">
              {summaries.map(
                (summary) => {
                  const isSelected =
                    selectedSummaryId ===
                    summary.id

                  return (
                    <button
                      key={summary.id}
                      type="button"
                      onClick={() => {
                        setSelectedSummaryId(
                          summary.id,
                        )
                      }}
                      className={[
                        'w-full rounded-xl border p-4 text-left transition',
                        isSelected
                          ? 'border-cyan/40 bg-cyan/10'
                          : 'border-white/10 bg-slate-950/20 hover:border-white/20',
                      ].join(' ')}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <p className="font-semibold">
                            Version{' '}
                            {
                              summary.version_number
                            }
                          </p>

                          <p className="mt-1 line-clamp-2 text-xs leading-5 text-slate-500">
                            {summary.title}
                          </p>
                        </div>

                        <GitBranch
                          size={17}
                          className={
                            isSelected
                              ? 'text-cyan'
                              : 'text-slate-600'
                          }
                        />
                      </div>

                      <div className="mt-3 flex flex-wrap items-center gap-2">
                        <span
                          className={[
                            'inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-[11px] font-semibold',
                            getStatusClasses(
                              summary.status,
                            ),
                          ].join(' ')}
                        >
                          {getStatusIcon(
                            summary.status,
                          )}

                          {formatLabel(
                            summary.status,
                          )}
                        </span>

                        <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-[11px] text-slate-400">
                          {
                            summary.confidence_score
                          }
                          % confidence
                        </span>
                      </div>

                      <p className="mt-3 text-[11px] text-slate-600">
                        {formatDate(
                          summary.created_at,
                        )}
                      </p>
                    </button>
                  )
                },
              )}
            </div>
          )}

          {totalPages > 1 && (
            <div className="mt-4 flex items-center justify-between border-t border-white/10 pt-4">
              <button
                type="button"
                disabled={
                  currentPage <= 1 ||
                  summaryListQuery
                    .isFetching
                }
                onClick={() => {
                  setPage(
                    Math.max(
                      1,
                      currentPage - 1,
                    ),
                  )
                }}
                className="rounded-lg border border-white/10 p-2 text-slate-400 transition hover:text-white disabled:opacity-30"
                aria-label="Previous versions"
              >
                <ChevronLeft
                  size={17}
                />
              </button>

              <span className="text-xs text-slate-500">
                {currentPage} /{' '}
                {totalPages}
              </span>

              <button
                type="button"
                disabled={
                  currentPage >=
                    totalPages ||
                  summaryListQuery
                    .isFetching
                }
                onClick={() => {
                  setPage(
                    Math.min(
                      totalPages,
                      currentPage + 1,
                    ),
                  )
                }}
                className="rounded-lg border border-white/10 p-2 text-slate-400 transition hover:text-white disabled:opacity-30"
                aria-label="Next versions"
              >
                <ChevronRight
                  size={17}
                />
              </button>
            </div>
          )}
        </aside>

        <div className="min-w-0">
          {selectedSummaryQuery.isPending &&
            selectedSummaryId && (
              <div className="grid min-h-96 place-items-center rounded-2xl border border-white/10 bg-white/5">
                <div className="text-center">
                  <LoaderCircle
                    size={31}
                    className="mx-auto animate-spin text-cyan"
                  />

                  <p className="mt-3 text-sm text-slate-500">
                    Loading summary version...
                  </p>
                </div>
              </div>
            )}

          {selectedSummaryQuery.isError && (
            <div className="rounded-2xl border border-red-400/30 bg-red-400/10 p-5 text-red-200">
              {getErrorMessage(
                selectedSummaryQuery.error,
              )}
            </div>
          )}

          {!selectedSummaryId &&
            !summaryListQuery.isPending && (
              <div className="grid min-h-96 place-items-center rounded-2xl border border-dashed border-white/10 bg-white/5 text-center">
                <div className="max-w-md p-6">
                  <FileText
                    size={42}
                    className="mx-auto text-slate-600"
                  />

                  <p className="mt-4 font-semibold">
                    No summary selected
                  </p>

                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    Generate a new
                    investigation summary or
                    select an existing version
                    from the history panel.
                  </p>
                </div>
              </div>
            )}

          {selectedSummary && (
            <div className="space-y-6">
              <section className="rounded-2xl border border-white/10 bg-white/5 p-5 sm:p-6">
                <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={[
                          'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold',
                          getStatusClasses(
                            selectedSummary.status,
                          ),
                        ].join(' ')}
                      >
                        {getStatusIcon(
                          selectedSummary.status,
                        )}

                        {formatLabel(
                          selectedSummary.status,
                        )}
                      </span>

                      <span className="rounded-full border border-violet-400/30 bg-violet-400/10 px-3 py-1 text-xs font-semibold text-violet-200">
                        Version{' '}
                        {
                          selectedSummary.version_number
                        }
                      </span>

                      <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-300">
                        {formatLabel(
                          selectedSummary
                            .generation_source,
                        )}
                      </span>
                    </div>

                    <h3 className="mt-4 break-words text-2xl font-bold">
                      {selectedSummary.title}
                    </h3>

                    <p className="mt-3 text-sm text-slate-500">
                      Generated{' '}
                      {formatDate(
                        selectedSummary
                          .generation_completed_at,
                      )}
                    </p>
                  </div>

                  <Can permission="cases.update">
                    <button
                      type="button"
                      disabled={
                        isAnyMutationPending
                      }
                      onClick={() => {
                        startRevision(
                          selectedSummary,
                        )
                      }}
                      className="flex items-center justify-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm font-semibold text-cyan transition hover:bg-cyan/20 disabled:opacity-40"
                    >
                      <PencilLine
                        size={17}
                      />

                      Create revision
                    </button>
                  </Can>
                </div>

                <div className="mt-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
                  <SummaryMetric
                    label="Confidence"
                    value={`${selectedSummary.confidence_score}%`}
                    icon={
                      <Target
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="Timeline entries"
                    value={
                      selectedSummary
                        .incident_scope
                        .total_timeline_entries
                    }
                    icon={
                      <History
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="Evidence"
                    value={
                      selectedSummary
                        .incident_scope
                        .evidence_count
                    }
                    icon={
                      <Database
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="Findings"
                    value={
                      selectedSummary
                        .incident_scope
                        .security_finding_count
                    }
                    icon={
                      <ShieldAlert
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="Correlations"
                    value={
                      selectedSummary
                        .incident_scope
                        .event_correlation_count
                    }
                    icon={
                      <GitBranch
                        size={18}
                      />
                    }
                  />
                </div>
              </section>

              <SummarySection
                title="Executive Summary"
                description="High-level assessment generated from the stored investigation records."
                icon={
                  <FileText size={20} />
                }
              >
                <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">
                  {
                    selectedSummary
                      .executive_summary
                  }
                </p>
              </SummarySection>

              <SummarySection
                title="Technical Narrative"
                description="Technical account of the available forensic activity and observed indicators."
                icon={
                  <BrainCircuit
                    size={20}
                  />
                }
              >
                <p className="whitespace-pre-wrap text-sm leading-7 text-slate-300">
                  {
                    selectedSummary
                      .technical_narrative
                  }
                </p>
              </SummarySection>

              <SummarySection
                title="Incident Scope"
                description="Entities and activity represented in the current case records."
                icon={
                  <Target size={20} />
                }
              >
                <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                  <SummaryMetric
                    label="Critical"
                    value={
                      selectedSummary
                        .incident_scope
                        .critical_count
                    }
                    icon={
                      <CircleAlert
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="High"
                    value={
                      selectedSummary
                        .incident_scope
                        .high_count
                    }
                    icon={
                      <AlertCircle
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="First activity"
                    value={formatDate(
                      selectedSummary
                        .incident_scope
                        .first_activity_at,
                    )}
                    icon={
                      <CalendarClock
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="Last activity"
                    value={formatDate(
                      selectedSummary
                        .incident_scope
                        .last_activity_at,
                    )}
                    icon={
                      <Clock3
                        size={18}
                      />
                    }
                  />
                </div>

                <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-3">
                  {[
                    {
                      label: 'Hosts',
                      values:
                        selectedSummary
                          .incident_scope
                          .affected_hosts,
                    },
                    {
                      label: 'Usernames',
                      values:
                        selectedSummary
                          .incident_scope
                          .affected_usernames,
                    },
                    {
                      label: 'Source IPs',
                      values:
                        selectedSummary
                          .incident_scope
                          .observed_source_ips,
                    },
                    {
                      label:
                        'Destination IPs',
                      values:
                        selectedSummary
                          .incident_scope
                          .observed_destination_ips,
                    },
                    {
                      label: 'Processes',
                      values:
                        selectedSummary
                          .incident_scope
                          .observed_processes,
                    },
                  ].map((group) => (
                    <div
                      key={group.label}
                      className="rounded-xl border border-white/10 bg-slate-950/20 p-4"
                    >
                      <p className="text-xs uppercase tracking-wider text-slate-500">
                        {group.label}
                      </p>

                      {group.values.length >
                      0 ? (
                        <div className="mt-3 flex flex-wrap gap-2">
                          {group.values.map(
                            (value) => (
                              <span
                                key={value}
                                className="break-all rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300"
                              >
                                {value}
                              </span>
                            ),
                          )}
                        </div>
                      ) : (
                        <p className="mt-3 text-sm text-slate-600">
                          None recorded
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </SummarySection>

              <SummarySection
                title="Technical Findings"
                description="Automated findings and correlations included in this summary version."
                icon={
                  <ShieldAlert
                    size={20}
                  />
                }
              >
                {selectedSummary
                  .technical_findings
                  .length === 0 ? (
                  <p className="text-sm text-slate-500">
                    No automated technical
                    findings were included.
                  </p>
                ) : (
                  <div className="space-y-4">
                    {selectedSummary
                      .technical_findings
                      .map(
                        (
                          finding,
                          index,
                        ) => (
                          <article
                            key={[
                              finding
                                .security_finding_id,
                              finding
                                .correlation_id,
                              index,
                            ].join(':')}
                            className="rounded-xl border border-white/10 bg-slate-950/20 p-5"
                          >
                            <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
                              <div>
                                <div className="flex flex-wrap items-center gap-2">
                                  <h4 className="font-semibold">
                                    {
                                      finding.title
                                    }
                                  </h4>

                                  <span
                                    className={[
                                      'rounded-full border px-2.5 py-1 text-xs font-semibold',
                                      getSeverityClasses(
                                        finding.severity,
                                      ),
                                    ].join(' ')}
                                  >
                                    {formatLabel(
                                      finding.severity,
                                    )}
                                  </span>

                                  <span className="rounded-full border border-white/10 bg-white/5 px-2.5 py-1 text-xs text-slate-300">
                                    {
                                      finding.confidence
                                    }
                                    % confidence
                                  </span>
                                </div>

                                <p className="mt-3 text-sm leading-6 text-slate-300">
                                  {
                                    finding.description
                                  }
                                </p>
                              </div>

                              <p className="shrink-0 text-xs text-slate-500">
                                {formatDate(
                                  finding.event_time,
                                )}
                              </p>
                            </div>

                            <div className="mt-4 flex flex-wrap gap-2 text-xs">
                              {finding.rule_id && (
                                <span className="rounded-lg border border-white/10 px-2.5 py-1 text-slate-400">
                                  Rule:{' '}
                                  {
                                    finding.rule_id
                                  }
                                </span>
                              )}

                              {finding.event_code && (
                                <span className="rounded-lg border border-white/10 px-2.5 py-1 text-slate-400">
                                  Event:{' '}
                                  {
                                    finding.event_code
                                  }
                                </span>
                              )}

                              {finding
                                .mitre_technique_id && (
                                <span className="rounded-lg border border-violet-400/20 bg-violet-400/10 px-2.5 py-1 text-violet-200">
                                  {
                                    finding
                                      .mitre_technique_id
                                  }{' '}
                                  {
                                    finding
                                      .mitre_technique_name
                                  }
                                </span>
                              )}
                            </div>
                          </article>
                        ),
                      )}
                  </div>
                )}
              </SummarySection>

              <SummarySection
                title="MITRE ATT&CK Coverage"
                description="Tactics and techniques associated with stored findings and correlations."
                icon={
                  <Target size={20} />
                }
              >
                <div className="grid gap-4 sm:grid-cols-2">
                  <SummaryMetric
                    label="Tactics"
                    value={
                      selectedSummary
                        .mitre_coverage
                        .tactic_count
                    }
                    icon={
                      <ShieldAlert
                        size={18}
                      />
                    }
                  />

                  <SummaryMetric
                    label="Techniques"
                    value={
                      selectedSummary
                        .mitre_coverage
                        .technique_count
                    }
                    icon={
                      <Target
                        size={18}
                      />
                    }
                  />
                </div>

                {selectedSummary
                  .mitre_coverage
                  .techniques.length >
                0 ? (
                  <div className="mt-5 grid gap-4 md:grid-cols-2">
                    {selectedSummary
                      .mitre_coverage
                      .techniques.map(
                        (technique) => (
                          <article
                            key={
                              technique
                                .technique_id
                            }
                            className="rounded-xl border border-violet-400/20 bg-violet-400/5 p-4"
                          >
                            <p className="font-semibold text-violet-200">
                              {
                                technique
                                  .technique_id
                              }
                              {technique
                                .technique_name
                                ? ` — ${technique.technique_name}`
                                : ''}
                            </p>

                            <p className="mt-2 text-sm text-slate-400">
                              {technique.tactic ||
                                'Tactic not recorded'}
                            </p>

                            <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-500">
                              <span>
                                Findings:{' '}
                                {
                                  technique
                                    .finding_count
                                }
                              </span>

                              <span>
                                Correlations:{' '}
                                {
                                  technique
                                    .correlation_count
                                }
                              </span>
                            </div>
                          </article>
                        ),
                      )}
                  </div>
                ) : (
                  <p className="mt-5 text-sm text-slate-500">
                    No MITRE ATT&CK
                    techniques were mapped.
                  </p>
                )}
              </SummarySection>

              <SummarySection
                title="Evidence References"
                description="Evidence items represented in the generated source snapshot."
                icon={
                  <FileCheck2
                    size={20}
                  />
                }
              >
                {selectedSummary
                  .evidence_references
                  .length === 0 ? (
                  <p className="text-sm text-slate-500">
                    No evidence references
                    were included.
                  </p>
                ) : (
                  <div className="grid gap-4 md:grid-cols-2">
                    {selectedSummary
                      .evidence_references
                      .map(
                        (evidence) => (
                          <article
                            key={
                              evidence
                                .evidence_id
                            }
                            className="rounded-xl border border-white/10 bg-slate-950/20 p-5"
                          >
                            <p className="break-words font-semibold">
                              {
                                evidence
                                  .original_filename
                              }
                            </p>

                            <div className="mt-3 flex flex-wrap gap-2 text-xs">
                              <span className="rounded-lg border border-white/10 px-2.5 py-1 text-slate-400">
                                {formatLabel(
                                  evidence
                                    .evidence_type,
                                )}
                              </span>

                              <span className="rounded-lg border border-white/10 px-2.5 py-1 text-slate-400">
                                {formatFileSize(
                                  evidence
                                    .size_bytes,
                                )}
                              </span>
                            </div>

                            <dl className="mt-4 space-y-3 text-xs">
                              <div>
                                <dt className="text-slate-600">
                                  SHA-256
                                </dt>

                                <dd className="mt-1 break-all font-mono text-slate-400">
                                  {
                                    evidence.sha256
                                  }
                                </dd>
                              </div>

                              <div className="grid grid-cols-3 gap-3">
                                <div>
                                  <dt className="text-slate-600">
                                    Events
                                  </dt>

                                  <dd className="mt-1 font-semibold">
                                    {
                                      evidence
                                        .related_event_count
                                    }
                                  </dd>
                                </div>

                                <div>
                                  <dt className="text-slate-600">
                                    Findings
                                  </dt>

                                  <dd className="mt-1 font-semibold">
                                    {
                                      evidence
                                        .related_finding_count
                                    }
                                  </dd>
                                </div>

                                <div>
                                  <dt className="text-slate-600">
                                    Correlations
                                  </dt>

                                  <dd className="mt-1 font-semibold">
                                    {
                                      evidence
                                        .related_correlation_count
                                    }
                                  </dd>
                                </div>
                              </div>
                            </dl>
                          </article>
                        ),
                      )}
                  </div>
                )}
              </SummarySection>

              <SummarySection
                title="Recommended Actions"
                description="Prioritised response and investigation steps requiring analyst assessment."
                icon={
                  <CheckCircle2
                    size={20}
                  />
                }
              >
                {selectedSummary
                  .recommended_actions
                  .length === 0 ? (
                  <p className="text-sm text-slate-500">
                    No recommended actions
                    were included.
                  </p>
                ) : (
                  <div className="space-y-4">
                    {selectedSummary
                      .recommended_actions
                      .map(
                        (
                          action,
                          index,
                        ) => (
                          <article
                            key={[
                              action.priority,
                              action.title,
                              index,
                            ].join(':')}
                            className="rounded-xl border border-white/10 bg-slate-950/20 p-5"
                          >
                            <div className="flex flex-wrap items-center gap-2">
                              <h4 className="font-semibold">
                                {action.title}
                              </h4>

                              <span
                                className={[
                                  'rounded-full border px-2.5 py-1 text-xs font-semibold',
                                  getPriorityClasses(
                                    action.priority,
                                  ),
                                ].join(' ')}
                              >
                                {formatLabel(
                                  action.priority,
                                )}
                              </span>
                            </div>

                            <p className="mt-3 text-sm leading-6 text-slate-300">
                              {
                                action.description
                              }
                            </p>

                            {action.rationale && (
                              <p className="mt-3 text-xs leading-5 text-slate-500">
                                Rationale:{' '}
                                {
                                  action.rationale
                                }
                              </p>
                            )}
                          </article>
                        ),
                      )}
                  </div>
                )}
              </SummarySection>

              <div className="grid gap-6 xl:grid-cols-2">
                <SummarySection
                  title="Verified Facts"
                  icon={
                    <BadgeCheck
                      size={20}
                    />
                  }
                >
                  {selectedSummary
                    .verified_facts
                    .length === 0 ? (
                    <p className="text-sm text-slate-500">
                      No verified facts were
                      recorded.
                    </p>
                  ) : (
                    <div className="space-y-3">
                      {selectedSummary
                        .verified_facts
                        .map(
                          (
                            fact,
                            index,
                          ) => (
                            <div
                              key={`${fact.source_type}:${index}`}
                              className="rounded-xl border border-emerald-400/20 bg-emerald-400/5 p-4"
                            >
                              <p className="text-sm leading-6 text-emerald-100/90">
                                {
                                  fact.statement
                                }
                              </p>

                              <p className="mt-2 text-xs text-emerald-300/60">
                                {
                                  fact.confidence
                                }
                                % confidence ·{' '}
                                {formatLabel(
                                  fact.source_type,
                                )}
                              </p>
                            </div>
                          ),
                        )}
                    </div>
                  )}
                </SummarySection>

                <SummarySection
                  title="Assumptions and Limitations"
                  icon={
                    <CircleAlert
                      size={20}
                    />
                  }
                >
                  <div className="space-y-3">
                    {selectedSummary
                      .assumptions
                      .map(
                        (
                          assumption,
                          index,
                        ) => (
                          <div
                            key={`${assumption.statement}:${index}`}
                            className="rounded-xl border border-amber-400/20 bg-amber-400/5 p-4"
                          >
                            <p className="text-sm leading-6 text-amber-100/90">
                              {
                                assumption.statement
                              }
                            </p>

                            <p className="mt-2 text-xs leading-5 text-amber-300/60">
                              {
                                assumption.reason
                              }
                            </p>
                          </div>
                        ),
                      )}

                    {selectedSummary
                      .limitations
                      .map(
                        (
                          limitation,
                          index,
                        ) => (
                          <div
                            key={`${limitation}:${index}`}
                            className="rounded-xl border border-white/10 bg-white/5 p-4 text-sm leading-6 text-slate-400"
                          >
                            {limitation}
                          </div>
                        ),
                      )}

                    {selectedSummary
                      .assumptions
                      .length === 0 &&
                      selectedSummary
                        .limitations
                        .length === 0 && (
                        <p className="text-sm text-slate-500">
                          No assumptions or
                          limitations were
                          recorded.
                        </p>
                      )}
                  </div>
                </SummarySection>
              </div>

              <SummarySection
                title="Generation Integrity"
                description="Hashes preserve the generated output and the source snapshot used to produce it."
                icon={
                  <FileCheck2
                    size={20}
                  />
                }
              >
                <dl className="grid gap-4 md:grid-cols-2">
                  <div className="rounded-xl border border-white/10 bg-slate-950/20 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Source snapshot SHA-256
                    </dt>

                    <dd className="mt-3 break-all font-mono text-xs leading-5 text-slate-300">
                      {
                        selectedSummary
                          .source_snapshot_sha256
                      }
                    </dd>
                  </div>

                  <div className="rounded-xl border border-white/10 bg-slate-950/20 p-4">
                    <dt className="text-xs uppercase tracking-wider text-slate-500">
                      Output SHA-256
                    </dt>

                    <dd className="mt-3 break-all font-mono text-xs leading-5 text-slate-300">
                      {
                        selectedSummary
                          .output_sha256
                      }
                    </dd>
                  </div>
                </dl>
              </SummarySection>

              {selectedSummary.status ===
                'pending_review' && (
                <Can permission="cases.update">
                  <SummarySection
                    title="Analyst Review"
                    description="Approve the version only after validating its statements against the original evidence."
                    icon={
                      <UserCheck
                        size={20}
                      />
                    }
                  >
                    <label className="text-sm">
                      Review notes

                      <textarea
                        value={reviewNotes}
                        onChange={(
                          event,
                        ) => {
                          setReviewNotes(
                            event.target
                              .value,
                          )
                        }}
                        rows={5}
                        maxLength={5000}
                        placeholder="Document the evidence reviewed, corrections required, or the reason for approval or rejection."
                        className="mt-2 w-full resize-y rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
                      />
                    </label>

                    <div className="mt-4 flex flex-col gap-3 sm:flex-row">
                      <button
                        type="button"
                        disabled={
                          reviewMutation
                            .isPending
                        }
                        onClick={() => {
                          submitReview(
                            'approved',
                          )
                        }}
                        className="flex items-center justify-center gap-2 rounded-xl bg-emerald-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:opacity-40"
                      >
                        {reviewMutation.isPending &&
                        activeReviewDecision ===
                          'approved' ? (
                          <LoaderCircle
                            size={18}
                            className="animate-spin"
                          />
                        ) : (
                          <BadgeCheck
                            size={18}
                          />
                        )}

                        Approve summary
                      </button>

                      <button
                        type="button"
                        disabled={
                          reviewMutation
                            .isPending
                        }
                        onClick={() => {
                          submitReview(
                            'rejected',
                          )
                        }}
                        className="flex items-center justify-center gap-2 rounded-xl border border-red-400/30 bg-red-400/10 px-5 py-3 text-sm font-semibold text-red-200 transition hover:bg-red-400/20 disabled:opacity-40"
                      >
                        {reviewMutation.isPending &&
                        activeReviewDecision ===
                          'rejected' ? (
                          <LoaderCircle
                            size={18}
                            className="animate-spin"
                          />
                        ) : (
                          <XCircle
                            size={18}
                          />
                        )}

                        Reject summary
                      </button>
                    </div>
                  </SummarySection>
                </Can>
              )}

              {selectedSummary.status !==
                'pending_review' && (
                <SummarySection
                  title="Review Decision"
                  icon={
                    <UserCheck
                      size={20}
                    />
                  }
                >
                  <div className="rounded-xl border border-white/10 bg-slate-950/20 p-5">
                    <div className="flex flex-wrap items-center gap-2">
                      <span
                        className={[
                          'inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold',
                          getStatusClasses(
                            selectedSummary.status,
                          ),
                        ].join(' ')}
                      >
                        {getStatusIcon(
                          selectedSummary.status,
                        )}

                        {formatLabel(
                          selectedSummary.status,
                        )}
                      </span>

                      <span className="text-xs text-slate-500">
                        {formatDate(
                          selectedSummary
                            .reviewed_at,
                        )}
                      </span>
                    </div>

                    <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-300">
                      {selectedSummary
                        .review_notes ||
                        'No analyst review notes were recorded.'}
                    </p>
                  </div>
                </SummarySection>
              )}
            </div>
          )}
        </div>
      </div>

      {isRevisionEditorOpen &&
        selectedSummary && (
          <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4 backdrop-blur-sm">
            <div className="max-h-[92vh] w-full max-w-4xl overflow-y-auto rounded-3xl border border-white/10 bg-slate-950 p-6 shadow-2xl sm:p-8">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <p className="text-sm text-cyan">
                    Analyst revision
                  </p>

                  <h3 className="mt-1 text-2xl font-bold">
                    Create Summary Version{' '}
                    {
                      selectedSummary
                        .version_number + 1
                    }
                  </h3>

                  <p className="mt-2 text-sm leading-6 text-slate-500">
                    The new version retains
                    the original findings,
                    evidence references,
                    scope, MITRE coverage,
                    actions, and source
                    snapshot while allowing
                    analyst corrections to the
                    written assessment.
                  </p>
                </div>

                <button
                  type="button"
                  disabled={
                    revisionMutation
                      .isPending
                  }
                  onClick={() => {
                    setIsRevisionEditorOpen(
                      false,
                    )
                  }}
                  className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:text-white disabled:opacity-40"
                  aria-label="Close revision editor"
                >
                  <X size={19} />
                </button>
              </div>

              <form
                onSubmit={
                  submitRevision
                }
                className="mt-7 space-y-5"
              >
                <label className="block text-sm">
                  Title

                  <input
                    required
                    maxLength={255}
                    value={
                      revisionForm.title
                    }
                    onChange={(event) => {
                      setRevisionForm(
                        (current) => ({
                          ...current,
                          title:
                            event.target
                              .value,
                        }),
                      )
                    }}
                    className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
                  />
                </label>

                <label className="block text-sm">
                  Executive summary

                  <textarea
                    required
                    rows={7}
                    value={
                      revisionForm
                        .executiveSummary
                    }
                    onChange={(event) => {
                      setRevisionForm(
                        (current) => ({
                          ...current,
                          executiveSummary:
                            event.target
                              .value,
                        }),
                      )
                    }}
                    className="mt-2 w-full resize-y rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
                  />
                </label>

                <label className="block text-sm">
                  Technical narrative

                  <textarea
                    required
                    rows={10}
                    value={
                      revisionForm
                        .technicalNarrative
                    }
                    onChange={(event) => {
                      setRevisionForm(
                        (current) => ({
                          ...current,
                          technicalNarrative:
                            event.target
                              .value,
                        }),
                      )
                    }}
                    className="mt-2 w-full resize-y rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
                  />
                </label>

                <div className="grid gap-5 md:grid-cols-[180px_minmax(0,1fr)]">
                  <label className="block text-sm">
                    Confidence score

                    <input
                      required
                      type="number"
                      min={0}
                      max={100}
                      value={
                        revisionForm
                          .confidenceScore
                      }
                      onChange={(
                        event,
                      ) => {
                        setRevisionForm(
                          (current) => ({
                            ...current,
                            confidenceScore:
                              event.target
                                .value,
                          }),
                        )
                      }}
                      className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
                    />
                  </label>

                  <label className="block text-sm">
                    Limitations

                    <textarea
                      rows={6}
                      value={
                        revisionForm
                          .limitations
                      }
                      onChange={(
                        event,
                      ) => {
                        setRevisionForm(
                          (current) => ({
                            ...current,
                            limitations:
                              event.target
                                .value,
                          }),
                        )
                      }}
                      placeholder="Enter one limitation per line."
                      className="mt-2 w-full resize-y rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
                    />
                  </label>
                </div>

                <div className="flex flex-col-reverse gap-3 border-t border-white/10 pt-5 sm:flex-row sm:justify-end">
                  <button
                    type="button"
                    disabled={
                      revisionMutation
                        .isPending
                    }
                    onClick={() => {
                      setIsRevisionEditorOpen(
                        false,
                      )
                    }}
                    className="flex items-center justify-center gap-2 rounded-xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:text-white disabled:opacity-40"
                  >
                    <RotateCcw
                      size={17}
                    />

                    Cancel
                  </button>

                  <button
                    type="submit"
                    disabled={
                      revisionMutation
                        .isPending ||
                      !revisionForm.title
                        .trim() ||
                      !revisionForm
                        .executiveSummary
                        .trim() ||
                      !revisionForm
                        .technicalNarrative
                        .trim()
                    }
                    className="flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:opacity-40"
                  >
                    {revisionMutation.isPending ? (
                      <LoaderCircle
                        size={18}
                        className="animate-spin"
                      />
                    ) : (
                      <Save size={18} />
                    )}

                    Save revision
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
    </section>
  )
}