import {
  useEffect,
  useMemo,
  useState,
} from 'react'
import {
  Activity,
  AlertCircle,
  Archive,
  BookOpenCheck,
  ChevronRight,
  Clock3,
  FileSearch,
  Files,
  Fingerprint,
  FolderSearch2,
  ListFilter,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  Workflow,
} from 'lucide-react'
import {
  useQuery,
} from '@tanstack/react-query'
import {
  Link,
  useSearchParams,
} from 'react-router-dom'

import {
  getCases,
} from '../api/cases'
import {
  CaseAuditTimeline,
} from '../components/cases/CaseAuditTimeline'
import {
  CaseEventCorrelations,
} from '../components/cases/CaseEventCorrelations'
import {
  CaseEvidencePanel,
} from '../components/cases/CaseEvidencePanel'
import {
  CaseForensicTimeline,
} from '../components/cases/CaseForensicTimeline'
import {
  CaseInvestigationSummaries,
} from '../components/cases/CaseInvestigationSummaries'
import {
  CaseLogEventExplorer,
} from '../components/cases/CaseLogEventExplorer'
import {
  CaseSecurityFindings,
} from '../components/cases/CaseSecurityFindings'
import type {
  CaseSeverity,
  CaseStatus,
  InvestigationCase,
} from '../types/case'

type WorkspaceTab =
  | 'overview'
  | 'evidence'
  | 'findings'
  | 'correlations'
  | 'timeline'
  | 'summaries'
  | 'logs'
  | 'audit'

type WorkspaceTabDefinition = {
  id: WorkspaceTab
  label: string
  description: string
  icon: typeof Activity
}

const workspaceTabs: WorkspaceTabDefinition[] = [
  {
    id: 'overview',
    label: 'Overview',
    description: 'Case context and investigation workflow',
    icon: FolderSearch2,
  },
  {
    id: 'evidence',
    label: 'Evidence',
    description: 'Uploaded forensic evidence and custody',
    icon: Files,
  },
  {
    id: 'findings',
    label: 'Findings',
    description: 'Detected security findings',
    icon: ShieldAlert,
  },
  {
    id: 'correlations',
    label: 'Correlations',
    description: 'Cross-evidence event relationships',
    icon: Workflow,
  },
  {
    id: 'timeline',
    label: 'Timeline',
    description: 'Unified forensic activity timeline',
    icon: Clock3,
  },
  {
    id: 'summaries',
    label: 'Summaries',
    description: 'AI-assisted investigation summaries',
    icon: BookOpenCheck,
  },
  {
    id: 'logs',
    label: 'Log Explorer',
    description: 'Parsed and normalised log events',
    icon: FileSearch,
  },
  {
    id: 'audit',
    label: 'Audit',
    description: 'Case activity and accountability history',
    icon: Fingerprint,
  },
]

const severityClasses: Record<
  CaseSeverity,
  string
> = {
  low: (
    'border-emerald-500/30 '
    + 'bg-emerald-500/10 '
    + 'text-emerald-300'
  ),
  medium: (
    'border-amber-500/30 '
    + 'bg-amber-500/10 '
    + 'text-amber-300'
  ),
  high: (
    'border-orange-500/30 '
    + 'bg-orange-500/10 '
    + 'text-orange-300'
  ),
  critical: (
    'border-red-500/30 '
    + 'bg-red-500/10 '
    + 'text-red-300'
  ),
}

const statusClasses: Record<
  CaseStatus,
  string
> = {
  open: (
    'border-sky-500/30 '
    + 'bg-sky-500/10 '
    + 'text-sky-300'
  ),
  investigating: (
    'border-cyan-500/30 '
    + 'bg-cyan-500/10 '
    + 'text-cyan-300'
  ),
  review: (
    'border-violet-500/30 '
    + 'bg-violet-500/10 '
    + 'text-violet-300'
  ),
  closed: (
    'border-slate-500/30 '
    + 'bg-slate-500/10 '
    + 'text-slate-300'
  ),
}

function formatLabel(
  value: string,
): string {
  return value
    .split('_').join(' ')
    .replace(/\b\w/g, (letter) =>
      letter.toUpperCase(),
    )
}

function formatDateTime(
  value: string,
): string {
  const date = new Date(value)

  if (Number.isNaN(date.getTime())) {
    return value
  }

  return date.toLocaleString()
}

function WorkspaceOverview({
  investigationCase,
}: {
  investigationCase: InvestigationCase
}) {
  const workflowItems = [
    {
      title: 'Collect evidence',
      description: (
        'Upload forensic artefacts and preserve '
        + 'their SHA-256 integrity records.'
      ),
      icon: Files,
    },
    {
      title: 'Analyse activity',
      description: (
        'Review parsed events, security findings '
        + 'and cross-evidence correlations.'
      ),
      icon: FileSearch,
    },
    {
      title: 'Build the timeline',
      description: (
        'Reconstruct activity using the unified '
        + 'forensic timeline.'
      ),
      icon: Clock3,
    },
    {
      title: 'Review conclusions',
      description: (
        'Generate evidence-linked summaries and '
        + 'complete analyst validation.'
      ),
      icon: BookOpenCheck,
    },
  ]

  return (
    <div className="space-y-6">
      <section className="rounded-2xl border border-slate-700 bg-slate-900/70 p-6">
        <div className="flex items-center gap-3">
          <Archive className="h-5 w-5 text-cyan-400" />

          <h2 className="text-lg font-semibold text-slate-100">
            Case Overview
          </h2>
        </div>

        <div className="mt-5 grid gap-4 md:grid-cols-2 xl:grid-cols-4">
          <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
            <div className="text-xs uppercase tracking-wider text-slate-500">
              Severity
            </div>

            <div className="mt-3">
              <span
                className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${
                  severityClasses[
                    investigationCase.severity
                  ]
                }`}
              >
                {formatLabel(
                  investigationCase.severity,
                )}
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
            <div className="text-xs uppercase tracking-wider text-slate-500">
              Status
            </div>

            <div className="mt-3">
              <span
                className={`inline-flex rounded-full border px-3 py-1 text-xs font-semibold ${
                  statusClasses[
                    investigationCase.status
                  ]
                }`}
              >
                {formatLabel(
                  investigationCase.status,
                )}
              </span>
            </div>
          </div>

          <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
            <div className="text-xs uppercase tracking-wider text-slate-500">
              Created
            </div>

            <div className="mt-3 text-sm font-medium text-slate-200">
              {formatDateTime(
                investigationCase.created_at,
              )}
            </div>
          </div>

          <div className="rounded-xl border border-slate-700 bg-slate-950/50 p-4">
            <div className="text-xs uppercase tracking-wider text-slate-500">
              Last updated
            </div>

            <div className="mt-3 text-sm font-medium text-slate-200">
              {formatDateTime(
                investigationCase.updated_at,
              )}
            </div>
          </div>
        </div>

        <div className="mt-5 rounded-xl border border-slate-700 bg-slate-950/40 p-5">
          <div className="text-xs uppercase tracking-wider text-slate-500">
            Description
          </div>

          <p className="mt-3 whitespace-pre-wrap text-sm leading-7 text-slate-300">
            {investigationCase.description
              || 'No case description has been recorded.'}
          </p>
        </div>
      </section>

      <section className="rounded-2xl border border-slate-700 bg-slate-900/70 p-6">
        <div className="flex items-center gap-3">
          <Workflow className="h-5 w-5 text-cyan-400" />

          <div>
            <h2 className="text-lg font-semibold text-slate-100">
              Investigation Workflow
            </h2>

            <p className="mt-1 text-sm text-slate-500">
              Follow the evidence-driven workflow
              from collection to analyst review.
            </p>
          </div>
        </div>

        <div className="mt-5 grid gap-4 lg:grid-cols-2">
          {workflowItems.map(
            (
              {
                title,
                description,
                icon: Icon,
              },
              index,
            ) => (
              <article
                key={title}
                className="rounded-xl border border-slate-700 bg-slate-950/50 p-5"
              >
                <div className="flex items-start gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-cyan-500/20 bg-cyan-500/10">
                    <Icon className="h-5 w-5 text-cyan-300" />
                  </div>

                  <div>
                    <div className="text-xs font-semibold uppercase tracking-wider text-cyan-400">
                      Step {index + 1}
                    </div>

                    <h3 className="mt-1 font-semibold text-slate-100">
                      {title}
                    </h3>

                    <p className="mt-2 text-sm leading-6 text-slate-500">
                      {description}
                    </p>
                  </div>
                </div>
              </article>
            ),
          )}
        </div>
      </section>
    </div>
  )
}

export function InvestigationPage() {
  const [
    searchParams,
    setSearchParams,
  ] = useSearchParams()

  const requestedCaseId =
    searchParams.get('case') ?? ''

  const [
    selectedCaseId,
    setSelectedCaseId,
  ] = useState(
    requestedCaseId,
  )

  const [
    activeTab,
    setActiveTab,
  ] = useState<WorkspaceTab>(
    'overview',
  )

  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const casesQuery = useQuery({
    queryKey: [
      'investigation-workspace',
      'cases',
    ],
    queryFn: () =>
      getCases({
        page: 1,
        page_size: 100,
      }),
  })

  const cases = useMemo(
    () => casesQuery.data?.items ?? [],
    [
      casesQuery.data?.items,
    ],
  )

  const filteredCases = useMemo(() => {
    const search =
      searchInput.trim().toLowerCase()

    if (!search) {
      return cases
    }

    return cases.filter(
      (investigationCase) =>
        investigationCase.title
          .toLowerCase()
          .includes(search)
        || investigationCase.description
          .toLowerCase()
          .includes(search)
        || investigationCase.severity
          .toLowerCase()
          .includes(search)
        || investigationCase.status
          .toLowerCase()
          .includes(search),
    )
  }, [
    cases,
    searchInput,
  ])

  const selectedCase =
    cases.find(
      (investigationCase) =>
        investigationCase.id
        === selectedCaseId,
    ) ?? null

  useEffect(() => {
    if (cases.length === 0) {
      return
    }

    const requestedCaseExists =
      requestedCaseId
      && cases.some(
        (investigationCase) =>
          investigationCase.id
          === requestedCaseId,
      )

    if (requestedCaseExists) {
      if (
        selectedCaseId
        !== requestedCaseId
      ) {
        setSelectedCaseId(
          requestedCaseId,
        )
      }

      return
    }

    const selectedCaseExists =
      selectedCaseId
      && cases.some(
        (investigationCase) =>
          investigationCase.id
          === selectedCaseId,
      )

    if (selectedCaseExists) {
      return
    }

    const preferredCase =
      cases.find(
        (investigationCase) =>
          investigationCase.status
          === 'investigating',
      )
      ?? cases.find(
        (investigationCase) =>
          investigationCase.status
          !== 'closed',
      )
      ?? cases[0]

    setSelectedCaseId(
      preferredCase.id,
    )

    setSearchParams(
      {
        case: preferredCase.id,
      },
      {
        replace: true,
      },
    )
  }, [
    cases,
    requestedCaseId,
    selectedCaseId,
    setSearchParams,
  ])

  function selectCase(
    caseId: string,
  ) {
    setSelectedCaseId(caseId)
    setActiveTab('overview')

    setSearchParams(
      {
        case: caseId,
      },
      {
        replace: true,
      },
    )
  }

  function renderWorkspaceContent() {
    if (!selectedCase) {
      return null
    }

    switch (activeTab) {
      case 'evidence':
        return (
          <CaseEvidencePanel
            caseId={selectedCase.id}
          />
        )

      case 'findings':
        return (
          <CaseSecurityFindings
            caseId={selectedCase.id}
          />
        )

      case 'correlations':
        return (
          <CaseEventCorrelations
            caseId={selectedCase.id}
          />
        )

      case 'timeline':
        return (
          <CaseForensicTimeline
            caseId={selectedCase.id}
          />
        )

      case 'summaries':
        return (
          <CaseInvestigationSummaries
            caseId={selectedCase.id}
          />
        )

      case 'logs':
        return (
          <CaseLogEventExplorer
            caseId={selectedCase.id}
          />
        )

      case 'audit':
        return (
          <CaseAuditTimeline
            caseId={selectedCase.id}
          />
        )

      default:
        return (
          <WorkspaceOverview
            investigationCase={
              selectedCase
            }
          />
        )
    }
  }

  return (
    <section className="space-y-6">
      <header className="flex flex-col gap-4 xl:flex-row xl:items-end xl:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <FolderSearch2 className="h-7 w-7 text-cyan-400" />

            <h1 className="text-3xl font-bold text-slate-100">
              Investigation Workspace
            </h1>
          </div>

          <p className="mt-2 max-w-3xl text-sm leading-6 text-slate-500">
            Select a case and move through evidence,
            findings, correlations, timeline analysis,
            summaries and reporting from one workspace.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <button
            type="button"
            onClick={() =>
              void casesQuery.refetch()
            }
            disabled={
              casesQuery.isFetching
            }
            className="inline-flex items-center gap-2 rounded-lg border border-slate-600 bg-slate-900 px-4 py-2.5 text-sm font-medium text-slate-200 transition hover:border-cyan-500/40 hover:text-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
          >
            <RefreshCw
              className={`h-4 w-4 ${
                casesQuery.isFetching
                  ? 'animate-spin'
                  : ''
              }`}
            />

            Refresh cases
          </button>

          {selectedCase && (
            <Link
              to={`/cases/${selectedCase.id}`}
              className="inline-flex items-center gap-2 rounded-lg bg-cyan-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition hover:bg-cyan-400"
            >
              Open case details

              <ChevronRight className="h-4 w-4" />
            </Link>
          )}
        </div>
      </header>

      <div className="grid gap-6 xl:grid-cols-[320px_minmax(0,1fr)]">
        <aside className="self-start rounded-2xl border border-slate-700 bg-slate-900/70 p-4 xl:sticky xl:top-6">
          <div className="flex items-center gap-2">
            <ListFilter className="h-4 w-4 text-cyan-400" />

            <h2 className="font-semibold text-slate-100">
              Investigation Cases
            </h2>
          </div>

          <div className="relative mt-4">
            <Search className="pointer-events-none absolute left-3 top-3 h-4 w-4 text-slate-500" />

            <input
              type="search"
              value={searchInput}
              onChange={(event) =>
                setSearchInput(
                  event.target.value,
                )
              }
              placeholder="Search cases"
              className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2.5 pl-10 pr-3 text-sm text-slate-200 outline-none transition placeholder:text-slate-600 focus:border-cyan-500/50"
            />
          </div>

          {casesQuery.isLoading && (
            <div className="flex items-center justify-center gap-2 py-12 text-sm text-slate-500">
              <Loader2 className="h-5 w-5 animate-spin" />

              Loading cases...
            </div>
          )}

          {casesQuery.isError && (
            <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-4">
              <div className="flex items-start gap-3">
                <AlertCircle className="mt-0.5 h-5 w-5 text-red-300" />

                <div>
                  <div className="text-sm font-semibold text-red-100">
                    Cases could not be loaded
                  </div>

                  <button
                    type="button"
                    onClick={() =>
                      void casesQuery.refetch()
                    }
                    className="mt-2 text-xs font-medium text-red-200 underline"
                  >
                    Retry request
                  </button>
                </div>
              </div>
            </div>
          )}

          {!casesQuery.isLoading
            && !casesQuery.isError
            && filteredCases.length === 0 && (
              <div className="py-12 text-center">
                <FolderSearch2 className="mx-auto h-8 w-8 text-slate-700" />

                <p className="mt-3 text-sm text-slate-500">
                  No matching cases found.
                </p>
              </div>
            )}

          <div className="mt-4 max-h-[62vh] space-y-2 overflow-y-auto pr-1">
            {filteredCases.map(
              (investigationCase) => {
                const selected =
                  investigationCase.id
                  === selectedCaseId

                return (
                  <button
                    key={
                      investigationCase.id
                    }
                    type="button"
                    onClick={() =>
                      selectCase(
                        investigationCase.id,
                      )
                    }
                    className={`w-full rounded-xl border p-4 text-left transition ${
                      selected
                        ? (
                            'border-cyan-500/50 '
                            + 'bg-cyan-500/10'
                          )
                        : (
                            'border-slate-700 '
                            + 'bg-slate-950/40 '
                            + 'hover:border-slate-600 '
                            + 'hover:bg-slate-950/70'
                          )
                    }`}
                  >
                    <div className="line-clamp-2 text-sm font-semibold text-slate-100">
                      {investigationCase.title}
                    </div>

                    <div className="mt-3 flex flex-wrap gap-2">
                      <span
                        className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                          severityClasses[
                            investigationCase
                              .severity
                          ]
                        }`}
                      >
                        {formatLabel(
                          investigationCase
                            .severity,
                        )}
                      </span>

                      <span
                        className={`rounded-full border px-2 py-0.5 text-[11px] font-medium ${
                          statusClasses[
                            investigationCase
                              .status
                          ]
                        }`}
                      >
                        {formatLabel(
                          investigationCase
                            .status,
                        )}
                      </span>
                    </div>

                    <div className="mt-3 text-xs text-slate-600">
                      Updated{' '}
                      {formatDateTime(
                        investigationCase
                          .updated_at,
                      )}
                    </div>
                  </button>
                )
              },
            )}
          </div>
        </aside>

        <main className="min-w-0">
          {!selectedCase
            && !casesQuery.isLoading && (
              <div className="rounded-2xl border border-dashed border-slate-700 bg-slate-900/40 px-6 py-20 text-center">
                <FolderSearch2 className="mx-auto h-12 w-12 text-slate-700" />

                <h2 className="mt-4 text-lg font-semibold text-slate-200">
                  Select an investigation case
                </h2>

                <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-slate-500">
                  Choose a case from the case list
                  to open its investigation workflow.
                </p>
              </div>
            )}

          {selectedCase && (
            <div className="space-y-6">
              <section className="rounded-2xl border border-slate-700 bg-slate-900/70 p-5">
                <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="min-w-0">
                    <div className="text-xs font-semibold uppercase tracking-widest text-cyan-400">
                      Active investigation
                    </div>

                    <h2 className="mt-2 break-words text-2xl font-bold text-slate-100">
                      {selectedCase.title}
                    </h2>

                    <p className="mt-2 line-clamp-2 max-w-3xl text-sm leading-6 text-slate-500">
                      {selectedCase.description
                        || 'No case description has been recorded.'}
                    </p>
                  </div>

                  <div className="flex shrink-0 flex-wrap gap-2">
                    <span
                      className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                        severityClasses[
                          selectedCase.severity
                        ]
                      }`}
                    >
                      {formatLabel(
                        selectedCase.severity,
                      )}
                    </span>

                    <span
                      className={`rounded-full border px-3 py-1 text-xs font-semibold ${
                        statusClasses[
                          selectedCase.status
                        ]
                      }`}
                    >
                      {formatLabel(
                        selectedCase.status,
                      )}
                    </span>
                  </div>
                </div>
              </section>

              <nav className="overflow-x-auto rounded-2xl border border-slate-700 bg-slate-900/70 p-2">
                <div className="flex min-w-max gap-2">
                  {workspaceTabs.map(
                    ({
                      id,
                      label,
                      description,
                      icon: Icon,
                    }) => {
                      const selected =
                        activeTab === id

                      return (
                        <button
                          key={id}
                          type="button"
                          title={description}
                          onClick={() =>
                            setActiveTab(id)
                          }
                          className={`inline-flex items-center gap-2 rounded-xl px-4 py-3 text-sm font-medium transition ${
                            selected
                              ? (
                                  'bg-cyan-500 '
                                  + 'text-slate-950'
                                )
                              : (
                                  'text-slate-400 '
                                  + 'hover:bg-slate-800 '
                                  + 'hover:text-slate-100'
                                )
                          }`}
                        >
                          <Icon className="h-4 w-4" />

                          {label}
                        </button>
                      )
                    },
                  )}
                </div>
              </nav>

              <div key={`${selectedCase.id}-${activeTab}`}>
                {renderWorkspaceContent()}
              </div>
            </div>
          )}
        </main>
      </div>
    </section>
  )
}