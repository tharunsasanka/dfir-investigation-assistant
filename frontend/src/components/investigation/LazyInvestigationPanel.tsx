import {
  lazy,
  Suspense,
  type ReactNode,
} from 'react'
import {
  Loader2,
} from 'lucide-react'

const CaseEvidencePanel = lazy(
  async () => {
    const module = await import(
      '../cases/CaseEvidencePanel'
    )

    return {
      default:
        module.CaseEvidencePanel,
    }
  },
)

const CaseSecurityFindings = lazy(
  async () => {
    const module = await import(
      '../cases/CaseSecurityFindings'
    )

    return {
      default:
        module.CaseSecurityFindings,
    }
  },
)

const CaseEventCorrelations = lazy(
  async () => {
    const module = await import(
      '../cases/CaseEventCorrelations'
    )

    return {
      default:
        module.CaseEventCorrelations,
    }
  },
)

const CaseForensicTimeline = lazy(
  async () => {
    const module = await import(
      '../cases/CaseForensicTimeline'
    )

    return {
      default:
        module.CaseForensicTimeline,
    }
  },
)

const CaseInvestigationSummaries = lazy(
  async () => {
    const module = await import(
      '../cases/CaseInvestigationSummaries'
    )

    return {
      default:
        module.CaseInvestigationSummaries,
    }
  },
)

const CaseLogEventExplorer = lazy(
  async () => {
    const module = await import(
      '../cases/CaseLogEventExplorer'
    )

    return {
      default:
        module.CaseLogEventExplorer,
    }
  },
)

const CaseAuditTimeline = lazy(
  async () => {
    const module = await import(
      '../cases/CaseAuditTimeline'
    )

    return {
      default:
        module.CaseAuditTimeline,
    }
  },
)

export type InvestigationPanelId =
  | 'evidence'
  | 'findings'
  | 'correlations'
  | 'timeline'
  | 'summaries'
  | 'logs'
  | 'audit'

type LazyInvestigationPanelProps = {
  panel: InvestigationPanelId
  caseId: string
}

const panelLabels: Record<
  InvestigationPanelId,
  string
> = {
  evidence: 'evidence records',
  findings: 'security findings',
  correlations: 'event correlations',
  timeline: 'forensic timeline',
  summaries: 'investigation summaries',
  logs: 'parsed log events',
  audit: 'case audit history',
}

function PanelLoader({
  panel,
}: {
  panel: InvestigationPanelId
}) {
  return (
    <div
      role="status"
      aria-live="polite"
      className="flex min-h-64 items-center justify-center rounded-2xl border border-slate-700 bg-slate-900/70 px-6 py-16"
    >
      <div className="text-center">
        <Loader2 className="mx-auto h-8 w-8 animate-spin text-cyan-400" />

        <p className="mt-4 text-sm font-medium text-slate-300">
          Loading {panelLabels[panel]}
        </p>

        <p className="mt-2 text-xs text-slate-500">
          Retrieving the requested investigation data...
        </p>
      </div>
    </div>
  )
}

function renderPanel(
  panel: InvestigationPanelId,
  caseId: string,
): ReactNode {
  switch (panel) {
    case 'evidence':
      return (
        <CaseEvidencePanel
          caseId={caseId}
        />
      )

    case 'findings':
      return (
        <CaseSecurityFindings
          caseId={caseId}
        />
      )

    case 'correlations':
      return (
        <CaseEventCorrelations
          caseId={caseId}
        />
      )

    case 'timeline':
      return (
        <CaseForensicTimeline
          caseId={caseId}
        />
      )

    case 'summaries':
      return (
        <CaseInvestigationSummaries
          caseId={caseId}
        />
      )

    case 'logs':
      return (
        <CaseLogEventExplorer
          caseId={caseId}
        />
      )

    case 'audit':
      return (
        <CaseAuditTimeline
          caseId={caseId}
        />
      )
  }
}

export function LazyInvestigationPanel({
  panel,
  caseId,
}: LazyInvestigationPanelProps) {
  return (
    <Suspense
      fallback={
        <PanelLoader
          panel={panel}
        />
      }
    >
      {renderPanel(
        panel,
        caseId,
      )}
    </Suspense>
  )
}