import {
  ExternalLink,
  FolderSearch2,
} from 'lucide-react'
import {
  Link,
} from 'react-router-dom'

type OpenInvestigationWorkspaceButtonProps = {
  caseId: string
  compact?: boolean
  className?: string
}

export function OpenInvestigationWorkspaceButton({
  caseId,
  compact = false,
  className = '',
}: OpenInvestigationWorkspaceButtonProps) {
  const label = compact
    ? 'Workspace'
    : 'Open Investigation Workspace'

  return (
    <Link
      to={`/investigation?case=${encodeURIComponent(caseId)}`}
      className={`inline-flex items-center justify-center gap-2 rounded-lg border border-cyan-500/30 bg-cyan-500/10 font-medium text-cyan-300 transition hover:border-cyan-400/60 hover:bg-cyan-500/20 hover:text-cyan-200 ${
        compact
          ? 'px-3 py-2 text-xs'
          : 'px-4 py-2.5 text-sm'
      } ${className}`}
    >
      <FolderSearch2
        className={
          compact
            ? 'h-4 w-4'
            : 'h-5 w-5'
        }
      />

      {label}

      {!compact && (
        <ExternalLink className="h-4 w-4" />
      )}
    </Link>
  )
}