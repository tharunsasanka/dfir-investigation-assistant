import {
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  CheckCircle2,
  Download,
  FileArchive,
  FileCheck2,
  History,
  LoaderCircle,
  ShieldAlert,
  XCircle,
} from 'lucide-react'
import { useState } from 'react'

import {
  downloadEvidenceContent,
  verifyEvidenceIntegrity,
} from '../../api/evidence'
import { Can } from '../../auth/Can'
import type {
  EvidenceIntegrityResponse,
  EvidenceRecord,
} from '../../types/evidence'
import {
  EvidenceCustodyDialog,
} from './EvidenceCustodyDialog'

type EvidenceCardProps = {
  evidence: EvidenceRecord
}

function formatDate(
  value: string | null,
): string {
  if (!value) {
    return 'Not recorded'
  }

  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'medium',
      timeStyle: 'short',
    },
  ).format(new Date(value))
}

function formatBytes(
  sizeBytes: number,
): string {
  if (sizeBytes < 1024) {
    return `${sizeBytes} B`
  }

  if (sizeBytes < 1024 * 1024) {
    return `${(
      sizeBytes / 1024
    ).toFixed(2)} KB`
  }

  if (
    sizeBytes <
    1024 * 1024 * 1024
  ) {
    return `${(
      sizeBytes /
      (1024 * 1024)
    ).toFixed(2)} MB`
  }

  return `${(
    sizeBytes /
    (1024 * 1024 * 1024)
  ).toFixed(2)} GB`
}

function formatLabel(
  value: string,
): string {
  return value
    .replace(/_/g, ' ')
    .replace(
      /\b\w/g,
      (character) =>
        character.toUpperCase(),
    )
}

function getApiErrorMessage(
  error: unknown,
  fallback: string,
): string {
  if (
    isAxiosError(error) &&
    typeof error.response?.data?.detail
      === 'string'
  ) {
    return error.response.data.detail
  }

  return fallback
}

export function EvidenceCard({
  evidence,
}: EvidenceCardProps) {
  const queryClient = useQueryClient()

  const [
    integrityResult,
    setIntegrityResult,
  ] =
    useState<EvidenceIntegrityResponse | null>(
      null,
    )

  const [
    isCustodyDialogOpen,
    setIsCustodyDialogOpen,
  ] = useState(false)

  const [
    errorMessage,
    setErrorMessage,
  ] = useState('')

  async function refreshCustodyHistory() {
    await queryClient.invalidateQueries({
      queryKey: [
        'evidence',
        'custody',
        evidence.id,
      ],
    })
  }

  const verifyMutation = useMutation({
    mutationFn: () =>
      verifyEvidenceIntegrity(
        evidence.id,
      ),

    onSuccess: async (result) => {
      setIntegrityResult(result)
      setErrorMessage('')

      await refreshCustodyHistory()
    },

    onError: (error) => {
      setErrorMessage(
        getApiErrorMessage(
          error,
          'Evidence integrity could not be verified.',
        ),
      )
    },
  })

  const downloadMutation = useMutation({
    mutationFn: () =>
      downloadEvidenceContent(
        evidence,
      ),

    onSuccess: async () => {
      setErrorMessage('')

      await refreshCustodyHistory()
    },

    onError: (error) => {
      setErrorMessage(
        getApiErrorMessage(
          error,
          'The evidence file could not be downloaded.',
        ),
      )
    },
  })

  return (
    <>
      <article className="rounded-2xl border border-white/10 bg-white/5 p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <div className="rounded-xl bg-cyan/10 p-3 text-cyan">
              <FileArchive size={21} />
            </div>

            <div className="min-w-0">
              <h3 className="break-words font-semibold">
                {evidence.original_filename}
              </h3>

              <p className="mt-1 text-sm text-slate-400">
                {formatLabel(
                  evidence.evidence_type,
                )}
                {' · '}
                {formatBytes(
                  evidence.size_bytes,
                )}
              </p>
            </div>
          </div>

          <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1 text-xs text-slate-400">
            {evidence.content_type}
          </span>
        </div>

        {evidence.description && (
          <p className="mt-4 whitespace-pre-wrap text-sm leading-6 text-slate-300">
            {evidence.description}
          </p>
        )}

        <dl className="mt-5 grid gap-4 text-sm md:grid-cols-2">
          <div>
            <dt className="text-xs uppercase tracking-wider text-slate-500">
              Source
            </dt>

            <dd className="mt-1 break-words text-slate-300">
              {evidence.source ||
                'Not recorded'}
            </dd>
          </div>

          <div>
            <dt className="text-xs uppercase tracking-wider text-slate-500">
              Collected
            </dt>

            <dd className="mt-1 text-slate-300">
              {formatDate(
                evidence.collected_at,
              )}
            </dd>
          </div>

          <div>
            <dt className="text-xs uppercase tracking-wider text-slate-500">
              Uploaded
            </dt>

            <dd className="mt-1 text-slate-300">
              {formatDate(
                evidence.created_at,
              )}
            </dd>
          </div>

          <div>
            <dt className="text-xs uppercase tracking-wider text-slate-500">
              Evidence ID
            </dt>

            <dd className="mt-1 break-all text-xs text-slate-400">
              {evidence.id}
            </dd>
          </div>
        </dl>

        <div className="mt-5 rounded-xl border border-white/10 bg-slate-950/40 p-4">
          <p className="text-xs uppercase tracking-wider text-slate-500">
            SHA-256
          </p>

          <p className="mt-2 break-all font-mono text-xs leading-5 text-cyan">
            {evidence.sha256}
          </p>
        </div>

        {integrityResult && (
          <div
            className={[
              'mt-4 flex items-start gap-3 rounded-xl border p-4',
              integrityResult.matches
                ? 'border-emerald-400/30 bg-emerald-400/10 text-emerald-200'
                : 'border-red-400/30 bg-red-400/10 text-red-200',
            ].join(' ')}
          >
            {integrityResult.matches ? (
              <CheckCircle2
                size={20}
                className="mt-0.5 shrink-0"
              />
            ) : (
              <XCircle
                size={20}
                className="mt-0.5 shrink-0"
              />
            )}

            <div>
              <p className="font-semibold">
                {integrityResult.matches
                  ? 'Integrity verified'
                  : 'Integrity failure detected'}
              </p>

              <p className="mt-1 text-xs opacity-80">
                Checked{' '}
                {formatDate(
                  integrityResult.checked_at,
                )}
              </p>
            </div>
          </div>
        )}

        {errorMessage && (
          <div
            role="alert"
            className="mt-4 flex items-start gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-red-200"
          >
            <ShieldAlert
              size={19}
              className="mt-0.5 shrink-0"
            />

            <p className="text-sm">
              {errorMessage}
            </p>
          </div>
        )}

        <div className="mt-5 flex flex-wrap gap-3 border-t border-white/10 pt-5">
          <Can permission="cases.update">
            <button
              type="button"
              disabled={
                verifyMutation.isPending
              }
              onClick={() => {
                setErrorMessage('')
                verifyMutation.mutate()
              }}
              className="flex items-center gap-2 rounded-xl border border-cyan/30 bg-cyan/10 px-4 py-2 text-sm font-semibold text-cyan transition hover:bg-cyan/20 disabled:opacity-50"
            >
              {verifyMutation.isPending ? (
                <LoaderCircle
                  size={17}
                  className="animate-spin"
                />
              ) : (
                <FileCheck2 size={17} />
              )}

              Verify integrity
            </button>
          </Can>

          <button
            type="button"
            disabled={
              downloadMutation.isPending
            }
            onClick={() => {
              setErrorMessage('')
              downloadMutation.mutate()
            }}
            className="flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-white/20 hover:text-white disabled:opacity-50"
          >
            {downloadMutation.isPending ? (
              <LoaderCircle
                size={17}
                className="animate-spin"
              />
            ) : (
              <Download size={17} />
            )}

            Download
          </button>

          <button
            type="button"
            onClick={() => {
              setIsCustodyDialogOpen(true)
            }}
            className="flex items-center gap-2 rounded-xl border border-violet-400/30 bg-violet-400/10 px-4 py-2 text-sm font-semibold text-violet-200 transition hover:bg-violet-400/20"
          >
            <History size={17} />
            Chain of custody
          </button>
        </div>
      </article>

      {isCustodyDialogOpen && (
        <EvidenceCustodyDialog
          evidence={evidence}
          onClose={() => {
            setIsCustodyDialogOpen(false)
          }}
        />
      )}
    </>
  )
}