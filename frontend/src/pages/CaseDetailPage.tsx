import { useQuery } from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  AlertTriangle,
  Archive,
  ArrowLeft,
  CalendarClock,
  FileSearch,
  LoaderCircle,
  Pencil,
  ShieldAlert,
} from 'lucide-react'
import { useState } from 'react'
import {
  Link,
  useParams,
} from 'react-router-dom'

import { getCase } from '../api/cases'
import { Can } from '../auth/Can'
import {
  CaseAuditTimeline,
} from '../components/cases/CaseAuditTimeline'
import {
  CaseEvidencePanel,
} from '../components/cases/CaseEvidencePanel'
import {
  CaseLogEventExplorer,
} from '../components/cases/CaseLogEventExplorer'
import {
  DeleteCaseDialog,
} from '../components/cases/DeleteCaseDialog'
import {
  EditCaseForm,
} from '../components/cases/EditCaseForm'
import {
  LogIngestionHistory,
} from '../components/cases/LogIngestionHistory'
import type {
  CaseSeverity,
  CaseStatus,
} from '../types/case'

function formatDate(
  dateValue: string,
): string {
  return new Intl.DateTimeFormat(
    'en-GB',
    {
      dateStyle: 'full',
      timeStyle: 'short',
    },
  ).format(new Date(dateValue))
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

function getSeverityClasses(
  severity: CaseSeverity,
): string {
  const classes: Record<
    CaseSeverity,
    string
  > = {
    low: [
      'border-emerald-400/30',
      'bg-emerald-400/10',
      'text-emerald-300',
    ].join(' '),

    medium: [
      'border-sky-400/30',
      'bg-sky-400/10',
      'text-sky-300',
    ].join(' '),

    high: [
      'border-amber-400/30',
      'bg-amber-400/10',
      'text-amber-300',
    ].join(' '),

    critical: [
      'border-red-400/30',
      'bg-red-400/10',
      'text-red-300',
    ].join(' '),
  }

  return classes[severity]
}

function getStatusClasses(
  status: CaseStatus,
): string {
  const classes: Record<
    CaseStatus,
    string
  > = {
    open: 'text-cyan',
    investigating: 'text-amber-300',
    review: 'text-violet-300',
    closed: 'text-emerald-300',
  }

  return classes[status]
}

export function CaseDetailPage() {
  const { caseId } = useParams<{
    caseId: string
  }>()

  const [
    isEditFormOpen,
    setIsEditFormOpen,
  ] = useState(false)

  const [
    isArchiveDialogOpen,
    setIsArchiveDialogOpen,
  ] = useState(false)

  const caseQuery = useQuery({
    queryKey: [
      'cases',
      'detail',
      caseId,
    ],

    queryFn: () => {
      if (!caseId) {
        throw new Error(
          'A valid case ID is required.',
        )
      }

      return getCase(caseId)
    },

    enabled: Boolean(caseId),
    retry: false,
  })

  if (caseQuery.isLoading) {
    return (
      <section>
        <div className="glass flex items-center justify-center gap-3 rounded-2xl p-10 text-slate-300">
          <LoaderCircle
            size={22}
            className="animate-spin text-cyan"
          />

          Loading investigation case...
        </div>
      </section>
    )
  }

  if (caseQuery.isError) {
    let errorMessage =
      'The investigation case could not be loaded.'

    if (
      isAxiosError(caseQuery.error) &&
      caseQuery.error.response
        ?.status === 404
    ) {
      errorMessage =
        'The requested investigation case does not exist or has been archived.'
    }

    return (
      <section>
        <Link
          to="/cases"
          className="inline-flex items-center gap-2 text-sm text-slate-400 transition hover:text-cyan"
        >
          <ArrowLeft size={17} />
          Return to cases
        </Link>

        <div className="glass mt-6 flex items-start gap-3 rounded-2xl border border-red-400/30 p-6 text-red-200">
          <ShieldAlert
            size={24}
            className="mt-0.5 shrink-0"
          />

          <div>
            <h1 className="font-semibold">
              Case unavailable
            </h1>

            <p className="mt-2 text-sm text-red-200/80">
              {errorMessage}
            </p>
          </div>
        </div>
      </section>
    )
  }

  const investigationCase =
    caseQuery.data

  if (!investigationCase) {
    return null
  }

  return (
    <section>
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Link
          to="/cases"
          className="inline-flex items-center gap-2 text-sm text-slate-400 transition hover:text-cyan"
        >
          <ArrowLeft size={17} />
          Return to cases
        </Link>

        <div className="flex flex-wrap gap-3">
          <Can permission="cases.update">
            <button
              type="button"
              onClick={() => {
                setIsEditFormOpen(true)
              }}
              className="flex items-center gap-2 rounded-xl bg-cyan px-4 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110"
            >
              <Pencil size={17} />
              Edit case
            </button>
          </Can>

          <Can permission="cases.delete">
            <button
              type="button"
              onClick={() => {
                setIsArchiveDialogOpen(
                  true,
                )
              }}
              className="flex items-center gap-2 rounded-xl border border-red-400/30 bg-red-400/10 px-4 py-2 text-sm font-semibold text-red-200 transition hover:bg-red-400/20"
            >
              <Archive size={17} />
              Archive case
            </button>
          </Can>
        </div>
      </div>

      <div className="mt-6 flex flex-wrap items-start justify-between gap-5">
        <div>
          <p className="text-sm text-cyan">
            Investigation Case
          </p>

          <h1 className="mt-2 max-w-4xl text-3xl font-bold">
            {investigationCase.title}
          </h1>

          <p className="mt-3 break-all text-xs text-slate-500">
            Case ID:{' '}
            {investigationCase.id}
          </p>
        </div>

        <div className="flex flex-wrap gap-3">
          <span
            className={[
              'rounded-full border px-4 py-2 text-sm font-medium',
              getSeverityClasses(
                investigationCase.severity,
              ),
            ].join(' ')}
          >
            {formatLabel(
              investigationCase.severity,
            )}{' '}
            severity
          </span>

          <span
            className={[
              'glass rounded-full px-4 py-2 text-sm font-medium',
              getStatusClasses(
                investigationCase.status,
              ),
            ].join(' ')}
          >
            {formatLabel(
              investigationCase.status,
            )}
          </span>
        </div>
      </div>

      <div className="mt-8 grid gap-6 xl:grid-cols-[1.5fr_1fr]">
        <article className="glass rounded-2xl p-6">
          <div className="flex items-center gap-3">
            <FileSearch className="text-cyan" />

            <h2 className="font-semibold">
              Case description
            </h2>
          </div>

          <p className="mt-5 whitespace-pre-wrap text-sm leading-7 text-slate-300">
            {investigationCase.description ||
              'No investigation description has been provided.'}
          </p>
        </article>

        <div className="grid gap-5">
          <article className="glass rounded-2xl p-6">
            <div className="flex items-center gap-3">
              <AlertTriangle className="text-cyan" />

              <h2 className="font-semibold">
                Classification
              </h2>
            </div>

            <dl className="mt-5 space-y-4 text-sm">
              <div className="flex items-center justify-between gap-4">
                <dt className="text-slate-400">
                  Severity
                </dt>

                <dd className="font-semibold">
                  {formatLabel(
                    investigationCase
                      .severity,
                  )}
                </dd>
              </div>

              <div className="flex items-center justify-between gap-4">
                <dt className="text-slate-400">
                  Status
                </dt>

                <dd
                  className={[
                    'font-semibold',
                    getStatusClasses(
                      investigationCase
                        .status,
                    ),
                  ].join(' ')}
                >
                  {formatLabel(
                    investigationCase
                      .status,
                  )}
                </dd>
              </div>
            </dl>
          </article>

          <article className="glass rounded-2xl p-6">
            <div className="flex items-center gap-3">
              <CalendarClock className="text-cyan" />

              <h2 className="font-semibold">
                Record timestamps
              </h2>
            </div>

            <dl className="mt-5 space-y-5 text-sm">
              <div>
                <dt className="text-slate-400">
                  Created
                </dt>

                <dd className="mt-1 font-medium">
                  {formatDate(
                    investigationCase
                      .created_at,
                  )}
                </dd>
              </div>

              <div>
                <dt className="text-slate-400">
                  Last updated
                </dt>

                <dd className="mt-1 font-medium">
                  {formatDate(
                    investigationCase
                      .updated_at,
                  )}
                </dd>
              </div>
            </dl>
          </article>
        </div>
      </div>

      <div className="mt-8">
        <CaseEvidencePanel
          caseId={investigationCase.id}
        />
      </div>

      <div className="mt-8">
        <CaseLogEventExplorer
          caseId={investigationCase.id}
        />
      </div>

      <div className="mt-8">
        <LogIngestionHistory
          caseId={investigationCase.id}
        />
      </div>

      <Can permission="audit.read">
        <div className="mt-8">
          <CaseAuditTimeline
            caseId={investigationCase.id}
          />
        </div>
      </Can>

      {isEditFormOpen && (
        <EditCaseForm
          investigationCase={
            investigationCase
          }
          onClose={() => {
            setIsEditFormOpen(false)
          }}
        />
      )}

      {isArchiveDialogOpen && (
        <DeleteCaseDialog
          investigationCase={
            investigationCase
          }
          onClose={() => {
            setIsArchiveDialogOpen(
              false,
            )
          }}
        />
      )}
    </section>
  )
}