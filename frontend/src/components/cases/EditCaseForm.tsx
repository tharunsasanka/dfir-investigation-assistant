import {
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  LoaderCircle,
  ShieldAlert,
  X,
} from 'lucide-react'
import {
  useState,
  type FormEvent,
} from 'react'

import { updateCase } from '../../api/cases'
import type {
  CaseSeverity,
  CaseStatus,
  CaseUpdateRequest,
  InvestigationCase,
} from '../../types/case'

type EditCaseFormProps = {
  investigationCase: InvestigationCase
  onClose: () => void
}

const severityOptions: Array<{
  value: CaseSeverity
  label: string
}> = [
  {
    value: 'low',
    label: 'Low',
  },
  {
    value: 'medium',
    label: 'Medium',
  },
  {
    value: 'high',
    label: 'High',
  },
  {
    value: 'critical',
    label: 'Critical',
  },
]

const statusOptions: Array<{
  value: CaseStatus
  label: string
}> = [
  {
    value: 'open',
    label: 'Open',
  },
  {
    value: 'investigating',
    label: 'Investigating',
  },
  {
    value: 'review',
    label: 'Review',
  },
  {
    value: 'closed',
    label: 'Closed',
  },
]

export function EditCaseForm({
  investigationCase,
  onClose,
}: EditCaseFormProps) {
  const queryClient = useQueryClient()

  const [title, setTitle] = useState(
    investigationCase.title,
  )

  const [description, setDescription] =
    useState(
      investigationCase.description,
    )

  const [severity, setSeverity] =
    useState<CaseSeverity>(
      investigationCase.severity,
    )

  const [caseStatus, setCaseStatus] =
    useState<CaseStatus>(
      investigationCase.status,
    )

  const [errorMessage, setErrorMessage] =
    useState('')

  const updateCaseMutation = useMutation({
    mutationFn: (
      request: CaseUpdateRequest,
    ) =>
      updateCase(
        investigationCase.id,
        request,
      ),

    onSuccess: async (updatedCase) => {
      queryClient.setQueryData(
        [
          'cases',
          'detail',
          investigationCase.id,
        ],
        updatedCase,
      )

      await Promise.all([
        queryClient.invalidateQueries({
          queryKey: ['cases'],
        }),

        queryClient.invalidateQueries({
          queryKey: [
            'dashboard',
            'case-summary',
          ],
        }),

        queryClient.invalidateQueries({
          queryKey: [
            'cases',
            'audit',
            investigationCase.id,
          ],
        }),
      ])

      onClose()
    },
  })

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()
    setErrorMessage('')

    const normalizedTitle = title.trim()
    const normalizedDescription =
      description.trim()

    if (normalizedTitle.length < 3) {
      setErrorMessage(
        'The case title must contain at least 3 characters.',
      )

      return
    }

    const updateRequest: CaseUpdateRequest = {}

    if (
      normalizedTitle !==
      investigationCase.title
    ) {
      updateRequest.title =
        normalizedTitle
    }

    if (
      normalizedDescription !==
      investigationCase.description
    ) {
      updateRequest.description =
        normalizedDescription
    }

    if (
      severity !==
      investigationCase.severity
    ) {
      updateRequest.severity = severity
    }

    if (
      caseStatus !==
      investigationCase.status
    ) {
      updateRequest.status = caseStatus
    }

    if (
      Object.keys(updateRequest).length === 0
    ) {
      setErrorMessage(
        'No case changes have been made.',
      )

      return
    }

    try {
      await updateCaseMutation.mutateAsync(
        updateRequest,
      )
    } catch (error) {
      if (isAxiosError(error)) {
        const detail =
          error.response?.data?.detail

        if (typeof detail === 'string') {
          setErrorMessage(detail)
          return
        }

        if (Array.isArray(detail)) {
          setErrorMessage(
            'One or more case fields are invalid.',
          )

          return
        }
      }

      setErrorMessage(
        'The investigation case could not be updated.',
      )
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/80 p-4 backdrop-blur-sm">
      <div className="glass max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-3xl p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm text-cyan">
              Investigation Management
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Edit investigation case
            </h2>

            <p className="mt-2 text-sm text-slate-400">
              Changes will update the PostgreSQL
              case record and create a permanent
              audit event.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={
              updateCaseMutation.isPending
            }
            aria-label="Close edit case form"
            className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:border-cyan/30 hover:text-cyan disabled:opacity-50"
          >
            <X size={20} />
          </button>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className="mt-6 flex items-start gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-red-200"
          >
            <ShieldAlert
              size={20}
              className="mt-0.5 shrink-0"
            />

            <p className="text-sm">
              {errorMessage}
            </p>
          </div>
        )}

        <form
          onSubmit={handleSubmit}
          className="mt-6 space-y-5"
        >
          <label className="block">
            <span className="text-sm text-slate-300">
              Case title
            </span>

            <input
              type="text"
              value={title}
              onChange={(event) => {
                setTitle(event.target.value)
              }}
              minLength={3}
              maxLength={160}
              required
              disabled={
                updateCaseMutation.isPending
              }
              className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60 disabled:opacity-60"
            />

            <p className="mt-2 text-xs text-slate-500">
              {title.length}/160 characters
            </p>
          </label>

          <label className="block">
            <span className="text-sm text-slate-300">
              Description
            </span>

            <textarea
              value={description}
              onChange={(event) => {
                setDescription(
                  event.target.value,
                )
              }}
              maxLength={5000}
              rows={7}
              disabled={
                updateCaseMutation.isPending
              }
              className="mt-2 w-full resize-y rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60 disabled:opacity-60"
            />

            <p className="mt-2 text-xs text-slate-500">
              {description.length}/5000 characters
            </p>
          </label>

          <div className="grid gap-5 sm:grid-cols-2">
            <label className="block">
              <span className="text-sm text-slate-300">
                Severity
              </span>

              <select
                value={severity}
                onChange={(event) => {
                  setSeverity(
                    event.target
                      .value as CaseSeverity,
                  )
                }}
                disabled={
                  updateCaseMutation.isPending
                }
                className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60 disabled:opacity-60"
              >
                {severityOptions.map(
                  (option) => (
                    <option
                      key={option.value}
                      value={option.value}
                    >
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </label>

            <label className="block">
              <span className="text-sm text-slate-300">
                Investigation status
              </span>

              <select
                value={caseStatus}
                onChange={(event) => {
                  setCaseStatus(
                    event.target
                      .value as CaseStatus,
                  )
                }}
                disabled={
                  updateCaseMutation.isPending
                }
                className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60 disabled:opacity-60"
              >
                {statusOptions.map(
                  (option) => (
                    <option
                      key={option.value}
                      value={option.value}
                    >
                      {option.label}
                    </option>
                  ),
                )}
              </select>
            </label>
          </div>

          <div className="flex flex-col-reverse gap-3 border-t border-white/10 pt-5 sm:flex-row sm:justify-end">
            <button
              type="button"
              onClick={onClose}
              disabled={
                updateCaseMutation.isPending
              }
              className="rounded-xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:border-white/20 hover:text-white disabled:opacity-50"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={
                updateCaseMutation.isPending
              }
              className="flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {updateCaseMutation.isPending ? (
                <>
                  <LoaderCircle
                    size={18}
                    className="animate-spin"
                  />
                  Saving changes...
                </>
              ) : (
                'Save changes'
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}