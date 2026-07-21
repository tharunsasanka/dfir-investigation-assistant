import {
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  Archive,
  LoaderCircle,
  ShieldAlert,
  X,
} from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'

import { deleteCase } from '../../api/cases'
import type { InvestigationCase } from '../../types/case'

type DeleteCaseDialogProps = {
  investigationCase: InvestigationCase
  onClose: () => void
}

const CONFIRMATION_TEXT = 'ARCHIVE'

export function DeleteCaseDialog({
  investigationCase,
  onClose,
}: DeleteCaseDialogProps) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()

  const [
    confirmation,
    setConfirmation,
  ] = useState('')

  const [
    errorMessage,
    setErrorMessage,
  ] = useState('')

  const deleteMutation = useMutation({
    mutationFn: () =>
      deleteCase(
        investigationCase.id
      ),

    onSuccess: async () => {
      queryClient.removeQueries({
        queryKey: [
          'cases',
          'detail',
          investigationCase.id,
        ],
      })

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
      ])

      navigate('/cases', {
        replace: true,
      })
    },
  })

  async function handleArchive(): Promise<void> {
    setErrorMessage('')

    if (
      confirmation.trim().toUpperCase()
      !== CONFIRMATION_TEXT
    ) {
      setErrorMessage(
        `Type ${CONFIRMATION_TEXT} to confirm this action.`,
      )

      return
    }

    try {
      await deleteMutation.mutateAsync()
    } catch (error) {
      if (isAxiosError(error)) {
        const detail =
          error.response?.data?.detail

        if (typeof detail === 'string') {
          setErrorMessage(detail)
          return
        }
      }

      setErrorMessage(
        'The case could not be archived.',
      )
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/85 p-4 backdrop-blur-sm">
      <div className="glass w-full max-w-lg rounded-3xl p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="rounded-2xl bg-red-400/10 p-3 text-red-300">
              <Archive size={24} />
            </div>

            <div>
              <h2 className="text-xl font-bold">
                Archive investigation case
              </h2>

              <p className="mt-2 text-sm text-slate-400">
                The case will be removed from active
                views but retained in PostgreSQL for
                accountability and future restoration.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={deleteMutation.isPending}
            aria-label="Close archive dialog"
            className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:text-white disabled:opacity-50"
          >
            <X size={19} />
          </button>
        </div>

        <div className="mt-6 rounded-2xl border border-red-400/20 bg-red-400/5 p-4">
          <p className="text-sm text-slate-400">
            Case
          </p>

          <p className="mt-1 font-semibold">
            {investigationCase.title}
          </p>

          <p className="mt-2 break-all text-xs text-slate-500">
            {investigationCase.id}
          </p>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className="mt-5 flex items-start gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-red-200"
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

        <label className="mt-6 block">
          <span className="text-sm text-slate-300">
            Type{' '}
            <strong className="text-white">
              ARCHIVE
            </strong>{' '}
            to confirm
          </span>

          <input
            type="text"
            value={confirmation}
            onChange={(event) => {
              setConfirmation(
                event.target.value
              )
            }}
            autoComplete="off"
            disabled={deleteMutation.isPending}
            className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-red-400/60 disabled:opacity-60"
          />
        </label>

        <div className="mt-6 flex flex-col-reverse gap-3 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={onClose}
            disabled={deleteMutation.isPending}
            className="rounded-xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:text-white disabled:opacity-50"
          >
            Cancel
          </button>

          <button
            type="button"
            onClick={() => {
              void handleArchive()
            }}
            disabled={
              deleteMutation.isPending ||
              confirmation.trim().toUpperCase()
                !== CONFIRMATION_TEXT
            }
            className="flex items-center justify-center gap-2 rounded-xl bg-red-400 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {deleteMutation.isPending ? (
              <>
                <LoaderCircle
                  size={18}
                  className="animate-spin"
                />
                Archiving...
              </>
            ) : (
              <>
                <Archive size={18} />
                Archive case
              </>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}