import {
  useMutation,
  useQueryClient,
} from '@tanstack/react-query'
import { isAxiosError } from 'axios'
import {
  FileUp,
  LoaderCircle,
  ShieldAlert,
  X,
} from 'lucide-react'
import {
  useState,
  type FormEvent,
} from 'react'

import { uploadEvidence } from '../../api/evidence'
import type {
  EvidenceType,
  EvidenceUploadRequest,
} from '../../types/evidence'

type EvidenceUploadFormProps = {
  caseId: string
  onClose: () => void
}

const MAX_FILE_SIZE_BYTES =
  100 * 1024 * 1024

const evidenceTypeOptions: Array<{
  value: EvidenceType
  label: string
}> = [
  {
    value: 'log',
    label: 'Log file',
  },
  {
    value: 'disk_image',
    label: 'Disk image',
  },
  {
    value: 'memory_dump',
    label: 'Memory dump',
  },
  {
    value: 'network_capture',
    label: 'Network capture',
  },
  {
    value: 'document',
    label: 'Document',
  },
  {
    value: 'image',
    label: 'Image',
  },
  {
    value: 'archive',
    label: 'Archive',
  },
  {
    value: 'other',
    label: 'Other',
  },
]

export function EvidenceUploadForm({
  caseId,
  onClose,
}: EvidenceUploadFormProps) {
  const queryClient = useQueryClient()

  const [file, setFile] =
    useState<File | null>(null)

  const [
    evidenceType,
    setEvidenceType,
  ] = useState<EvidenceType>('log')

  const [description, setDescription] =
    useState('')

  const [source, setSource] =
    useState('')

  const [collectedAt, setCollectedAt] =
    useState('')

  const [
    errorMessage,
    setErrorMessage,
  ] = useState('')

  const uploadMutation = useMutation({
    mutationFn: (
      request: EvidenceUploadRequest,
    ) =>
      uploadEvidence(
        caseId,
        request,
      ),

    onSuccess: async () => {
      await queryClient.invalidateQueries({
        queryKey: [
          'evidence',
          'case',
          caseId,
        ],
      })

      onClose()
    },
  })

  async function handleSubmit(
    event: FormEvent<HTMLFormElement>,
  ): Promise<void> {
    event.preventDefault()
    setErrorMessage('')

    if (!file) {
      setErrorMessage(
        'Select an evidence file.',
      )

      return
    }

    if (file.size === 0) {
      setErrorMessage(
        'Empty evidence files are not accepted.',
      )

      return
    }

    if (file.size > MAX_FILE_SIZE_BYTES) {
      setErrorMessage(
        'The evidence file exceeds the 100 MB upload limit.',
      )

      return
    }

    let collectedAtValue:
      | string
      | undefined

    if (collectedAt) {
      const collectedDate =
        new Date(collectedAt)

      if (
        Number.isNaN(
          collectedDate.getTime(),
        )
      ) {
        setErrorMessage(
          'Enter a valid collection date and time.',
        )

        return
      }

      collectedAtValue =
        collectedDate.toISOString()
    }

    try {
      await uploadMutation.mutateAsync({
        file,
        evidence_type: evidenceType,
        description:
          description.trim(),
        source: source.trim(),
        collected_at:
          collectedAtValue,
      })
    } catch (error) {
      if (isAxiosError(error)) {
        const detail =
          error.response?.data?.detail

        if (typeof detail === 'string') {
          setErrorMessage(detail)
          return
        }

        if (error.response?.status === 413) {
          setErrorMessage(
            'The evidence file exceeds the server upload limit.',
          )

          return
        }
      }

      setErrorMessage(
        'The evidence file could not be uploaded.',
      )
    }
  }

  return (
    <div className="fixed inset-0 z-50 grid place-items-center bg-slate-950/85 p-4 backdrop-blur-sm">
      <div className="glass max-h-[90vh] w-full max-w-2xl overflow-y-auto rounded-3xl p-6 sm:p-8">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm text-cyan">
              Evidence Management
            </p>

            <h2 className="mt-1 text-2xl font-bold">
              Upload digital evidence
            </h2>

            <p className="mt-2 text-sm text-slate-400">
              The server will calculate and
              preserve the SHA-256 hash while
              storing the file.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={
              uploadMutation.isPending
            }
            aria-label="Close evidence upload form"
            className="rounded-xl border border-white/10 p-2 text-slate-400 transition hover:text-white disabled:opacity-50"
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
              Evidence file
            </span>

            <input
              type="file"
              required
              disabled={
                uploadMutation.isPending
              }
              onChange={(event) => {
                setFile(
                  event.target.files?.[0]
                    ?? null,
                )
              }}
              className="mt-2 block w-full rounded-xl border border-dashed border-white/20 bg-white/5 px-4 py-5 text-sm text-slate-300 file:mr-4 file:rounded-lg file:border-0 file:bg-cyan file:px-4 file:py-2 file:font-semibold file:text-slate-950"
            />

            <p className="mt-2 text-xs text-slate-500">
              Maximum file size: 100 MB
            </p>
          </label>

          <label className="block">
            <span className="text-sm text-slate-300">
              Evidence type
            </span>

            <select
              value={evidenceType}
              onChange={(event) => {
                setEvidenceType(
                  event.target
                    .value as EvidenceType,
                )
              }}
              disabled={
                uploadMutation.isPending
              }
              className="mt-2 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
            >
              {evidenceTypeOptions.map(
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
              Evidence source
            </span>

            <input
              type="text"
              value={source}
              onChange={(event) => {
                setSource(
                  event.target.value,
                )
              }}
              maxLength={500}
              placeholder="Example: Windows endpoint WORKSTATION-01"
              disabled={
                uploadMutation.isPending
              }
              className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
            />
          </label>

          <label className="block">
            <span className="text-sm text-slate-300">
              Collected date and time
            </span>

            <input
              type="datetime-local"
              value={collectedAt}
              onChange={(event) => {
                setCollectedAt(
                  event.target.value,
                )
              }}
              disabled={
                uploadMutation.isPending
              }
              className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
            />
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
              rows={5}
              placeholder="Describe the evidence and collection context."
              disabled={
                uploadMutation.isPending
              }
              className="mt-2 w-full resize-y rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none transition focus:border-cyan/60"
            />
          </label>

          <div className="flex flex-col-reverse gap-3 border-t border-white/10 pt-5 sm:flex-row sm:justify-end">
            <button
              type="button"
              onClick={onClose}
              disabled={
                uploadMutation.isPending
              }
              className="rounded-xl border border-white/10 px-5 py-3 text-sm font-semibold text-slate-300 transition hover:text-white disabled:opacity-50"
            >
              Cancel
            </button>

            <button
              type="submit"
              disabled={
                uploadMutation.isPending
              }
              className="flex items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {uploadMutation.isPending ? (
                <>
                  <LoaderCircle
                    size={18}
                    className="animate-spin"
                  />
                  Uploading evidence...
                </>
              ) : (
                <>
                  <FileUp size={18} />
                  Upload evidence
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}