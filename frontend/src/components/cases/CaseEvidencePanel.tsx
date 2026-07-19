import { useQuery } from '@tanstack/react-query'
import {
  FileArchive,
  FileSearch,
  FileUp,
  LoaderCircle,
  Search,
  ShieldAlert,
} from 'lucide-react'
import {
  useState,
  type FormEvent,
} from 'react'

import {
  getCaseEvidence,
} from '../../api/evidence'
import { Can } from '../../auth/Can'
import type {
  EvidenceType,
} from '../../types/evidence'
import { EvidenceCard } from './EvidenceCard'
import {
  EvidenceUploadForm,
} from './EvidenceUploadForm'

type CaseEvidencePanelProps = {
  caseId: string
}

const PAGE_SIZE = 10

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

export function CaseEvidencePanel({
  caseId,
}: CaseEvidencePanelProps) {
  const [
    isUploadFormOpen,
    setIsUploadFormOpen,
  ] = useState(false)

  const [page, setPage] =
    useState(1)

  const [
    searchInput,
    setSearchInput,
  ] = useState('')

  const [search, setSearch] =
    useState('')

  const [
    evidenceType,
    setEvidenceType,
  ] =
    useState<EvidenceType | ''>('')

  const evidenceQuery = useQuery({
    queryKey: [
      'evidence',
      'case',
      caseId,
      page,
      search,
      evidenceType,
    ],

    queryFn: () =>
      getCaseEvidence(caseId, {
        page,
        page_size: PAGE_SIZE,
        search:
          search || undefined,
        evidence_type:
          evidenceType || undefined,
      }),

    retry: false,
  })

  function handleSearch(
    event: FormEvent<HTMLFormElement>,
  ): void {
    event.preventDefault()

    setPage(1)
    setSearch(
      searchInput.trim(),
    )
  }

  const data = evidenceQuery.data
  const evidenceItems =
    data?.items ?? []

  return (
    <>
      <article className="glass mt-6 rounded-2xl p-6">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <FileSearch className="mt-0.5 text-cyan" />

            <div>
              <h2 className="font-semibold">
                Digital evidence
              </h2>

              <p className="mt-1 text-sm text-slate-400">
                Secure evidence storage,
                integrity verification, and
                chain-of-custody tracking.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <span className="rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm text-slate-400">
              Evidence:{' '}
              <strong className="text-white">
                {data?.total ?? 0}
              </strong>
            </span>

            <Can permission="cases.update">
              <button
                type="button"
                onClick={() => {
                  setIsUploadFormOpen(true)
                }}
                className="flex items-center gap-2 rounded-xl bg-cyan px-4 py-2 text-sm font-semibold text-slate-950 transition hover:brightness-110"
              >
                <FileUp size={17} />
                Upload evidence
              </button>
            </Can>
          </div>
        </div>

        <form
          onSubmit={handleSearch}
          className="mt-6 grid gap-3 md:grid-cols-[1fr_220px_auto]"
        >
          <div className="relative">
            <Search
              size={17}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-slate-500"
            />

            <input
              type="search"
              value={searchInput}
              onChange={(event) => {
                setSearchInput(
                  event.target.value,
                )
              }}
              placeholder="Search filename, source, hash..."
              className="w-full rounded-xl border border-white/10 bg-white/5 py-3 pl-10 pr-4 outline-none transition focus:border-cyan/60"
            />
          </div>

          <select
            value={evidenceType}
            onChange={(event) => {
              setPage(1)

              setEvidenceType(
                event.target
                  .value as EvidenceType | '',
              )
            }}
            className="rounded-xl border border-white/10 bg-slate-900 px-4 py-3 outline-none transition focus:border-cyan/60"
          >
            <option value="">
              All evidence types
            </option>

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

          <button
            type="submit"
            className="rounded-xl border border-cyan/30 bg-cyan/10 px-5 py-3 text-sm font-semibold text-cyan transition hover:bg-cyan/20"
          >
            Search
          </button>
        </form>

        {evidenceQuery.isLoading && (
          <div className="mt-6 flex items-center justify-center gap-3 rounded-xl border border-white/10 p-8 text-slate-300">
            <LoaderCircle
              size={20}
              className="animate-spin text-cyan"
            />

            Loading evidence...
          </div>
        )}

        {evidenceQuery.isError && (
          <div
            role="alert"
            className="mt-6 flex items-start gap-3 rounded-xl border border-red-400/30 bg-red-400/10 p-4 text-red-200"
          >
            <ShieldAlert
              size={20}
              className="mt-0.5 shrink-0"
            />

            <p className="text-sm">
              Case evidence could not be loaded.
            </p>
          </div>
        )}

        {!evidenceQuery.isLoading &&
          !evidenceQuery.isError &&
          evidenceItems.length === 0 && (
            <div className="mt-6 rounded-xl border border-white/10 bg-white/5 p-8 text-center">
              <FileArchive
                size={32}
                className="mx-auto text-slate-500"
              />

              <p className="mt-3 font-medium">
                No evidence found
              </p>

              <p className="mt-2 text-sm text-slate-400">
                Upload digital evidence or
                change the current filters.
              </p>
            </div>
          )}

        {evidenceItems.length > 0 && (
          <div className="mt-6 grid gap-4">
            {evidenceItems.map(
              (evidence) => (
                <EvidenceCard
                  key={evidence.id}
                  evidence={evidence}
                />
              ),
            )}
          </div>
        )}

        {data && data.pages > 1 && (
          <div className="mt-6 flex flex-wrap items-center justify-between gap-4 border-t border-white/10 pt-5">
            <p className="text-sm text-slate-400">
              Page {data.page} of{' '}
              {data.pages}
            </p>

            <div className="flex gap-3">
              <button
                type="button"
                disabled={page <= 1}
                onClick={() => {
                  setPage((current) =>
                    Math.max(
                      1,
                      current - 1,
                    ),
                  )
                }}
                className="rounded-xl border border-white/10 px-4 py-2 text-sm transition hover:border-white/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Previous
              </button>

              <button
                type="button"
                disabled={
                  page >= data.pages
                }
                onClick={() => {
                  setPage(
                    (current) =>
                      current + 1,
                  )
                }}
                className="rounded-xl border border-white/10 px-4 py-2 text-sm transition hover:border-white/20 disabled:cursor-not-allowed disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </article>

      {isUploadFormOpen && (
        <EvidenceUploadForm
          caseId={caseId}
          onClose={() => {
            setIsUploadFormOpen(false)
          }}
        />
      )}
    </>
  )
}