import {
  Bot,
  CircleAlert,
  Cpu,
  LoaderCircle,
  ShieldCheck,
  Sparkles,
} from 'lucide-react'

import type {
  InvestigationSummary,
  InvestigationSummarySource,
} from '../../types/investigationSummary'

type InvestigationSummaryGenerationControlsProps = {
  source: InvestigationSummarySource
  pending: boolean
  summary:
    | InvestigationSummary
    | undefined
  onSourceChange: (
    source: InvestigationSummarySource,
  ) => void
  onGenerate: () => void
}

const generationOptions: Array<{
  value: InvestigationSummarySource
  label: string
  description: string
}> = [
  {
    value: 'deterministic',
    label: 'Deterministic analysis',
    description:
      'Generate a reproducible summary using stored findings, timeline events, evidence references, and MITRE mappings.',
  },
  {
    value: 'local_ai',
    label: 'Local AI assisted',
    description:
      'Use the locally configured Ollama provider to improve the executive summary and technical narrative.',
  },
]

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

function getStringParameter(
  summary: InvestigationSummary,
  key: string,
): string {
  const value =
    summary.generation_parameters[
      key
    ]

  return typeof value === 'string'
    ? value
    : ''
}

function getBooleanParameter(
  summary: InvestigationSummary,
  key: string,
): boolean {
  return (
    summary.generation_parameters[
      key
    ] === true
  )
}

export function InvestigationSummaryGenerationControls({
  source,
  pending,
  summary,
  onSourceChange,
  onGenerate,
}: InvestigationSummaryGenerationControlsProps) {
  const selectedOption =
    generationOptions.find(
      (option) =>
        option.value === source,
    )

  const requestedSource = summary
    ? getStringParameter(
        summary,
        'requested_generation_source',
      ) || summary.generation_source
    : ''

  const effectiveSource = summary
    ? getStringParameter(
        summary,
        'effective_generation_source',
      ) || summary.generation_source
    : ''

  const fallbackApplied = summary
    ? getBooleanParameter(
        summary,
        'fallback_applied',
      )
    : false

  const localAiUsed = summary
    ? getBooleanParameter(
        summary,
        'local_ai_used',
      )
    : false

  return (
    <div className="w-full rounded-2xl border border-white/10 bg-white/5 p-4 xl:w-[390px]">
      <label
        htmlFor="summary-generation-source"
        className="text-xs font-semibold uppercase tracking-wider text-slate-500"
      >
        Generation method
      </label>

      <select
        id="summary-generation-source"
        value={source}
        disabled={pending}
        onChange={(event) => {
          onSourceChange(
            event.target
              .value as InvestigationSummarySource,
          )
        }}
        className="mt-3 w-full rounded-xl border border-white/10 bg-slate-900 px-4 py-3 text-sm outline-none transition focus:border-cyan/60 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {generationOptions.map(
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

      <p className="mt-3 text-xs leading-5 text-slate-500">
        {selectedOption?.description}
      </p>

      {source === 'local_ai' && (
        <div className="mt-4 flex items-start gap-3 rounded-xl border border-violet-400/20 bg-violet-400/5 p-3">
          <Bot
            size={18}
            className="mt-0.5 shrink-0 text-violet-300"
          />

          <p className="text-xs leading-5 text-violet-100/75">
            Local AI availability and model
            selection are controlled by the
            backend. A provider failure can
            automatically use the deterministic
            fallback.
          </p>
        </div>
      )}

      <button
        type="button"
        disabled={pending}
        onClick={onGenerate}
        className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl bg-cyan px-5 py-3 text-sm font-semibold text-slate-950 transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-50"
      >
        {pending ? (
          <LoaderCircle
            size={18}
            className="animate-spin"
          />
        ) : source === 'local_ai' ? (
          <Bot size={18} />
        ) : (
          <Sparkles size={18} />
        )}

        {pending
          ? 'Generating summary...'
          : source === 'local_ai'
            ? 'Generate with local AI'
            : 'Generate deterministic summary'}
      </button>

      {summary && (
        <div className="mt-5 border-t border-white/10 pt-4">
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-1">
            <div className="rounded-xl border border-white/10 bg-slate-950/30 p-3">
              <div className="flex items-center gap-2 text-slate-500">
                <Cpu size={15} />

                <p className="text-xs uppercase tracking-wider">
                  Requested
                </p>
              </div>

              <p className="mt-2 text-sm font-semibold text-slate-200">
                {formatLabel(
                  requestedSource,
                )}
              </p>
            </div>

            <div className="rounded-xl border border-white/10 bg-slate-950/30 p-3">
              <div className="flex items-center gap-2 text-slate-500">
                <ShieldCheck size={15} />

                <p className="text-xs uppercase tracking-wider">
                  Effective
                </p>
              </div>

              <p className="mt-2 text-sm font-semibold text-slate-200">
                {formatLabel(
                  effectiveSource,
                )}
              </p>
            </div>
          </div>

          <dl className="mt-4 space-y-3 text-xs">
            <div className="flex items-start justify-between gap-4">
              <dt className="text-slate-500">
                Provider
              </dt>

              <dd className="break-all text-right font-semibold text-slate-300">
                {summary.provider_name ||
                  'Not recorded'}
              </dd>
            </div>

            <div className="flex items-start justify-between gap-4">
              <dt className="text-slate-500">
                Model
              </dt>

              <dd className="break-all text-right font-semibold text-slate-300">
                {summary.model_name ||
                  'Not recorded'}
              </dd>
            </div>
          </dl>

          {fallbackApplied && (
            <div className="mt-4 flex items-start gap-3 rounded-xl border border-amber-400/30 bg-amber-400/10 p-3">
              <CircleAlert
                size={18}
                className="mt-0.5 shrink-0 text-amber-300"
              />

              <p className="text-xs leading-5 text-amber-100/80">
                Local AI was requested, but the
                saved version was produced using
                the deterministic fallback.
              </p>
            </div>
          )}

          {localAiUsed &&
            !fallbackApplied && (
              <div className="mt-4 flex items-start gap-3 rounded-xl border border-emerald-400/30 bg-emerald-400/10 p-3">
                <ShieldCheck
                  size={18}
                  className="mt-0.5 shrink-0 text-emerald-300"
                />

                <p className="text-xs leading-5 text-emerald-100/80">
                  The narrative was processed by
                  the configured local AI provider
                  and remains pending analyst
                  validation.
                </p>
              </div>
            )}
        </div>
      )}
    </div>
  )
}