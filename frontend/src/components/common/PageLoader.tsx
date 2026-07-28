import {
  LoaderCircle,
  ShieldCheck,
} from 'lucide-react'

export function PageLoader() {
  return (
    <div
      role="status"
      aria-live="polite"
      className="grid min-h-[50vh] place-items-center px-6 py-16"
    >
      <div className="flex flex-col items-center text-center">
        <div className="relative">
          <div className="grid h-16 w-16 place-items-center rounded-2xl border border-cyan-500/20 bg-cyan-500/10">
            <ShieldCheck className="h-7 w-7 text-cyan-300" />
          </div>

          <LoaderCircle className="absolute -right-2 -top-2 h-6 w-6 animate-spin text-cyan-400" />
        </div>

        <p className="mt-5 text-sm font-medium text-slate-300">
          Loading secure workspace
        </p>

        <p className="mt-2 text-xs text-slate-500">
          Preparing the requested page...
        </p>
      </div>
    </div>
  )
}