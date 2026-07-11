import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, BriefcaseBusiness, ShieldAlert, TimerReset } from 'lucide-react'
import { apiClient } from '../api/client'

const metrics = [
  ['Active investigations', '12', BriefcaseBusiness],
  ['Critical alerts', '4', ShieldAlert],
  ['Threat score', '78', AlertTriangle],
  ['Avg. response time', '18m', TimerReset],
]

export function DashboardPage() {
  const health = useQuery({ queryKey: ['health'], queryFn: async () => (await apiClient.get('/health')).data, retry: 1 })
  return (
    <section>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div><p className="text-sm text-cyan">Security Operations Overview</p><h1 className="mt-1 text-3xl font-bold">Investigation Dashboard</h1></div>
        <div className="glass rounded-xl px-4 py-2 text-sm"><span className={`mr-2 inline-block h-2 w-2 rounded-full ${health.isSuccess ? 'bg-emerald-400' : 'bg-amber-400'}`} />API {health.isSuccess ? 'connected' : 'checking'}</div>
      </div>
      <div className="mt-8 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {metrics.map(([label, value, Icon]) => { const MetricIcon = Icon as typeof BriefcaseBusiness; return <article key={label as string} className="glass rounded-2xl p-5"><MetricIcon className="text-cyan" /><p className="mt-5 text-sm text-slate-400">{label as string}</p><p className="mt-1 text-3xl font-bold">{value as string}</p></article> })}
      </div>
      <div className="mt-6 grid gap-6 xl:grid-cols-[1.5fr_1fr]">
        <article className="glass min-h-80 rounded-2xl p-6"><h2 className="font-semibold">Threat activity</h2><div className="mt-8 grid h-52 place-items-center rounded-xl border border-dashed border-white/10 text-sm text-slate-500">Recharts threat trend widget lands in the analytics milestone.</div></article>
        <article className="glass rounded-2xl p-6"><h2 className="font-semibold">Research features</h2><ol className="mt-4 space-y-3 text-sm text-slate-300">{['Evidence traceability','Cross-evidence correlation','Confidence-aware AI','Hypothesis board','Alternative explanations','Replay mode','Evaluation laboratory','Forensic reproducibility'].map((item, index) => <li key={item} className="rounded-xl bg-white/5 px-3 py-3"><span className="mr-2 text-cyan">{index + 1}.</span>{item}</li>)}</ol></article>
      </div>
    </section>
  )
}
