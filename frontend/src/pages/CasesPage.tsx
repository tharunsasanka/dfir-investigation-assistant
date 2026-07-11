import { useQuery } from '@tanstack/react-query'
import { apiClient } from '../api/client'

type CaseItem = { id: string; title: string; description: string; severity: string; status: string }

export function CasesPage() {
  const query = useQuery<CaseItem[]>({ queryKey: ['cases'], queryFn: async () => (await apiClient.get('/cases')).data })
  return <section><h1 className="text-3xl font-bold">Cases</h1><p className="mt-2 text-slate-400">Case management API foundation is connected.</p><div className="mt-6 grid gap-4">{query.isLoading && <div className="glass rounded-2xl p-5">Loading cases…</div>}{query.isError && <div className="glass rounded-2xl p-5 text-amber-300">The database API is not available yet. Start Docker services and refresh.</div>}{query.data?.length === 0 && <div className="glass rounded-2xl p-5 text-slate-400">No cases have been created.</div>}{query.data?.map(item => <article key={item.id} className="glass rounded-2xl p-5"><div className="flex items-center justify-between gap-4"><h2 className="font-semibold">{item.title}</h2><span className="rounded-full bg-cyan/10 px-3 py-1 text-xs text-cyan">{item.severity}</span></div><p className="mt-3 text-sm text-slate-400">{item.description || 'No description'}</p><p className="mt-4 text-xs uppercase tracking-wider text-slate-500">{item.status}</p></article>)}</div></section>
}
