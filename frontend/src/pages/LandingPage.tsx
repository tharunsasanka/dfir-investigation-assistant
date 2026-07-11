import { motion } from 'framer-motion'
import { Link } from 'react-router-dom'
import { BrainCircuit, Network, ShieldCheck } from 'lucide-react'

export function LandingPage() {
  return (
    <main className="mx-auto flex min-h-screen max-w-7xl items-center px-6 py-16">
      <div className="grid items-center gap-12 lg:grid-cols-2">
        <motion.section initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }}>
          <span className="rounded-full border border-cyan/30 bg-cyan/10 px-3 py-1 text-sm text-cyan">Evidence-grounded DFIR</span>
          <h1 className="mt-6 text-4xl font-bold tracking-tight sm:text-6xl">Investigate incidents with traceable, confidence-aware AI.</h1>
          <p className="mt-6 max-w-2xl text-lg text-slate-300">Correlate evidence, reconstruct attack timelines, map MITRE ATT&CK techniques and generate defensible forensic findings.</p>
          <div className="mt-8 flex gap-3">
            <Link to="/dashboard" className="rounded-xl bg-cyan px-5 py-3 font-semibold text-slate-950">Open Console</Link>
            <Link to="/login" className="rounded-xl border border-white/15 px-5 py-3 font-semibold">Sign in</Link>
          </div>
        </motion.section>
        <motion.section className="glass grid gap-4 rounded-3xl p-6" initial={{ opacity: 0, scale: .96 }} animate={{ opacity: 1, scale: 1 }}>
          {[['Traceable findings', ShieldCheck], ['Cross-evidence correlation', Network], ['Explainable AI', BrainCircuit]].map(([label, Icon]) => {
            const FeatureIcon = Icon as typeof ShieldCheck
            return <div key={label as string} className="rounded-2xl border border-white/10 bg-white/5 p-5"><FeatureIcon className="mb-4 text-cyan" /><h2 className="font-semibold">{label as string}</h2><p className="mt-2 text-sm text-slate-400">Designed for transparent, reproducible investigations.</p></div>
          })}
        </motion.section>
      </div>
    </main>
  )
}
