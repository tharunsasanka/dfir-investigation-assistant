import { Link } from 'react-router-dom'

export function LoginPage() {
  return (
    <main className="grid min-h-screen place-items-center p-6">
      <form className="glass w-full max-w-md rounded-3xl p-8">
        <h1 className="text-2xl font-bold">Secure analyst login</h1>
        <p className="mt-2 text-sm text-slate-400">Authentication wiring is completed in the next milestone.</p>
        <label className="mt-6 block text-sm">Email<input type="email" className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none focus:border-cyan/60" /></label>
        <label className="mt-4 block text-sm">Password<input type="password" className="mt-2 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 outline-none focus:border-cyan/60" /></label>
        <button type="button" className="mt-6 w-full rounded-xl bg-cyan py-3 font-semibold text-slate-950">Sign in</button>
        <Link to="/" className="mt-5 block text-center text-sm text-slate-400 hover:text-cyan">Return to landing page</Link>
      </form>
    </main>
  )
}
