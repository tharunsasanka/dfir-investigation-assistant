import { NavLink, Outlet } from 'react-router-dom'
import { Activity, BriefcaseBusiness, LayoutDashboard, Settings, ShieldCheck } from 'lucide-react'

const links = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/cases', label: 'Cases', icon: BriefcaseBusiness },
  { to: '/investigation', label: 'Investigation', icon: Activity },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export function AppShell() {
  return (
    <div className="min-h-screen lg:grid lg:grid-cols-[260px_1fr]">
      <aside className="glass border-b border-white/10 p-5 lg:min-h-screen lg:border-b-0 lg:border-r">
        <div className="mb-8 flex items-center gap-3">
          <div className="rounded-2xl bg-cyan/15 p-2 text-cyan"><ShieldCheck /></div>
          <div>
            <p className="font-semibold">DFIR Assistant</p>
            <p className="text-xs text-slate-400">Investigation Console</p>
          </div>
        </div>
        <nav className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-1">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-xl px-3 py-3 text-sm transition ${
                  isActive ? 'bg-cyan/15 text-cyan' : 'text-slate-300 hover:bg-white/5 hover:text-white'
                }`
              }
            >
              <Icon size={18} /> {label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="p-4 sm:p-6 lg:p-8"><Outlet /></main>
    </div>
  )
}
