import { Navigate, Route, Routes } from 'react-router-dom'
import { AppShell } from '../components/layout/AppShell'
import { CasesPage } from '../pages/CasesPage'
import { DashboardPage } from '../pages/DashboardPage'
import { LandingPage } from '../pages/LandingPage'
import { LoginPage } from '../pages/LoginPage'
import { PlaceholderPage } from '../pages/PlaceholderPage'

export function AppRoutes() {
  return <Routes>
    <Route path="/" element={<LandingPage />} />
    <Route path="/login" element={<LoginPage />} />
    <Route element={<AppShell />}>
      <Route path="/dashboard" element={<DashboardPage />} />
      <Route path="/cases" element={<CasesPage />} />
      <Route path="/investigation" element={<PlaceholderPage title="Investigation Workspace" />} />
      <Route path="/settings" element={<PlaceholderPage title="Settings" />} />
    </Route>
    <Route path="*" element={<Navigate to="/" replace />} />
  </Routes>
}
