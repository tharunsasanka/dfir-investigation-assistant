import {
  Navigate,
  Route,
  Routes,
} from 'react-router-dom'

import { AppShell } from '../components/layout/AppShell'
import { CaseDetailPage } from '../pages/CaseDetailPage'
import { CasesPage } from '../pages/CasesPage'
import { DashboardPage } from '../pages/DashboardPage'
import { InvestigationPage } from '../pages/InvestigationPage'
import { LandingPage } from '../pages/LandingPage'
import { LoginPage } from '../pages/LoginPage'
import { PlaceholderPage } from '../pages/PlaceholderPage'
import { PermissionRoute } from './PermissionRoute'
import { ProtectedRoute } from './ProtectedRoute'

export function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/"
        element={<LandingPage />}
      />

      <Route
        path="/login"
        element={<LoginPage />}
      />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route
            path="/dashboard"
            element={<DashboardPage />}
          />

          <Route
            path="/cases"
            element={
              <PermissionRoute permission="cases.read">
                <CasesPage />
              </PermissionRoute>
            }
          />

          <Route
            path="/cases/:caseId"
            element={
              <PermissionRoute permission="cases.read">
                <CaseDetailPage />
              </PermissionRoute>
            }
          />

          <Route
            path="/investigation"
            element={
              <PermissionRoute permission="cases.read">
                <InvestigationPage />
              </PermissionRoute>
            }
          />

          <Route
            path="/settings"
            element={
              <PlaceholderPage title="Settings" />
            }
          />
        </Route>
      </Route>

      <Route
        path="*"
        element={
          <Navigate
            to="/"
            replace
          />
        }
      />
    </Routes>
  )
}