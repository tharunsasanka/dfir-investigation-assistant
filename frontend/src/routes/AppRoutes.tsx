import {
  lazy,
  Suspense,
  type ReactNode,
} from 'react'
import {
  Navigate,
  Route,
  Routes,
} from 'react-router-dom'

import { PageLoader } from '../components/common/PageLoader'
import { AppShell } from '../components/layout/AppShell'
import { PermissionRoute } from './PermissionRoute'
import { ProtectedRoute } from './ProtectedRoute'

const LandingPage = lazy(
  async () => {
    const module = await import(
      '../pages/LandingPage'
    )

    return {
      default: module.LandingPage,
    }
  },
)

const LoginPage = lazy(
  async () => {
    const module = await import(
      '../pages/LoginPage'
    )

    return {
      default: module.LoginPage,
    }
  },
)

const DashboardPage = lazy(
  async () => {
    const module = await import(
      '../pages/DashboardPage'
    )

    return {
      default: module.DashboardPage,
    }
  },
)

const CasesPage = lazy(
  async () => {
    const module = await import(
      '../pages/CasesPage'
    )

    return {
      default: module.CasesPage,
    }
  },
)

const CaseDetailPage = lazy(
  async () => {
    const module = await import(
      '../pages/CaseDetailPage'
    )

    return {
      default: module.CaseDetailPage,
    }
  },
)

const InvestigationPage = lazy(
  async () => {
    const module = await import(
      '../pages/InvestigationPage'
    )

    return {
      default: module.InvestigationPage,
    }
  },
)

const SettingsPage = lazy(
  async () => {
    const module = await import(
      '../pages/SettingsPage'
    )

    return {
      default: module.SettingsPage,
    }
  },
)

type SuspendedPageProps = {
  children: ReactNode
}

function SuspendedPage({
  children,
}: SuspendedPageProps) {
  return (
    <Suspense fallback={<PageLoader />}>
      {children}
    </Suspense>
  )
}

export function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/"
        element={
          <SuspendedPage>
            <LandingPage />
          </SuspendedPage>
        }
      />

      <Route
        path="/login"
        element={
          <SuspendedPage>
            <LoginPage />
          </SuspendedPage>
        }
      />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppShell />}>
          <Route
            path="/dashboard"
            element={
              <SuspendedPage>
                <DashboardPage />
              </SuspendedPage>
            }
          />

          <Route
            path="/cases"
            element={
              <PermissionRoute permission="cases.read">
                <SuspendedPage>
                  <CasesPage />
                </SuspendedPage>
              </PermissionRoute>
            }
          />

          <Route
            path="/cases/:caseId"
            element={
              <PermissionRoute permission="cases.read">
                <SuspendedPage>
                  <CaseDetailPage />
                </SuspendedPage>
              </PermissionRoute>
            }
          />

          <Route
            path="/investigation"
            element={
              <PermissionRoute permission="cases.read">
                <SuspendedPage>
                  <InvestigationPage />
                </SuspendedPage>
              </PermissionRoute>
            }
          />

          <Route
            path="/settings"
            element={
              <SuspendedPage>
                <SettingsPage />
              </SuspendedPage>
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