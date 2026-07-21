import { apiClient } from './client'
import type { DashboardCaseSummary } from '../types/dashboard'

export async function getDashboardCaseSummary(): Promise<DashboardCaseSummary> {
  const response =
    await apiClient.get<DashboardCaseSummary>(
      '/dashboard/case-summary',
    )

  return response.data
}