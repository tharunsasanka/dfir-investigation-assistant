export type DashboardCaseSummary = {
  total_cases: number
  active_cases: number
  critical_active_cases: number
  review_cases: number
  closed_cases: number
  latest_case_updated_at: string | null
}