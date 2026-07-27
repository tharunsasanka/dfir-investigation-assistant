import { apiClient } from './client'
import type {
  InvestigationSummaryTraceability,
  SummaryTraceabilityIntegrity,
} from '../types/summaryTraceability'

export async function getInvestigationSummaryTraceability(
  summaryId: string,
): Promise<InvestigationSummaryTraceability> {
  const response =
    await apiClient.get<InvestigationSummaryTraceability>(
      `/investigation-summaries/${summaryId}/traceability`,
    )

  return response.data
}

export async function verifyInvestigationSummaryTraceability(
  summaryId: string,
): Promise<SummaryTraceabilityIntegrity> {
  const response =
    await apiClient.get<SummaryTraceabilityIntegrity>(
      `/investigation-summaries/${summaryId}/traceability/integrity`,
    )

  return response.data
}