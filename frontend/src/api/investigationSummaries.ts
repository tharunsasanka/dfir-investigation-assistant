import { apiClient } from './client'
import type {
  CreateInvestigationSummaryRevisionRequest,
  GenerateInvestigationSummaryRequest,
  InvestigationSummary,
  InvestigationSummaryListResponse,
  ListInvestigationSummariesParams,
  ReviewInvestigationSummaryRequest,
} from '../types/investigationSummary'

export async function generateCaseInvestigationSummary(
  caseId: string,
  payload: GenerateInvestigationSummaryRequest = {},
): Promise<InvestigationSummary> {
  const response =
    await apiClient.post<InvestigationSummary>(
      `/cases/${caseId}/investigation-summaries/generate`,
      payload,
    )

  return response.data
}

export async function listCaseInvestigationSummaries(
  caseId: string,
  params: ListInvestigationSummariesParams = {},
): Promise<InvestigationSummaryListResponse> {
  const response =
    await apiClient.get<InvestigationSummaryListResponse>(
      `/cases/${caseId}/investigation-summaries`,
      {
        params,
      },
    )

  return response.data
}

export async function getInvestigationSummary(
  summaryId: string,
): Promise<InvestigationSummary> {
  const response =
    await apiClient.get<InvestigationSummary>(
      `/investigation-summaries/${summaryId}`,
    )

  return response.data
}

export async function reviewInvestigationSummary(
  summaryId: string,
  payload: ReviewInvestigationSummaryRequest,
): Promise<InvestigationSummary> {
  const response =
    await apiClient.post<InvestigationSummary>(
      `/investigation-summaries/${summaryId}/review`,
      payload,
    )

  return response.data
}

export async function createInvestigationSummaryRevision(
  summaryId: string,
  payload: CreateInvestigationSummaryRevisionRequest,
): Promise<InvestigationSummary> {
  const response =
    await apiClient.post<InvestigationSummary>(
      `/investigation-summaries/${summaryId}/revisions`,
      payload,
    )

  return response.data
}