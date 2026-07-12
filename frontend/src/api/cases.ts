import { apiClient } from './client'

import type {
  CaseCreateRequest,
  CaseListParameters,
  CaseListResponse,
  CaseUpdateRequest,
  InvestigationCase,
} from '../types/case'

export async function getCases(
  parameters: CaseListParameters = {},
): Promise<CaseListResponse> {
  const response =
    await apiClient.get<CaseListResponse>(
      '/cases',
      {
        params: parameters,
      },
    )

  return response.data
}

export async function getCase(
  caseId: string,
): Promise<InvestigationCase> {
  const response =
    await apiClient.get<InvestigationCase>(
      `/cases/${caseId}`,
    )

  return response.data
}

export async function createCase(
  request: CaseCreateRequest,
): Promise<InvestigationCase> {
  const response =
    await apiClient.post<InvestigationCase>(
      '/cases',
      request,
    )

  return response.data
}

export async function updateCase(
  caseId: string,
  request: CaseUpdateRequest,
): Promise<InvestigationCase> {
  const response =
    await apiClient.patch<InvestigationCase>(
      `/cases/${caseId}`,
      request,
    )

  return response.data
}

export async function deleteCase(
  caseId: string,
): Promise<void> {
  await apiClient.delete(
    `/cases/${caseId}`,
  )
}