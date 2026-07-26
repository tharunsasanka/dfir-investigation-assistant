import { apiClient } from './client'
import type {
  EventCorrelationDetail,
  EventCorrelationListResponse,
  EventCorrelationRunResponse,
  ListEventCorrelationsParams,
} from '../types/eventCorrelations'

export async function runCaseEventCorrelation(
  caseId: string,
): Promise<EventCorrelationRunResponse> {
  const response =
    await apiClient.post<EventCorrelationRunResponse>(
      `/cases/${caseId}/event-correlations/run`,
    )

  return response.data
}

export async function getEventCorrelation(
  correlationId: string,
): Promise<EventCorrelationDetail> {
  const response =
    await apiClient.get<EventCorrelationDetail>(
      `/event-correlations/${correlationId}`,
    )

  return response.data
}

export async function listCaseEventCorrelations(
  caseId: string,
  params: ListEventCorrelationsParams = {},
): Promise<EventCorrelationListResponse> {
  const response =
    await apiClient.get<EventCorrelationListResponse>(
      `/cases/${caseId}/event-correlations`,
      {
        params,
      },
    )

  return response.data
}