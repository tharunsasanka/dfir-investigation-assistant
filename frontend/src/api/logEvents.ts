import { apiClient } from './client'

import type {
  ListCaseLogEventsParams,
  ParsedLogEventListResponse,
} from '../types/logEvents'

export async function listCaseLogEvents(
  caseId: string,
  params: ListCaseLogEventsParams = {},
): Promise<ParsedLogEventListResponse> {
  const response =
    await apiClient.get<ParsedLogEventListResponse>(
      `/cases/${caseId}/log-events`,
      {
        params: {
          page: params.page ?? 1,
          page_size:
            params.page_size ?? 50,
          search:
            params.search || undefined,
          severity:
            params.severity || undefined,
          evidence_id:
            params.evidence_id ||
            undefined,
        },
      },
    )

  return response.data
}