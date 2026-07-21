import { apiClient } from './client'

import type {
  CaseAuditEventListResponse,
} from '../types/caseAudit'


export async function getCaseAuditEvents(
  caseId: string,
  page = 1,
  pageSize = 20,
): Promise<CaseAuditEventListResponse> {
  const response =
    await apiClient.get<CaseAuditEventListResponse>(
      `/cases/${caseId}/audit-events`,
      {
        params: {
          page,
          page_size: pageSize,
        },
      },
    )

  return response.data
}