import { apiClient } from './client'
import type {
  ListSecurityFindingsParams,
  SecurityFinding,
  SecurityFindingListResponse,
} from '../types/securityFindings'

export async function getSecurityFinding(
  findingId: string,
): Promise<SecurityFinding> {
  const response =
    await apiClient.get<SecurityFinding>(
      `/security-findings/${findingId}`,
    )

  return response.data
}

export async function listCaseSecurityFindings(
  caseId: string,
  params: ListSecurityFindingsParams = {},
): Promise<SecurityFindingListResponse> {
  const response =
    await apiClient.get<SecurityFindingListResponse>(
      `/cases/${caseId}/security-findings`,
      {
        params,
      },
    )

  return response.data
}