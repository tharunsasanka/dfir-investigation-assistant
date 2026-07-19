import { apiClient } from './client'

import type {
  EvidenceCustodyEventListResponse,
  EvidenceIntegrityResponse,
  EvidenceListParameters,
  EvidenceListResponse,
  EvidenceRecord,
  EvidenceUploadRequest,
} from '../types/evidence'

export async function getCaseEvidence(
  caseId: string,
  parameters: EvidenceListParameters = {},
): Promise<EvidenceListResponse> {
  const response =
    await apiClient.get<EvidenceListResponse>(
      `/cases/${caseId}/evidence`,
      {
        params: parameters,
      },
    )

  return response.data
}

export async function uploadEvidence(
  caseId: string,
  request: EvidenceUploadRequest,
): Promise<EvidenceRecord> {
  const formData = new FormData()

  formData.append(
    'file',
    request.file,
  )

  formData.append(
    'evidence_type',
    request.evidence_type,
  )

  formData.append(
    'description',
    request.description,
  )

  formData.append(
    'source',
    request.source,
  )

  if (request.collected_at) {
    formData.append(
      'collected_at',
      request.collected_at,
    )
  }

  const response =
    await apiClient.post<EvidenceRecord>(
      `/cases/${caseId}/evidence`,
      formData,
    )

  return response.data
}

export async function getEvidenceCustodyEvents(
  evidenceId: string,
  page = 1,
  pageSize = 10,
): Promise<EvidenceCustodyEventListResponse> {
  const response =
    await apiClient.get<EvidenceCustodyEventListResponse>(
      `/evidence/${evidenceId}/custody-events`,
      {
        params: {
          page,
          page_size: pageSize,
        },
      },
    )

  return response.data
}

export async function verifyEvidenceIntegrity(
  evidenceId: string,
): Promise<EvidenceIntegrityResponse> {
  const response =
    await apiClient.post<EvidenceIntegrityResponse>(
      `/evidence/${evidenceId}/verify-integrity`,
    )

  return response.data
}

export async function downloadEvidenceContent(
  evidence: EvidenceRecord,
): Promise<void> {
  const response = await apiClient.get<Blob>(
    `/evidence/${evidence.id}/content`,
    {
      responseType: 'blob',
    },
  )

  const downloadUrl = URL.createObjectURL(
    response.data,
  )

  const downloadLink =
    document.createElement('a')

  downloadLink.href = downloadUrl
  downloadLink.download =
    evidence.original_filename

  document.body.appendChild(downloadLink)

  downloadLink.click()
  downloadLink.remove()

  URL.revokeObjectURL(downloadUrl)
}