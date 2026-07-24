import { apiClient } from './client'

import type {
  ListLogIngestionJobsParams,
  LogIngestionJob,
  LogIngestionJobListResponse,
  LogIngestionRequest,
} from '../types/logIngestion'

export async function ingestEvidenceLogs(
  evidenceId: string,
  request: LogIngestionRequest,
): Promise<LogIngestionJob> {
  const response =
    await apiClient.post<LogIngestionJob>(
      `/evidence/${evidenceId}/ingest-logs`,
      request,
    )

  return response.data
}

export async function getLogIngestionJob(
  jobId: string,
): Promise<LogIngestionJob> {
  const response =
    await apiClient.get<LogIngestionJob>(
      `/log-ingestion-jobs/${jobId}`,
    )

  return response.data
}

export async function listCaseLogIngestionJobs(
  caseId: string,
  params: ListLogIngestionJobsParams = {},
): Promise<LogIngestionJobListResponse> {
  const response =
    await apiClient.get<LogIngestionJobListResponse>(
      `/cases/${caseId}/log-ingestion-jobs`,
      {
        params: {
          page: params.page ?? 1,
          page_size:
            params.page_size ?? 20,
          status:
            params.status || undefined,
          evidence_id:
            params.evidence_id || undefined,
        },
      },
    )

  return response.data
}