import { apiClient } from './client'

import type {
  LogIngestionJob,
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