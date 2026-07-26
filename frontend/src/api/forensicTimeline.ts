import { apiClient } from './client'
import type {
  ForensicTimelineResponse,
  ListForensicTimelineParams,
} from '../types/forensicTimeline'

function buildTimelineParams(
  params: ListForensicTimelineParams,
): URLSearchParams {
  const query =
    new URLSearchParams()

  if (params.page !== undefined) {
    query.set(
      'page',
      String(params.page),
    )
  }

  if (
    params.page_size !== undefined
  ) {
    query.set(
      'page_size',
      String(params.page_size),
    )
  }

  if (params.search) {
    query.set(
      'search',
      params.search,
    )
  }

  if (params.entry_type) {
    for (
      const entryType
      of params.entry_type
    ) {
      query.append(
        'entry_type',
        entryType,
      )
    }
  }

  if (params.severity) {
    query.set(
      'severity',
      params.severity,
    )
  }

  if (params.evidence_id) {
    query.set(
      'evidence_id',
      params.evidence_id,
    )
  }

  if (params.start_time) {
    query.set(
      'start_time',
      params.start_time,
    )
  }

  if (params.end_time) {
    query.set(
      'end_time',
      params.end_time,
    )
  }

  if (params.sort_order) {
    query.set(
      'sort_order',
      params.sort_order,
    )
  }

  return query
}

export async function listCaseForensicTimeline(
  caseId: string,
  params: ListForensicTimelineParams = {},
): Promise<ForensicTimelineResponse> {
  const response =
    await apiClient.get<ForensicTimelineResponse>(
      `/cases/${caseId}/forensic-timeline`,
      {
        params:
          buildTimelineParams(
            params,
          ),
      },
    )

  return response.data
}