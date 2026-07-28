import { apiClient } from './client'
import type {
  InvestigationReportDownload,
  InvestigationReportExportRequest,
  InvestigationReportFormat,
} from '../types/investigationReport'

function readHeader(
  headers: Record<string, unknown>,
  name: string,
): string | null {
  const value =
    headers[name]
    ?? headers[name.toLowerCase()]

  if (typeof value === 'string') {
    return value
  }

  if (
    typeof value === 'number'
    || typeof value === 'boolean'
  ) {
    return String(value)
  }

  return null
}

function decodeFilename(
  value: string,
): string {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

function extractFilename(
  contentDisposition: string | null,
  format: InvestigationReportFormat,
): string {
  if (!contentDisposition) {
    return `investigation-report.${format}`
  }

  const encodedMatch =
    contentDisposition.match(
      /filename\*=UTF-8''([^;]+)/i,
    )

  if (encodedMatch?.[1]) {
    return decodeFilename(
      encodedMatch[1].trim(),
    )
  }

  const quotedMatch =
    contentDisposition.match(
      /filename="([^"]+)"/i,
    )

  if (quotedMatch?.[1]) {
    return quotedMatch[1].trim()
  }

  const plainMatch =
    contentDisposition.match(
      /filename=([^;]+)/i,
    )

  if (plainMatch?.[1]) {
    return plainMatch[1]
      .trim()
      .replace(/^['"]|['"]$/g, '')
  }

  return `investigation-report.${format}`
}

export async function exportInvestigationReport(
  request: InvestigationReportExportRequest,
): Promise<InvestigationReportDownload> {
  const response = await apiClient.post<Blob>(
    '/investigation-reports/export',
    request,
    {
      responseType: 'blob',
    },
  )

  const headers =
    response.headers as Record<
      string,
      unknown
    >

  const contentDisposition =
    readHeader(
      headers,
      'content-disposition',
    )

  return {
    content: response.data,
    filename: extractFilename(
      contentDisposition,
      request.format,
    ),
    reportId: readHeader(
      headers,
      'x-report-id',
    ),
    caseId: readHeader(
      headers,
      'x-case-id',
    ),
    summaryId: readHeader(
      headers,
      'x-summary-id',
    ),
    format: request.format,
    documentSha256: readHeader(
      headers,
      'x-document-sha256',
    ),
  }
}

export function saveInvestigationReport(
  download: InvestigationReportDownload,
): void {
  const objectUrl = URL.createObjectURL(
    download.content,
  )

  const anchor =
    document.createElement('a')

  anchor.href = objectUrl
  anchor.download = download.filename
  anchor.style.display = 'none'

  document.body.appendChild(anchor)
  anchor.click()
  anchor.remove()

  window.setTimeout(() => {
    URL.revokeObjectURL(objectUrl)
  }, 1000)
}