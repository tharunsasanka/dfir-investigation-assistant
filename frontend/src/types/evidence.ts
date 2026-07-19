export type EvidenceType =
  | 'log'
  | 'disk_image'
  | 'memory_dump'
  | 'network_capture'
  | 'document'
  | 'image'
  | 'archive'
  | 'other'

export type EvidenceCustodyEventType =
  | 'uploaded'
  | 'accessed'
  | 'integrity_verified'
  | 'integrity_failed'

export type EvidenceRecord = {
  id: string
  case_id: string

  original_filename: string
  content_type: string
  size_bytes: number
  sha256: string
  evidence_type: EvidenceType

  description: string
  source: string
  collected_at: string | null

  uploaded_by_user_id: string | null

  created_at: string
  updated_at: string
}

export type EvidenceListResponse = {
  items: EvidenceRecord[]
  total: number
  page: number
  page_size: number
  pages: number
}

export type EvidenceListParameters = {
  page?: number
  page_size?: number
  search?: string
  evidence_type?: EvidenceType
}

export type EvidenceUploadRequest = {
  file: File
  evidence_type: EvidenceType
  description: string
  source: string
  collected_at?: string
}

export type EvidenceIntegrityResponse = {
  evidence_id: string
  matches: boolean

  expected_sha256: string
  actual_sha256: string

  expected_size_bytes: number
  actual_size_bytes: number

  checked_at: string
}

export type EvidenceCustodyEvent = {
  id: string
  evidence_id: string
  event_type: EvidenceCustodyEventType

  actor_user_id: string | null
  actor_email: string
  actor_full_name: string

  details: Record<string, unknown>

  ip_address: string | null
  user_agent: string | null
  created_at: string
}

export type EvidenceCustodyEventListResponse = {
  items: EvidenceCustodyEvent[]
  total: number
  page: number
  page_size: number
  pages: number
}