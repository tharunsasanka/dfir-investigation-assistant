export type LogFormat =
| 'auto'
| 'json'
| 'json_lines'
| 'csv'
| 'syslog'
| 'plain_text'
export type LogIngestionStatus =
| 'pending'
| 'processing'
| 'completed'
| 'completed_with_errors'
| 'failed'
export type LogIngestionRequest = {
log_format: LogFormat
}
export type LogIngestionJob = {
id: string
case_id: string
evidence_id: string
 requested_format: LogFormat
detected_format: LogFormat | null
status: LogIngestionStatus
 parser_name: string
parser_version: string
total_records: number
parsed_records: number
failed_records: number
processed_bytes: number
error_message: string | null
requested_by_user_id: string | null
started_at: string | null
completed_at: string | null
 created_at: string
 updated_at: string
}
