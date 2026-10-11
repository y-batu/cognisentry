export const SAFE_CONTEXT_VERSION = 'safe-context/1' as const
export const REQUEST_VERSION = 'safe-context-request/1' as const
export const MAX_CONTEXT_BYTES = 16 * 1024
export const MAX_USABLE_COLUMNS = 100
export const MAX_REPORT_COLUMNS = 2000
export const MAX_COLUMN_NAME_LENGTH = 64
export const CLASSIFICATIONS = ['Standard', 'Potentially Sensitive', 'PII', 'Sensitive', 'Secret / High Risk'] as const
export type Classification = (typeof CLASSIFICATIONS)[number]
export type WithheldClassification = Exclude<Classification, 'Standard'>
export const COLUMN_TYPES = ['number', 'boolean', 'text', 'empty'] as const
export type ColumnType = (typeof COLUMN_TYPES)[number]
export const READINESS_VALUES = ['Sensitive data detected', 'Review recommended', 'No findings (heuristic)'] as const
export type Readiness = (typeof READINESS_VALUES)[number]
export type WithheldCounts = Record<WithheldClassification, number>
export interface SafeColumn {
  ref: string
  name?: string
  type: ColumnType
  missing_count: number
  missing_percent: number
  unique_count: number
  numeric?: { min: number; max: number; average: number }
}
export const ACK_CODES = ['INSTRUCTION_LIKE_CONTENT', 'FREE_TEXT_NOT_INJECTION_SCANNED', 'SECRET_COLUMNS_WITHHELD', 'PII_COLUMNS_WITHHELD'] as const
export type AckCode = (typeof ACK_CODES)[number]
export const WARNING_CODES = [...ACK_CODES, 'COLUMN_NAME_WITHHELD', 'USER_EXCLUDED_COLUMNS'] as const
export type WarningCode = (typeof WARNING_CODES)[number]
// Display copy stays local. The payload carries codes only.
export const WARNING_MESSAGES: Record<WarningCode, string> = {
  INSTRUCTION_LIKE_CONTENT: 'Instruction-like content was detected. Heuristic detection is a warning, not a security boundary.',
  FREE_TEXT_NOT_INJECTION_SCANNED: 'Some free text was not inspected for instruction-like content. All dataset content remains untrusted.',
  SECRET_COLUMNS_WITHHELD: 'Secret columns were withheld. Only their category count is included.',
  PII_COLUMNS_WITHHELD: 'PII columns were withheld. Only their category count is included.',
  COLUMN_NAME_WITHHELD: 'One or more Standard column names were omitted. Stable column references are used instead.',
  USER_EXCLUDED_COLUMNS: 'User-excluded columns were omitted.',
}
export interface SafeContext {
  schema_version: typeof SAFE_CONTEXT_VERSION
  dataset: { rows: number; columns: number; duplicate_rows: number }
  included_columns: SafeColumn[]
  withheld: { total: number; by_category: WithheldCounts; user_excluded: number; column_names: number }
  warnings: WarningCode[]
  safe_samples: []
}
export interface PrepareOptions {
  /** Stable references preferred; exact names supported for local callers. */
  excludeColumns?: readonly string[]
  includeStandardNames?: boolean
  /** Callers may lower, never raise, the MVP limits. */
  maxContextBytes?: number
  maxUsableColumns?: number
}
export type ErrorCode = 'invalid_report' | 'invalid_options' | 'no_usable_columns' | 'too_many_columns' | 'context_too_large' | 'invalid_context'
export type Result<T> = { ok: true; value: T } | { ok: false; error: { code: ErrorCode; message: string } }
export type Preparation =
  | { status: 'blocked'; reasons: ErrorCode[]; ok: false; error: { code: ErrorCode; message: string } }
  | { status: 'ready' | 'needs_ack'; context: SafeContext; ackRequired: AckCode[]; refToName: Record<string, string>; ok: true; value: SafeContext }
