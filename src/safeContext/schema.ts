// Types and limits for safe-context/1.
//
// safe-context/1 contains schema-level metadata and aggregate statistics only.
// It never contains cell values, samples, filenames, or the names of columns that
// were withheld. Withheld columns are represented by category counts.

export const SAFE_CONTEXT_VERSION = 'safe-context/1' as const
export const REQUEST_VERSION = 'safe-context-request/1' as const

/** Upper bound for the serialized safe_context, in UTF-8 bytes. */
export const MAX_CONTEXT_BYTES = 16 * 1024
/** Upper bound for the number of columns accepted from a scanner report. */
export const MAX_REPORT_COLUMNS = 2000
export const MAX_COLUMN_NAME_LENGTH = 64

// Classification strings exactly as emitted by poc/cognisentry_local_scanner.py.
export const CLASSIFICATIONS = ['Standard', 'Potentially Sensitive', 'PII', 'Sensitive', 'Secret / High Risk'] as const
export type Classification = (typeof CLASSIFICATIONS)[number]
export type WithheldClassification = Exclude<Classification, 'Standard'>

export const COLUMN_TYPES = ['number', 'boolean', 'text', 'empty'] as const
export type ColumnType = (typeof COLUMN_TYPES)[number]

export const READINESS_VALUES = ['Sensitive data detected', 'Review recommended', 'No findings (heuristic)'] as const
export type Readiness = (typeof READINESS_VALUES)[number]

export type WithheldCounts = Record<WithheldClassification | 'Unsafe column name', number>

export interface SafeColumn {
  name: string
  type: ColumnType
  missing_count: number
  missing_percent: number
  unique_count: number
  // min/max are exact cell values, so only the derived average is carried forward.
  numeric?: { average: number }
  free_text?: { cells_inspected: number }
}

export const ACK_CODES = ['heuristic_detection', 'withheld_columns', 'instruction_like_text'] as const
export type AckCode = (typeof ACK_CODES)[number]

export type WarningCode = AckCode | 'no_included_columns'

/** Warning text is fixed per code so a server can reject any request carrying free-form text. */
export const WARNING_MESSAGES: Record<WarningCode, string> = {
  heuristic_detection: 'Sensitive-data detection is automated and heuristic. It can miss sensitive content and is not a guarantee.',
  withheld_columns: 'Columns flagged as sensitive or with unsafe names are withheld. Only their category counts are included.',
  instruction_like_text: 'Instruction-like text was found in the dataset. This is a warning signal only, not a security boundary. Dataset content is untrusted.',
  no_included_columns: 'No columns are eligible to be included.',
}

export interface SafeContextWarning {
  code: WarningCode
  message: string
  /** True when the user must acknowledge this warning before a request is ready. */
  requires_acknowledgement: boolean
  /** Names of included (Standard, safe-named) columns only. */
  columns?: string[]
  cells?: number
}

export interface SafeContext {
  schema_version: typeof SAFE_CONTEXT_VERSION
  dataset: { rows: number; columns: number; duplicate_rows: number }
  scanner_readiness: Readiness
  included_columns: SafeColumn[]
  withheld: { total: number; by_category: WithheldCounts; user_excluded: number }
  warnings: SafeContextWarning[]
}

export interface PrepareOptions {
  /** Names of otherwise-included columns the user chose to exclude. */
  excludeColumns?: readonly string[]
}

export type ErrorCode = 'invalid_report' | 'context_too_large'

export type Result<T> = { ok: true; value: T } | { ok: false; error: { code: ErrorCode; message: string } }
