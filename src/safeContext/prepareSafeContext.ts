import { parseScanReport } from './scanReport.ts'
import type { ScanColumnProfile } from './scanReport.ts'
import { MAX_COLUMN_NAME_LENGTH, MAX_CONTEXT_BYTES, SAFE_CONTEXT_VERSION, WARNING_MESSAGES } from './schema.ts'
import type { AckCode, PrepareOptions, Result, SafeColumn, SafeContext, SafeContextWarning, WithheldCounts } from './schema.ts'

const NAME_CHARS_RE = /^[\p{L}\p{N}][\p{L}\p{N} _.\-()%]*$/u
const LONG_RUN_RE = /[A-Za-z0-9]{20,}/
const JWT_LIKE_RE = /eyJ[\w-]{8,}/
// Warning-level heuristic only; column names are never treated as instructions regardless.
const INSTRUCTION_LIKE_RE = /\b(?:ignore|disregard|reveal|override)\b|\binstructions?\b|\b(?:system|developer)\s+(?:prompt|message)\b/i

/**
 * A Standard column's name is sent as-is, so it must look like an ordinary label.
 * Names that could carry data (emails, tokens, free sentences, control characters)
 * are withheld and counted instead.
 */
export function isSafeColumnName(name: string): boolean {
  return (
    name.length <= MAX_COLUMN_NAME_LENGTH &&
    NAME_CHARS_RE.test(name) &&
    !LONG_RUN_RE.test(name) &&
    !JWT_LIKE_RE.test(name) &&
    !INSTRUCTION_LIKE_RE.test(name)
  )
}

function emptyCounts(): WithheldCounts {
  return { 'Potentially Sensitive': 0, PII: 0, Sensitive: 0, 'Secret / High Risk': 0, 'Unsafe column name': 0 }
}

function toSafeColumn(p: ScanColumnProfile): SafeColumn {
  const col: SafeColumn = {
    name: p.name,
    type: p.type,
    missing_count: p.missing_count,
    missing_percent: p.missing_percent,
    unique_count: p.unique_count,
  }
  if (p.numeric) col.numeric = { average: p.numeric.average }
  if (p.free_text) col.free_text = { cells_inspected: p.free_text.cells_inspected }
  return col
}

const byteLength = (s: string) => new TextEncoder().encode(s).length

/** Pure and deterministic: the same report and options always yield the same context. */
export function prepareSafeContext(report: unknown, options: PrepareOptions = {}): Result<SafeContext> {
  const parsed = parseScanReport(report)
  if (!parsed.ok) return parsed
  const { dataset, ai_analysis_readiness, column_profiles } = parsed.value

  const excluded = new Set(options.excludeColumns ?? [])
  const counts = emptyCounts()
  const included: SafeColumn[] = []
  const instructionColumns: string[] = []
  let userExcluded = 0
  let instructionCells = 0

  for (const p of column_profiles) {
    instructionCells += p.free_text?.instruction_like ?? 0
    if (p.classification !== 'Standard') {
      counts[p.classification] += 1
    } else if (!isSafeColumnName(p.name)) {
      counts['Unsafe column name'] += 1
    } else if (excluded.has(p.name)) {
      userExcluded += 1
    } else {
      included.push(toSafeColumn(p))
      if (p.free_text && p.free_text.instruction_like > 0) instructionColumns.push(p.name)
    }
  }

  const withheldTotal = Object.values(counts).reduce((a, b) => a + b, 0)
  const warnings: SafeContextWarning[] = [
    {
      code: 'heuristic_detection',
      message: WARNING_MESSAGES.heuristic_detection,
      requires_acknowledgement: true,
    },
  ]
  if (withheldTotal > 0) {
    warnings.push({
      code: 'withheld_columns',
      message: WARNING_MESSAGES.withheld_columns,
      requires_acknowledgement: true,
    })
  }
  if (instructionCells > 0) {
    warnings.push({
      code: 'instruction_like_text',
      message: WARNING_MESSAGES.instruction_like_text,
      requires_acknowledgement: true,
      columns: instructionColumns,
      cells: instructionCells,
    })
  }
  if (included.length === 0) {
    warnings.push({ code: 'no_included_columns', message: WARNING_MESSAGES.no_included_columns, requires_acknowledgement: false })
  }

  const context: SafeContext = {
    schema_version: SAFE_CONTEXT_VERSION,
    dataset: { rows: dataset.rows, columns: dataset.columns, duplicate_rows: dataset.duplicate_rows },
    scanner_readiness: ai_analysis_readiness,
    included_columns: included,
    withheld: { total: withheldTotal, by_category: counts, user_excluded: userExcluded },
    warnings,
  }

  if (byteLength(JSON.stringify(context)) > MAX_CONTEXT_BYTES) {
    return { ok: false, error: { code: 'context_too_large', message: `Safe context exceeds ${MAX_CONTEXT_BYTES} bytes. Exclude columns and try again.` } }
  }
  return { ok: true, value: context }
}

export function requiredAcknowledgements(context: SafeContext): AckCode[] {
  return context.warnings.filter(w => w.requires_acknowledgement).map(w => w.code as AckCode)
}
