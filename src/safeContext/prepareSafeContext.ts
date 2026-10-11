import { parseScanReport } from './scanReport.ts'
import { isSafeColumnName } from './names.ts'
import { validateSafeContext } from './validateContext.ts'
import { ACK_CODES, MAX_CONTEXT_BYTES, MAX_USABLE_COLUMNS, SAFE_CONTEXT_VERSION, WARNING_CODES } from './schema.ts'
import type { AckCode, ErrorCode, PrepareOptions, Preparation, SafeColumn, SafeContext, WarningCode, WithheldCounts } from './schema.ts'
export { isSafeColumnName } from './names.ts'

const blocked = (code: ErrorCode, message: string): Preparation => ({ status: 'blocked', reasons: [code], ok: false, error: { code, message } })
/** Pure projection: arbitrary scanner fields and the local name map cannot enter context. */
export function prepareSafeContext(report: unknown, options: PrepareOptions = {}): Preparation {
  const parsed = parseScanReport(report)
  if (!parsed.ok) return blocked('invalid_report', parsed.error.message)
  if (!options || typeof options !== 'object' || Array.isArray(options) ||
      (options.excludeColumns !== undefined && (!Array.isArray(options.excludeColumns) || !options.excludeColumns.every(x => typeof x === 'string'))) ||
      (options.includeStandardNames !== undefined && typeof options.includeStandardNames !== 'boolean')) return blocked('invalid_options', 'Invalid preparation options.')
  const maxBytes = options.maxContextBytes ?? MAX_CONTEXT_BYTES
  const maxColumns = options.maxUsableColumns ?? MAX_USABLE_COLUMNS
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_CONTEXT_BYTES || !Number.isSafeInteger(maxColumns) || maxColumns < 1 || maxColumns > MAX_USABLE_COLUMNS) return blocked('invalid_options', 'Limits may only be lowered from MVP defaults.')
  const { dataset, column_profiles } = parsed.value
  const excluded = new Set(options.excludeColumns ?? [])
  const counts: WithheldCounts = { 'Potentially Sensitive': 0, PII: 0, Sensitive: 0, 'Secret / High Risk': 0 }
  const included: SafeColumn[] = []
  const refToName: Record<string, string> = {}
  const warnings = new Set<WarningCode>()
  let userExcluded = 0
  let namesWithheld = 0
  column_profiles.forEach((p, index) => {
    const ref = `c${index + 1}`
    if (p.free_text?.instruction_like) warnings.add('INSTRUCTION_LIKE_CONTENT')
    if (p.free_text && p.free_text.cells_inspected < dataset.rows - p.missing_count) warnings.add('FREE_TEXT_NOT_INJECTION_SCANNED')
    if (p.classification !== 'Standard') { counts[p.classification]++; return }
    refToName[ref] = p.name
    if (excluded.has(ref) || excluded.has(p.name)) { userExcluded++; return }
    const col: SafeColumn = { ref, type: p.type, missing_count: p.missing_count, missing_percent: p.missing_percent, unique_count: p.unique_count }
    if (options.includeStandardNames && isSafeColumnName(p.name)) col.name = p.name
    else namesWithheld++
    if (p.type === 'number' && p.numeric) col.numeric = { min: p.numeric.min, max: p.numeric.max, average: p.numeric.average }
    included.push(col)
  })
  if (!included.length) return blocked('no_usable_columns', 'No Standard columns remain. Include at least one Standard column.')
  if (included.length > maxColumns) return blocked('too_many_columns', `At most ${maxColumns} usable columns are allowed.`)
  if (counts['Secret / High Risk']) warnings.add('SECRET_COLUMNS_WITHHELD')
  if (counts.PII) warnings.add('PII_COLUMNS_WITHHELD')
  if (namesWithheld) warnings.add('COLUMN_NAME_WITHHELD')
  if (userExcluded) warnings.add('USER_EXCLUDED_COLUMNS')
  const context: SafeContext = {
    schema_version: SAFE_CONTEXT_VERSION,
    dataset: { rows: dataset.rows, columns: dataset.columns, duplicate_rows: dataset.duplicate_rows },
    included_columns: included,
    withheld: { total: Object.values(counts).reduce((a, b) => a + b, 0), by_category: counts, user_excluded: userExcluded, column_names: namesWithheld },
    warnings: WARNING_CODES.filter(code => warnings.has(code)),
    safe_samples: [],
  }
  if (new TextEncoder().encode(JSON.stringify(context)).length > maxBytes) return blocked('context_too_large', `Safe context exceeds ${maxBytes} UTF-8 bytes.`)
  if (!validateSafeContext(context)) return blocked('invalid_context', 'Output violates the safe-context allowlist.')
  const ackRequired = requiredAcknowledgements(context)
  return { status: ackRequired.length ? 'needs_ack' : 'ready', context, ackRequired, refToName, ok: true, value: context }
}
export function requiredAcknowledgements(context: SafeContext): AckCode[] {
  return ACK_CODES.filter(code => context.warnings.includes(code))
}
