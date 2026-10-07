// Server-side validation of a safe-context request. Defense in depth: the gateway
// never trusts that the browser built the payload with prepareSafeContext.
//
// Strict allowlist, no unknown keys, fixed warning text, and the body must be
// byte-identical to the canonical serialization of what was parsed. That last check
// is what makes "the previewed string is the sent string" verifiable on the server.

import { requiredAcknowledgements, isSafeColumnName } from './prepareSafeContext.ts'
import { serializeRequest } from './request.ts'
import {
  ACK_CODES, COLUMN_TYPES, MAX_CONTEXT_BYTES, READINESS_VALUES, REQUEST_VERSION, SAFE_CONTEXT_VERSION, WARNING_MESSAGES,
} from './schema.ts'
import type { AckCode, SafeContext, SafeContextWarning, WarningCode, WithheldCounts } from './schema.ts'

export type ValidationCode = 'malformed_json' | 'invalid_request' | 'noncanonical_body' | 'acknowledgement_required'
export type ValidationResult =
  | { ok: true; context: SafeContext; acknowledged: AckCode[] }
  | { ok: false; code: ValidationCode; message: string }

type Rec = Record<string, unknown>
class Invalid extends Error {}
const bad = (msg: string): never => {
  throw new Invalid(msg)
}

const isRec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v)
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0
const isNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const oneOf = <T extends string>(list: readonly T[], v: unknown): v is T => typeof v === 'string' && (list as readonly string[]).includes(v)

function exactKeys(obj: Rec, required: string[], optional: string[], where: string) {
  for (const k of Object.keys(obj)) if (!required.includes(k) && !optional.includes(k)) bad(`${where}: unexpected key "${k}"`)
  for (const k of required) if (!(k in obj)) bad(`${where}: missing key "${k}"`)
}

const CATEGORY_KEYS = ['Potentially Sensitive', 'PII', 'Sensitive', 'Secret / High Risk', 'Unsafe column name']
const WARNING_CODES = Object.keys(WARNING_MESSAGES) as WarningCode[]

function parseColumn(raw: unknown, i: number): SafeContext['included_columns'][number] {
  const w = `included_columns[${i}]`
  if (!isRec(raw)) return bad(`${w} must be an object`)
  exactKeys(raw, ['name', 'type', 'missing_count', 'missing_percent', 'unique_count'], ['numeric', 'free_text'], w)
  if (typeof raw.name !== 'string' || !isSafeColumnName(raw.name)) return bad(`${w}.name is not an acceptable column name`)
  if (!oneOf(COLUMN_TYPES, raw.type)) return bad(`${w}.type is invalid`)
  if (!isCount(raw.missing_count) || !isCount(raw.unique_count)) return bad(`${w} counts must be non-negative integers`)
  if (!isNum(raw.missing_percent) || raw.missing_percent < 0 || raw.missing_percent > 100) return bad(`${w}.missing_percent must be within 0-100`)
  const col: SafeContext['included_columns'][number] = {
    name: raw.name, type: raw.type, missing_count: raw.missing_count, missing_percent: raw.missing_percent, unique_count: raw.unique_count,
  }
  if (raw.numeric !== undefined) {
    if (!isRec(raw.numeric)) return bad(`${w}.numeric must be an object`)
    exactKeys(raw.numeric, ['average'], [], `${w}.numeric`)
    if (!isNum(raw.numeric.average)) return bad(`${w}.numeric.average must be finite`)
    col.numeric = { average: raw.numeric.average }
  }
  if (raw.free_text !== undefined) {
    if (!isRec(raw.free_text)) return bad(`${w}.free_text must be an object`)
    exactKeys(raw.free_text, ['cells_inspected'], [], `${w}.free_text`)
    if (!isCount(raw.free_text.cells_inspected)) return bad(`${w}.free_text.cells_inspected must be a count`)
    col.free_text = { cells_inspected: raw.free_text.cells_inspected }
  }
  return col
}

function parseWarning(raw: unknown, i: number, includedNames: Set<string>): SafeContextWarning {
  const w = `warnings[${i}]`
  if (!isRec(raw)) return bad(`${w} must be an object`)
  exactKeys(raw, ['code', 'message', 'requires_acknowledgement'], ['columns', 'cells'], w)
  if (!oneOf(WARNING_CODES, raw.code)) return bad(`${w}.code is unknown`)
  if (raw.message !== WARNING_MESSAGES[raw.code]) return bad(`${w}.message must be the fixed text for its code`)
  if (typeof raw.requires_acknowledgement !== 'boolean') return bad(`${w}.requires_acknowledgement must be boolean`)
  const out: SafeContextWarning = { code: raw.code, message: raw.message, requires_acknowledgement: raw.requires_acknowledgement }
  if (raw.columns !== undefined) {
    if (!Array.isArray(raw.columns) || !raw.columns.every(c => typeof c === 'string' && includedNames.has(c))) return bad(`${w}.columns must name included columns only`)
    out.columns = raw.columns as string[]
  }
  if (raw.cells !== undefined) {
    if (!isCount(raw.cells)) return bad(`${w}.cells must be a count`)
    out.cells = raw.cells
  }
  return out
}

function parseContext(raw: unknown): SafeContext {
  if (!isRec(raw)) return bad('safe_context must be an object')
  exactKeys(raw, ['schema_version', 'dataset', 'scanner_readiness', 'included_columns', 'withheld', 'warnings'], [], 'safe_context')
  if (raw.schema_version !== SAFE_CONTEXT_VERSION) return bad('unsupported safe_context schema_version')
  const d = raw.dataset
  if (!isRec(d)) return bad('dataset must be an object')
  exactKeys(d, ['rows', 'columns', 'duplicate_rows'], [], 'dataset')
  if (!isCount(d.rows) || !isCount(d.columns) || !isCount(d.duplicate_rows)) return bad('dataset values must be non-negative integers')
  if (!oneOf(READINESS_VALUES, raw.scanner_readiness)) return bad('scanner_readiness is invalid')
  if (!Array.isArray(raw.included_columns)) return bad('included_columns must be an array')
  const cols = raw.included_columns.map(parseColumn)
  const names = new Set(cols.map(c => c.name))
  if (names.size !== cols.length) return bad('included_columns contains duplicate names')
  const wh = raw.withheld
  if (!isRec(wh)) return bad('withheld must be an object')
  exactKeys(wh, ['total', 'by_category', 'user_excluded'], [], 'withheld')
  if (!isRec(wh.by_category)) return bad('withheld.by_category must be an object')
  exactKeys(wh.by_category, CATEGORY_KEYS, [], 'withheld.by_category')
  const counts = wh.by_category
  if (!CATEGORY_KEYS.every(k => isCount(counts[k])) || !isCount(wh.total) || !isCount(wh.user_excluded)) return bad('withheld counts must be non-negative integers')
  const sum = CATEGORY_KEYS.reduce((a, k) => a + (counts[k] as number), 0)
  if (sum !== wh.total) return bad('withheld.total does not match its categories')
  if (cols.length + sum + wh.user_excluded !== d.columns) return bad('column counts do not add up to dataset.columns')
  if (!Array.isArray(raw.warnings) || raw.warnings.length > WARNING_CODES.length) return bad('warnings must be a short array')
  const warnings = raw.warnings.map((x, i) => parseWarning(x, i, names))
  if (new Set(warnings.map(x => x.code)).size !== warnings.length) return bad('warnings contains duplicate codes')
  return {
    schema_version: SAFE_CONTEXT_VERSION,
    dataset: { rows: d.rows, columns: d.columns, duplicate_rows: d.duplicate_rows },
    scanner_readiness: raw.scanner_readiness,
    included_columns: cols,
    withheld: { total: wh.total, by_category: counts as unknown as WithheldCounts, user_excluded: wh.user_excluded },
    warnings,
  }
}

export function validateSafeContextRequest(body: string): ValidationResult {
  let parsed: unknown
  try {
    parsed = JSON.parse(body)
  } catch {
    return { ok: false, code: 'malformed_json', message: 'Body is not valid JSON.' }
  }
  try {
    if (!isRec(parsed)) return bad('body must be an object')
    exactKeys(parsed, ['request_schema', 'safe_context', 'acknowledged'], [], 'request')
    if (parsed.request_schema !== REQUEST_VERSION) return bad('unsupported request_schema')
    if (!Array.isArray(parsed.acknowledged) || !parsed.acknowledged.every(a => oneOf(ACK_CODES, a))) return bad('acknowledged must list known acknowledgement codes')
    const acknowledged = parsed.acknowledged as AckCode[]
    const context = parseContext(parsed.safe_context)
    if (new TextEncoder().encode(JSON.stringify(context)).length > MAX_CONTEXT_BYTES) return bad('safe_context is too large')
    if (serializeRequest(context, acknowledged) !== body) {
      return { ok: false, code: 'noncanonical_body', message: 'Body is not the canonical serialization of its contents.' }
    }
    const missing = requiredAcknowledgements(context).filter(code => !acknowledged.includes(code))
    if (missing.length > 0) {
      return { ok: false, code: 'acknowledgement_required', message: `Missing acknowledgements: ${missing.join(', ')}` }
    }
    return { ok: true, context, acknowledged }
  } catch (e) {
    if (e instanceof Invalid) return { ok: false, code: 'invalid_request', message: e.message }
    throw e
  }
}
