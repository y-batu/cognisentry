// Runtime validation of the report produced by poc/cognisentry_local_scanner.py.
// Only the fields safe-context needs are read; everything else (including any
// unexpected extra fields) is ignored and never copied forward.

import { CLASSIFICATIONS, COLUMN_TYPES, MAX_REPORT_COLUMNS, READINESS_VALUES } from './schema.ts'
import type { Classification, ColumnType, Readiness, Result } from './schema.ts'

export interface ScanColumnProfile {
  name: string
  type: ColumnType
  missing_count: number
  missing_percent: number
  unique_count: number
  classification: Classification
  numeric?: { min: number; max: number; average: number }
  free_text?: { cells_inspected: number; instruction_like: number }
}

export interface ScanReport {
  dataset: { rows: number; columns: number; duplicate_rows: number }
  ai_analysis_readiness: Readiness
  column_profiles: ScanColumnProfile[]
}

type Rec = Record<string, unknown>

const isRec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v)
const isCount = (v: unknown): v is number => typeof v === 'number' && Number.isInteger(v) && v >= 0
const isFiniteNum = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const oneOf = <T extends string>(list: readonly T[], v: unknown): v is T => typeof v === 'string' && (list as readonly string[]).includes(v)

class ReportError extends Error {}
const fail = (msg: string): never => {
  throw new ReportError(msg)
}

function parseProfile(raw: unknown, index: number): ScanColumnProfile {
  const where = `column_profiles[${index}]`
  if (!isRec(raw)) return fail(`${where} must be an object`)
  if (typeof raw.name !== 'string' || raw.name.length === 0) return fail(`${where}.name must be a non-empty string`)
  if (!oneOf(COLUMN_TYPES, raw.type)) return fail(`${where}.type is not a known column type`)
  if (!isCount(raw.missing_count)) return fail(`${where}.missing_count must be a non-negative integer`)
  if (!isFiniteNum(raw.missing_percent) || raw.missing_percent < 0 || raw.missing_percent > 100) return fail(`${where}.missing_percent must be within 0-100`)
  if (!isCount(raw.unique_count)) return fail(`${where}.unique_count must be a non-negative integer`)
  if (!oneOf(CLASSIFICATIONS, raw.classification)) return fail(`${where}.classification is not a known classification`)

  const profile: ScanColumnProfile = {
    name: raw.name,
    type: raw.type,
    missing_count: raw.missing_count,
    missing_percent: raw.missing_percent,
    unique_count: raw.unique_count,
    classification: raw.classification,
  }

  if (raw.numeric !== undefined) {
    const n = raw.numeric
    if (!isRec(n) || !isFiniteNum(n.min) || !isFiniteNum(n.max) || !isFiniteNum(n.average)) return fail(`${where}.numeric must hold finite min/max/average`)
    profile.numeric = { min: n.min, max: n.max, average: n.average }
  }

  if (raw.free_text === true) {
    const insp = raw.free_text_inspection
    if (!isRec(insp) || !isCount(insp.cells_inspected) || !isRec(insp.findings)) return fail(`${where}.free_text_inspection is malformed`)
    const instruction = insp.findings.instruction_like
    if (!isCount(instruction)) return fail(`${where}.free_text_inspection.findings.instruction_like must be a non-negative integer`)
    profile.free_text = { cells_inspected: insp.cells_inspected, instruction_like: instruction }
  }

  return profile
}

export function parseScanReport(input: unknown): Result<ScanReport> {
  try {
    if (!isRec(input)) return fail('report must be an object')
    const d = input.dataset
    if (!isRec(d) || !isCount(d.rows) || !isCount(d.columns) || !isCount(d.duplicate_rows)) return fail('dataset.rows/columns/duplicate_rows must be non-negative integers')
    if (!oneOf(READINESS_VALUES, input.ai_analysis_readiness)) return fail('ai_analysis_readiness is not a known value')
    if (!Array.isArray(input.column_profiles)) return fail('column_profiles must be an array')
    if (input.column_profiles.length > MAX_REPORT_COLUMNS) return fail(`column_profiles exceeds ${MAX_REPORT_COLUMNS} columns`)
    if (input.column_profiles.length !== d.columns) return fail('dataset.columns does not match column_profiles length')
    const profiles = input.column_profiles.map((p, i) => parseProfile(p, i))
    return {
      ok: true,
      value: {
        dataset: { rows: d.rows, columns: d.columns, duplicate_rows: d.duplicate_rows },
        ai_analysis_readiness: input.ai_analysis_readiness,
        column_profiles: profiles,
      },
    }
  } catch (e) {
    if (e instanceof ReportError) return { ok: false, error: { code: 'invalid_report', message: e.message } }
    throw e
  }
}
