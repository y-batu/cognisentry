// Deterministic data-quality findings derived from a scan report.
// Reads only profile statistics (counts, percentages, types); never cell values.

export interface QualityProfile {
  name: string
  type: string
  missing_count: number
  missing_percent: number
  unique_count: number
}

export interface QualityInput {
  dataset: { rows: number; columns: number; duplicate_rows: number }
  column_profiles: QualityProfile[]
}

export type QualitySeverity = 'high' | 'medium' | 'low'
export type QualityCode = 'empty_dataset' | 'duplicate_rows' | 'all_missing' | 'high_missing' | 'constant_column' | 'identifier_like'

export interface QualityFinding {
  code: QualityCode
  severity: QualitySeverity
  column?: string
  message: string
}

export const HIGH_MISSING_PERCENT = 30
const MIN_ROWS_FOR_COLUMN_CHECKS = 5

const order: Record<QualitySeverity, number> = { high: 0, medium: 1, low: 2 }

export function findQualityIssues(report: QualityInput): QualityFinding[] {
  const { rows, duplicate_rows } = report.dataset
  const out: QualityFinding[] = []

  if (rows === 0) {
    return [{ code: 'empty_dataset', severity: 'high', message: 'The file has a header but no data rows.' }]
  }

  if (duplicate_rows > 0) {
    const pct = Math.round((duplicate_rows / rows) * 100)
    out.push({
      code: 'duplicate_rows',
      severity: pct >= 10 ? 'high' : 'medium',
      message: `${duplicate_rows} duplicate row${duplicate_rows === 1 ? '' : 's'} (${pct}% of ${rows}).`,
    })
  }

  for (const c of report.column_profiles) {
    if (c.missing_count >= rows) {
      out.push({ code: 'all_missing', severity: 'high', column: c.name, message: `"${c.name}" has no values at all.` })
      continue
    }
    if (c.missing_percent >= HIGH_MISSING_PERCENT) {
      out.push({ code: 'high_missing', severity: c.missing_percent >= 60 ? 'high' : 'medium', column: c.name, message: `"${c.name}" is ${c.missing_percent}% missing.` })
    }
    if (rows < MIN_ROWS_FOR_COLUMN_CHECKS) continue
    if (c.unique_count === 1) {
      out.push({ code: 'constant_column', severity: 'low', column: c.name, message: `"${c.name}" has a single distinct value, so it carries no signal.` })
    } else if (c.type === 'text' && c.unique_count === rows - c.missing_count && c.unique_count >= MIN_ROWS_FOR_COLUMN_CHECKS) {
      out.push({ code: 'identifier_like', severity: 'low', column: c.name, message: `"${c.name}" is unique on every row; likely an identifier, not an analysis feature.` })
    }
  }

  return out.sort((a, b) => order[a.severity] - order[b.severity])
}
