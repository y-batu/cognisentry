import { isSafeColumnName } from './names.ts'
import { COLUMN_TYPES, MAX_CONTEXT_BYTES, MAX_REPORT_COLUMNS, MAX_USABLE_COLUMNS, SAFE_CONTEXT_VERSION, WARNING_CODES } from './schema.ts'
import type { SafeContext } from './schema.ts'
type Rec = Record<string, unknown>
const rec = (v: unknown): v is Rec => typeof v === 'object' && v !== null && !Array.isArray(v) && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null)
const array = (v: unknown): v is unknown[] => Array.isArray(v) && Object.getPrototypeOf(v) === Array.prototype && Reflect.ownKeys(v).length === v.length + 1 && Array.from({ length: v.length }, (_, i) => Object.getOwnPropertyDescriptor(v, String(i))).every(d => d && 'value' in d && d.enumerable)
const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
const num = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v)
const keys = (o: Rec, required: string[], optional: string[] = []) => required.every(k => Object.hasOwn(o, k)) && Reflect.ownKeys(o).every(k => typeof k === 'string' && (required.includes(k) || optional.includes(k))) && Object.values(Object.getOwnPropertyDescriptors(o)).every(d => 'value' in d && d.enumerable)
const categories = ['Potentially Sensitive', 'PII', 'Sensitive', 'Secret / High Risk']
/** Strict recursive allowlist plus count/type relationships. Does not repair bad output. */
export function validateSafeContext(raw: unknown): raw is SafeContext {
  if (!rec(raw) || !keys(raw, ['schema_version', 'dataset', 'included_columns', 'withheld', 'warnings', 'safe_samples']) || raw.schema_version !== SAFE_CONTEXT_VERSION) return false
  const d = raw.dataset
  if (!rec(d) || !keys(d, ['rows', 'columns', 'duplicate_rows']) || !count(d.rows) || !count(d.columns) || !count(d.duplicate_rows) || d.columns > MAX_REPORT_COLUMNS || d.duplicate_rows > Math.max(0, d.rows - 1)) return false
  if (!array(raw.included_columns) || raw.included_columns.length < 1 || raw.included_columns.length > MAX_USABLE_COLUMNS) return false
  let lastRef = 0
  let omittedNames = 0
  for (const c of raw.included_columns) {
    if (!rec(c) || !keys(c, ['ref', 'type', 'missing_count', 'missing_percent', 'unique_count'], ['name', 'numeric'])) return false
    if (typeof c.ref !== 'string' || !/^c[1-9][0-9]*$/.test(c.ref)) return false
    const index = Number(c.ref.slice(1))
    if (index <= lastRef || index > d.columns) return false
    lastRef = index
    if (typeof c.type !== 'string' || !(COLUMN_TYPES as readonly string[]).includes(c.type)) return false
    if (!count(c.missing_count) || !count(c.unique_count) || !num(c.missing_percent) || c.missing_count > d.rows || c.unique_count > d.rows - c.missing_count) return false
    if (c.missing_percent < 0 || c.missing_percent > 100 || Math.abs(c.missing_percent - (d.rows ? c.missing_count / d.rows * 100 : 0)) > 0.011) return false
    const present = d.rows - c.missing_count
    if ((c.type === 'empty') !== (present === 0) || (present > 0 && c.unique_count === 0)) return false
    if (Object.hasOwn(c, 'name')) { if (typeof c.name !== 'string' || !isSafeColumnName(c.name)) return false }
    else omittedNames++
    if (c.type === 'number') {
      const n = c.numeric
      if (!rec(n) || !keys(n, ['min', 'max', 'average']) || !num(n.min) || !num(n.max) || !num(n.average) || n.min > n.max || n.average < n.min - 0.0001 || n.average > n.max + 0.0001) return false
    } else if (Object.hasOwn(c, 'numeric')) return false
  }
  const w = raw.withheld
  if (!rec(w) || !keys(w, ['total', 'by_category', 'user_excluded', 'column_names']) || !count(w.total) || !count(w.user_excluded) || !count(w.column_names) || w.column_names !== omittedNames) return false
  const cat = w.by_category
  if (!rec(cat) || !keys(cat, categories) || !categories.every(k => count(cat[k]))) return false
  if (categories.reduce((s, k) => s + (cat[k] as number), 0) !== w.total || raw.included_columns.length + w.total + w.user_excluded !== d.columns) return false
  if (!array(raw.warnings) || !raw.warnings.every(code => (WARNING_CODES as readonly unknown[]).includes(code)) || new Set(raw.warnings).size !== raw.warnings.length) return false
  const warnings = raw.warnings
  if (WARNING_CODES.filter(c => warnings.includes(c)).join() !== warnings.join()) return false
  for (const [code, needed] of [['SECRET_COLUMNS_WITHHELD', Number(cat['Secret / High Risk']) > 0], ['PII_COLUMNS_WITHHELD', Number(cat.PII) > 0], ['COLUMN_NAME_WITHHELD', w.column_names > 0], ['USER_EXCLUDED_COLUMNS', w.user_excluded > 0]] as const) {
    if (warnings.includes(code) !== needed) return false
  }
  if (!array(raw.safe_samples) || raw.safe_samples.length !== 0) return false
  return new TextEncoder().encode(JSON.stringify(raw)).length <= MAX_CONTEXT_BYTES
}
