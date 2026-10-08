// TypeScript port of poc/cognisentry_local_scanner.py.
//
// The Python scanner is the reference implementation. Golden fixtures generated from it
// (src/scanner/fixtures) and the committed sample report keep this port honest.
// Known, accepted differences: JS \w, \d and \b are ASCII-only; Python's float() also
// accepts underscores and "infinity" spellings that this port does not treat as numbers.

import { parseCsv } from './csv.ts'

type Cls = 'Standard' | 'Potentially Sensitive' | 'PII' | 'Sensitive' | 'Secret / High Risk'

const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/
const URL_RE = /^https?:\/\//i

const HINTS: Array<[string, Cls]> = [
  ['email', 'PII'], ['e_mail', 'PII'],
  ['phone', 'PII'], ['phone_number', 'PII'], ['mobile_phone', 'PII'], ['mobile_number', 'PII'],
  ['contact_phone', 'PII'], ['telephone', 'PII'],
  ['first_name', 'PII'], ['last_name', 'PII'], ['full_name', 'PII'],
  ['date_of_birth', 'PII'], ['birth_date', 'PII'], ['birthdate', 'PII'], ['dob', 'PII'],
  ['street_address', 'PII'], ['home_address', 'PII'], ['billing_address', 'PII'],
  ['shipping_address', 'PII'], ['mailing_address', 'PII'],
  ['ip', 'Potentially Sensitive'], ['ip_address', 'Potentially Sensitive'],
  ['customer_id', 'Sensitive'], ['user_id', 'Sensitive'], ['national_id', 'Sensitive'], ['ssn', 'Sensitive'],
  ['credit_card', 'Sensitive'], ['card_number', 'Sensitive'], ['cvv', 'Sensitive'], ['cvc', 'Sensitive'],
  ['iban', 'Sensitive'], ['passport', 'Sensitive'], ['passport_number', 'Sensitive'], ['tax_id', 'Sensitive'],
  ['password', 'Secret / High Risk'], ['passwd', 'Secret / High Risk'], ['pwd', 'Secret / High Risk'],
  ['passphrase', 'Secret / High Risk'], ['api_key', 'Secret / High Risk'], ['apikey', 'Secret / High Risk'],
  ['token', 'Secret / High Risk'], ['secret', 'Secret / High Risk'],
  ['private_key', 'Secret / High Risk'], ['access_key', 'Secret / High Risk'],
]
const RISK: Record<Cls, number> = { Standard: 0, 'Potentially Sensitive': 1, PII: 2, Sensitive: 2, 'Secret / High Risk': 3 }
const SAFE_FIRST = new Set(['is', 'has', 'num'])
const SAFE_LAST = new Set(['count', 'flag', 'enabled', 'status', 'type', 'rate', 'ratio', 'total', 'in'])

const PHONE_CANDIDATE_RE = /^(?:\+\d|\(\d|\d)[\d\s()-]*\d$/
const DATE_LIKE_RE = /^(?:\d{4}-\d{1,2}-\d{1,2}|\d{1,2}-\d{1,2}-\d{2,4})$/

const SECRET_PATTERNS = [
  /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}/,
  /\bgh[pousr]_[A-Za-z0-9]{36,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bxox[abprs]-[A-Za-z0-9-]{10,}/,
  /\bAIza[0-9A-Za-z_-]{35}/,
  /\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}/,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
]

const FREE_TEXT_MAX_CELLS = 1000
const EMBEDDED_EMAIL_RE = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/
const EMBEDDED_PHONE_RES = [/(?<!\w)\+\d[\d\s()-]{7,}\d/, /\(\d{3}\)\s?\d{3}[-\s]?\d{4}/]
const INSTRUCTION_PATTERNS = [
  /\b(?:ignore|disregard)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above)\s+(?:instructions?|prompts?)/i,
  /\b(?:reveal|print|show|repeat)\s+(?:the\s+|your\s+)?(?:system|developer)\s+(?:prompt|message)/i,
  /\bnew\s+instructions\s*:/i,
  /<\s*\/?\s*(?:system|instructions?)\s*>/i,
]

const NUMBER_RE = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/
const IPV4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/

export function nameTokens(name: string): string[] {
  let s = name.trim().replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
  s = s.replace(/([a-z0-9])([A-Z])/g, '$1_$2')
  return s.toLowerCase().split(/[^a-z0-9]+/).filter(t => t.length > 0)
}

function nameMatches(tokens: string[], hint: string): boolean {
  if (tokens.length === 0 || SAFE_FIRST.has(tokens[0]!) || SAFE_LAST.has(tokens[tokens.length - 1]!)) return false
  const h = hint.split('_')
  for (let i = 0; i + h.length <= tokens.length; i++) {
    if (h.every((t, j) => tokens[i + j] === t)) return true
  }
  return false
}

const isIpv4 = (v: string) => IPV4_RE.test(v.trim())

function looksLikePhone(value: string): boolean {
  const v = value.trim()
  if (!PHONE_CANDIDATE_RE.test(v) || DATE_LIKE_RE.test(v)) return false
  const digits = (v.match(/\d/g) ?? []).length
  if (digits < 8 || digits > 15) return false
  return v.startsWith('+') || v.startsWith('(') || /[\s-]/.test(v)
}

const containsSecretFormat = (v: string) => SECRET_PATTERNS.some(rx => rx.test(v))

function maybeNumber(value: string): number | null {
  const v = value.trim()
  if (!v) return null
  const cleaned = v.replace(/,/g, '')
  if (!NUMBER_RE.test(cleaned)) return null
  const n = Number(cleaned)
  return Number.isFinite(n) ? n : null
}

function inferType(values: string[]): 'empty' | 'number' | 'boolean' | 'text' {
  const present = values.map(v => v.trim()).filter(v => v)
  if (present.length === 0) return 'empty'
  if (present.every(v => maybeNumber(v) !== null)) return 'number'
  if (present.every(v => ['true', 'false', 'yes', 'no', '0', '1'].includes(v.toLowerCase()))) return 'boolean'
  return 'text'
}

const raise = (cur: Cls, level: Cls): Cls => (RISK[level] > RISK[cur] ? level : cur)
const addReason = (reasons: string[], msg: string) => {
  if (!reasons.includes(msg)) reasons.push(msg)
}
// Python rounds via the exact binary value; toFixed does the same for the cases we hit.
const round = (x: number, d: number) => Number(x.toFixed(d))

function classifyColumn(name: string, values: string[]): { classification: Cls; reasons: string[] } {
  const tokens = nameTokens(name)
  let classification: Cls = 'Standard'
  const reasons: string[] = []
  for (const [hint, risk] of HINTS) {
    if (nameMatches(tokens, hint)) {
      classification = raise(classification, risk)
      addReason(reasons, `column name suggests ${risk.toLowerCase()}`)
    }
  }
  const present = values.map(v => v.trim()).filter(v => v)
  if (present.length === 0) return { classification, reasons }
  const sample = present.slice(0, 200)
  const counts = { email: 0, phone: 0, ipv4: 0, url: 0, secret: 0 }
  for (const v of sample) {
    if (EMAIL_RE.test(v)) counts.email++
    if (looksLikePhone(v)) counts.phone++
    if (isIpv4(v)) counts.ipv4++
    if (URL_RE.test(v)) counts.url++
    if (containsSecretFormat(v)) counts.secret++
  }
  const threshold = Math.max(1, Math.ceil(sample.length * 0.2))
  if (counts.email >= threshold) {
    classification = raise(classification, 'PII')
    addReason(reasons, 'values resemble email addresses')
  }
  if (counts.phone >= threshold) {
    classification = raise(classification, 'PII')
    addReason(reasons, 'values resemble phone numbers')
  }
  if (counts.ipv4 >= threshold) {
    classification = raise(classification, 'Potentially Sensitive')
    addReason(reasons, 'values resemble IPv4 addresses')
  }
  if (counts.secret >= 1) {
    classification = raise(classification, 'Secret / High Risk')
    addReason(reasons, 'values contain known secret/token formats')
  }
  if (counts.url >= threshold && classification === 'Standard') addReason(reasons, 'values resemble URLs')
  return { classification, reasons }
}

interface FreeText {
  cells_inspected: number
  findings: { email: number; phone: number; secret: number; instruction_like: number }
}

function scanFreeText(values: string[]): FreeText | null {
  const present = values.map(v => v.trim()).filter(v => v)
  if (present.length === 0) return null
  const sample = present.slice(0, 200)
  if (sample.filter(v => /\s/.test(v)).length < Math.max(1, Math.ceil(sample.length * 0.2))) return null
  const cells = present.slice(0, FREE_TEXT_MAX_CELLS)
  const findings = { email: 0, phone: 0, secret: 0, instruction_like: 0 }
  for (const cell of cells) {
    if (EMBEDDED_EMAIL_RE.test(cell)) findings.email++
    if (EMBEDDED_PHONE_RES.some(rx => rx.test(cell))) findings.phone++
    if (containsSecretFormat(cell)) findings.secret++
    if (INSTRUCTION_PATTERNS.some(rx => rx.test(cell))) findings.instruction_like++
  }
  return { cells_inspected: cells.length, findings }
}

function applyFreeText(classification: Cls, reasons: string[], ft: FreeText) {
  const f = ft.findings
  if (f.secret) {
    classification = raise(classification, 'Secret / High Risk')
    if (!reasons.includes('values contain known secret/token formats')) addReason(reasons, `free text contains secret-like strings in ${f.secret} cell(s)`)
  }
  if (f.email) {
    classification = raise(classification, 'PII')
    addReason(reasons, `free text contains email addresses in ${f.email} cell(s)`)
  }
  if (f.phone) {
    classification = raise(classification, 'PII')
    addReason(reasons, `free text contains phone numbers in ${f.phone} cell(s)`)
  }
  if (f.instruction_like) addReason(reasons, `instruction-like text in ${f.instruction_like} cell(s) (warning only)`)
  return { classification, reasons }
}

export interface ColumnProfile {
  name: string
  type: string
  missing_count: number
  missing_percent: number
  unique_count: number
  classification: Cls
  reasons: string[]
  free_text?: true
  free_text_inspection?: FreeText
  review_recommended?: true
  numeric?: { min: number; max: number; average: number }
  stats_withheld?: string
}

export function scanCsvText(text: string, filename: string) {
  const parsed = parseCsv(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text)
  const fields = parsed[0]
  if (!fields || fields.length === 0) throw new Error('CSV has no header row.')
  // Python's DictReader: skip blank rows, pad short rows, ignore extra cells, later duplicate headers win.
  const lastIndex = new Map<string, number>()
  fields.forEach((f, i) => lastIndex.set(f, i))
  const rows = parsed.slice(1).filter(r => r.length > 0)
  const cell = (r: string[], field: string) => r[lastIndex.get(field)!] ?? ''
  const seen = new Set<string>()
  for (const r of rows) seen.add(JSON.stringify(fields.map(f => cell(r, f))))
  const duplicateRows = rows.length - seen.size

  const columns: ColumnProfile[] = []
  let highest = 0
  for (const field of fields) {
    const values = rows.map(r => cell(r, field))
    const missing = values.filter(v => !v.trim()).length
    const inferred = inferType(values)
    let { classification, reasons } = classifyColumn(field, values)
    const ft = inferred === 'text' ? scanFreeText(values) : null
    if (ft) ({ classification, reasons } = applyFreeText(classification, reasons, ft))
    highest = Math.max(highest, RISK[classification])
    const profile: ColumnProfile = {
      name: field, type: inferred, missing_count: missing,
      missing_percent: rows.length ? round((missing / rows.length) * 100, 2) : 0,
      unique_count: new Set(values.filter(v => v.trim())).size,
      classification, reasons,
    }
    if (ft) {
      profile.free_text = true
      profile.free_text_inspection = ft
      if (Object.values(ft.findings).some(x => x)) profile.review_recommended = true
    }
    if (inferred === 'number') {
      if (classification !== 'Standard') profile.stats_withheld = `column classified as ${classification}`
      else {
        const nums = values.map(maybeNumber).filter((n): n is number => n !== null)
        if (nums.length) profile.numeric = { min: Math.min(...nums), max: Math.max(...nums), average: round(nums.reduce((a, b) => a + b, 0) / nums.length, 4) }
      }
    }
    columns.push(profile)
  }
  const anyReview = columns.some(c => c.review_recommended)
  const readiness = highest >= 3 ? 'Sensitive data detected' : highest >= 1 || anyReview ? 'Review recommended' : 'No findings (heuristic)'
  return {
    product: 'Cognisentry AI',
    scanner: 'Local CSV Security & Data Quality Scanner PoC',
    privacy: { processing: 'local', uploaded: false, note: 'This script reads the CSV locally and does not send it to any external service.' },
    dataset: { filename, rows: rows.length, columns: fields.length, duplicate_rows: duplicateRows },
    ai_analysis_readiness: readiness,
    flagged_fields: columns.filter(c => c.classification !== 'Standard' || c.review_recommended).map(c => ({ name: c.name, classification: c.classification, reasons: c.reasons })),
    column_profiles: columns,
    limitations: [
      'Heuristic detection can produce false positives and false negatives.',
      'This PoC does not provide compliance certification or a security guarantee.',
      'No Claude API call is made by this scanner.',
      'Free-text inspection covers at most the first 1000 non-empty values per column.',
      'Instruction-like text detection is a warning signal only, not a security boundary.',
    ],
  }
}
