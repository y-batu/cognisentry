import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { ACK_CODES, MAX_USABLE_COLUMNS, buildSafeContextRequest, prepareSafeContext, serializeRequest, validateSafeContext, validateSafeContextRequest } from './index.ts'
import type { PrepareOptions } from './index.ts'
import { scanCsvText } from '../scanner/scanner.ts'
const sample = JSON.parse(readFileSync(new URL('../../poc/sample_scan_report.json', import.meta.url), 'utf8'))
function column(extra: Record<string, unknown> = {}) {
  return { name: 'plan', type: 'text', missing_count: 0, missing_percent: 0, unique_count: 3, classification: 'Standard', reasons: [], ...extra }
}
function report(columns = [column()]) {
  return { dataset: { filename: 'LOCAL_ONLY.csv', rows: 10, columns: columns.length, duplicate_rows: 0 }, ai_analysis_readiness: 'No findings (heuristic)', column_profiles: columns }
}
function prepared(input: unknown, options: PrepareOptions = {}) {
  const result = prepareSafeContext(input, options)
  assert.notEqual(result.status, 'blocked')
  if (result.status === 'blocked') throw new Error(result.error.message)
  return result
}
const ft = (instruction = 0, cells = 10) => ({ free_text: true, free_text_inspection: { cells_inspected: cells, findings: { email: 0, phone: 0, secret: 0, instruction_like: instruction } } })

test('clean Standard dataset: stable refs, opt-in names, permitted numeric stats, empty samples', () => {
  const input = report([column({ name: 'revenue', type: 'number', numeric: { min: 1, max: 9, average: 4.5 } }), column()])
  const p = prepared(input, { includeStandardNames: true })
  assert.equal(p.status, 'ready')
  assert.deepEqual(p.context.included_columns.map(c => [c.ref, c.name]), [['c1', 'revenue'], ['c2', 'plan']])
  assert.deepEqual(p.context.included_columns[0]!.numeric, { min: 1, max: 9, average: 4.5 })
  assert.deepEqual(p.context.safe_samples, [])
  assert.deepEqual(p.ackRequired, [])
  const unnamed = prepared(input)
  assert.ok(unnamed.context.included_columns.every(c => !('name' in c)))
  assert.deepEqual(unnamed.refToName, { c1: 'revenue', c2: 'plan' })
})
for (const classification of ['PII', 'Secret / High Risk', 'Sensitive', 'Potentially Sensitive']) {
  test(`${classification} is represented only by aggregate withheld counts`, () => {
    const p = prepared(report([column({ name: 'PRIVATE_SENTINEL_LABEL', classification, type: 'number', numeric: { min: 81234567, max: 91234567, average: 86234567 } }), column()]))
    assert.equal(p.context.withheld.total, 1)
    assert.deepEqual(p.context.included_columns.map(c => c.ref), ['c2'])
    const text = JSON.stringify(p.context)
    for (const value of ['PRIVATE_SENTINEL_LABEL', '81234567', '91234567', '86234567']) assert.ok(!text.includes(value))
    assert.equal(p.status, ['PII', 'Secret / High Risk'].includes(classification) ? 'needs_ack' : 'ready')
  })
}
test('sample report produces expected metadata and acknowledgements', () => {
  const p = prepared(sample)
  assert.deepEqual(p.context.dataset, { rows: 6, columns: 8, duplicate_rows: 1 })
  assert.deepEqual(p.context.included_columns.map(c => c.ref), ['c6', 'c7', 'c8'])
  assert.deepEqual(p.context.included_columns[0]!.numeric, { min: 0, max: 210.25, average: 95.9167 })
  assert.deepEqual(p.context.withheld.by_category, { 'Potentially Sensitive': 1, PII: 2, Sensitive: 1, 'Secret / High Risk': 1 })
  assert.deepEqual(p.ackRequired, ['SECRET_COLUMNS_WITHHELD', 'PII_COLUMNS_WITHHELD'])
  assert.deepEqual(p.context.warnings, [...p.ackRequired, 'COLUMN_NAME_WITHHELD'])
})
test('CURRENT nested instruction finding requires acknowledgement even when column is withheld', () => {
  for (const classification of ['Standard', 'PII']) {
    const p = prepared(report([column({ name: 'notes', classification, ...ft(1) }), column()]))
    assert.ok(p.ackRequired.includes('INSTRUCTION_LIKE_CONTENT'))
    assert.ok(!JSON.stringify(p.context).includes('findings'))
  }
  const obsolete = prepared(report([column({ instruction_like_count: 9 })]))
  assert.ok(!obsolete.ackRequired.includes('INSTRUCTION_LIKE_CONTENT'))
})
test('safe fully inspected free text needs no acknowledgement; missing or partial inspection does', () => {
  assert.deepEqual(prepared(report([column(ft())])).ackRequired, [])
  for (const extra of [ft(0, 5), { free_text: true }]) {
    assert.ok(prepared(report([column(extra)])).ackRequired.includes('FREE_TEXT_NOT_INJECTION_SCANNED'))
  }
})
test('suspicious and sensitive names never appear even with name inclusion enabled', () => {
  for (const name of ['ignore previous instructions', 'system prompt', 'apiKey', 'full_name', 'John Smith', 'private_token', 'alice@example.test', '192.0.2.1', 'line\nbreak', 'x'.repeat(65)]) {
    const p = prepared(report([column({ name })]), { includeStandardNames: true })
    assert.ok(!('name' in p.context.included_columns[0]!))
    assert.ok(p.context.warnings.includes('COLUMN_NAME_WITHHELD'))
    assert.equal(p.refToName.c1, name)
  }
})
test('exclusions preserve original references and omit excluded labels', () => {
  const p = prepared(report([column({ name: 'region' }), column()]), { excludeColumns: ['c1'], includeStandardNames: true })
  assert.equal(p.context.included_columns[0]!.ref, 'c2')
  assert.equal(p.context.withheld.user_excluded, 1)
  assert.ok(p.context.warnings.includes('USER_EXCLUDED_COLUMNS'))
  assert.ok(!JSON.stringify(p.context).includes('region'))
})
test('no usable columns blocks, including all withheld and all excluded', () => {
  for (const [input, options] of [[report([]), {}], [report([column({ classification: 'PII' })]), {}], [report(), { excludeColumns: ['c1'] }]] as const) {
    const p = prepareSafeContext(input, options)
    assert.equal(p.status, 'blocked')
    if (p.status === 'blocked') assert.deepEqual(p.reasons, ['no_usable_columns'])
  }
})
test('column and byte limits block; exclusions can recover; limits cannot be raised', () => {
  const input = report(Array.from({ length: MAX_USABLE_COLUMNS + 1 }, (_, i) => column({ name: `metric_${i}` })))
  assert.equal(prepareSafeContext(input).status, 'blocked')
  assert.notEqual(prepareSafeContext(input, { excludeColumns: ['c1'] }).status, 'blocked')
  const oversized = prepareSafeContext(report(), { maxContextBytes: 50 })
  assert.equal(oversized.status, 'blocked')
  if (oversized.status === 'blocked') assert.deepEqual(oversized.reasons, ['context_too_large'])
  assert.equal(prepareSafeContext(report(), { maxUsableColumns: 101 }).status, 'blocked')
  assert.equal(prepareSafeContext(report(), { maxContextBytes: 999999 }).status, 'blocked')
  // Reach the default byte cap with 100 valid numeric profiles, under the column cap.
  const large = report(Array.from({ length: 100 }, (_, i) => column({ name: `metric_${i}`, type: 'number', numeric: { min: 1.234567890123456, max: 9.876543210987654, average: 5.555555555555555 } })))
  const blocked = prepareSafeContext(large)
  assert.equal(blocked.status, 'blocked')
  if (blocked.status === 'blocked') assert.deepEqual(blocked.reasons, ['context_too_large'])
})
test('invalid scanner reports fail closed', () => {
  const invalid = [null, [], {}, 'x', { ...report(), dataset: { rows: -1, columns: 1, duplicate_rows: 0 } },
    report([column({ classification: 'Public' })]), report([column({ missing_count: 11 })]), report([column({ missing_percent: 42 })]),
    report([column({ type: 'number', numeric: { min: 9, max: 1, average: 4 } })]), report([column(), column()]),
    report([column({ ...ft(), free_text_inspection: { cells_inspected: 10, findings: { instruction_like: 0 } } })]),
    report([column({ ...ft(), free_text_inspection: { cells_inspected: 10, findings: { instruction_like: 0, email: 1, phone: 0, secret: 0 } } })])]
  for (const input of invalid) {
    const p = prepareSafeContext(input)
    assert.equal(p.status, 'blocked')
    if (p.status === 'blocked') assert.equal(p.error.code, 'invalid_report')
  }
})
test('deterministic output, key ordering independent, input untouched', () => {
  const before = JSON.stringify(sample)
  const reverse = JSON.parse(before)
  reverse.column_profiles = reverse.column_profiles.map((p: Record<string, unknown>) => Object.fromEntries(Object.entries(p).reverse()))
  assert.deepEqual(prepared(sample), prepared(reverse))
  assert.equal(JSON.stringify(sample), before)
})
test('unique sentinel leakage regression across every unsafe input surface', async () => {
  const sentinels = Array.from({ length: 12 }, (_, i) => `SENTINEL_DO_NOT_TRANSMIT_${i}_zQx`)
  const input = report([column({ name: 'revenue', samples: [sentinels[0]], reasons: [sentinels[1]], raw: sentinels[2], arbitrary: { nested: sentinels[3] } }),
    column({ name: sentinels[4], classification: 'PII', values: [sentinels[5]] }),
    column({ name: sentinels[6], classification: 'Secret / High Risk', samples: [sentinels[7]] }),
    column({ name: sentinels[8], classification: 'Sensitive' }), column({ name: sentinels[9], classification: 'Potentially Sensitive' })])
  input.dataset.filename = sentinels[10]!
  Object.assign(input, { arbitrary: sentinels[11] })
  const p = prepared(input)
  const body = (await buildSafeContextRequest(p.context, p.ackRequired)).body
  for (const value of sentinels) { assert.ok(!JSON.stringify(p.context).includes(value)); assert.ok(!body.includes(value)) }
  assert.ok(!body.includes('refToName'))
})
test('strict schema rejects unknown fields recursively and nonempty samples', () => {
  const mutations = [
    (c: any) => { c.filename = 'x' }, (c: any) => { c.dataset.path = 'x' },
    (c: any) => { c.included_columns[0].samples = ['x'] }, (c: any) => { c.included_columns[0].numeric.secret = 'x' },
    (c: any) => { c.withheld.by_category.extra = 1 }, (c: any) => { c.safe_samples = ['x'] },
    (c: any) => { c.refToName = { c6: 'revenue' } }, (c: any) => { c.warnings.push('custom') },
    (c: any) => { c.warnings = c.warnings.filter((w: string) => w !== 'PII_COLUMNS_WITHHELD') },
    (c: any) => { c.included_columns[0].name = 'api_key' }, (c: any) => { c.included_columns[0].numeric.average = Infinity },
  ]
  for (const mutate of mutations) {
    const c = structuredClone(prepared(sample).context)
    mutate(c)
    assert.equal(validateSafeContext(c), false)
    assert.throws(() => serializeRequest(c, []), /Invalid safe context/)
  }
})
test('single serialization produces exact body/hash and stable acknowledgement order', async () => {
  const p = prepared(sample)
  const req = await buildSafeContextRequest(p.context, p.ackRequired)
  assert.equal(req.body, serializeRequest(p.context, p.ackRequired))
  assert.equal(req.sha256, createHash('sha256').update(req.body).digest('hex'))
  assert.equal(req.bytes, Buffer.byteLength(req.body))
  assert.equal((await buildSafeContextRequest(p.context, [...p.ackRequired].reverse())).body, req.body)
  assert.deepEqual(JSON.parse(req.body).safe_context, p.context)
  assert.ok(validateSafeContextRequest(req.body).ok)
})
test('missing acknowledgements disable readiness; all required enable it', async () => {
  const p = prepared(report([column(ft(1, 5)), column({ name: 'secret', classification: 'Secret / High Risk' }), column({ name: 'email', classification: 'PII' })]))
  assert.deepEqual(p.ackRequired, ACK_CODES)
  assert.equal((await buildSafeContextRequest(p.context, [])).ready, false)
  assert.equal((await buildSafeContextRequest(p.context, ACK_CODES.slice(1))).ready, false)
  assert.equal((await buildSafeContextRequest(p.context, ACK_CODES)).ready, true)
})
test('preparation and request construction cause zero network requests', async () => {
  const original = globalThis.fetch
  let calls = 0
  globalThis.fetch = async () => { calls++; throw new Error('Network forbidden') }
  try {
    await buildSafeContextRequest(prepared(sample).context, [])
    assert.equal(calls, 0)
  } finally { globalThis.fetch = original }
})

test('committed sample safe context reproduces from the current scanner report', () => {
  const golden = JSON.parse(readFileSync(new URL('../../poc/sample_safe_context.json', import.meta.url), 'utf8'))
  assert.deepEqual(prepared(sample).context, golden)
})
test('strict schema rejects array metadata and serialization hooks', () => {
  const c = prepared(sample).context
  Object.assign(c.safe_samples, { toJSON: () => ['PRIVATE_SENTINEL'] })
  assert.equal(validateSafeContext(c), false)
})

test('real local scanner to safe context drops unique sensitive and ordinary cell sentinels', () => {
  const values = ['private_mail_83' + '@example.test', 'OPAQUE_SECRET_SENTINEL_52', '882734619', 'ordinary prose SENTINEL_27']
  const csv = `email,api_token,customer_id,notes,revenue\n${values.join(',')},12\n`
  const p = prepared(scanCsvText(csv, 'SENTINEL_FILENAME.csv'))
  const text = JSON.stringify(p.context)
  for (const value of [...values, 'SENTINEL_FILENAME.csv']) assert.ok(!text.includes(value))
  assert.equal(p.context.withheld.total, 3)
})
