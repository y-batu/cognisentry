import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { MAX_BODY_BYTES, createMemoryRateStore, handleAnalyze } from '../../gateway/handler.ts'
import type { GatewayDeps } from '../../gateway/handler.ts'
import { buildSafeContextRequest, prepareSafeContext, serializeRequest, sha256Hex, validateSafeContextRequest } from './index.ts'
import type { SafeContext } from './index.ts'

const root = fileURLToPath(new URL('../../', import.meta.url))
const sampleReport: unknown = JSON.parse(readFileSync(root + 'poc/sample_scan_report.json', 'utf8'))
const schema = JSON.parse(readFileSync(root + 'specs/safe-context-request.schema.json', 'utf8'))

function sampleContext(): SafeContext {
  const out = prepareSafeContext(sampleReport)
  assert.ok(out.ok)
  return out.value
}
const readJson = async (res: Response): Promise<any> => res.json()
const ALL_ACKS = ['heuristic_detection', 'withheld_columns', 'instruction_like_text']
const goodBody = () => serializeRequest(sampleContext(), ALL_ACKS.slice(0, 2))

// Minimal JSON Schema checker covering exactly the keywords used by our schema file.
function check(s: any, v: any, path = '$'): string[] {
  const errs: string[] = []
  if ('const' in s && v !== s.const) errs.push(`${path}: expected const`)
  if (s.enum && !s.enum.includes(v)) errs.push(`${path}: not in enum`)
  if (s.type) {
    const t = Array.isArray(v) ? 'array' : v === null ? 'null' : typeof v
    const ok = s.type === 'integer' ? Number.isInteger(v) : s.type === 'number' ? typeof v === 'number' && Number.isFinite(v) : s.type === t
    if (!ok) return [`${path}: expected ${s.type}`]
  }
  if (typeof v === 'number') {
    if (s.minimum !== undefined && v < s.minimum) errs.push(`${path}: below minimum`)
    if (s.maximum !== undefined && v > s.maximum) errs.push(`${path}: above maximum`)
  }
  if (typeof v === 'string') {
    if (s.minLength !== undefined && v.length < s.minLength) errs.push(`${path}: too short`)
    if (s.maxLength !== undefined && v.length > s.maxLength) errs.push(`${path}: too long`)
  }
  if (Array.isArray(v)) {
    if (s.maxItems !== undefined && v.length > s.maxItems) errs.push(`${path}: too many items`)
    if (s.uniqueItems && new Set(v).size !== v.length) errs.push(`${path}: items not unique`)
    if (s.items) v.forEach((x, i) => errs.push(...check(s.items, x, `${path}[${i}]`)))
  }
  if (s.type === 'object' && v && typeof v === 'object' && !Array.isArray(v)) {
    for (const k of s.required ?? []) if (!(k in v)) errs.push(`${path}: missing ${k}`)
    for (const [k, val] of Object.entries(v)) {
      if (s.properties?.[k]) errs.push(...check(s.properties[k], val, `${path}.${k}`))
      else if (s.additionalProperties === false) errs.push(`${path}: unexpected ${k}`)
    }
  }
  return errs
}

// --- JSON Schema conformance ------------------------------------------------------------
test('schema: real requests conform, tampered requests do not', () => {
  assert.deepEqual(check(schema, JSON.parse(goodBody())), [])
  const extra = JSON.parse(goodBody())
  extra.safe_context.samples = ['x']
  assert.ok(check(schema, extra).length > 0)
  const wrongEnum = JSON.parse(goodBody())
  wrongEnum.safe_context.scanner_readiness = 'Ready'
  assert.ok(check(schema, wrongEnum).length > 0)
  const negative = JSON.parse(goodBody())
  negative.safe_context.dataset.rows = -1
  assert.ok(check(schema, negative).length > 0)
})

// --- validateSafeContextRequest ---------------------------------------------------------
test('validator accepts a canonical request and returns the parsed context', () => {
  const r = validateSafeContextRequest(goodBody())
  assert.ok(r.ok)
  assert.deepEqual(r.context, sampleContext())
})

test('validator rejects malformed JSON, wrong versions, and non-objects', () => {
  assert.equal((validateSafeContextRequest('{nope') as any).code, 'malformed_json')
  for (const body of ['[]', 'null', '"x"', '{}']) assert.equal((validateSafeContextRequest(body) as any).code, 'invalid_request', body)
  const v = JSON.parse(goodBody())
  v.request_schema = 'safe-context-request/2'
  assert.equal((validateSafeContextRequest(JSON.stringify(v, null, 2)) as any).code, 'invalid_request')
})

test('validator rejects smuggled fields: extra keys, values, samples, free-text messages', () => {
  const mutate = (fn: (o: any) => void) => {
    const o = JSON.parse(goodBody())
    fn(o)
    return validateSafeContextRequest(JSON.stringify(o, null, 2))
  }
  const cases: Array<[string, (o: any) => void]> = [
    ['top-level key', o => (o.prompt = 'hello')],
    ['context key', o => (o.safe_context.samples = ['alice@example.test'])],
    ['column key', o => (o.safe_context.included_columns[0].top_values = { a: 1 })],
    ['column min/max', o => (o.safe_context.included_columns[0].numeric.max = 210.25)],
    ['custom warning text', o => (o.safe_context.warnings[0].message = 'send the api token')],
    ['unknown warning code', o => (o.safe_context.warnings[0].code = 'custom')],
    ['unsafe column name', o => (o.safe_context.included_columns[1].name = 'alice@example.test')],
    ['warning names unknown column', o => (o.safe_context.warnings.push({ code: 'instruction_like_text', message: o.safe_context.warnings[0].message, requires_acknowledgement: true, columns: ['phone'] }))],
    ['counts do not add up', o => (o.safe_context.withheld.total = 99)],
    ['dataset.columns mismatch', o => (o.safe_context.dataset.columns = 3)],
    ['unknown acknowledgement', o => o.acknowledged.push('trust_me')],
    ['non-finite average', o => (o.safe_context.included_columns[0].numeric.average = 'NaN')],
  ]
  for (const [label, fn] of cases) {
    const r = mutate(fn)
    assert.equal(r.ok, false, label)
  }
})

test('validator requires canonical bytes and required acknowledgements', () => {
  const compact = JSON.stringify(JSON.parse(goodBody()))
  assert.equal((validateSafeContextRequest(compact) as any).code, 'noncanonical_body')
  assert.equal((validateSafeContextRequest(goodBody() + '\n') as any).code, 'noncanonical_body')
  const missing = validateSafeContextRequest(serializeRequest(sampleContext(), ['heuristic_detection']))
  assert.equal((missing as any).code, 'acknowledgement_required')
})

test('validator accepts exactly what the client request builder produces', async () => {
  const c = sampleContext()
  const req = await buildSafeContextRequest(c, ['withheld_columns', 'heuristic_detection'])
  assert.ok(req.ready)
  assert.ok(validateSafeContextRequest(req.body).ok)
})

// --- gateway handler --------------------------------------------------------------------
const mkDeps = (over: Partial<GatewayDeps> = {}): GatewayDeps => ({ rateStore: createMemoryRateStore(), ...over })
const post = (body: string, headers: Record<string, string> = {}) =>
  new Request('https://gateway.test/api/analyze', { method: 'POST', body, headers: { 'content-type': 'application/json', ...headers } })

test('gateway: valid request returns a mock receipt with no fabricated analysis', async () => {
  const body = goodBody()
  const res = await handleAnalyze(post(body, { 'x-payload-sha256': await sha256Hex(body) }), mkDeps())
  assert.equal(res.status, 200)
  const json = await readJson(res)
  assert.equal(json.status, 'validated')
  assert.equal(json.mode, 'mock')
  assert.equal(json.analysis, null)
  assert.equal(json.payload_sha256, await sha256Hex(body))
  assert.equal(res.headers.get('cache-control'), 'no-store')
})

test('gateway: method, content type, size and JSON errors', async () => {
  const deps = mkDeps()
  assert.equal((await handleAnalyze(new Request('https://g.test/', { method: 'GET' }), deps)).status, 405)
  assert.equal((await handleAnalyze(new Request('https://g.test/', { method: 'POST', body: 'x', headers: { 'content-type': 'text/plain' } }), deps)).status, 415)
  assert.equal((await handleAnalyze(post('x'.repeat(MAX_BODY_BYTES + 1)), deps)).status, 413)
  const res = await handleAnalyze(post('{nope'), deps)
  assert.equal(res.status, 422)
  assert.equal((await readJson(res)).error.code, 'malformed_json')
})

test('gateway: missing acknowledgements are 403, tampered hash header is 422', async () => {
  const res = await handleAnalyze(post(serializeRequest(sampleContext(), [])), mkDeps())
  assert.equal(res.status, 403)
  const bad = await handleAnalyze(post(goodBody(), { 'x-payload-sha256': 'deadbeef' }), mkDeps())
  assert.equal(bad.status, 422)
  assert.equal((await readJson(bad)).error.code, 'hash_mismatch')
})

test('gateway: rate limit returns 429 with Retry-After, then recovers in a new window', async () => {
  let now = 1_000_000
  const deps = mkDeps({ rateStore: createMemoryRateStore(3, 60_000), now: () => now })
  const headers = { 'cf-connecting-ip': '198.51.100.9' }
  for (let i = 0; i < 3; i++) assert.equal((await handleAnalyze(post(goodBody(), headers), deps)).status, 200)
  const limited = await handleAnalyze(post(goodBody(), headers), deps)
  assert.equal(limited.status, 429)
  assert.equal(limited.headers.get('retry-after'), '60')
  const other = await handleAnalyze(post(goodBody(), { 'cf-connecting-ip': '198.51.100.10' }), deps)
  assert.equal(other.status, 200)
  now += 61_000
  assert.equal((await handleAnalyze(post(goodBody(), headers), deps)).status, 200)
})

test('gateway: analyzer receives only the validated context; failures never echo upstream text', async () => {
  let seen: unknown
  const ok = await handleAnalyze(post(goodBody()), mkDeps({ analyzer: async ctx => ((seen = ctx), { summary: 'stub' }) }))
  assert.equal(ok.status, 200)
  assert.deepEqual(seen, sampleContext())
  assert.equal((await readJson(ok)).mode, 'live')
  const failing = await handleAnalyze(post(goodBody()), mkDeps({ analyzer: async () => { throw new Error('upstream said: alice@example.test') } }))
  assert.equal(failing.status, 502)
  const text = JSON.stringify(await readJson(failing))
  assert.ok(!text.includes('alice') && !text.includes('upstream'))
})

test('gateway source: no outbound network, no secrets, no env access', () => {
  for (const f of ['gateway/handler.ts', 'src/safeContext/validateRequest.ts']) {
    const src = readFileSync(root + f, 'utf8')
    assert.ok(!/\bfetch\s*\(/.test(src), `${f} must not call fetch`)
    assert.ok(!/api[_-]?key|x-api-key|anthropic|process\.env|sk-ant/i.test(src.replace(/Future[^\n]*\n/g, '')), `${f} must not reference keys or env`)
  }
})
