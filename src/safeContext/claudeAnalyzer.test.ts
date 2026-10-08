import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { ANALYSIS_MODEL, analyzerFromEnv, createClaudeAnalyzer, parseAnalysis } from '../../gateway/claudeAnalyzer.ts'
import type { MessagesClient } from '../../gateway/claudeAnalyzer.ts'
import { createMemoryRateStore, handleAnalyze } from '../../gateway/handler.ts'
import { prepareSafeContext, serializeRequest } from './index.ts'

const root = fileURLToPath(new URL('../../', import.meta.url))
const report: unknown = JSON.parse(readFileSync(root + 'poc/sample_scan_report.json', 'utf8'))
const prepared = prepareSafeContext(report)
assert.ok(prepared.ok)
const context = prepared.value

const GOOD = {
  summary: 'Customer activity table; half of the columns are withheld.',
  data_quality_notes: [{ column: 'region', note: 'One duplicate row exists.' }, { column: null, note: 'Small sample.' }],
  suggested_questions: ['Which plans have the highest activity?'],
  limitations: ['Metadata only.'],
}

type Params = Parameters<MessagesClient['messages']['create']>[0]
function fakeClient(reply: Record<string, unknown>) {
  const calls: Params[] = []
  const client = {
    messages: {
      create: async (params: Params) => {
        calls.push(params)
        return { stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify(GOOD) }], ...reply }
      },
    },
  } as unknown as MessagesClient
  return { client, calls }
}
const signal = () => new AbortController().signal

test('sends only the safe context, with the pinned model and a JSON schema', async () => {
  const { client, calls } = fakeClient({})
  const analysis = await createClaudeAnalyzer(client)(context, signal())
  assert.deepEqual(analysis, GOOD)
  assert.equal(calls.length, 1)
  const call = calls[0]!
  assert.equal(call.model, ANALYSIS_MODEL)
  assert.equal(call.output_config?.format?.type, 'json_schema')
  assert.equal(call.messages.length, 1)
  assert.ok(String(call.messages[0]!.content).includes('safe-context/1'))
  assert.ok(!('tool_choice' in call) && !('temperature' in call) && !('thinking' in call))
})

test('prompt carries no cell values or filename from the sample dataset', async () => {
  const { client, calls } = fakeClient({})
  await createClaudeAnalyzer(client)(context, signal())
  const sent = JSON.stringify(calls[0])
  const csv = readFileSync(root + 'poc/sample_customer_activity.csv', 'utf8').split('\n').slice(1)
  for (const cell of csv.flatMap(l => l.split(',')).filter(c => c.length > 4)) {
    assert.ok(!sent.includes(cell), `cell value leaked: ${cell}`)
  }
  assert.ok(!sent.includes('sample_customer_activity'))
})

test('refusals, truncation and empty replies are errors', async () => {
  for (const reply of [{ stop_reason: 'refusal' }, { stop_reason: 'max_tokens' }, { content: [] }]) {
    await assert.rejects(createClaudeAnalyzer(fakeClient(reply).client)(context, signal()))
  }
})

test('parseAnalysis rejects malformed model output', () => {
  assert.deepEqual(parseAnalysis(JSON.stringify(GOOD)), GOOD)
  for (const bad of [
    'not json',
    '[]',
    JSON.stringify({ ...GOOD, summary: '' }),
    JSON.stringify({ ...GOOD, limitations: [1] }),
    JSON.stringify({ ...GOOD, data_quality_notes: [{ column: 5, note: 'x' }] }),
    JSON.stringify({ ...GOOD, suggested_questions: Array(21).fill('q') }),
  ]) {
    assert.throws(() => parseAnalysis(bad), /./, bad)
  }
})

test('extra keys from the model are dropped', () => {
  const out = parseAnalysis(JSON.stringify({ ...GOOD, secret: 'x' })) as unknown as Record<string, unknown>
  assert.ok(!('secret' in out))
})

test('full gateway flow returns a live analysis for a valid request', async () => {
  const analyzer = createClaudeAnalyzer(fakeClient({}).client)
  const body = serializeRequest(context, ['heuristic_detection', 'withheld_columns'])
  const res = await handleAnalyze(
    new Request('https://x/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
    { rateStore: createMemoryRateStore(), analyzer },
  )
  const json: any = await res.json()
  assert.equal(res.status, 200)
  assert.equal(json.mode, 'live')
  assert.deepEqual(json.analysis, GOOD)
})

test('an invalid request never reaches the model', async () => {
  const { client, calls } = fakeClient({})
  const res = await handleAnalyze(
    new Request('https://x/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"hello":1}' }),
    { rateStore: createMemoryRateStore(), analyzer: createClaudeAnalyzer(client) },
  )
  assert.equal(res.status, 422)
  assert.equal(calls.length, 0)
})

test('upstream failures return a generic 502 without echoing error text', async () => {
  const client = { messages: { create: async () => { throw new Error('boom: leaked-detail') } } } as unknown as MessagesClient
  const body = serializeRequest(context, ['heuristic_detection', 'withheld_columns'])
  const res = await handleAnalyze(
    new Request('https://x/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
    { rateStore: createMemoryRateStore(), analyzer: createClaudeAnalyzer(client) },
  )
  assert.equal(res.status, 502)
  assert.ok(!(await res.text()).includes('leaked-detail'))
})

test('without ANTHROPIC_API_KEY the gateway stays in mock mode', () => {
  assert.equal(analyzerFromEnv({}), undefined)
  assert.equal(analyzerFromEnv({ ANTHROPIC_API_KEY: '' }), undefined)
  assert.equal(typeof analyzerFromEnv({ ANTHROPIC_API_KEY: 'test-key' }), 'function')
})

test('no API key is committed anywhere in gateway code', () => {
  for (const f of ['gateway/claudeAnalyzer.ts', 'gateway/handler.ts', 'functions/api/analyze.ts']) {
    assert.ok(!/sk-ant-[A-Za-z0-9_-]{10,}/.test(readFileSync(root + f, 'utf8')), f)
  }
})
