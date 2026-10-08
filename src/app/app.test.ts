import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { buildSafeContextRequest, prepareSafeContext } from '../safeContext/index.ts'
import { ANALYZE_ENDPOINT, requestAnalysis } from './analyze.ts'

// The privacy claim is enforced in code: the browser may talk to the network only through
// src/app/analyze.ts, and that module may only send the previewed request body to one endpoint.
const dirs = ['../app/', '../components/', '../scanner/', '../safeContext/'].map(d => fileURLToPath(new URL(d, import.meta.url)))
const sources = dirs.flatMap(dir =>
  readdirSync(dir, { recursive: true, encoding: 'utf8' })
    .filter(f => /\.(ts|tsx)$/.test(f) && !/\.test\.ts$/.test(f))
    .map(f => ({ file: dir + f, text: readFileSync(dir + f, 'utf8') })),
)
const NETWORK = /\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|importScripts/
const isGate = (file: string) => file.endsWith('/src/app/analyze.ts')

test('only analyze.ts may use network APIs', () => {
  assert.ok(sources.length > 10)
  for (const { file, text } of sources) {
    if (isGate(file)) continue
    assert.ok(!NETWORK.test(text), `${file} must not use network APIs`)
  }
})

test('analyze.ts makes exactly one request, to one fixed endpoint, with the previewed body', () => {
  const gate = sources.find(s => isGate(s.file))!.text
  assert.equal(gate.match(/\bfetch\s*\(/g)?.length, 1)
  assert.ok(!/XMLHttpRequest|sendBeacon|WebSocket|EventSource|importScripts/.test(gate))
  assert.equal(ANALYZE_ENDPOINT, '/api/analyze')
  assert.match(gate, /fetch\(ANALYZE_ENDPOINT,/)
  assert.match(gate, /body: request\.body,/)
  assert.match(gate, /if \(!request\.ready\) throw/)
  assert.ok(!/scanCsvText|column_profiles|readAsText|\.text\(\)/.test(gate), 'the gate must never touch the CSV or the scan report')
})

test('client code has no API keys, env access or model references', () => {
  for (const { file, text } of sources) {
    assert.ok(!/import\.meta\.env|process\.env|x-api-key|ANTHROPIC|sk-ant/i.test(text), file)
  }
})

test('UI states what is sent and requires acknowledgement', () => {
  const app = readFileSync(fileURLToPath(new URL('./App.tsx', import.meta.url)), 'utf8')
  assert.ok(app.includes('Local analysis: this file is processed in your browser and is not uploaded.'))
  assert.ok(app.includes('Nothing is sent until you acknowledge the warnings and press the button.'))
  assert.match(app, /disabled=\{!request\?\.ready/)
})

async function readyRequest(ack: boolean) {
  const report = JSON.parse(readFileSync(fileURLToPath(new URL('../../poc/sample_scan_report.json', import.meta.url)), 'utf8'))
  const prepared = prepareSafeContext(report)
  assert.ok(prepared.ok)
  return buildSafeContextRequest(prepared.value, ack ? ['heuristic_detection', 'withheld_columns'] : [])
}

test('requestAnalysis refuses to send without acknowledgements', async () => {
  const realFetch = globalThis.fetch
  let called = false
  globalThis.fetch = (async () => { called = true; return new Response('{}') }) as typeof fetch
  try {
    await assert.rejects(requestAnalysis(await readyRequest(false)), /Acknowledgements/)
    assert.equal(called, false)
  } finally {
    globalThis.fetch = realFetch
  }
})

test('requestAnalysis posts the previewed body unchanged with its hash', async () => {
  const realFetch = globalThis.fetch
  let seen: { url: string; init: RequestInit } | undefined
  globalThis.fetch = (async (url: string, init: RequestInit) => {
    seen = { url, init }
    return new Response(JSON.stringify({ mode: 'mock', analysis: null, payload_sha256: 'x' }), { status: 200 })
  }) as unknown as typeof fetch
  try {
    const request = await readyRequest(true)
    const result = await requestAnalysis(request)
    assert.equal(result.mode, 'mock')
    assert.equal(seen?.url, '/api/analyze')
    assert.equal(seen?.init.method, 'POST')
    assert.equal(seen?.init.body, request.body)
    assert.equal((seen?.init.headers as Record<string, string>)['x-payload-sha256'], request.sha256)
  } finally {
    globalThis.fetch = realFetch
  }
})

test('requestAnalysis surfaces the server error message', async () => {
  const realFetch = globalThis.fetch
  globalThis.fetch = (async () => new Response(JSON.stringify({ error: { code: 'rate_limited', message: 'Too many requests.' } }), { status: 429 })) as unknown as typeof fetch
  try {
    await assert.rejects(requestAnalysis(await readyRequest(true)), /Too many requests\./)
  } finally {
    globalThis.fetch = realFetch
  }
})
