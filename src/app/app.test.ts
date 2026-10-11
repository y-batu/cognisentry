import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { test } from 'node:test'
import { buildSafeContextRequest, prepareSafeContext } from '../safeContext/index.ts'
import { requestAnalysis } from './analyze.ts'
import { approvePayload } from './approval.ts'
import { onRequest } from '../../functions/api/analyze.ts'
const root = new URL('../../', import.meta.url)
const read = (file: string) => readFileSync(new URL(file, root), 'utf8')
async function request(ack = true) {
  const p = prepareSafeContext(JSON.parse(read('poc/sample_scan_report.json')))
  assert.ok(p.ok)
  return buildSafeContextRequest(p.context, ack ? p.ackRequired : [])
}
test('current app has no gateway call or generated model response', () => {
  const app = read('src/app/App.tsx')
  assert.ok(!/requestAnalysis|AnalysisResult|Send safe context to Claude/.test(app))
  assert.ok(app.includes('key={scanId}'))
  const preview = read('src/components/SafeContextPreview.tsx')
  assert.ok(!preview.includes('JSON.stringify'))
  assert.ok(preview.includes('current.body'))
  assert.ok(preview.includes('built?.context === context && built.acks === acked'))
  assert.ok(preview.includes('disabled={!current?.ready'))
  assert.ok(preview.includes('Payload approved and ready for secure analysis gateway.'))
})
test('only the deferred sender may access browser networking', () => {
  for (const dir of ['src/app', 'src/components', 'src/scanner', 'src/safeContext']) {
    for (const file of readdirSync(new URL(dir, root), { recursive: true, encoding: 'utf8' }).filter(f => /\.(ts|tsx)$/.test(f) && !f.endsWith('.test.ts'))) {
      if (file === 'analyze.ts') continue
      assert.ok(!/\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource/.test(read(`${dir}/${file}`)), file)
    }
  }
})
test('local approval and deferred Cloudflare endpoint perform zero requests', async () => {
  const original = globalThis.fetch
  let calls = 0
  globalThis.fetch = async () => { calls++; throw new Error('Forbidden') }
  try {
    const req = await request()
    assert.deepEqual(await approvePayload(req), { body: req.body, sha256: req.sha256 })
    assert.equal((await onRequest()).status, 503)
    assert.equal(calls, 0)
    await assert.rejects(approvePayload(await request(false)), /Acknowledgements/)
    await assert.rejects(approvePayload({ ...req, sha256: 'bad' }), /hash mismatch/)
    await assert.rejects(approvePayload({ ...await request(false), ready: true }), /Acknowledgements/)
  } finally { globalThis.fetch = original }
})
test('future fetch sends the exact preview string unchanged', async () => {
  const original = globalThis.fetch
  let seen: RequestInit | undefined
  globalThis.fetch = async (_url, init) => { seen = init; return new Response('{"mode":"mock","analysis":null}') }
  try {
    const req = await request()
    await requestAnalysis(req)
    assert.equal(seen?.body, req.body)
    assert.equal((seen?.headers as Record<string, string>)['x-payload-sha256'], req.sha256)
    seen = undefined
    await assert.rejects(requestAnalysis(await request(false)), /Acknowledgements/)
    assert.equal(seen, undefined)
  } finally { globalThis.fetch = original }
})
test('development entrypoint and sample CLI cannot activate historical analyzer', () => {
  for (const file of ['vite.config.ts', 'scripts/analyze-sample.ts', 'functions/api/analyze.ts']) {
    assert.ok(!/analyzerFromEnv|createClaudeAnalyzer/.test(read(file)))
  }
})

test('deferred transport cannot switch bodies during asynchronous approval', async () => {
  const original = globalThis.fetch
  let body: unknown
  globalThis.fetch = async (_url, init) => { body = init?.body; return new Response('{"mode":"mock","analysis":null}') }
  try {
    const req = await request()
    const preview = req.body
    const pending = requestAnalysis(req)
    req.body = 'UNAPPROVED_SENTINEL'
    await pending
    assert.equal(body, preview)
  } finally { globalThis.fetch = original }
})
