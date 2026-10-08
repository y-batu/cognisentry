import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

// The privacy claim "processed in your browser and not uploaded" must hold in code.
const dirs = ['../app/', '../components/', '../scanner/', '../safeContext/'].map(d => fileURLToPath(new URL(d, import.meta.url)))
const sources = dirs.flatMap(dir =>
  readdirSync(dir, { recursive: true, encoding: 'utf8' })
    .filter(f => /\.(ts|tsx)$/.test(f) && !/\.test\.ts$/.test(f))
    .map(f => ({ file: dir + f, text: readFileSync(dir + f, 'utf8') })),
)

test('client code makes no network requests', () => {
  assert.ok(sources.length > 10)
  for (const { file, text } of sources) {
    assert.ok(!/\bfetch\s*\(|XMLHttpRequest|sendBeacon|WebSocket|EventSource|importScripts/.test(text), `${file} must not use network APIs`)
  }
})

test('client code has no API keys, env access or model references', () => {
  for (const { file, text } of sources) {
    assert.ok(!/import\.meta\.env|process\.env|x-api-key|ANTHROPIC|sk-ant/i.test(text), file)
  }
})

test('privacy statement and disabled Claude section are present in the UI', () => {
  const app = readFileSync(fileURLToPath(new URL('./App.tsx', import.meta.url)), 'utf8')
  assert.ok(app.includes('Local analysis: this file is processed in your browser and is not uploaded.'))
  assert.ok(app.includes('Claude-powered analysis is the next stage of the MVP.'))
  assert.match(app, /<button type="button" disabled>/)
})
