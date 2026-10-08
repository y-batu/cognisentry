// End-to-end demo: CSV -> local scan -> safe context -> gateway -> (Claude | mock).
// Usage: node scripts/analyze-sample.ts [file.csv]
// With ANTHROPIC_API_KEY set, the gateway makes one real Claude call on the safe context only.

import { readFileSync } from 'node:fs'
import { basename } from 'node:path'
import { analyzerFromEnv } from '../gateway/claudeAnalyzer.ts'
import { createMemoryRateStore, handleAnalyze } from '../gateway/handler.ts'
import { prepareSafeContext, serializeRequest } from '../src/safeContext/index.ts'
import { scanCsvText } from '../src/scanner/scanner.ts'

const file = process.argv[2] ?? new URL('../poc/sample_customer_activity.csv', import.meta.url).pathname
const report = scanCsvText(readFileSync(file, 'utf8'), basename(file))
const prepared = prepareSafeContext(JSON.parse(JSON.stringify(report)))
if (!prepared.ok) throw new Error(prepared.error.message)

const ctx = prepared.value
const acks = ctx.warnings.filter(w => w.requires_acknowledgement).map(w => w.code)
const body = serializeRequest(ctx, acks)
const analyzer = analyzerFromEnv(process.env)

console.log(`Scan: ${report.dataset.rows} rows, ${report.dataset.columns} columns, readiness "${report.ai_analysis_readiness}"`)
console.log(`Safe context: ${ctx.included_columns.length} columns included, ${ctx.withheld.total} withheld (names not sent)`)
console.log(`Mode: ${analyzer ? 'live (Claude)' : 'mock (set ANTHROPIC_API_KEY for a live call)'}\n`)

const res = await handleAnalyze(
  new Request('https://local/api/analyze', { method: 'POST', headers: { 'content-type': 'application/json' }, body }),
  { rateStore: createMemoryRateStore(), analyzer },
)
console.log(`HTTP ${res.status}`)
console.log(JSON.stringify(await res.json(), null, 2))
