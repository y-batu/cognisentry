// Local preview only. Does not auto-acknowledge warnings or contact a gateway.
import { readFileSync } from 'node:fs'
import { prepareSafeContext, buildSafeContextRequest } from '../src/safeContext/index.ts'
const report: unknown = JSON.parse(readFileSync(new URL('../poc/sample_scan_report.json', import.meta.url), 'utf8'))
const prepared = prepareSafeContext(report)
if (prepared.status === 'blocked') throw new Error(prepared.error.message)
const request = await buildSafeContextRequest(prepared.context, [])
console.log(request.body)
console.log(`SHA-256: ${request.sha256}`)
console.log(`Required acknowledgements: ${request.missing.join(', ')}`)
