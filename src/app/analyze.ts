// The ONLY module in the browser app allowed to touch the network (enforced by app.test.ts).
//
// It sends exactly one thing to exactly one endpoint: the previewed request body, unchanged,
// to /api/analyze, and only when every required acknowledgement is present. It never sees
// the CSV, the scan report, or any cell value.

import type { SafeContextRequest } from '../safeContext/index.ts'

export const ANALYZE_ENDPOINT = '/api/analyze'

export interface AnalysisResult {
  mode: 'live' | 'mock'
  analysis: {
    summary: string
    data_quality_notes: { column: string | null; note: string }[]
    suggested_questions: string[]
    limitations: string[]
  } | null
  payload_sha256: string
}

export async function requestAnalysis(request: SafeContextRequest, signal?: AbortSignal): Promise<AnalysisResult> {
  if (!request.ready) throw new Error('Acknowledgements are required before anything can be sent.')
  const res = await fetch(ANALYZE_ENDPOINT, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-payload-sha256': request.sha256 },
    body: request.body,
    signal,
  })
  const json: unknown = await res.json().catch(() => null)
  if (!res.ok) {
    const message = (json as { error?: { message?: unknown } } | null)?.error?.message
    throw new Error(typeof message === 'string' ? message : `Request failed (${res.status}).`)
  }
  return json as AnalysisResult
}
