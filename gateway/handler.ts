// Mock analysis gateway, written against web-standard Request/Response so the same
// handler can later run as a Cloudflare Pages Function / Worker.
//
// What it does today: validates a safe-context request and answers with a receipt.
// What it does NOT do: call any model, hold any API key, or make any outbound request.
// The Analyzer hook is the single place a future server-side Claude call would attach.

import { validateSafeContextRequest } from '../src/safeContext/validateRequest.ts'
import { sha256Hex } from '../src/safeContext/request.ts'
import type { SafeContext } from '../src/safeContext/schema.ts'

export const MAX_BODY_BYTES = 64 * 1024
export const RATE_LIMIT = { limit: 20, windowMs: 60_000 }

/** Future hook. Receives only the validated safe context; never raw rows. */
export type Analyzer = (context: SafeContext, signal: AbortSignal) => Promise<unknown>

export interface RateStore {
  /** Returns true when the caller is within the limit and records the hit. */
  hit(key: string, now: number): boolean
}

/**
 * In-memory fixed-window limiter. It is per-isolate and therefore best-effort only;
 * production needs a shared store (Cloudflare rate limiting binding, KV or a Durable Object).
 */
export function createMemoryRateStore(limit = RATE_LIMIT.limit, windowMs = RATE_LIMIT.windowMs): RateStore {
  const windows = new Map<string, { start: number; count: number }>()
  return {
    hit(key, now) {
      const w = windows.get(key)
      if (!w || now - w.start >= windowMs) {
        windows.set(key, { start: now, count: 1 })
        return true
      }
      w.count += 1
      return w.count <= limit
    },
  }
}

export interface GatewayDeps {
  rateStore: RateStore
  now?: () => number
  analyzer?: Analyzer
}

const HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
}

function json(status: number, payload: unknown, extra: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(payload), { status, headers: { ...HEADERS, ...extra } })
}
const fail = (status: number, code: string, message: string, extra: Record<string, string> = {}) =>
  json(status, { error: { code, message } }, extra)

function clientKey(req: Request): string {
  return req.headers.get('cf-connecting-ip') ?? 'unknown'
}

async function readBody(req: Request): Promise<string | 'too_large'> {
  const declared = Number(req.headers.get('content-length') ?? '0')
  if (declared > MAX_BODY_BYTES) return 'too_large'
  const reader = req.body?.getReader()
  if (!reader) return ''
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > MAX_BODY_BYTES) {
      await reader.cancel()
      return 'too_large'
    }
    chunks.push(value)
  }
  const buf = new Uint8Array(total)
  let off = 0
  for (const c of chunks) {
    buf.set(c, off)
    off += c.byteLength
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(buf)
}

export async function handleAnalyze(req: Request, deps: GatewayDeps): Promise<Response> {
  if (req.method !== 'POST') return fail(405, 'method_not_allowed', 'Use POST.', { allow: 'POST' })
  const now = (deps.now ?? Date.now)()
  if (!deps.rateStore.hit(clientKey(req), now)) {
    return fail(429, 'rate_limited', 'Too many requests. Try again later.', { 'retry-after': String(Math.ceil(RATE_LIMIT.windowMs / 1000)) })
  }
  if (!(req.headers.get('content-type') ?? '').toLowerCase().startsWith('application/json')) {
    return fail(415, 'unsupported_media_type', 'Content-Type must be application/json.')
  }
  const body = await readBody(req)
  if (body === 'too_large') return fail(413, 'payload_too_large', `Body exceeds ${MAX_BODY_BYTES} bytes.`)

  const result = validateSafeContextRequest(body)
  if (!result.ok) {
    return fail(result.code === 'acknowledgement_required' ? 403 : 422, result.code, result.message)
  }

  const payloadSha256 = await sha256Hex(body)
  const declared = req.headers.get('x-payload-sha256')
  if (declared !== null && declared.toLowerCase() !== payloadSha256) {
    return fail(422, 'hash_mismatch', 'X-Payload-SHA256 does not match the received body.')
  }

  if (!deps.analyzer) {
    // Mock mode: validated, nothing analyzed, no analysis fabricated.
    return json(200, { status: 'validated', mode: 'mock', analysis: null, payload_sha256: payloadSha256, note: 'No model was called.' })
  }
  try {
    const analysis = await deps.analyzer(result.context, AbortSignal.timeout(20_000))
    return json(200, { status: 'analyzed', mode: 'live', analysis, payload_sha256: payloadSha256 })
  } catch {
    // Never echo upstream error text: it could contain request content.
    return fail(502, 'analysis_failed', 'The analysis service failed.')
  }
}
