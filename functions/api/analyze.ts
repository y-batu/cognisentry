// Cloudflare Pages Function: POST /api/analyze
// Without ANTHROPIC_API_KEY it runs in mock mode (validate + receipt, no model call).

import { analyzerFromEnv } from '../../gateway/claudeAnalyzer.ts'
import { createMemoryRateStore, handleAnalyze } from '../../gateway/handler.ts'

interface Env {
  ANTHROPIC_API_KEY?: string
}

// Per-isolate and best-effort; production needs a shared store (see gateway/README.md).
const rateStore = createMemoryRateStore()

export const onRequest = (ctx: { request: Request; env: Env }): Promise<Response> =>
  handleAnalyze(ctx.request, { rateStore, analyzer: analyzerFromEnv(ctx.env) })
