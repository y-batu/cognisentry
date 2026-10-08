# Analysis gateway

`handler.ts` is the server-side entry point for a future safe-context analysis request. It uses web-standard `Request`/`Response` so it can later be wrapped as a Cloudflare Pages Function or Worker.

**Mock mode (default):** strict validation and a receipt. No model is called.

**Live mode:** when `ANTHROPIC_API_KEY` is set in the server environment, `functions/api/analyze.ts` attaches `gateway/claudeAnalyzer.ts` and a valid request produces one Claude call on the validated safe context only. No key exists in this repository (a test checks for key-shaped strings).

| Status | Code | When |
|---|---|---|
| 200 | `validated` / `analyzed` | Valid request (`mode: mock`, `analysis: null` / `mode: live`, structured analysis) |
| 403 | `acknowledgement_required` | Required acknowledgements are missing |
| 405 | `method_not_allowed` | Not POST |
| 413 | `payload_too_large` | Body over 64 KiB |
| 415 | `unsupported_media_type` | Not `application/json` |
| 422 | `malformed_json`, `invalid_request`, `noncanonical_body`, `hash_mismatch` | Body fails validation |
| 429 | `rate_limited` | Over 20 requests/minute per client (best-effort, in-memory) |
| 502 | `analysis_failed` | Analyzer hook threw (error text is never echoed) |

Validation is a strict allowlist: no unknown keys, fixed warning text, column names re-checked, counts must add up, and the body must be byte-identical to the canonical serialization of what it parsed. An optional `X-Payload-SHA256` header is checked against the received body.

The `Analyzer` hook is where the model call attaches. The API key must live in the server environment only.
