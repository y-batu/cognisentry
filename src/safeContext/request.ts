// Builds the exact request body for a future server request.
//
// There is a single serialization path: serializeRequest(). The preview UI shows
// `body` and any future sender must transmit `body` unchanged. Nothing here sends
// anything, and no model name is chosen at this layer.

import { ACK_CODES, REQUEST_VERSION } from './schema.ts'
import type { AckCode, SafeContext } from './schema.ts'
import { requiredAcknowledgements } from './prepareSafeContext.ts'

export interface SafeContextRequest {
  /** The exact string to preview and, later, to send. */
  body: string
  sha256: string
  bytes: number
  required: AckCode[]
  missing: AckCode[]
  /** True only when every required acknowledgement is present. */
  ready: boolean
}

function normalizeAcks(acknowledged: readonly string[]): AckCode[] {
  return ACK_CODES.filter(code => acknowledged.includes(code))
}

export function serializeRequest(context: SafeContext, acknowledged: readonly string[]): string {
  return JSON.stringify(
    { request_schema: REQUEST_VERSION, safe_context: context, acknowledged: normalizeAcks(acknowledged) },
    null,
    2,
  )
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('')
}

export async function buildSafeContextRequest(context: SafeContext, acknowledged: readonly string[]): Promise<SafeContextRequest> {
  const body = serializeRequest(context, acknowledged)
  const have = new Set(normalizeAcks(acknowledged))
  const required = requiredAcknowledgements(context)
  const missing = required.filter(code => !have.has(code))
  return {
    body,
    sha256: await sha256Hex(body),
    bytes: new TextEncoder().encode(body).length,
    required,
    missing,
    ready: missing.length === 0,
  }
}
