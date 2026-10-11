import { requiredAcknowledgements } from './prepareSafeContext.ts'
import { serializeRequest } from './request.ts'
import { validateSafeContext } from './validateContext.ts'
import { ACK_CODES, REQUEST_VERSION } from './schema.ts'
import type { AckCode, SafeContext } from './schema.ts'
export type ValidationCode = 'malformed_json' | 'invalid_request' | 'noncanonical_body' | 'acknowledgement_required'
export type ValidationResult = { ok: true; context: SafeContext; acknowledged: AckCode[] } | { ok: false; code: ValidationCode; message: string }
export function validateSafeContextRequest(body: string): ValidationResult {
  const invalid = (): ValidationResult => ({ ok: false, code: 'invalid_request', message: 'Request violates the safe-context allowlist.' })
  if (typeof body !== 'string' || new TextEncoder().encode(body).length > 64 * 1024) return invalid()
  let raw: unknown
  try { raw = JSON.parse(body) } catch { return { ok: false, code: 'malformed_json', message: 'Body is not valid JSON.' } }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return invalid()
  const p = raw as Record<string, unknown>
  if (Object.keys(p).length !== 3 || !['request_schema', 'safe_context', 'acknowledged'].every(k => Object.hasOwn(p, k)) || p.request_schema !== REQUEST_VERSION || !validateSafeContext(p.safe_context)) return invalid()
  if (!Array.isArray(p.acknowledged) || !p.acknowledged.every(c => (ACK_CODES as readonly unknown[]).includes(c))) return invalid()
  const acknowledged = p.acknowledged as AckCode[]
  if (serializeRequest(p.safe_context, acknowledged) !== body) return { ok: false, code: 'noncanonical_body', message: 'Body is not the canonical serialization of its contents.' }
  if (requiredAcknowledgements(p.safe_context).some(c => !acknowledged.includes(c))) return { ok: false, code: 'acknowledgement_required', message: 'Required acknowledgements are missing.' }
  return { ok: true, context: p.safe_context, acknowledged }
}
