import { sha256Hex, validateSafeContextRequest } from '../safeContext/index.ts'
import type { SafeContextRequest } from '../safeContext/index.ts'
/** Local receipt only: approval never performs a network request or fabricates analysis. */
export async function approvePayload(request: SafeContextRequest): Promise<{ body: string; sha256: string }> {
  const { body, sha256, ready } = request
  if (!ready || !validateSafeContextRequest(body).ok) throw new Error('Acknowledgements and a valid payload are required.')
  if (await sha256Hex(body) !== sha256) throw new Error('Payload hash mismatch.')
  return { body, sha256 }
}
