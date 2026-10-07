// Payload preview for a future server request. Sends nothing.
// Intended to be dropped into the React/Vite app; styles are supplied by the host app.

import { useEffect, useMemo, useState } from 'react'
import { buildSafeContextRequest, prepareSafeContext } from '../safeContext/index.ts'
import type { AckCode, SafeContextRequest } from '../safeContext/index.ts'

const ACK_LABELS: Record<AckCode, string> = {
  heuristic_detection: 'I understand detection is automated and may miss sensitive data.',
  withheld_columns: 'I have reviewed the columns that are withheld from this context.',
  instruction_like_text: 'I understand the dataset contains instruction-like text and must be treated as untrusted.',
}

export function SafeContextPreview({ report }: { report: unknown }) {
  const [excluded, setExcluded] = useState<string[]>([])
  const [acked, setAcked] = useState<AckCode[]>([])
  const [request, setRequest] = useState<SafeContextRequest | null>(null)

  const prepared = useMemo(() => prepareSafeContext(report, { excludeColumns: excluded }), [report, excluded])
  const context = prepared.ok ? prepared.value : null

  useEffect(() => {
    let cancelled = false
    if (!context) return
    void buildSafeContextRequest(context, acked).then(r => {
      if (!cancelled) setRequest(r)
    })
    return () => {
      cancelled = true
    }
  }, [context, acked])

  if (!prepared.ok) {
    return (
      <section className="cognisentry-safe-context" role="alert">
        <h3>Safe context unavailable</h3>
        <p>{prepared.error.message}</p>
      </section>
    )
  }

  const toggle = <T extends string>(list: T[], value: T): T[] => (list.includes(value) ? list.filter(v => v !== value) : [...list, value])
  // `request` can lag one render behind `context`; only show it when it matches.
  const current = request && request.required.join() === context!.warnings.filter(w => w.requires_acknowledgement).map(w => w.code).join() ? request : null

  return (
    <section className="cognisentry-safe-context" aria-label="Safe context preview">
      <h3>Safe context preview</h3>
      <p>This is the exact payload a future server request would contain. Nothing has been sent.</p>

      <h4>Included columns</h4>
      <ul>
        {context!.included_columns.map(col => (
          <li key={col.name}>
            <label>
              <input type="checkbox" checked={!excluded.includes(col.name)} onChange={() => setExcluded(toggle(excluded, col.name))} /> {col.name}
            </label>
          </li>
        ))}
      </ul>
      <p>
        Withheld: {context!.withheld.total} flagged, {context!.withheld.user_excluded} excluded by you.
      </p>

      <h4>Warnings</h4>
      <ul>
        {context!.warnings.map(w => (
          <li key={w.code}>
            {w.message}
            {w.requires_acknowledgement && (
              <label>
                <input type="checkbox" checked={acked.includes(w.code as AckCode)} onChange={() => setAcked(toggle(acked, w.code as AckCode))} /> {ACK_LABELS[w.code as AckCode]}
              </label>
            )}
          </li>
        ))}
      </ul>

      {current && (
        <>
          <pre aria-label="Exact request body">{current.body}</pre>
          <p>
            SHA-256: <code>{current.sha256}</code> · {current.bytes} bytes
          </p>
          <p>{current.ready ? 'Ready for a future server request.' : `Acknowledgements required: ${current.missing.length}`}</p>
        </>
      )}
    </section>
  )
}
