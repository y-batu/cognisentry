import { useEffect, useMemo, useRef, useState } from 'react'
import { buildSafeContextRequest, parseScanReport, prepareSafeContext, WARNING_MESSAGES } from '../safeContext/index.ts'
import type { AckCode, SafeContext, SafeContextRequest } from '../safeContext/index.ts'
import { approvePayload } from '../app/approval.ts'

export function SafeContextPreview({ report }: { report: unknown }) {
  const reviewVersion = useRef(0)
  const [excluded, setExcluded] = useState<string[]>([])
  const [includeNames, setIncludeNames] = useState(false)
  const [started, setStarted] = useState(false)
  const [acked, setAcked] = useState<AckCode[]>([])
  const [built, setBuilt] = useState<{ context: SafeContext; acks: AckCode[]; request: SafeContextRequest } | null>(null)
  const [approvedBody, setApprovedBody] = useState<string | null>(null)
  const [buildError, setBuildError] = useState<string | null>(null)
  const parsed = useMemo(() => parseScanReport(report), [report])
  const prepared = useMemo(() => prepareSafeContext(report, { excludeColumns: excluded, includeStandardNames: includeNames }), [report, excluded, includeNames])
  const context = prepared.status === 'blocked' ? null : prepared.context
  useEffect(() => {
    let cancelled = false
    if (!started || !context) return
    void buildSafeContextRequest(context, acked).then(request => {
      if (!cancelled) { setBuilt({ context, acks: acked, request }); setBuildError(null) }
    }).catch(() => { if (!cancelled) setBuildError('Could not compute the payload hash. Approval is unavailable.') })
    return () => { cancelled = true }
  }, [context, acked, started])
  // Identity guards invalidate old previews synchronously, before effects or hashing finish.
  const current = built?.context === context && built.acks === acked ? built.request : null
  const resetReview = () => { reviewVersion.current++; setAcked([]); setBuilt(null); setApprovedBody(null); setBuildError(null) }
  const toggleColumn = (ref: string) => {
    resetReview()
    setExcluded(previous => previous.includes(ref) ? previous.filter(x => x !== ref) : [...previous, ref])
  }
  const approve = async () => {
    if (!current?.ready) return
    const version = reviewVersion.current
    try { await approvePayload(current); if (version === reviewVersion.current) setApprovedBody(current.body) }
    catch { if (version === reviewVersion.current) setBuildError('Payload validation failed. Prepare it again before approving.') }
  }
  return (
    <section className="cognisentry-safe-context" aria-label="Safe context preview">
      <p>Raw dataset values, samples, filenames, sensitive column names and scanner reason strings are not included. Standard numeric columns may include min/max/average; extrema can coincide with individual values.</p>
      <p className="note">Detection is heuristic and can miss sensitive data. Instruction-like detection is a warning, not a security boundary. Review the metadata before approving it.</p>
      <h3>Choose Standard columns</h3>
      <ul>
        {parsed.ok && parsed.value.column_profiles.map((col, index) => col.classification === 'Standard' ? (
          <li key={`c${index + 1}`}><label><input type="checkbox" checked={!excluded.includes(`c${index + 1}`)} onChange={() => toggleColumn(`c${index + 1}`)} /> c{index + 1}: {col.name} <small>(local label)</small></label></li>
        ) : null)}
      </ul>
      <label><input type="checkbox" checked={includeNames} onChange={e => { resetReview(); setIncludeNames(e.target.checked) }} /> Include eligible Standard column names (limited safe vocabulary)</label>
      {!started && <p><button type="button" onClick={() => setStarted(true)}>Prepare AI context</button></p>}
      {started && prepared.status === 'blocked' && <div role="alert"><h3>Preparation blocked</h3><p>{prepared.error.code}: {prepared.error.message}</p></div>}
      {started && context && <>
        <h3>Withheld summary</h3>
        <ul>{Object.entries(context.withheld.by_category).map(([category, count]) => <li key={category}>{category}: {count}</li>)}</ul>
        <p>{context.withheld.user_excluded} user-excluded columns; {context.withheld.column_names} included column names omitted.</p>
        <h3>Warnings and required acknowledgements</h3>
        {context.warnings.length === 0 && <p>No warning acknowledgements are required.</p>}
        <ul>{context.warnings.map(code => <li key={code}>
          <code>{code}</code>: {WARNING_MESSAGES[code]}
          {prepared.status !== 'blocked' && prepared.ackRequired.includes(code as AckCode) && <label>
            <input type="checkbox" checked={acked.includes(code as AckCode)} onChange={() => {
              reviewVersion.current++; setApprovedBody(null); setBuilt(null)
              setAcked(previous => previous.includes(code as AckCode) ? previous.filter(c => c !== code) : [...previous, code as AckCode])
            }} /> I acknowledge this warning.
          </label>}
        </li>)}</ul>
        {current ? <>
          <h3>Exact outbound JSON body</h3>
          <pre aria-label="Exact request body">{current.body}</pre>
          <p>SHA-256: <code>{current.sha256}</code> · {current.bytes} UTF-8 bytes</p>
        </> : <p role="status">Preparing the exact payload and SHA-256…</p>}
      </>}
      {buildError && <p role="alert" className="error">{buildError}</p>}
      {started && <>
        <button type="button" disabled={!current?.ready || prepared.status === 'blocked' || !!buildError} onClick={() => void approve()}>Approve payload</button>
        <p className="note">Approval is local only. No model or gateway is called.</p>
        {current && approvedBody === current.body && <p role="status" className="ok">Payload approved and ready for secure analysis gateway.</p>}
      </>}
    </section>
  )
}
