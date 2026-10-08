import { useCallback, useRef, useState } from 'react'
import type { DragEvent } from 'react'
import { SafeContextPreview } from '../components/SafeContextPreview.tsx'
import { validateSafeContextRequest } from '../safeContext/index.ts'
import type { SafeContextRequest } from '../safeContext/index.ts'
import { findQualityIssues } from '../scanner/quality.ts'
import { scanCsvText } from '../scanner/scanner.ts'
import { requestAnalysis } from './analyze.ts'
import type { AnalysisResult } from './analyze.ts'
import sampleCsv from '../../poc/sample_customer_activity.csv?raw'

type Report = ReturnType<typeof scanCsvText>

const MAX_BYTES = 10 * 1024 * 1024
const formatBytes = (n: number) => (n < 1024 ? `${n} B` : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1024 / 1024).toFixed(1)} MB`)
const badgeClass = (c: string) => `badge badge-${c.toLowerCase().replace(/[^a-z]+/g, '-').replace(/-$/, '')}`

export function App() {
  const [report, setReport] = useState<Report | null>(null)
  const [meta, setMeta] = useState<{ name: string; size: number } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragging, setDragging] = useState(false)
  const [request, setRequest] = useState<SafeContextRequest | null>(null)
  const [analysis, setAnalysis] = useState<{ state: 'idle' | 'running' | 'done' | 'error'; result?: AnalysisResult; message?: string }>({ state: 'idle' })
  const input = useRef<HTMLInputElement>(null)

  const load = useCallback((text: string, name: string, size: number) => {
    try {
      setReport(scanCsvText(text, name))
      setMeta({ name, size })
      setError(null)
    } catch (e) {
      setReport(null)
      setMeta(null)
      setError(e instanceof Error ? e.message : 'The file could not be read as CSV.')
    }
    setRequest(null)
    setAnalysis({ state: 'idle' })
  }, [])

  const handleFile = useCallback(
    async (file: File | undefined) => {
      if (!file) return
      if (!/\.csv$/i.test(file.name) && file.type !== 'text/csv') return setError('Please choose a .csv file.')
      if (file.size > MAX_BYTES) return setError(`File is ${formatBytes(file.size)}; the limit for this local scan is ${formatBytes(MAX_BYTES)}.`)
      load(await file.text(), file.name, file.size)
    },
    [load],
  )

  const onDrop = (e: DragEvent) => {
    e.preventDefault()
    setDragging(false)
    void handleFile(e.dataTransfer.files[0])
  }

  const quality = report ? findQualityIssues(report) : []
  const analyze = async () => {
    if (!request?.ready) return
    setAnalysis({ state: 'running' })
    try {
      setAnalysis({ state: 'done', result: await requestAnalysis(request) })
    } catch (e) {
      setAnalysis({ state: 'error', message: e instanceof Error ? e.message : 'The analysis request failed.' })
    }
  }

  const validation = request?.ready ? validateSafeContextRequest(request.body) : null

  return (
    <main className="cs-app">
      <header>
        <p className="kicker">COGNISENTRY AI · EARLY-STAGE MVP</p>
        <h1>Scan a dataset locally. Review before any AI sees it.</h1>
        <p className="privacy">Local analysis: this file is processed in your browser and is not uploaded. Only the safe-context preview below can be sent, and only after you approve it.</p>
      </header>

      <section aria-label="Upload">
        <div
          className={`drop${dragging ? ' is-over' : ''}`}
          onDragOver={e => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={onDrop}
        >
          <p>Drag a CSV here, or</p>
          <div className="row">
            <button type="button" onClick={() => input.current?.click()}>Choose CSV</button>
            <button type="button" className="ghost" onClick={() => load(sampleCsv, 'sample_customer_activity.csv', sampleCsv.length)}>Use synthetic sample</button>
          </div>
          <input ref={input} type="file" accept=".csv,text/csv" hidden onChange={e => void handleFile(e.target.files?.[0])} />
        </div>
        {meta && <p className="meta">{meta.name} · {formatBytes(meta.size)}</p>}
        {error && <p className="error" role="alert">{error}</p>}
      </section>

      {report && (
        <>
          <section aria-label="Scan result">
            <h2>1. Local scan</h2>
            <div className="stats">
              <div><b>{report.dataset.rows}</b><span>rows</span></div>
              <div><b>{report.dataset.columns}</b><span>columns</span></div>
              <div><b>{report.dataset.duplicate_rows}</b><span>duplicate rows</span></div>
              <div className="wide"><b>{report.ai_analysis_readiness}</b><span>AI analysis readiness (automated)</span></div>
            </div>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr><th>Column</th><th>Type</th><th>Missing</th><th>Class</th><th>Why</th></tr>
                </thead>
                <tbody>
                  {report.column_profiles.map(c => (
                    <tr key={c.name}>
                      <td>{c.name}</td>
                      <td>{c.type}</td>
                      <td>{c.missing_count} ({c.missing_percent}%)</td>
                      <td><span className={badgeClass(c.classification)}>{c.classification}</span></td>
                      <td>{c.reasons.length ? c.reasons.join('; ') : '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {quality.length > 0 && (
              <>
                <h3>Data-quality findings</h3>
                <ul className="quality">
                  {quality.map((q, i) => (
                    <li key={i}><span className={`sev sev-${q.severity}`}>{q.severity}</span> {q.message}</li>
                  ))}
                </ul>
              </>
            )}
            <p className="note">Automated, heuristic detection. It can miss sensitive data and flag harmless data. Not a guarantee or a compliance check. No cell values are shown or stored.</p>
          </section>

          <section aria-label="Safe context">
            <h2>2. Safe context for AI analysis</h2>
            <SafeContextPreview report={report} onRequestChange={setRequest} />
            {validation && (
              <p className={validation.ok ? 'ok' : 'error'}>
                {validation.ok ? 'Server-side validation (run locally here): passed.' : `Server-side validation (run locally here) failed: ${validation.message}`}
              </p>
            )}
          </section>

          <section aria-label="Claude analysis" className="claude">
            <h2>3. Claude analysis</h2>
            <p>Claude reads only the safe context shown above: schema-level metadata and aggregates, never cell values, samples or your filename. Nothing is sent until you acknowledge the warnings and press the button.</p>
            <button type="button" disabled={!request?.ready || analysis.state === 'running'} onClick={() => void analyze()}>
              {analysis.state === 'running' ? 'Analyzing…' : 'Send safe context to Claude'}
            </button>
            {!request?.ready && <p className="note">Acknowledge the warnings in step 2 to enable this.</p>}
            {analysis.state === 'error' && <p className="error" role="alert">{analysis.message}</p>}
            {analysis.state === 'done' && analysis.result && (
              analysis.result.analysis ? (
                <div className="analysis" aria-label="Claude analysis result">
                  <p>{analysis.result.analysis.summary}</p>
                  <h3>Data-quality notes</h3>
                  <ul>{analysis.result.analysis.data_quality_notes.map((n, i) => <li key={i}>{n.column ? <b>{n.column}: </b> : null}{n.note}</li>)}</ul>
                  <h3>Questions this data could answer</h3>
                  <ul>{analysis.result.analysis.suggested_questions.map((q, i) => <li key={i}>{q}</li>)}</ul>
                  <h3>Limitations</h3>
                  <ul>{analysis.result.analysis.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
                  <p className="note">AI-generated from metadata only. Verify before relying on it. Request SHA-256: <code>{analysis.result.payload_sha256}</code></p>
                </div>
              ) : (
                <p className="note">The server validated the request but is in mock mode (no API key configured), so no model was called.</p>
              )
            )}
          </section>
        </>
      )}
    </main>
  )
}
