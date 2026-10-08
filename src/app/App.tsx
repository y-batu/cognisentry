import { useCallback, useRef, useState } from 'react'
import type { DragEvent } from 'react'
import { SafeContextPreview } from '../components/SafeContextPreview.tsx'
import { validateSafeContextRequest } from '../safeContext/index.ts'
import type { SafeContextRequest } from '../safeContext/index.ts'
import { scanCsvText } from '../scanner/scanner.ts'
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

  const validation = request?.ready ? validateSafeContextRequest(request.body) : null

  return (
    <main className="cs-app">
      <header>
        <p className="kicker">COGNISENTRY AI · EARLY-STAGE MVP</p>
        <h1>Scan a dataset locally. Review before any AI sees it.</h1>
        <p className="privacy">Local analysis: this file is processed in your browser and is not uploaded.</p>
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
            <p>Claude-powered analysis is the next stage of the MVP. Sensitive-data review will occur before any data is sent for AI-assisted analysis.</p>
            <button type="button" disabled>Not connected yet</button>
            <p className="note">Nothing is sent anywhere. This page makes no network requests with your data.</p>
          </section>
        </>
      )}
    </main>
  )
}
