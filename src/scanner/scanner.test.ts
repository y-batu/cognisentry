import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import { parseCsv } from './csv.ts'
import { nameTokens, scanCsvText } from './scanner.ts'
import { prepareSafeContext } from '../safeContext/index.ts'

const fixtures = fileURLToPath(new URL('./fixtures/', import.meta.url))
const poc = fileURLToPath(new URL('../../poc/', import.meta.url))

// Reports from the Python reference scanner are the oracle.
for (const file of readdirSync(fixtures).filter(f => f.endsWith('.csv'))) {
  test(`parity with Python reference: ${file}`, () => {
    // key-shaped synthetic values are committed with a marker; see poc/build_golden.py
    const text = readFileSync(fixtures + file, 'utf8').replaceAll('\u00a7', '')
    const golden = JSON.parse(readFileSync(fixtures + file.replace('.csv', '.golden.json'), 'utf8'))
    assert.deepEqual(JSON.parse(JSON.stringify(scanCsvText(text, file))), golden)
  })
}

test('parity with the committed sample report', () => {
  const text = readFileSync(poc + 'sample_customer_activity.csv', 'utf8')
  const golden = JSON.parse(readFileSync(poc + 'sample_scan_report.json', 'utf8'))
  assert.deepEqual(JSON.parse(JSON.stringify(scanCsvText(text, 'sample_customer_activity.csv'))), golden)
})

test('csv parser: quotes, escapes, line endings, blank lines', () => {
  assert.deepEqual(parseCsv('a,b\r\n"x,1","y""z"\n\nlast'), [['a', 'b'], ['x,1', 'y"z'], [], ['last']])
  assert.deepEqual(parseCsv('a,b\n'), [['a', 'b']])
  assert.deepEqual(parseCsv(''), [])
  assert.deepEqual(parseCsv('a,\n,b'), [['a', ''], ['', 'b']])
})

test('csv parser rejects an unterminated quote', () => {
  assert.throws(() => parseCsv('a,b\n"oops,1\n'), /unterminated/)
})

test('scanner errors: empty file and blank header line', () => {
  assert.throws(() => scanCsvText('', 'x.csv'), /no header row/)
  assert.throws(() => scanCsvText('\n1,2\n', 'x.csv'), /no header row/)
})

test('header-only file yields zero rows without crashing', () => {
  const r = scanCsvText('a,b\n', 'x.csv')
  assert.equal(r.dataset.rows, 0)
  assert.equal(r.ai_analysis_readiness, 'No findings (heuristic)')
})

test('name tokenization handles camelCase and separators', () => {
  assert.deepEqual(nameTokens('customerID'), ['customer', 'id'])
  assert.deepEqual(nameTokens('API_KEY'), ['api', 'key'])
  assert.deepEqual(nameTokens('  e-mail '), ['e', 'mail'])
})

test('scanner output never contains cell values', () => {
  const r = JSON.stringify(scanCsvText('secret_note,plan\nmy-private-value-123,Pro\n', 'x.csv'))
  assert.ok(!r.includes('my-private-value-123'))
})


test('numeric statistics handle 200,000 rows within the browser upload limit', () => {
  const text = 'revenue\n' + '1\n'.repeat(199998) + '-3\n5\n'
  assert.ok(Buffer.byteLength(text) < 10 * 1024 * 1024)
  const report = scanCsvText(text, 'synthetic.csv')
  assert.equal(report.dataset.rows, 200000)
  assert.deepEqual(report.column_profiles[0]!.numeric, { min: -3, max: 5, average: 1 })
  assert.notEqual(prepareSafeContext(report).status, 'blocked')
})

test('large finite numbers produce finite statistics and a usable safe context', () => {
  for (const [values, average] of [
    [[1e308, 1e308], 1e308],
    [[-1e308, -1e308], -1e308],
    [[1e308, 1e308, -1e308, -1e308], 0],
    [[Number.MAX_VALUE, Number.MAX_VALUE], Number.MAX_VALUE],
    [[1e308, 1e308, -1e308, -1e308, 1], 0.2],
    [Array(100).fill(1e300), 1e300],
    [Array(100).fill(-1e300), -1e300],
    [[0, 0], 0],
  ] as Array<[number[], number]>) {
    const report = scanCsvText('revenue\n' + values.join('\n'), 'synthetic.csv')
    const numeric = report.column_profiles[0]!.numeric!
    assert.deepEqual(numeric, { min: Math.min(...values), max: Math.max(...values), average })
    assert.ok(Object.values(numeric).every(Number.isFinite))
    assert.notEqual(prepareSafeContext(report).status, 'blocked')
  }
})
