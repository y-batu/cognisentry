import assert from 'node:assert/strict'
import { test } from 'node:test'

import { findQualityIssues } from './quality.ts'
import type { QualityInput } from './quality.ts'

const col = (name: string, o: Partial<QualityInput['column_profiles'][number]> = {}) => ({
  name, type: 'text', missing_count: 0, missing_percent: 0, unique_count: 3, ...o,
})
const report = (rows: number, columns: QualityInput['column_profiles'], duplicate_rows = 0): QualityInput => ({
  dataset: { rows, columns: columns.length, duplicate_rows }, column_profiles: columns,
})
const codes = (r: QualityInput) => findQualityIssues(r).map(f => f.code)

test('clean dataset has no findings', () => {
  assert.deepEqual(findQualityIssues(report(10, [col('a'), col('b', { type: 'integer', unique_count: 4 })])), [])
})

test('header-only dataset is reported and short-circuits', () => {
  assert.deepEqual(codes(report(0, [col('a')])), ['empty_dataset'])
})

test('duplicate rows: severity rises at 10%', () => {
  assert.equal(findQualityIssues(report(100, [col('a')], 1))[0]?.severity, 'medium')
  assert.equal(findQualityIssues(report(10, [col('a')], 1))[0]?.severity, 'high')
})

test('missing values: all, high, and below threshold', () => {
  const r = report(10, [
    col('empty', { missing_count: 10, missing_percent: 100 }),
    col('half', { missing_count: 5, missing_percent: 50 }),
    col('few', { missing_count: 1, missing_percent: 10 }),
  ])
  const f = findQualityIssues(r)
  assert.deepEqual(f.map(x => [x.code, x.column]), [['all_missing', 'empty'], ['high_missing', 'half']])
})

test('constant and identifier-like columns need enough rows', () => {
  const cols = [col('k', { unique_count: 1 }), col('id', { unique_count: 10 })]
  assert.deepEqual(codes(report(10, cols)), ['constant_column', 'identifier_like'])
  assert.deepEqual(codes(report(4, [col('k', { unique_count: 1 }), col('id', { unique_count: 4 })])), [])
})

test('identifier check ignores missing cells and non-text columns', () => {
  assert.deepEqual(codes(report(10, [col('id', { unique_count: 8, missing_count: 2, missing_percent: 20 })])), ['identifier_like'])
  assert.deepEqual(codes(report(10, [col('n', { type: 'integer', unique_count: 10 })])), [])
})

test('findings are sorted high before low', () => {
  const r = report(10, [col('k', { unique_count: 1 }), col('empty', { missing_count: 10, missing_percent: 100 })])
  assert.deepEqual(findQualityIssues(r).map(f => f.severity), ['high', 'low'])
})
