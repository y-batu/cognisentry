# Cognisentry AI — MVP Scanner Test Plan

## Objective
Verify that the local CSV scanner produces useful dataset-health and sensitive-data findings without uploading data.

## Test 1 — Normal CSV
Input:
- numeric columns
- categorical columns
- no sensitive fields

Expected:
- correct row/column counts
- inferred types
- numeric summary
- Ready for analysis

## Test 2 — PII
Input:
- email column
- phone column

Expected:
- both columns flagged
- Review recommended or Sensitive data detected

## Test 3 — Secrets
Input:
- api_key or token column containing long token-like strings

Expected:
- Secret / High Risk classification
- Sensitive data detected

## Test 4 — Missing data
Input:
- columns with empty values

Expected:
- correct missing counts and percentages

## Test 5 — Duplicate rows
Input:
- repeated rows

Expected:
- duplicate row count greater than zero

## Test 6 — False-positive pressure
Input:
- long random-looking product IDs
- UUID-like business identifiers
- URLs
- hashes

Expected:
- inspect whether secret detection is too aggressive
- document false positives

## Test 7 — Malformed CSV
Input:
- missing header
- inconsistent rows
- unusual delimiters

Expected:
- graceful error
- no crash with confusing traceback in product UI

## Test 8 — Large CSV
Input:
- progressively larger local files

Measure:
- parse time
- UI responsiveness
- memory use

## Test 9 — Privacy
Confirm:
- no network request is made during local scan
- file contents remain in the browser/local process

## Test 10 — Report consistency
Compare:
- CSV contents
- generated JSON report
- UI output

Expected:
- same classifications and counts across all views
