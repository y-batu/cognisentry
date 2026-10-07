# Safe Context (`safe-context/1`)

Status: implemented locally; no network call, no Claude API integration.

```
scan report → prepareSafeContext → exact payload preview → acknowledgements → (future) server request
```

## Input
The report emitted by `poc/cognisentry_local_scanner.py`. Only these fields are read; anything else is ignored:
`dataset.{rows,columns,duplicate_rows}`, `ai_analysis_readiness`, and per column
`name, type, missing_count, missing_percent, unique_count, classification, numeric.average`,
`free_text_inspection.{cells_inspected, findings.instruction_like}`.

Malformed reports are rejected (`invalid_report`).

## What is included
- Dataset counts and the scanner readiness label.
- Standard columns with safe names: type, missing and unique counts, numeric average, free-text cell count.
- Category counts for withheld columns (`Potentially Sensitive`, `PII`, `Sensitive`, `Secret / High Risk`, `Unsafe column name`) and a count of user-excluded columns.
- Warnings.

## What is never included
Cell values, samples, the filename, numeric min/max (exact cell values), and the names of withheld, unsafe or excluded columns.

## Warnings and acknowledgements
`heuristic_detection` (always), `withheld_columns`, and `instruction_like_text` each require acknowledgement before a request is `ready`. Instruction-like text detection is a warning signal, not a security boundary; dataset content is untrusted.

## Request
`serializeRequest` is the single serialization path. The preview shows `request.body` and a future sender must transmit that exact string; its SHA-256 is shown beside it. No model name is set here; that belongs to the future server-side gateway, which also keeps the API key.

## Run
```bash
npm test                       # node:test, Node 24+, no dependencies
npx -p typescript tsc --noEmit -p tsconfig.json
```
