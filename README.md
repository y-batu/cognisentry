# Cognisentry AI

Cognisentry is an early-stage dataset security and quality review MVP. It prepares a minimized, reviewable metadata payload before any future AI analysis.

## Exists today

- Local Python CSV scanner with conservative sensitive-data heuristics, free-text inspection, numeric-stat withholding and a reproducible sample report.
- React / TypeScript / Vite CSV upload and local browser scanner, checked against Python golden fixtures.
- Local security and data-quality results; no raw dataset upload.
- Deterministic `safe-context/1` generation with strict allowlist validation, stable column references, field exclusions and optional restricted Standard labels.
- Exact JSON payload preview, SHA-256 of that string, required acknowledgements and local payload approval.
- Automated Python and TypeScript scanner, leakage, schema, approval and deferred gateway contract tests.
- Chromium interaction tests for local payload approval, hashing and overlapping file selections on desktop and mobile viewports.

**The current app does not call Claude or send the approved payload.** Approval ends with “Payload approved and ready for secure analysis gateway.” There is no production Claude API integration or fabricated model response.

## Planned

- Cloudflare server-side Claude gateway with authentication, shared rate limits and request validation.
- First Claude dataset-quality workflow over approved metadata, with evaluated structured responses.
- Controlled read-only SQL, deferred until its execution boundary exists.
- Adaptive learning, deferred until the analytical workflow is validated.

There is no general chat assistant or unrestricted Python/SQL execution. Historical analyzer code is retained in `gateway/claudeAnalyzer.ts` for review and fake-client tests; it is disconnected from the app, development server, sample CLI and Cloudflare endpoint. Supplying an environment key does not enable those entrypoints.

## Run locally

Use Node 22.15+ and Python 3. The local test loader uses the existing TypeScript dependency so native Node TypeScript support is unnecessary.

```bash
npm ci
npm run dev
```

Choose CSV → local scan → security / quality results → prepare AI context → review exact JSON, withheld counts and warnings → acknowledge → approve payload.

```bash
python3 poc/cognisentry_local_scanner.py poc/sample_customer_activity.csv
npm run demo:analyze  # local preview only; no automatic acknowledgement or model call
```

The marketing website is separate from this repository's browser MVP and is unchanged.

## Verify

```bash
(cd poc && python3 -m unittest -v test_scanner_hardening test_eval)
python3 poc/build_golden.py --check
npm test
npm run typecheck
npm run build
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/audit-artifacts.py
```

Install the browser once, then run the interaction suite:

```bash
npx playwright install --with-deps chromium
npm run test:e2e
```

The browser suite builds the app and starts its own local preview on port 4174. It exercises desktop Chromium and an emulated Pixel 7 viewport; this is not physical-device coverage. Linux browser dependency installation may require administrator access. Test traces and reports are ignored by Git.

`python3 poc/build_golden.py --check` compares the committed CSV fixtures and reports without changing them. To regenerate them intentionally after reviewing a scanner change, run `python3 poc/build_golden.py` without `--check`.

`npm test` explicitly imports all suites through a local TypeScript loader and runs assertions with `node:test`. Type checking is a separate required check.

## Safe-context contract

The source report is the actual scanner output: `dataset.{rows,columns,duplicate_rows}`, `column_profiles[]` with `name`, `type`, `classification`, missing/unique counts and optional numeric statistics. Free-text warnings use `free_text: true` and `free_text_inspection.{cells_inspected,findings.{email,phone,secret,instruction_like}}`.

`prepareSafeContext(report, options)` returns `blocked` with reason codes, or `ready` / `needs_ack` with `context`, `ackRequired` and a **local-only** `refToName`. Compatibility `ok` / `value` fields are retained for existing internal consumers. Never serialize the preparation result; only the validated `context` goes into `buildSafeContextRequest`.

- Only Standard columns have per-column metadata. All other classifications become aggregate withheld counts.
- Names default off. Opt-in names must match a small ordinary-label vocabulary; other labels stay local.
- `safe_samples` is always `[]`. Cell arrays, filenames, paths, scanner reason strings and arbitrary report fields are never copied.
- Standard numeric min/max/average are allowed. Extrema can equal source values; this is metadata minimization, not anonymization or differential privacy.
- Limits: 2,000 input profiles, 100 usable Standard columns, 16 KiB compact UTF-8 context, 64-character optional names. Callers may lower usable-column and byte limits, never raise them.
- No usable columns, invalid input, excessive columns/bytes or invalid output blocks preparation.

`serializeRequest` is the only outbound JSON serializer. The UI displays `request.body`; SHA-256 is computed over it. The deferred sender passes that same string directly as `fetch`'s body and is not imported by the running app. Any selection change clears acknowledgements/approval and invalidates the old preview immediately.

See [safe-context details](docs/SAFE_CONTEXT.md), [security boundaries](docs/SECURITY_BOUNDARIES.md), [roadmap](docs/ROADMAP.md).

## Repository

- `poc/`: Python scanner, synthetic sample and evaluation tests.
- `src/scanner/`: browser scanner, quality findings and golden fixtures.
- `src/safeContext/`: preparation, validation, exact request builder and tests.
- `src/components/`, `src/app/`: existing browser MVP and local approval.
- `specs/`: strict safe-context schemas and local tool contracts.
- `gateway/`: deferred gateway prototypes and historical analyzer tests.
- `functions/api/analyze.ts`: disabled endpoint (503); no model calls.

Passing local tests does not imply a deployed production integration.
