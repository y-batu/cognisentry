# Cognisentry AI

Secure AI-native data analysis and adaptive learning.

Cognisentry AI is an early-stage platform designed to help people and teams work with real-world datasets while reducing unnecessary exposure of sensitive information.

## Current Status

MVP in development. Nothing here calls a model yet.

**Exists today**

- A browser app (Vite + React) that runs the whole local flow: choose a CSV, scan it in the browser, review the findings, and preview the exact safe-context request. It makes no network requests with your data (a test enforces this in code).
- A TypeScript port of the scanner for that app, verified against the Python reference scanner with golden fixtures.
- A local CSV scanner (Python, standard library only) that profiles a dataset and flags likely PII, credentials, IP addresses, identifiers, and token-like values, including inside free text, and produces a machine-readable AI-analysis readiness report.
- A deterministic safe-context step (TypeScript) that turns a scan report into a minimized `safe-context/1` payload: no cell values, no samples, no filename, and no names of withheld columns.
- An exact-payload request builder with SHA-256, acknowledgement gating, and a React preview component. The previewed string is the string that would be sent.
- A strict server-side request validator and a **mock** gateway handler (validation, error codes, rate limiting). It returns a receipt and calls no model.
- A synthetic evaluation harness that measures the scanner and reports its misses and false positives ([`docs/EVALUATION.md`](docs/EVALUATION.md)).
- Tests for all of the above (`poc/` Python tests, `src/safeContext/` Node tests).

**Planned, not built**

- A real server-side Claude call, limited to analyzing an approved safe context.
- A deployed Cloudflare gateway, authentication, and a shared rate-limit store.
- Controlled SQL/Python tools and adaptive learning mode.

The scanner runs locally and does not send the dataset to an external service. Detection is heuristic and can produce false positives and false negatives. The included sample dataset is synthetic. This repository contains the Python reference scanner, the browser demo, the safe-context and gateway code, documentation, and specifications. The marketing page is on the website below.

## Demo

See [`docs/DEMO.md`](docs/DEMO.md) for a walkthrough with real scanner output on the synthetic sample.

## Run the PoC

From the repository root:

```bash
python3 poc/cognisentry_local_scanner.py poc/sample_customer_activity.csv
```

To generate a report:

```bash
python3 poc/cognisentry_local_scanner.py poc/sample_customer_activity.csv --out report.json
```

The scanner uses the Python standard library and should not require external packages.

## Run the browser demo

```bash
npm install
npm run dev        # local dev server; choose a CSV or use the synthetic sample
npm run build
```

Run the tests (Node 24+):

```bash
(cd poc && python3 -m unittest test_scanner_hardening test_eval)
npm test           # TypeScript tests need no installs
npm run typecheck  # needs npm install
```

## Product Direction

The intended workflow is:

Dataset
→ Security Review
→ Safe Context Preparation
→ Claude Reasoning
→ Controlled Tools
→ Explainable Results
→ Adaptive Learning

## Planned Claude Integration

Claude is planned as the reasoning and orchestration layer for:

- structured dataset reasoning
- data-quality explanations
- anomaly analysis
- controlled analytical tools
- structured outputs
- adaptive SQL/Python/statistics tutoring

The planned architecture is:

React/Vite
→ local preprocessing
→ Cloudflare Worker / Pages Function
→ Claude API
→ controlled analytical tools

A production Claude API integration is not live yet. Where Claude is used, why, and the rollout are in [`docs/CLAUDE_INTEGRATION.md`](docs/CLAUDE_INTEGRATION.md).

## Architecture

```
CSV  ->  local scan  ->  safe-context  ->  exact payload preview  ->  user acknowledgement
                                                                          |
                                         (exists)  server-side validation + mock gateway
                                                                          |
                                         (planned) Claude call on the approved safe context only
```

The browser/local side decides what is allowed to leave. The server re-validates everything and never trusts the client. See [`gateway/README.md`](gateway/README.md) and [`docs/SAFE_CONTEXT.md`](docs/SAFE_CONTEXT.md).

## Security Direction

Key principles:

- inspect sensitive information before AI analysis
- minimize data sent to external models
- treat dataset content as untrusted
- keep API secrets server-side
- prefer controlled tool interfaces over unrestricted execution
- make analytical actions auditable

More details are available in [`docs/SECURITY_BOUNDARIES.md`](docs/SECURITY_BOUNDARIES.md).

## Repository Structure

- `poc/` — the local CSV scanner (`cognisentry_local_scanner.py`), a synthetic sample dataset and report, scanner tests, and the evaluation harness in `poc/eval/`.
- `src/app/`, `index.html` — the browser demo. `src/scanner/` — TypeScript scanner port and Python-generated golden fixtures.
- `src/safeContext/` — safe-context preparation, exact request builder, strict request validator, and tests. `src/components/` holds the preview component.
- `gateway/` — the mock analysis gateway handler (no model, no key).
- `docs/` — project brief, security boundaries, threat model, safe-context notes, evaluation, MVP test plan, and roadmap.
- `specs/` — draft Claude tool contracts (not implemented) and the JSON Schema for the safe-context request.

## Roadmap

1. **Local CSV scanner** — schema inference, missing values, duplicates, sensitive-data heuristics, readiness result.
2. **Safe context preparation** — field exclusion, redaction, safe samples, preview of what would be sent to a model.
3. **Claude API gateway** — Cloudflare Worker / Function with a server-side secret, request validation, and rate limiting.
4. **First Claude-assisted analytical workflow** — reasoning over safe schema, explaining data-quality findings, structured analysis plans.
5. **Controlled SQL/Python tools** — read-only SQL first, isolated Python later.
6. **Adaptive learning mode** — exercise generation, answer evaluation, hints, and feedback.

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for details.

## Website

https://ybatuhan.dev/cognisentry

## Status

Early-stage MVP development.
