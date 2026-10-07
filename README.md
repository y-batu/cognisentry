# Cognisentry AI

Secure AI-native data analysis and adaptive learning.

Cognisentry AI is an early-stage platform designed to help people and teams work with real-world datasets while reducing unnecessary exposure of sensitive information.

## Current Status

MVP in development.

The current proof-of-concept includes a local CSV scanner that can:

- inspect dataset structure
- count rows and columns
- detect duplicate rows
- infer basic column types
- calculate missing-value statistics
- profile numeric fields
- identify potentially sensitive fields
- detect likely PII, credentials, IP addresses, identifiers, and token-like values
- generate a machine-readable AI-analysis readiness report

The current scanner runs locally and does not send the dataset to an external service. Detection is heuristic and can produce false positives and false negatives. The included sample dataset is synthetic. This repository contains only the Python proof-of-concept, documentation, and specifications; the browser-based MVP is developed separately and is previewed on the website below.

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

A production Claude API integration is not live yet.

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

- `poc/` — the working local CSV scanner (`cognisentry_local_scanner.py`), a synthetic sample dataset, and the report the scanner generates for it.
- `docs/` — project brief, security boundaries, MVP test plan, and roadmap.
- `specs/` — draft structured contracts for future controlled Claude tools (`claude_tool_contracts.json`). These are specifications only and are not implemented.

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
