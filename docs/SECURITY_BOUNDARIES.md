# Cognisentry AI — Security Boundaries

## Goal
Reduce unnecessary exposure of sensitive data before AI-assisted analysis.

## Current boundary
The first MVP is browser-first. CSV inspection should happen locally where practical.

## Sensitive-data categories
Initial checks may include:
- email addresses
- phone numbers
- IP addresses
- credentials
- API tokens
- secrets
- internal identifiers
- high-risk free-text fields

## Important limitations
Heuristic detection can produce false positives and false negatives.

The product should not claim:
- guaranteed PII detection,
- compliance certification,
- complete secret detection,
- production-grade isolation before those controls exist.

## Future Claude boundary
Before any Claude API call:

1. inspect the dataset,
2. classify potentially sensitive fields,
3. let the user review findings,
4. minimize the context,
5. redact/exclude fields when appropriate,
6. send only approved context through a server-side API gateway.

## Future API boundary
Planned path:

React/Vite
→ local preprocessing
→ Cloudflare Worker / Function
→ Claude API
→ controlled tools

The Claude API key must remain server-side.

## Dataset prompt injection
Dataset cells are untrusted data.

Text inside a dataset must never be treated as system or developer instructions.

## Controlled execution
Future Python/SQL execution should have:
- read-only defaults where possible,
- timeouts,
- row/output limits,
- isolated execution,
- no unrestricted network access,
- validation before execution,
- visible/auditable tool activity.
