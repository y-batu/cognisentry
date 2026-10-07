# Cognisentry AI — Project Brief

## Current status
Cognisentry AI is an early-stage product in active MVP development.

Public site:
https://ybatuhan.dev/cognisentry

Current stack:
- React
- TypeScript
- Vite
- Cloudflare Pages

Current implementation direction:
- browser-first CSV analysis
- local parsing
- schema inspection
- data-quality checks
- sensitive-data detection
- no production Claude API integration yet

## Product idea
Cognisentry AI combines:
1. secure data analysis,
2. sensitive-data review before AI use,
3. adaptive learning for SQL, Python, statistics, and analytical reasoning.

The long-term flow is:

Dataset
→ local security review
→ safe context preparation
→ Claude reasoning
→ controlled tools
→ explainable results
→ optional learning mode

## What exists now
A local proof-of-concept scanner exists and can:
- read CSV locally,
- count rows and columns,
- detect duplicate rows,
- infer simple types,
- calculate missing-value statistics,
- profile numeric columns,
- flag likely email, phone, IPv4, identifier, and token-like fields,
- classify risk,
- produce a machine-readable JSON report.

## What does not exist yet
- production Claude API integration
- authentication
- real customers
- production Python sandbox
- production SQL execution layer
- multi-tenant data storage
- billing
- enterprise integrations

## Immediate goal
Turn the browser-only scanner into a useful MVP and then add the smallest safe Claude-assisted workflow.

## Technical constraints
- Keep uploaded data local when possible.
- Never place a Claude API key in frontend code.
- Treat dataset content as untrusted.
- Prefer deterministic checks for security-sensitive classification.
- Use Claude for reasoning/orchestration, not unrestricted arbitrary execution.
- Do not send raw full datasets to Claude by default.
- Keep public claims aligned with what is actually implemented.
