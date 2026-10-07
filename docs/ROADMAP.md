# Cognisentry AI — Near-Term Roadmap

## Milestone 1 — Local scanner
- CSV upload
- schema inference
- missing values
- duplicates
- sensitive-data heuristics
- numeric profiling
- AI-readiness result

## Milestone 2 — Review and safe context
- user can exclude fields
- redact selected values
- safe sample generation
- preview exactly what would be sent to an AI model

## Milestone 3 — Claude gateway
- Cloudflare Worker / Function
- server-side Claude API secret
- request validation
- rate limiting
- structured response format
- no arbitrary frontend API access

## Milestone 4 — First Claude workflow
Start narrow:
- reason over safe schema
- explain data-quality findings
- suggest analysis questions
- produce structured analytical plan

## Milestone 5 — Controlled tool use
- inspect_schema
- check_sensitive_data
- prepare_safe_context
- read-only SQL
- later: isolated Python

## Milestone 6 — Adaptive learning
- SQL exercise generation
- answer evaluation
- hints
- reasoning feedback
- difficulty progression
