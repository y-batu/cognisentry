# Claude Integration Plan

Status: **planned, not built.** Nothing in this repository calls the Claude API today. The gateway handler is a mock that returns a receipt.

## Why Claude

The deterministic parts of the product (scanning, redaction, payload building, validation) must be predictable and auditable, so they are plain code. Claude is used only where judgement over messy, open-ended input adds value:

| Where | What Claude does | Why not plain code |
|---|---|---|
| Data-quality explanation | Turns scanner findings into plain-language explanations and fixes | Findings are structured; the explanation needs context-aware language |
| Analysis planning | Proposes questions and an analysis plan from the safe schema | Open-ended reasoning over column names, types and statistics |
| Anomaly reasoning | Interprets profile statistics (ranges, missingness, duplicates) | Needs domain judgement, not a fixed rule |
| Controlled tool use | Chooses among read-only SQL / stats tools defined in [`specs/claude_tool_contracts.json`](../specs/claude_tool_contracts.json) | Tool selection and argument construction from a user goal |
| Adaptive learning | Generates exercises, evaluates answers, gives hints | Natural-language feedback |

## Where in the architecture

```
Browser: scan -> safe-context -> exact payload preview -> user acknowledgement
   |
Cloudflare Worker / Pages Function: strict validation, rate limit, API key (server-side only)
   |
Claude API: receives the approved safe-context only
   |
Structured output -> validated -> shown with an audit receipt
```

- The browser never holds the API key and never calls Claude directly.
- The server re-validates the payload (allowlist, fixed warning text, count consistency, canonical body) before any model call. This already exists in `src/safeContext/` and `gateway/`.
- Dataset content is untrusted: Claude receives schema and aggregate profile only, never raw cell values, and its output is validated before display.

## Rollout

1. **First workflow (narrow):** safe schema in, structured data-quality explanation and suggested analysis questions out. Replace the mock handler with one Messages API call using structured outputs.
2. **Controlled tools:** read-only SQL over a local copy, results returned as aggregates; Python isolation later.
3. **Learning mode:** exercise generation and answer evaluation.

## Open decisions

- Model choice per workflow (cost vs. reasoning depth) and prompt caching for the fixed system prompt.
- Persistent rate-limit store and authentication before any public deploy.
- Evaluation set for Claude outputs, alongside the existing scanner evaluation in [`EVALUATION.md`](EVALUATION.md).
