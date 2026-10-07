# Threat Model (current scope)

Scope: the local scanner, safe-context preparation, request validation, and the mock gateway. No model is called today. This is a design-level model written by the project authors; it has not been independently reviewed.

| Threat | Mitigation today | Residual risk |
|---|---|---|
| Sensitive values reach an external model | Safe context carries no cell values or samples; flagged columns are withheld and only counted | Detection is heuristic and can miss sensitive columns (see `EVALUATION.md`) |
| Unsafe column names leak data (a name that is itself an email or token) | Names are validated; unsafe names are withheld and counted | Name rules are conservative heuristics |
| Preview differs from what is sent | One serialization path; server requires byte-identical canonical body; optional SHA-256 header | Depends on the future sender transmitting `request.body` unchanged |
| Tampered or hand-crafted requests | Strict server-side allowlist: no unknown keys, fixed warning text, consistent counts | Validator and client share code; a bug there affects both |
| Prompt injection via dataset text | Cell text is never in the payload; instruction-like text raises a warning | Detection misses paraphrases and obfuscation; a warning, not a boundary |
| API key exposure | No key exists in this repo; the planned design keeps it server-side | Must be enforced when the real integration is added |
| Abuse and cost | Size limit, content-type check, per-client rate limit | The in-memory limiter is per-isolate and best-effort; needs a shared store |
| Upstream error leakage | Gateway never echoes upstream error text | Future logging must also avoid payload content |

Out of scope today: authentication, multi-tenancy, storage, SQL/Python execution, and compliance certification.
