# Security boundaries

## Current boundary

CSV processing and quality/security review run locally. The Python scanner uses the standard library; the React app uses the existing browser scanner. Preparation, exact preview and approval perform zero network requests. The Cloudflare endpoint returns 503 and the dev server has no model gateway.

Only a strict `safe-context/1` allowlist can be serialized: dataset counts; Standard column references/types/missing/unique counts; optional restricted Standard labels; Standard numeric min/max/average; warning codes; aggregate withheld counts; empty `safe_samples`. No raw cells, sample rows, file paths/names, non-Standard column names, scanner reason strings or arbitrary report fields are copied. Non-Standard numeric statistics never enter context, even if incorrectly present in an input report.

`refToName` stays local. Preparation results must never be sent wholesale. Strict output and request validation reject unknown keys recursively, nonempty samples, unsafe names, inconsistent counts and missing required acknowledgements. Limits and warning rules are in [SAFE_CONTEXT.md](SAFE_CONTEXT.md).

## Limitations

Classification is heuristic and may miss sensitive content or flag harmless content. Schema validation establishes the allowed structure, not the truth of a supplied report. The current tool accepts reports from its local scanner; a future service cannot trust arbitrary client classifications as proof of safety.

Standard min/max may coincide with individual cell values. Small-dataset aggregates and uniqueness counts can reveal information. This is data minimization, not anonymization, differential privacy, compliance certification or guaranteed PII/secret detection. Users review the exact metadata and can exclude Standard columns.

The scanner samples up to 200 values for some value checks, detects prose heuristically and inspects at most 1,000 nonempty free-text values per column. Incomplete declared free-text inspection requires acknowledgement. Missing prose detection may still escape this warning. Optional name inclusion uses a deliberately limited vocabulary; omitted labels may be harmless.

## Dataset instructions

All dataset content and labels are untrusted data. Instruction-like detection is a warning only, never a security boundary. Detected instructions and uninspected free text require explicit acknowledgement, even when the originating column is withheld. No raw text goes to a model in this milestone.

## Approval

Required acknowledgements: instruction-like findings, uninspected free text, secret columns withheld and PII columns withheld. Changing a CSV, column selection or name preference clears previous review. A stale preview cannot approve a new context. Exact JSON and SHA-256 refer to the same string; hash verification is not proof of human consent or request authentication.

## Future gateway

The deferred sender is disconnected from the app. Existing historical analyzer code is unused by every executable app/demo/server entrypoint; fake-client unit tests are not evidence of production integration. No API key belongs in the browser bundle.

Before enabling a Cloudflare server-side gateway: authentication/authorization, strict request revalidation, shared rate limiting, bounded bodies/timeouts, logging/retention policy, structured output validation, evaluated prompt-injection handling and an explicit approved-payload transport review are required. Do not enable the historical analyzer merely by supplying a key.

## Tools and execution

`inspect_schema`, `check_sensitive_data` and `prepare_safe_context` are local stages, not Claude-callable tools. Read-only SQL and adaptive learning remain deferred. No unrestricted Python/SQL execution or general chat assistant is included. The Python CSV scanner is a fixed local program, not a user code execution facility.
