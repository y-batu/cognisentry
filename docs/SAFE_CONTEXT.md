# Safe context / exact approval contract

Implemented locally. No network operation is performed by preparation, preview or approval.

## Input and projection

The Python scanner and browser port emit `dataset` counts and `column_profiles[]` with `name`, `type`, `missing_count`, `missing_percent`, `unique_count`, `classification`, optional `numeric.{min,max,average}` and optional `free_text: true` with `free_text_inspection.{cells_inspected,findings.{email,phone,secret,instruction_like}}`.

The input parser checks known classifications/types, finite numeric statistics, safe integer counts, percentages consistent with row counts, duplicate names, inspection limits and contradictory Standard/free-text findings. Unknown fields are ignored, not copied. Readiness is validated against the scanner's enum but is not transmitted. Missing inspection for a declared free-text column is accepted conservatively as uninspected; malformed present inspection is blocked. The obsolete flat `instruction_like_count` is ignored.

Every Standard column keeps its original one-based ordinal (`c6`, for example), including after exclusions. Non-Standard profiles contribute only category counts. `refToName` is separate local state; it is never part of `context` or request serialization.

Options: `excludeColumns` accepts stable refs (preferred) or exact local names; `includeStandardNames` defaults false. Optional names must pass the restricted vocabulary in `names.ts`. This intentionally withholds some harmless labels; heuristics cannot prove arbitrary names contain no PII. Names such as personal names, sensitive field labels and instruction-like phrases are omitted, while Standard metadata remains usable.

## Schema

`specs/safe-context.schema.json` and the nested request schema prohibit unknown fields recursively. `validateSafeContext` additionally enforces relational constraints, safe-name vocabulary, warning/count consistency, numeric-type relationships and byte limits. Preparation and request serialization both validate output.

Allowed: dataset counts, stable refs, optional eligible Standard names, type, missing/unique counts, Standard numeric min/max/average, withheld counts and fixed warning codes. `safe_samples` must be empty. No free-text inspection counts, scanner reason strings or readiness text enter the payload.

MVP limits: 2,000 input profiles; 100 usable columns; 16,384 compact JSON UTF-8 bytes; 64-character optional labels. These bound review burden and context volume. Limits are not model token budgets. Options can lower but not increase column/byte limits. The formatted request can be larger than the compact context; request validation is capped at 64 KiB.

## Warnings

| Code | Requires acknowledgement |
| --- | --- |
| INSTRUCTION_LIKE_CONTENT | Yes |
| FREE_TEXT_NOT_INJECTION_SCANNED | Yes |
| SECRET_COLUMNS_WITHHELD | Yes |
| PII_COLUMNS_WITHHELD | Yes |
| COLUMN_NAME_WITHHELD | No |
| USER_EXCLUDED_COLUMNS | No |

Instruction and incomplete-inspection warnings apply even to excluded/withheld columns. `cells_inspected < rows - missing_count` triggers incomplete coverage, including the scanner's 1,000-cell cap. Ordinary categorical text without a declared free-text flag does not imply prose; scanner misclassification remains a documented limitation.

Display explanations stay local. Outbound warnings are codes only. Heuristic instruction detection is not a security boundary.

## Exact preview and local approval

`serializeRequest` is the sole outbound serializer. `buildSafeContextRequest` snapshots and validates context, normalizes acknowledgements, serializes once, and hashes the exact body. The UI renders that body directly. The deferred sender passes it unchanged to `fetch`, verified by an intercepted-fetch test; the app does not import or invoke the sender.

Selections, name preference, acknowledgements and a newly loaded CSV invalidate stale previews. Hash completion is tied to the exact context and acknowledgement identities, so an old asynchronous result cannot enable approval. Excluded columns remain visible for re-inclusion even when preparation is blocked. Hash failure disables approval.

Local approval independently validates the body, acknowledgements and SHA-256. It returns a local receipt, not an AI response. There is no persistent approval, browser storage or network transmission.

The SHA-256 binds the visible bytes; it is not authentication, an authorization token or evidence that a human reviewed the payload. A future gateway must enforce its own controls.
