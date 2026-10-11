# Reproducible local demo

Run `npm run dev`, choose “Use synthetic sample”, inspect local security and quality results, then press “Prepare AI context”.

The current sample has 6 rows, 8 columns and 1 duplicate. Five columns are withheld: 2 PII, 1 Sensitive, 1 Potentially Sensitive and 1 Secret / High Risk. Only c6 (numeric), c7 (text) and c8 (text) remain. Local labels are revenue, plan and notes; default outbound context omits those names.

Review the exact JSON and SHA-256. Acknowledge `SECRET_COLUMNS_WITHHELD` and `PII_COLUMNS_WITHHELD`. `COLUMN_NAME_WITHHELD` is informational. Approve the payload: a local readiness message appears; no model is called.

Try excluding c6, re-including it, toggling eligible names or loading a new CSV. Previous approval must disappear and required acknowledgements must reset. Excluding every Standard column must block preparation while retaining controls to recover.

`npm run demo:analyze` prints the same default context and an unacknowledged body locally. `poc/sample_safe_context.json` records the reproducible context. Tests verify it against the current sample scan report.

This is a working local demo, not a screenshot or simulated Claude answer.
