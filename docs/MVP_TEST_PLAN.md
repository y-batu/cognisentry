# Cognisentry AI — MVP Scanner Test Plan

## Objective
Verify that the local CSV scanner produces useful dataset-health and sensitive-data findings without uploading data.

## Dataset-level status values
- `No findings (heuristic)` — no heuristic findings. This is NOT a safety guarantee.
- `Review recommended` — at least one PII / Sensitive / Potentially Sensitive column, or a free-text warning (for example instruction-like content).
- `Sensitive data detected` — at least one Secret / High Risk column.

## Automated tests
Run from the directory containing the scanner, `sample_customer_activity.csv` and `sample_scan_report.json`:

```bash
python3 -m unittest -v test_scanner_hardening
```

Regenerate the sample report (and re-run the tests afterwards; one test fails if the committed report is stale):

```bash
python3 cognisentry_local_scanner.py sample_customer_activity.csv --out sample_scan_report.json
```

## Test 1 — Normal CSV
Input:
- numeric columns
- categorical columns
- no sensitive fields

Expected:
- correct row/column counts
- inferred types
- numeric summary
- `No findings (heuristic)`

Automated: `test_rename_status`, `test_sample_csv_expectations`

## Test 2 — PII
Input:
- email column
- phone column (including formatted values such as `(202) 555-0101` and `+90 532 123 4567`)

Expected:
- both columns flagged as `PII` (by name or by value)
- `Review recommended` (or `Sensitive data detected` if a secret is also present)
- numeric statistics are NOT emitted for a flagged numeric column; `stats_withheld` is present instead

Automated: `test_phone_stats_withheld`, `test_value_detected_phone_is_pii_not_sensitive`, `test_value_detected_email_is_pii`, `test_specific_phone_names_are_pii`

## Test 3 — Secrets
Input:
- `api_token`, `private_key` or `access_key` column (any values)
- a neutrally named column containing a known-format secret (Stripe-like, GitHub, AWS access key ID, Slack, Google API key, `sk-`/`sk-ant-`, JWT, PEM private-key header)

Expected:
- `Secret / High Risk`
- `Sensitive data detected`
- name-hinted columns are classified even when values match no known format
- there is no generic "long string" secret rule

Automated: `test_name_hint_classifies_without_known_format`, `test_known_formats_detected_by_value_in_neutral_column`, `test_single_secret_among_many_values_is_caught`, `test_old_generic_token_rule_is_gone`

## Test 4 — Missing data
Input:
- columns with empty values

Expected:
- correct missing counts and percentages

Note: only blank cells count as missing. `N/A`, `null`, `-` are NOT treated as missing yet (see Known gaps).

## Test 5 — Duplicate rows
Input:
- repeated rows

Expected:
- duplicate row count greater than zero

Note: duplicate rows are still included in numeric statistics (see Known gaps).

## Test 6 — False-positive pressure
Input:
- long random-looking product IDs, UUIDs, hashes, long slugs, base64-looking strings
- URLs
- IPv4 addresses, ISO and US-style dates, epoch timestamps, 8+ digit order numbers
- column names such as `description`, `shipping_cost`, `zip`, `token_count`, `is_mobile`, `mobile_app_version`, `email_opt_in`, `BusinessName`, `address`

Expected:
- none of the above is classified above `Standard` by value or by name
- IPv4 columns are `Potentially Sensitive` only, with no "phone" reason

Automated: `test_long_non_secrets_are_not_flagged`, `test_phone_negatives`, `test_dates_epochs_ids_standard`, `test_ip_column_no_phone_reason`, `test_substring_false_positives_gone`, `test_mobile_is_no_longer_a_hint`

Residual false positives to keep documenting: a hyphenated slug that starts with a literal `sk-` and is 20+ characters; hyphenated digit groups such as `100-200-300` can match the phone rule.

## Test 7 — Malformed CSV
Input:
- missing header
- inconsistent rows
- unusual delimiters
- non-UTF-8 encoding

Expected (target):
- graceful error
- no crash with confusing traceback in product UI

Status: NOT addressed by this iteration. Known gap.

## Test 8 — Large CSV
Input:
- progressively larger local files, including a free-text column with more than 1000 rows

Measure:
- parse time
- UI responsiveness
- memory use

Expected:
- free-text inspection never covers more than 1000 non-empty values per column, and `cells_inspected` says so

Automated: `test_free_text_cell_cap` (cap only; performance is still manual)

## Test 9 — Privacy
Confirm:
- no network request is made during local scan
- file contents remain in the browser/local process

Automated (partial): `test_scanner_imports_are_local_only` statically checks that the scanner imports only an allowlist of standard-library modules. This supports, but does not prove, the claim. Still verify the browser build manually (network panel).

## Test 10 — Report consistency
Compare:
- CSV contents
- generated JSON report
- UI output

Expected:
- same classifications and counts across all views

Automated: `test_committed_sample_report_is_in_sync` (CSV vs committed report only; UI comparison is still manual)

## Test 11 — Strict JSON
Input:
- numeric-looking cells such as `nan`, `inf`, `-inf`, `1e999`

Expected:
- those cells are not treated as numbers
- the generated report parses with a strict JSON parser (no `NaN`/`Infinity` constants)

Automated: `test_non_finite_rejected`, `test_strict_json_cli_output`

## Test 12 — Free-text inspection
Input:
- prose column with no sensitive content
- prose column with embedded email, formatted phone, known-format secret
- prose column with instruction-like text
- prose column with benign phrases (`you are now eligible…`, `system: down for maintenance`)

Expected:
- prose with no findings stays `Standard`, gets `free_text: true`, and is not flagged
- embedded email / phone → `PII`; embedded known-format secret → `Secret / High Risk`
- instruction-like text → classification unchanged, `review_recommended: true`, a "(warning only)" reason, dataset status `Review recommended`
- benign phrases produce no instruction-like finding
- the report contains counts only and never the matched text

Automated: all `TestFreeText` tests

## Test 13 — Name-matching precision
Input:
- camelCase and separator variants (`customerId`, `APIKey`, `User-Email`)

Expected:
- names are split into tokens before matching; no substring matching
- duplicate reason strings never appear in a report

Automated: `test_name_tokens`, `test_camel_case_hits`, `test_no_duplicate_reasons`, `test_ip_address_not_upgraded_by_address_hint`

## Known gaps (not covered; do not claim otherwise)
- `N/A`, `null`, `-`, `?` are not counted as missing
- duplicate rows are included in numeric statistics; non-unique key columns are not flagged
- `1_000` and European decimals such as `1,5` are still parsed as numbers; leading-zero IDs are still typed as numbers
- only the first 200 non-empty values are sampled for value-based detection
- IPv6 addresses are not detected
- dot-separated phone numbers and bare unformatted digit runs are detected by column name only
- instruction-like detection is a warning signal, not a security boundary, and will miss most real attacks
- malformed CSV handling (Test 7)
