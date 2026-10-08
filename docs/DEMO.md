# Demo

Cognisentry AI is a local-first flow: **scan → review → safe-context preview**. Nothing leaves the machine, and no model is called yet.

## 1. CLI scan (Python reference scanner)

```bash
python3 poc/cognisentry_local_scanner.py poc/sample_customer_activity.csv
```

Output for the synthetic sample (6 rows, 8 columns), abridged:

```
ai_analysis_readiness: "Sensitive data detected"
duplicate_rows: 1

flagged_fields:
  customer_id  Sensitive              column name suggests sensitive
  email        PII                    name + values resemble email addresses
  phone        PII                    name + values resemble phone numbers
  ip_address   Potentially Sensitive  name + values resemble IPv4 addresses
  api_token    Secret / High Risk     column name suggests secret / high risk
```

The full machine-readable report is in [`poc/sample_scan_report.json`](../poc/sample_scan_report.json).

## 2. Browser demo

```bash
npm install
npm run dev
```

1. Choose a CSV (or use the built-in synthetic sample). The file is parsed and scanned in the browser.
2. Review the findings per column.
3. Preview the exact `safe-context/1` request: no cell values, no samples, no filename, no names of withheld columns. The previewed string is byte-for-byte what would be sent, with its SHA-256 and an acknowledgement gate.

> Screenshots: run `npm run dev` and capture the three steps above into `docs/screenshots/` (not committed yet).

## 3. Verify

```bash
npm test                                                    # 45 TypeScript tests
(cd poc && python3 -m unittest test_scanner_hardening test_eval)   # 42 Python tests
```
