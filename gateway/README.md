# Deferred gateway prototypes

The current app stops at local approval. `functions/api/analyze.ts` returns 503; Vite has no gateway middleware; the sample CLI prints an unacknowledged preview. Supplying a key does not enable these entrypoints.

`handler.ts` and historical `claudeAnalyzer.ts` remain isolated prototypes with contract tests using fake clients. They are not production integration. The existing model setting is unverified. The in-memory limiter is per process and is not a production shared rate-limit mechanism.

Before connecting a future Cloudflare gateway, complete the controls in [security boundaries](../docs/SECURITY_BOUNDARIES.md). The UI must pass the already-previewed request body unchanged. Do not send CSVs, source reports, local name maps or arbitrary prompts.
