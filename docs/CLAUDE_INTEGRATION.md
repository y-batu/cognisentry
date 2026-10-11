# Claude integration status

The current milestone ends at local payload approval. There is no production Claude API integration. The browser app, development server, CLI sample and Cloudflare endpoint do not invoke Claude.

Historical `gateway/claudeAnalyzer.ts` code remains for review and fake-client regression tests. Its existing model configuration has not been verified for live use. Passing these tests is not a claim of model availability or a successful API request.

Planned: a Cloudflare server-side gateway and one bounded dataset-quality workflow over approved safe metadata. Implement authentication, shared rate limiting, strict request validation and evaluated structured responses before connecting the UI. API credentials must remain server-side. Read-only SQL and adaptive learning are deferred.

See [ROADMAP.md](ROADMAP.md) and [SECURITY_BOUNDARIES.md](SECURITY_BOUNDARIES.md).
