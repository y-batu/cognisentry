# Cognisentry roadmap

## Implemented locally

1. CSV upload, Python reference scanner and browser port, type/missing/duplicate statistics, conservative sensitivity checks, free-text inspection and reproducible sample reports.
2. Strict versioned safe-context generation: Standard metadata only, stable refs, exclusions, opt-in restricted labels, all non-Standard fields withheld by category, empty samples.
3. Exact JSON preview and SHA-256, explicit warning acknowledgements, stale-preview invalidation and local payload approval. No model call or fabricated response.

## Next: secure Cloudflare gateway (planned)

Review the existing disconnected prototype before use. Add authentication, shared rate limits, bounded request handling and retention/logging controls. Revalidate approved context server-side; accept exactly the reviewed body. Keep secrets exclusively server-side. Do not treat a payload hash or acknowledgement array as authentication.

## First Claude workflow (planned)

A narrow dataset-quality workflow: explain approved metadata, identify quality issues and limitations, suggest grounded analysis questions and return a validated structured plan. No general chat and no raw dataset values. Establish fake-client and adversarial evals, then a separately authorized live smoke test. Production integration is not claimed today.

## Controlled SQL (deferred)

Read-only SQL requires an isolated executor, validated statements, time/output limits and explicit approval semantics. It is not currently Claude-callable. No unrestricted Python execution is on this milestone's scope.

## Adaptive learning (deferred)

SQL exercises, hints, answer evaluation and difficulty progression follow a measured, reliable analytical workflow.
