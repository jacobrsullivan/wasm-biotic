# Artifacts

This folder contains sample `task artifact`, `run checkpoint`, event, approval, and audit fixtures used by standalone `aiaf-v1`.

Current fixture set:

- [supervisor-approval-resume-worker-complete](fixtures/supervisor-approval-resume-worker-complete)
- [factory-01](factory-01) for the canonical OpenAI-driven `Factory_01` operator payloads
- [openrouter](openrouter) for an opt-in OpenRouter provider registration example

The static fixture set is intentionally narrow. The acceptance suite and local runner generate broader replay, promotion, rollback, and `v1 completion` bundles on the fly, so not every bounded runtime artifact is stored here as a checked-in fixture. Most richer bundles are emitted during tests or under `.aiaf-local/exports/` when the runner is used locally.
