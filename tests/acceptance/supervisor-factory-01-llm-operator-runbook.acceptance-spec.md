# Acceptance Spec: supervisor-factory-01-llm-operator-runbook

## Intent

Prove that the canonical seeded `Factory_01` line is executable as a real OpenAI-driven bounded single-factory program and that the operator runbook stays aligned with the runtime.

## Coverage

- seed `Factory_01` spec and `Factory_01` LLM driver profile on fresh startup
- create `Factory_01` through `POST /api/programs` using the seeded spec id
- drive `Factory_01` through `POST /api/programs/{instance_id}/llm-drive`
- surface approval-blocked, denied, quarantined, and failed branches through governed ledgers
- persist recursive cycle, lineage, and health state across reload
- keep runbook ids and payload files aligned with the seeded runtime assets

## Expected Truth

- `factory-program-spec:factory-01` is present in the workspace without a profile write API
- `llm-driver-profile:factory-01-openai` is present in the profile ledger with `SupervisorTurnV1`
- `provider:openai:factory-01` and `generation-policy:factory-01` remain the canonical runbook example ids
- approval grant produces an adopted bounded cycle
- denied, quarantined, and failed incident branches put the recursive claim on hold
- operator runbook and planning surfaces explicitly mention `Factory_01`
