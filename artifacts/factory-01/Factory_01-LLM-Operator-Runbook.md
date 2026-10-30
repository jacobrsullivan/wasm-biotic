# Factory_01 LLM Operator Runbook

This runbook operates a real OpenAI-driven `Factory_01` inside the live bounded `aiaf-v1` line.

Scope:

- single-factory
- local-first
- governed
- not an open federation
- not an unrestricted ecosystem runtime

Stable identifiers used in this runbook:

- spec id: `factory-program-spec:factory-01`
- profile id: `llm-driver-profile:factory-01-openai`
- provider example id: `provider:openai:factory-01`
- generation policy id: `generation-policy:factory-01`

Referenced payloads:

- [`artifacts/factory-01/provider-openai-example.json`](./provider-openai-example.json)
- [`artifacts/factory-01/program-create-factory-01.json`](./program-create-factory-01.json)
- [`artifacts/factory-01/llm-drive-factory-01.json`](./llm-drive-factory-01.json)

## 1. Preconditions

- Work from the repository root.
- Export a real OpenAI key as `OPENAI_API_KEY`.
- Keep the default local runtime root at `./.aiaf-local/`.
- Treat the operator console as the visibility surface and the API/CLI as the mutation surface.

Expected evidence:

- `OPENAI_API_KEY` is available to the runner process.
- No additional profile provisioning step is required. `Factory_01` is seeded by runtime startup.

## 2. Workspace Bootstrap

Prepare the local runtime root:

```bash
mkdir -p .aiaf-local
```

Expected evidence:

- The operator root exists at `.aiaf-local/`.
- Runtime state will be persisted under `.aiaf-local/` and `.aiaf-local/llm-interface-store/`.

## 3. Start Console

Start the observer console:

```bash
env CARGO_TARGET_DIR=/tmp/aiaf-v1-target cargo run --bin aiaf-v1-runner -- serve
```

Open `http://127.0.0.1:4176`.

Expected evidence:

- The console loads `System Overview`, `Factory`, `Agent`, `Review`, `History`, `Portfolio`, `Evidence`, `Operator`, `Runbook`, and `Planning`.
- The API root is reachable at `http://127.0.0.1:4176/api/...`.

## 4. Verify Seeded Factory_01 Assets

Set a shell variable for the API:

```bash
export BASE_URL=http://127.0.0.1:4176
```

Verify the seeded spec:

```bash
rg -n '"factory-program-spec:factory-01"' .aiaf-local/factory-program-specs.json
```

Verify the seeded profile:

```bash
curl -sS "$BASE_URL/api/llm-interface/llm-driver-profiles"
```

Expected evidence:

- `.aiaf-local/factory-program-specs.json` contains `factory-program-spec:factory-01`.
- `GET /api/llm-interface/llm-driver-profiles` contains `llm-driver-profile:factory-01-openai`.
- `response_schema_family` is `supervisor_turn_v1`.
- `allowed_resource_scopes` stay bounded to the active program instance and active task scope.

## 5. Register Real OpenAI Provider

Register the provider using the canonical example payload:

```bash
curl -sS \
  -X POST \
  "$BASE_URL/api/llm-interface/providers" \
  -H "content-type: application/json" \
  --data @artifacts/factory-01/provider-openai-example.json
```

Expected evidence:

- The response echoes `provider_id` as `provider:openai:factory-01`.
- `provider_mode` is `open_ai_responses`.
- The provider appears in `GET /api/llm-interface/providers`.

## 6. Create Factory_01 Program Instance

Create a new `Factory_01` instance from the seeded spec:

```bash
curl -sS \
  -X POST \
  "$BASE_URL/api/programs" \
  -H "content-type: application/json" \
  --data @artifacts/factory-01/program-create-factory-01.json
```

Expected evidence:

- The response contains `instance.instance_id`.
- `spec.spec_id` remains `factory-program-spec:factory-01`.
- `spec.llm_driver_profile_ref` is `llm-driver-profile:factory-01-openai`.
- `GET /api/programs` shows `Factory_01` in the program ledger.
- The console `Factory` surface shows a new `Factory_01` entry.

## 7. Drive The LLM Cycle

Drive the first bounded cycle:

```bash
curl -sS \
  -X POST \
  "$BASE_URL/api/programs/<instance-id>/llm-drive" \
  -H "content-type: application/json" \
  --data @artifacts/factory-01/llm-drive-factory-01.json
```

Expected evidence:

- A turn package is recorded in `GET /api/llm-interface/turn-packages`.
- A parsed result is recorded in `GET /api/llm-interface/parsed-turn-results`.
- The program view at `GET /api/programs/<instance-id>` contains `model_factory_cycles`.
- The console `Factory`, `Review`, and `Evidence` surfaces now show live cycle material.

## 8. Observe Turn Packages, Tools, Approvals, Quarantines, And Health

Review the bounded cycle surfaces:

```bash
curl -sS "$BASE_URL/api/programs/<instance-id>"
curl -sS "$BASE_URL/api/llm-interface/turn-packages"
curl -sS "$BASE_URL/api/llm-interface/parsed-turn-results"
curl -sS "$BASE_URL/api/llm-interface/tool-executions"
curl -sS "$BASE_URL/api/llm-interface/model-factory-cycles"
curl -sS "$BASE_URL/api/llm-interface/recursive-lineages"
curl -sS "$BASE_URL/api/llm-interface/recursive-factory-health"
curl -sS "$BASE_URL/api/operator/runbook"
curl -sS "$BASE_URL/api/operator/planning"
```

Expected evidence:

- `turn-packages` shows a `llm-factory-turn-package:*` record.
- `tool-executions` shows bounded membrane decisions, not raw shell authority.
- `model-factory-cycles` shows the latest recursive cycle outcome.
- `recursive-lineages` and `recursive-factory-health` show whether the claim is governed, on hold, or insufficient.
- `operator/runbook` and `operator/planning` explicitly reference `Factory_01`.

## 9. Resolve Approval Or Quarantine Branches

If the cycle is approval-blocked, fetch the approval request id:

```bash
curl -sS "$BASE_URL/api/llm-interface/model-approval-requests"
```

Grant the bounded promotion:

```bash
curl -sS \
  -X POST \
  "$BASE_URL/api/llm-interface/model-approval-requests/<approval-id>/grant"
```

Deny instead if the claim is not ready:

```bash
curl -sS \
  -X POST \
  "$BASE_URL/api/llm-interface/model-approval-requests/<approval-id>/deny"
```

If the cycle is quarantined:

- inspect `GET /api/llm-interface/model-factory-cycles`
- inspect `GET /api/llm-interface/recursive-lineages`
- inspect `GET /api/llm-interface/recursive-factory-health`
- do not treat quarantine as cleared until a later bounded cycle supplies replacement evidence

Expected evidence:

- A granted approval moves the cycle to an adopted tick-backed result.
- A denied approval keeps the incumbent unchanged and preserves explicit governance evidence.
- A quarantined cycle puts the recursive claim on hold instead of silently continuing.

## 10. Export Evidence And Close The Cycle

The current line does not expose a dedicated factory-program export endpoint. Export is an operator snapshot assembled from governed readouts.

Create a review bundle:

```bash
mkdir -p .aiaf-local/exports/factory-01-review
curl -sS "$BASE_URL/api/programs/<instance-id>" > .aiaf-local/exports/factory-01-review/program.json
curl -sS "$BASE_URL/api/llm-interface/model-factory-cycles" > .aiaf-local/exports/factory-01-review/model-factory-cycles.json
curl -sS "$BASE_URL/api/llm-interface/recursive-lineages" > .aiaf-local/exports/factory-01-review/recursive-lineages.json
curl -sS "$BASE_URL/api/llm-interface/recursive-factory-health" > .aiaf-local/exports/factory-01-review/recursive-factory-health.json
curl -sS "$BASE_URL/api/llm-interface/tool-executions" > .aiaf-local/exports/factory-01-review/tool-executions.json
curl -sS "$BASE_URL/api/operator/runbook" > .aiaf-local/exports/factory-01-review/operator-runbook.json
curl -sS "$BASE_URL/api/operator/planning" > .aiaf-local/exports/factory-01-review/operator-planning.json
```

Expected evidence:

- The review bundle contains the program view, cycle ledger, lineage ledger, health view, tool execution ledger, and operator steering surfaces.
- The bundle is reconstructable from local persisted artifacts only.

## 11. Failure, Recovery, And Rollback Handling

Use these rules:

- `approval_blocked`: resolve through grant or deny before driving again.
- `denied`: inspect the parsed result and tool membrane output, fix the request path, then re-drive.
- `quarantined`: inspect quarantine evidence first; the recursive claim remains on hold.
- `failed`: treat the turn as contract-invalid or transport-invalid until the request shape is corrected.
- `rolled_back`: confirm `current_factory_ref` in `GET /api/programs/<instance-id>` points back to the last adopted incumbent.

Expected evidence:

- `current_factory_ref` never advances without an adopted governed cycle.
- `recursive-lineages` and the recursion closure dossier show when the claim is on hold.
- Recovery happens through another bounded cycle, not through hidden state mutation.

## 12. Claim-Boundary Checks

Confirm these fields before calling the cycle complete:

- `spec.title` is `Factory_01`.
- `spec.root_factory_ref` is `factory:aiaf-v1:root`.
- `spec.stable_interface_ref` is `contract:aiaf-v1:bounded-v1`.
- `llm_driver_profile.profile.llm_factory_program_profile_id` is `llm-driver-profile:factory-01-openai`.
- `response_schema_family` is `supervisor_turn_v1`.
- The recursive lineage, architectural dependency statement, and recursion closure dossier use governed bounded language.
- Nothing in the evidence bundle claims open federation, unrestricted autonomy, or multi-factory expansion.

## Next Extension

Once one governed `Factory_01` line is stable, the next bounded step is to add adjacent factories as explicit downstream work. Do not collapse that into this runbook. This document is only for the single-factory `Factory_01` line.
