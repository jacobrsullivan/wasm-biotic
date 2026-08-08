use crate::local_runtime_support::{
    get_json, post_empty, post_json, reloaded_service_from_existing_workspace, router, service,
};
use aiaf_v1::execution::{
    FactoryProgramSpec, RecursionClaimPosture, RecursiveCycleOutcome, TurnResponseSchemaFamily,
};
use aiaf_v1::local_runtime::{
    FactoryProgramLedgerView, FactoryProgramView, InferenceProviderView,
    LlmFactoryProgramProfileLedgerView, ModelApprovalRequestLedgerView,
    ModelDrivenFactoryCycleLedgerView, OperatorRunbookView, ParsedTurnResultLedgerView,
    PlanningGuidanceView, RecursiveFactoryHealthView, RecursiveLineageExecutionLedgerView,
    ToolExecutionLedgerView, TurnPackageLedgerView,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router as AxumRouter};
use serde_json::{Value, json};
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use tokio::net::TcpListener;

const FACTORY_01_SPEC_ID: &str = "factory-program-spec:factory-01";
const FACTORY_01_PROFILE_ID: &str = "llm-driver-profile:factory-01-openai";
const FACTORY_01_PROVIDER_ID: &str = "provider:openai:factory-01";
const FACTORY_01_GENERATION_POLICY_ID: &str = "generation-policy:factory-01";
const RUNBOOK_PATH: &str =
    "design-and-planning/AI-Agent-Factory/Factory_01-LLM-Operator-Runbook.md";
const PROVIDER_FIXTURE_PATH: &str = "artifacts/factory-01/provider-openai-example.json";
const PROGRAM_FIXTURE_PATH: &str = "artifacts/factory-01/program-create-factory-01.json";
const DRIVE_FIXTURE_PATH: &str = "artifacts/factory-01/llm-drive-factory-01.json";

#[derive(Clone, Copy)]
enum MockResponseKind {
    ApprovalBlocked,
    UnsupportedTool,
    Quarantined,
    InvalidContract,
}

#[derive(Clone, Copy)]
struct MockState {
    response_kind: MockResponseKind,
}

fn load_json(path: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn factory_01_program_payload() -> Value {
    load_json(PROGRAM_FIXTURE_PATH)
}

fn factory_01_drive_payload(provider_id: &str) -> Value {
    let mut payload = load_json(DRIVE_FIXTURE_PATH);
    payload["provider_ref"] = json!(provider_id);
    payload
}

fn factory_01_provider_payload(provider_id: &str, base_url: &str) -> Value {
    let mut payload = load_json(PROVIDER_FIXTURE_PATH);
    payload["provider_id"] = json!(provider_id);
    payload["api_base_url"] = json!(base_url);
    payload["api_key_env_var"] = json!("PATH");
    payload
}

async fn mock_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    let body = match state.response_kind {
        MockResponseKind::ApprovalBlocked => json!({
            "id": "resp_factory_01_approval",
            "output_parsed": {
                "summary": "approval-blocked Factory_01 cycle",
                "proposals": [
                    {"proposal_family": "approval_request", "summary": "request promotion approval"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "program.submit_cycle_decision",
                        "arguments": {
                            "candidate_factory_ref": "factory:factory-01:g1",
                            "proving_refs": ["proving:factory-01:g1"],
                            "observation_refs": ["observation:factory-01:g1"],
                            "comparison_refs": ["comparison:factory-01:g1"],
                            "risk_refs": ["risk:factory-01:g1"],
                            "trend_refs": ["trend:factory-01:g1"],
                            "rollback_refs": ["rollback:factory-01:g1"],
                            "decision": "adopted",
                            "operator_note": "Factory_01 bounded promotion request"
                        }
                    }
                ],
                "stop_recommendation": "constrain"
            },
            "usage": {"input_tokens": 80, "output_tokens": 24, "total_tokens": 104}
        }),
        MockResponseKind::UnsupportedTool => json!({
            "id": "resp_factory_01_denied",
            "output_parsed": {
                "summary": "denied Factory_01 cycle",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "unsupported request"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "unsupported.synthetic_tool",
                        "arguments": {"summary": "not in the membrane"}
                    }
                ],
                "stop_recommendation": "pause"
            },
            "usage": {"input_tokens": 32, "output_tokens": 12, "total_tokens": 44}
        }),
        MockResponseKind::Quarantined => json!({
            "id": "resp_factory_01_quarantine",
            "output_parsed": {
                "summary": "quarantined Factory_01 cycle",
                "proposals": [
                    {"proposal_family": "halt_or_escalate", "summary": "quarantine the cycle"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "governance.recommend_quarantine",
                        "arguments": {
                            "reason_class": "policy_violation",
                            "affected_refs": ["factory:factory-01:g2"],
                            "summary": "Factory_01 widened scope"
                        }
                    }
                ],
                "stop_recommendation": "pause"
            },
            "usage": {"input_tokens": 40, "output_tokens": 14, "total_tokens": 54}
        }),
        MockResponseKind::InvalidContract => json!({
            "id": "resp_factory_01_invalid_contract",
            "output_parsed": {
                "summary": "missing required supervisor fields"
            },
            "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16}
        }),
    };
    (
        StatusCode::OK,
        [("x-request-id".to_string(), "req_factory_01".to_string())],
        body.to_string(),
    )
}

async fn spawn_mock_server(kind: MockResponseKind) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = AxumRouter::new()
        .route("/v1/responses", post(mock_handler))
        .with_state(MockState {
            response_kind: kind,
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, handle)
}

fn write_export_bundle(path: &Path, name: &str, value: &Value) {
    fs::write(path.join(name), serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

#[tokio::test]
async fn seeded_factory_01_assets_match_runbook_payloads_and_surface_in_operator_views() {
    let service = service("factory-01-seeded-assets").await;
    let app = router(service.clone());

    let seeded_specs: Vec<FactoryProgramSpec> = serde_json::from_str(
        &fs::read_to_string(
            service
                .workspace()
                .root()
                .join("factory-program-specs.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let seeded_spec = seeded_specs
        .iter()
        .find(|spec| spec.spec_id == FACTORY_01_SPEC_ID)
        .cloned()
        .unwrap();
    let fixture_spec: FactoryProgramSpec =
        serde_json::from_value(factory_01_program_payload()).unwrap();
    assert_eq!(seeded_spec, fixture_spec);
    assert_eq!(seeded_spec.title, "Factory_01");

    let profile_ledger: LlmFactoryProgramProfileLedgerView =
        get_json(&app, "/api/llm-interface/llm-driver-profiles").await;
    let profile = profile_ledger
        .profiles
        .iter()
        .find(|view| view.profile.llm_factory_program_profile_id == FACTORY_01_PROFILE_ID)
        .cloned()
        .unwrap();
    assert_eq!(profile.profile.title, "Factory_01 Governed OpenAI Driver");
    assert_eq!(
        profile.profile.response_schema_family,
        TurnResponseSchemaFamily::SupervisorTurnV1
    );
    assert_eq!(
        profile.profile.capability_envelope.allowed_resource_scopes,
        vec![
            "{{program_instance_ref}}".to_string(),
            "{{task_ref}}".to_string()
        ]
    );
    assert_eq!(
        profile.profile.default_campaign_ref.as_deref(),
        Some("campaign:factory-01:{{program_instance_short_token}}:{{next_campaign_number}}")
    );

    let runbook: OperatorRunbookView = get_json(&app, "/api/operator/runbook").await;
    assert!(
        runbook
            .steering_context
            .contains("Factory_01 is preseeded locally")
    );
    assert!(runbook.steering_context.contains(FACTORY_01_SPEC_ID));
    assert!(runbook.steering_context.contains(FACTORY_01_PROFILE_ID));

    let planning: PlanningGuidanceView = get_json(&app, "/api/operator/planning").await;
    assert_eq!(planning.recommendations[0].title, "Instantiate Factory_01");
    assert!(
        planning.recommendations[0]
            .supporting_refs
            .contains(&FACTORY_01_PROVIDER_ID.to_string())
    );
    assert!(
        planning.recommendations[0]
            .supporting_refs
            .contains(&FACTORY_01_GENERATION_POLICY_ID.to_string())
    );

    let runbook_text = fs::read_to_string(RUNBOOK_PATH).unwrap();
    assert!(runbook_text.contains(FACTORY_01_SPEC_ID));
    assert!(runbook_text.contains(FACTORY_01_PROFILE_ID));
    assert!(runbook_text.contains(FACTORY_01_PROVIDER_ID));
    assert!(runbook_text.contains(FACTORY_01_GENERATION_POLICY_ID));
    assert!(runbook_text.contains("/api/programs"));
    assert!(runbook_text.contains("/api/programs/<instance-id>/llm-drive"));
    assert!(
        runbook_text.contains("/api/llm-interface/model-approval-requests/<approval-id>/grant")
    );
    assert!(runbook_text.contains("artifacts/factory-01/provider-openai-example.json"));
    assert!(runbook_text.contains("artifacts/factory-01/program-create-factory-01.json"));
    assert!(runbook_text.contains("artifacts/factory-01/llm-drive-factory-01.json"));

    let provider_fixture = load_json(PROVIDER_FIXTURE_PATH);
    assert_eq!(provider_fixture["provider_id"], FACTORY_01_PROVIDER_ID);
    assert_eq!(provider_fixture["api_key_env_var"], "OPENAI_API_KEY");
    let drive_fixture = load_json(DRIVE_FIXTURE_PATH);
    assert_eq!(
        drive_fixture["generation_policy"]["generation_policy_id"],
        FACTORY_01_GENERATION_POLICY_ID
    );
    assert_eq!(drive_fixture["provider_ref"], FACTORY_01_PROVIDER_ID);

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "factory-01-seeded-assets-reloaded")
            .await;
    let reloaded_app = router(reloaded);
    let reloaded_profiles: LlmFactoryProgramProfileLedgerView =
        get_json(&reloaded_app, "/api/llm-interface/llm-driver-profiles").await;
    assert!(
        reloaded_profiles
            .profiles
            .iter()
            .any(|view| view.profile.llm_factory_program_profile_id == FACTORY_01_PROFILE_ID)
    );
}

#[tokio::test]
async fn factory_01_public_api_flow_grants_adopted_cycle_and_exports_review_bundle() {
    let service = service("factory-01-approval-grant-flow").await;
    let app = router(service.clone());

    let created: FactoryProgramView =
        post_json(&app, "/api/programs", &factory_01_program_payload()).await;
    assert_eq!(created.spec.spec_id, FACTORY_01_SPEC_ID);
    assert_eq!(created.spec.title, "Factory_01");
    assert_eq!(
        created.spec.llm_driver_profile_ref.as_deref(),
        Some(FACTORY_01_PROFILE_ID)
    );

    let planning_before_drive: PlanningGuidanceView =
        get_json(&app, "/api/operator/planning").await;
    assert_eq!(
        planning_before_drive.recommendations[0].title,
        "Drive Factory_01 through the seeded profile"
    );

    let (address, handle) = spawn_mock_server(MockResponseKind::ApprovalBlocked).await;
    let provider_payload =
        factory_01_provider_payload(FACTORY_01_PROVIDER_ID, &format!("http://{address}"));
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &provider_payload).await;

    let blocked: FactoryProgramView = post_json(
        &app,
        &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
        &factory_01_drive_payload(FACTORY_01_PROVIDER_ID),
    )
    .await;
    assert_eq!(blocked.instance.campaign_count, 0);
    assert_eq!(blocked.model_factory_cycles.len(), 1);
    assert_eq!(
        blocked.model_factory_cycles[0].cycle.outcome,
        RecursiveCycleOutcome::ApprovalBlocked
    );
    assert_eq!(
        blocked
            .recursive_lineage_execution
            .as_ref()
            .unwrap()
            .lineage
            .claim_posture,
        RecursionClaimPosture::InsufficientEvidence
    );

    let approvals: ModelApprovalRequestLedgerView =
        get_json(&app, "/api/llm-interface/model-approval-requests").await;
    assert_eq!(approvals.approvals.len(), 1);
    let approval_id = approvals.approvals[0]
        .approval
        .model_approval_request_id
        .clone();

    let turn_packages: TurnPackageLedgerView =
        get_json(&app, "/api/llm-interface/turn-packages").await;
    assert_eq!(turn_packages.turn_packages.len(), 1);
    let parsed_turns: ParsedTurnResultLedgerView =
        get_json(&app, "/api/llm-interface/parsed-turn-results").await;
    assert_eq!(parsed_turns.parsed_turn_results.len(), 1);

    let planning_approval: PlanningGuidanceView = get_json(&app, "/api/operator/planning").await;
    assert_eq!(
        planning_approval.recommendations[0].title,
        "Resolve Factory_01 approval boundary"
    );

    let _: Value = post_empty(
        &app,
        &format!("/api/llm-interface/model-approval-requests/{approval_id}/grant"),
    )
    .await;

    let adopted: FactoryProgramView = get_json(
        &app,
        &format!("/api/programs/{}", created.instance.instance_id),
    )
    .await;
    assert_eq!(adopted.instance.campaign_count, 1);
    assert_eq!(adopted.model_factory_cycles.len(), 1);
    assert_eq!(
        adopted.model_factory_cycles[0].cycle.outcome,
        RecursiveCycleOutcome::Adopted
    );
    assert_eq!(
        adopted
            .recursive_lineage_execution
            .as_ref()
            .unwrap()
            .lineage
            .claim_posture,
        RecursionClaimPosture::GovernedBounded
    );
    assert!(
        adopted
            .architectural_dependency_statement
            .as_ref()
            .unwrap()
            .statement
            .claim_boundary_statement
            .contains("governed, bounded")
    );

    let ledger: FactoryProgramLedgerView = get_json(&app, "/api/programs").await;
    assert!(
        ledger
            .programs
            .iter()
            .any(|program| program.spec.title == "Factory_01")
    );

    let tool_executions: ToolExecutionLedgerView =
        get_json(&app, "/api/llm-interface/tool-executions").await;
    assert_eq!(tool_executions.tool_executions.len(), 1);

    let cycles: ModelDrivenFactoryCycleLedgerView =
        get_json(&app, "/api/llm-interface/model-factory-cycles").await;
    assert_eq!(cycles.cycles.len(), 1);

    let lineages: RecursiveLineageExecutionLedgerView =
        get_json(&app, "/api/llm-interface/recursive-lineages").await;
    assert_eq!(lineages.lineages.len(), 1);
    assert_eq!(
        lineages.lineages[0].lineage.claim_posture,
        RecursionClaimPosture::GovernedBounded
    );

    let health: RecursiveFactoryHealthView =
        get_json(&app, "/api/llm-interface/recursive-factory-health").await;
    assert_eq!(health.model_driven_cycle_count, 1);
    assert_eq!(health.completed_cycle_decision_count, 1);
    assert_eq!(health.adopted_count, 1);

    let operator_runbook: OperatorRunbookView = get_json(&app, "/api/operator/runbook").await;
    assert!(
        operator_runbook
            .steering_context
            .contains("Factory_01 is active")
    );
    assert!(
        operator_runbook
            .steering_context
            .contains(&created.instance.instance_id)
    );

    let planning_after_grant: PlanningGuidanceView = get_json(&app, "/api/operator/planning").await;
    assert_eq!(
        planning_after_grant.recommendations[0].title,
        "Review Factory_01 cycle evidence"
    );

    let export_root = service
        .workspace()
        .root()
        .join("exports")
        .join("factory-01-review");
    fs::create_dir_all(&export_root).unwrap();
    let adopted_value = serde_json::to_value(&adopted).unwrap();
    let cycles_value = serde_json::to_value(&cycles).unwrap();
    let lineages_value = serde_json::to_value(&lineages).unwrap();
    let health_value = serde_json::to_value(&health).unwrap();
    let tools_value = serde_json::to_value(&tool_executions).unwrap();
    let runbook_value = serde_json::to_value(&operator_runbook).unwrap();
    let planning_value = serde_json::to_value(&planning_after_grant).unwrap();
    write_export_bundle(&export_root, "program.json", &adopted_value);
    write_export_bundle(&export_root, "model-factory-cycles.json", &cycles_value);
    write_export_bundle(&export_root, "recursive-lineages.json", &lineages_value);
    write_export_bundle(&export_root, "recursive-factory-health.json", &health_value);
    write_export_bundle(&export_root, "tool-executions.json", &tools_value);
    write_export_bundle(&export_root, "operator-runbook.json", &runbook_value);
    write_export_bundle(&export_root, "operator-planning.json", &planning_value);
    assert_eq!(
        serde_json::from_str::<Value>(
            &fs::read_to_string(export_root.join("program.json")).unwrap()
        )
        .unwrap()["instance"]["instance_id"],
        created.instance.instance_id
    );

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "factory-01-approval-grant-reloaded")
            .await;
    let reloaded_app = router(reloaded);
    let reloaded_program: FactoryProgramView = get_json(
        &reloaded_app,
        &format!("/api/programs/{}", created.instance.instance_id),
    )
    .await;
    assert_eq!(reloaded_program.instance, adopted.instance);
    assert_eq!(reloaded_program.model_factory_cycles.len(), 1);
    assert_eq!(
        reloaded_program.model_factory_cycles[0].cycle.outcome,
        RecursiveCycleOutcome::Adopted
    );

    handle.abort();
}

#[tokio::test]
async fn factory_01_denied_quarantined_and_failed_cycles_hold_claim_boundary() {
    for (label, kind, expected_outcome, expected_title) in [
        (
            "denied",
            MockResponseKind::UnsupportedTool,
            RecursiveCycleOutcome::Denied,
            "Inspect Factory_01 incident evidence",
        ),
        (
            "quarantined",
            MockResponseKind::Quarantined,
            RecursiveCycleOutcome::Quarantined,
            "Review Factory_01 quarantine evidence",
        ),
        (
            "failed",
            MockResponseKind::InvalidContract,
            RecursiveCycleOutcome::Failed,
            "Inspect Factory_01 incident evidence",
        ),
    ] {
        let service = service(&format!("factory-01-incident-{label}")).await;
        let app = router(service.clone());
        let created: FactoryProgramView =
            post_json(&app, "/api/programs", &factory_01_program_payload()).await;

        let (seed_address, seed_handle) =
            spawn_mock_server(MockResponseKind::ApprovalBlocked).await;
        let seed_provider_id = format!("provider:openai:factory-01:{label}:seed");
        let seed_provider_payload =
            factory_01_provider_payload(&seed_provider_id, &format!("http://{seed_address}"));
        let _: InferenceProviderView =
            post_json(&app, "/api/llm-interface/providers", &seed_provider_payload).await;
        let seed_drive = factory_01_drive_payload(&seed_provider_id);
        let _: FactoryProgramView = post_json(
            &app,
            &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
            &seed_drive,
        )
        .await;
        let approvals: ModelApprovalRequestLedgerView =
            get_json(&app, "/api/llm-interface/model-approval-requests").await;
        let approval_id = approvals.approvals[0]
            .approval
            .model_approval_request_id
            .clone();
        let _: Value = post_empty(
            &app,
            &format!("/api/llm-interface/model-approval-requests/{approval_id}/grant"),
        )
        .await;
        seed_handle.abort();

        let (incident_address, incident_handle) = spawn_mock_server(kind).await;
        let incident_provider_id = format!("provider:openai:factory-01:{label}:incident");
        let incident_provider_payload = factory_01_provider_payload(
            &incident_provider_id,
            &format!("http://{incident_address}"),
        );
        let _: InferenceProviderView = post_json(
            &app,
            "/api/llm-interface/providers",
            &incident_provider_payload,
        )
        .await;
        let incident_drive = factory_01_drive_payload(&incident_provider_id);
        let incident: FactoryProgramView = post_json(
            &app,
            &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
            &incident_drive,
        )
        .await;

        assert_eq!(incident.instance.campaign_count, 1);
        assert_eq!(incident.model_factory_cycles.len(), 2);
        assert_eq!(
            incident.model_factory_cycles[1].cycle.outcome,
            expected_outcome
        );
        assert_eq!(
            incident
                .recursive_lineage_execution
                .as_ref()
                .unwrap()
                .lineage
                .claim_posture,
            RecursionClaimPosture::GovernedBoundedOnHold
        );
        assert!(
            incident
                .architectural_dependency_statement
                .as_ref()
                .unwrap()
                .statement
                .claim_boundary_statement
                .contains("on hold")
        );
        assert!(
            incident
                .recursion_closure_dossier
                .as_ref()
                .unwrap()
                .dossier
                .claim_boundary_statement
                .contains("on hold")
        );

        let planning: PlanningGuidanceView = get_json(&app, "/api/operator/planning").await;
        assert_eq!(planning.recommendations[0].title, expected_title);

        let health: RecursiveFactoryHealthView =
            get_json(&app, "/api/llm-interface/recursive-factory-health").await;
        assert_eq!(health.model_driven_cycle_count, 2);
        match expected_outcome {
            RecursiveCycleOutcome::Denied => assert_eq!(health.denial_incident_count, 1),
            RecursiveCycleOutcome::Quarantined => {
                assert_eq!(health.quarantine_incident_count, 1)
            }
            RecursiveCycleOutcome::Failed => assert_eq!(health.failure_incident_count, 1),
            _ => unreachable!(),
        }

        incident_handle.abort();
    }
}
