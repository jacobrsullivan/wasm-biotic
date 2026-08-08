use crate::local_runtime_support::{
    get_json, post_empty, post_json, reloaded_service_from_existing_workspace, router, service,
};
use aiaf_v1::execution::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityOperationApproval,
    CapabilityWorld, CapabilityWorldGrant, InferenceGenerationPolicy, InferenceProviderMode,
    InferenceProviderModelEntry, InferenceProviderRegistryEntry, IsolationProfile,
    LlmFactoryProgramProfile, RecursionClaimPosture, RecursiveCycleOutcome,
    TurnResponseSchemaFamily, WorkerAgentProductionMode, WorkerRoleKind,
};
use aiaf_v1::local_runtime::{
    ArchitecturalDependencyStatementLedgerView, FactoryProgramView, InferenceProviderView,
    LlmFactoryProgramProfileLedgerView, ModelApprovalRequestLedgerView,
    ModelDrivenFactoryCycleLedgerView, ParsedTurnResultLedgerView, ProducedWorkerAgentLedgerView,
    RecursionClosureDossierLedgerView, RecursiveFactoryHealthView,
    RecursiveLineageExecutionLedgerView, ToolExecutionLedgerView, TurnGovernanceView,
    TurnPackageLedgerView,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router as AxumRouter};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[derive(Clone, Copy)]
enum MockResponseKind {
    RecursiveAdoptingCycle,
    ApprovalBlocked,
    UnsupportedTool,
    Quarantined,
    InvalidContract,
}

#[derive(Clone, Copy)]
struct MockState {
    response_kind: MockResponseKind,
}

fn provider(provider_id: &str, base_url: &str) -> InferenceProviderRegistryEntry {
    InferenceProviderRegistryEntry {
        provider_id: provider_id.to_string(),
        provider_mode: InferenceProviderMode::OpenAiResponses,
        models: vec![InferenceProviderModelEntry {
            model_ref: "gpt-5.4-mini".to_string(),
            input_cost_per_million_microunits: 750_000,
            output_cost_per_million_microunits: 4_500_000,
            supports_json_schema: true,
            supports_function_tools: true,
        }],
        capability_summary: "OpenAI Responses transport".to_string(),
        policy_summary: "bounded recursive factory inference".to_string(),
        active: true,
        api_base_url: base_url.to_string(),
        api_key_env_var: "PATH".to_string(),
        organization_env_var: None,
        project_env_var: None,
        request_timeout_ms: 50,
    }
}

fn generation_policy(id: &str) -> InferenceGenerationPolicy {
    InferenceGenerationPolicy {
        generation_policy_id: id.to_string(),
        max_output_tokens: 256,
        max_retries: 1,
        summary: "bounded recursive factory generation policy".to_string(),
    }
}

fn stable_short_token(value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{hash:016x}")
}

fn task_scope(instance_id: &str, campaign_number: usize) -> String {
    format!(
        "factory-program-task:{}:{}",
        stable_short_token(instance_id),
        campaign_number
    )
}

fn allowed_scopes(instance_id: &str, max_campaigns: usize) -> Vec<String> {
    let mut scopes = vec![instance_id.to_string()];
    for campaign_number in 1..=max_campaigns {
        scopes.push(task_scope(instance_id, campaign_number));
    }
    scopes
}

fn recursive_profile(
    profile_id: &str,
    instance_id: &str,
    max_campaigns: usize,
    review_approval_class: ApprovalClass,
    include_quarantine_operation: bool,
) -> LlmFactoryProgramProfile {
    let mut review_operations = vec!["program.submit_cycle_decision".to_string()];
    let mut operation_approval_overrides = Vec::new();
    if include_quarantine_operation {
        review_operations.push("governance.recommend_quarantine".to_string());
        operation_approval_overrides.push(CapabilityOperationApproval {
            operation: "governance.recommend_quarantine".to_string(),
            approval_class: ApprovalClass::QuarantineOnExpand,
        });
    }

    LlmFactoryProgramProfile {
        llm_factory_program_profile_id: profile_id.to_string(),
        title: "Recursive Driver Profile".to_string(),
        system_frame_text: "You are the bounded recursive supervisor.".to_string(),
        program_frame_template:
            "Operate factory program {{program_title}} for cycle {{next_campaign_number}}."
                .to_string(),
        capability_frame_text: "Remain inside the bounded recursive membrane.".to_string(),
        agenda_template:
            "Inspect {{current_factory_ref}} and decide the next governed recursive step."
                .to_string(),
        response_schema_family: TurnResponseSchemaFamily::SupervisorTurnV1,
        max_rendered_prompt_chars: 8_000,
        max_continuity_entries: 4,
        capability_envelope: CapabilityEnvelope {
            envelope_id: format!("envelope:{profile_id}"),
            actor_scope: "llm-turn".to_string(),
            world_grants: vec![
                CapabilityWorldGrant {
                    world: CapabilityWorld::WorkerMessaging,
                    allowed_operations: vec![
                        "ecology.dispatch_worker".to_string(),
                        "ecology.collect_results".to_string(),
                    ],
                    default_authority_class: AuthorityClass::CampaignControl,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: Vec::new(),
                },
                CapabilityWorldGrant {
                    world: CapabilityWorld::ReviewPromotion,
                    allowed_operations: review_operations,
                    default_authority_class: AuthorityClass::PromotionControl,
                    default_approval_class: review_approval_class,
                    operation_approval_overrides,
                },
            ],
            authority_ceiling: AuthorityClass::PromotionControl,
            isolation_profile: IsolationProfile::SupervisorExclusive,
            allowed_resource_scopes: allowed_scopes(instance_id, max_campaigns),
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: None,
            epoch_scope: None,
        },
        default_pointer_index_ref: None,
        default_ecology_snapshot_ref: None,
        default_workspace_scope_ref: None,
        default_campaign_ref: None,
        default_epoch_ref: None,
        created_at: "2026-04-18T00:00:00Z".to_string(),
    }
}

async fn mock_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    let body = match state.response_kind {
        MockResponseKind::RecursiveAdoptingCycle => json!({
            "id": "resp_recursive_adopt",
            "output_parsed": {
                "summary": "recursive factory cycle completed",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "advance the recursive campaign"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "ecology.dispatch_worker",
                        "arguments": {
                            "worker_id": "worker:recursive-validator",
                            "worker_task_ref": "worker-task:recursive-validator",
                            "task_kind": "validate",
                            "requested_capabilities": [
                                {
                                    "world": "review_promotion",
                                    "operation": "review",
                                    "resource_scope": "task:recursive"
                                }
                            ]
                        }
                    },
                    {
                        "tool_id": "ecology.collect_results",
                        "arguments": {
                            "dispatch_id": "dispatch:recursive-validator",
                            "worker_id": "worker:recursive-validator",
                            "worker_task_ref": "worker-task:recursive-validator",
                            "result_ref": "worker-result:recursive-validator",
                            "summary": "validator completed bounded comparison"
                        }
                    },
                    {
                        "tool_id": "program.submit_cycle_decision",
                        "arguments": {
                            "candidate_factory_ref": "factory:recursive-next",
                            "proving_refs": ["proving:recursive-next"],
                            "observation_refs": ["observation:recursive-next"],
                            "comparison_refs": ["comparison:recursive-next"],
                            "risk_refs": ["risk:recursive-next"],
                            "trend_refs": ["trend:recursive-next"],
                            "rollback_refs": ["rollback:recursive-next"],
                            "decision": "adopted",
                            "operator_note": "bounded recursive adoption"
                        }
                    }
                ],
                "stop_recommendation": "continue"
            },
            "usage": {"input_tokens": 120, "output_tokens": 40, "total_tokens": 160}
        }),
        MockResponseKind::ApprovalBlocked => json!({
            "id": "resp_recursive_approval",
            "output_parsed": {
                "summary": "approval-blocked recursive cycle",
                "proposals": [
                    {"proposal_family": "approval_request", "summary": "request promotion approval"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "program.submit_cycle_decision",
                        "arguments": {
                            "candidate_factory_ref": "factory:recursive-approved",
                            "proving_refs": ["proving:recursive-approved"],
                            "observation_refs": ["observation:recursive-approved"],
                            "comparison_refs": ["comparison:recursive-approved"],
                            "risk_refs": ["risk:recursive-approved"],
                            "trend_refs": ["trend:recursive-approved"],
                            "rollback_refs": ["rollback:recursive-approved"],
                            "decision": "adopted",
                            "operator_note": "requires approval"
                        }
                    }
                ],
                "stop_recommendation": "constrain"
            },
            "usage": {"input_tokens": 80, "output_tokens": 24, "total_tokens": 104}
        }),
        MockResponseKind::UnsupportedTool => json!({
            "id": "resp_recursive_denied",
            "output_parsed": {
                "summary": "denied recursive cycle",
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
            "id": "resp_recursive_quarantine",
            "output_parsed": {
                "summary": "quarantined recursive cycle",
                "proposals": [
                    {"proposal_family": "halt_or_escalate", "summary": "quarantine the cycle"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "governance.recommend_quarantine",
                        "arguments": {
                            "reason_class": "policy_violation",
                            "affected_refs": ["factory:recursive-next"],
                            "summary": "recursive claim widened scope"
                        }
                    }
                ],
                "stop_recommendation": "pause"
            },
            "usage": {"input_tokens": 40, "output_tokens": 14, "total_tokens": 54}
        }),
        MockResponseKind::InvalidContract => json!({
            "id": "resp_recursive_invalid_contract",
            "output_parsed": {
                "summary": "missing required supervisor fields"
            },
            "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16}
        }),
    };
    (
        StatusCode::OK,
        [(
            "x-request-id".to_string(),
            "req_recursive_factory".to_string(),
        )],
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

#[tokio::test]
async fn llm_driver_records_cycles_workers_lineage_and_reloads_cleanly() {
    let service = service("llm-recursive-factory-success").await;
    let app = router(service.clone());
    let profile_id = "profile:recursive-success";
    let created: FactoryProgramView = post_json(
        &app,
        "/api/programs",
        &json!({
            "spec_id": "factory-program-spec:recursive-success",
            "title": "Recursive Success Program",
            "root_factory_ref": "factory:root",
            "stable_interface_ref": "stable-interface:v1",
            "goal_refs": ["goal:recursive-success"],
            "workload_refs": ["workload:recursive-success"],
            "utility_metric_refs": ["metric:recursive-success"],
            "mutation_scope_refs": ["scope:recursive-success"],
            "promotion_gate_refs": ["promotion-gate:recursive-success"],
            "rollback_gate_refs": ["rollback-gate:recursive-success"],
            "recursion_budget": {
                "recursion_budget_id": "recursion-budget:recursive-success",
                "max_depth": 2,
                "max_campaigns": 3,
                "risk_threshold_refs": ["risk-threshold:recursive-success"],
                "exhaustion_policy": "stop"
            },
            "policy_ref": "policy:recursive-success",
            "llm_driver_profile_ref": profile_id
        }),
    )
    .await;
    service
        .upsert_llm_factory_program_profile(recursive_profile(
            profile_id,
            &created.instance.instance_id,
            3,
            ApprovalClass::SupervisorAllowed,
            false,
        ))
        .await
        .unwrap();

    let (address, handle) = spawn_mock_server(MockResponseKind::RecursiveAdoptingCycle).await;
    let provider = provider("provider:recursive-success", &format!("http://{address}"));
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let driven: FactoryProgramView = post_json(
        &app,
        &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
        &json!({
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:recursive-success"),
            "max_cycles": 3
        }),
    )
    .await;

    assert_eq!(driven.instance.generation_depth, 2);
    assert_eq!(driven.instance.campaign_count, 2);
    assert_eq!(
        driven.instance.program_state,
        aiaf_v1::execution::FactoryProgramState::Completed
    );
    assert!(driven.llm_driver_profile.is_some());
    assert_eq!(driven.model_factory_cycles.len(), 2);
    assert!(
        driven
            .model_factory_cycles
            .iter()
            .all(|cycle| cycle.cycle.outcome == RecursiveCycleOutcome::Adopted)
    );
    assert_eq!(driven.produced_worker_agents.len(), 1);
    assert_eq!(
        driven.produced_worker_agents[0].worker_card.role_kind,
        WorkerRoleKind::Validator
    );
    assert_eq!(
        driven.produced_worker_agents[0].worker_card.production_mode,
        Some(WorkerAgentProductionMode::ModelProduced)
    );
    assert_eq!(
        driven.produced_worker_agents[0]
            .worker_card
            .production_program_instance_ref
            .as_deref(),
        Some(driven.instance.instance_id.as_str())
    );
    assert_eq!(
        driven
            .recursive_lineage_execution
            .as_ref()
            .unwrap()
            .lineage
            .claim_posture,
        RecursionClaimPosture::GovernedBounded
    );
    assert!(
        driven
            .architectural_dependency_statement
            .as_ref()
            .unwrap()
            .statement
            .claim_boundary_statement
            .contains("governed, bounded")
    );
    let dossier_claim = &driven
        .recursion_closure_dossier
        .as_ref()
        .unwrap()
        .dossier
        .claim_boundary_statement;
    assert!(dossier_claim.contains("governed"));
    assert!(dossier_claim.contains("bounded"));

    let profile_ledger: LlmFactoryProgramProfileLedgerView =
        get_json(&app, "/api/llm-interface/llm-driver-profiles").await;
    assert!(
        profile_ledger
            .profiles
            .iter()
            .any(|view| { view.profile.llm_factory_program_profile_id == profile_id })
    );

    let turn_packages: TurnPackageLedgerView =
        get_json(&app, "/api/llm-interface/turn-packages").await;
    assert_eq!(turn_packages.turn_packages.len(), 2);

    let parsed_turns: ParsedTurnResultLedgerView =
        get_json(&app, "/api/llm-interface/parsed-turn-results").await;
    assert_eq!(parsed_turns.parsed_turn_results.len(), 2);

    let tool_executions: ToolExecutionLedgerView =
        get_json(&app, "/api/llm-interface/tool-executions").await;
    assert_eq!(tool_executions.tool_executions.len(), 6);

    let cycle_ledger: ModelDrivenFactoryCycleLedgerView =
        get_json(&app, "/api/llm-interface/model-factory-cycles").await;
    assert_eq!(cycle_ledger.cycles.len(), 2);

    let lineage_ledger: RecursiveLineageExecutionLedgerView =
        get_json(&app, "/api/llm-interface/recursive-lineages").await;
    assert_eq!(lineage_ledger.lineages.len(), 1);
    assert_eq!(
        lineage_ledger.lineages[0].lineage.claim_posture,
        RecursionClaimPosture::GovernedBounded
    );

    let produced_workers: ProducedWorkerAgentLedgerView =
        get_json(&app, "/api/llm-interface/produced-worker-agents").await;
    assert_eq!(produced_workers.workers.len(), 1);

    let dependencies: ArchitecturalDependencyStatementLedgerView =
        get_json(&app, "/api/llm-interface/architectural-dependencies").await;
    assert_eq!(dependencies.statements.len(), 1);

    let dossiers: RecursionClosureDossierLedgerView =
        get_json(&app, "/api/llm-interface/recursion-closure-dossiers").await;
    assert_eq!(dossiers.dossiers.len(), 1);

    let health: RecursiveFactoryHealthView =
        get_json(&app, "/api/llm-interface/recursive-factory-health").await;
    assert_eq!(health.model_driven_cycle_count, 2);
    assert_eq!(health.completed_cycle_decision_count, 2);
    assert_eq!(health.produced_worker_agent_count, 1);
    assert_eq!(health.adopted_count, 2);
    assert_eq!(health.max_generation_depth, 2);

    let reloaded = reloaded_service_from_existing_workspace(
        &service,
        "llm-recursive-factory-success-reloaded",
    )
    .await;
    let reloaded_app = router(reloaded);
    let reloaded_program: FactoryProgramView = get_json(
        &reloaded_app,
        &format!("/api/programs/{}", driven.instance.instance_id),
    )
    .await;
    assert_eq!(reloaded_program.instance, driven.instance);
    assert_eq!(reloaded_program.model_factory_cycles.len(), 2);
    assert_eq!(reloaded_program.produced_worker_agents.len(), 1);
    assert_eq!(
        reloaded_program
            .recursive_lineage_execution
            .as_ref()
            .unwrap()
            .lineage
            .campaign_count,
        2
    );
    handle.abort();
}

#[tokio::test]
async fn approval_blocked_llm_drive_requires_explicit_grant_without_hidden_next_cycle() {
    let service = service("llm-recursive-factory-approval").await;
    let app = router(service.clone());
    let profile_id = "profile:recursive-approval";
    let created: FactoryProgramView = post_json(
        &app,
        "/api/programs",
        &json!({
            "spec_id": "factory-program-spec:recursive-approval",
            "title": "Recursive Approval Program",
            "root_factory_ref": "factory:root",
            "stable_interface_ref": "stable-interface:v1",
            "goal_refs": ["goal:recursive-approval"],
            "workload_refs": ["workload:recursive-approval"],
            "utility_metric_refs": ["metric:recursive-approval"],
            "mutation_scope_refs": ["scope:recursive-approval"],
            "promotion_gate_refs": ["promotion-gate:recursive-approval"],
            "rollback_gate_refs": ["rollback-gate:recursive-approval"],
            "recursion_budget": {
                "recursion_budget_id": "recursion-budget:recursive-approval",
                "max_depth": 2,
                "max_campaigns": 2,
                "risk_threshold_refs": ["risk-threshold:recursive-approval"],
                "exhaustion_policy": "stop"
            },
            "policy_ref": "policy:recursive-approval",
            "llm_driver_profile_ref": profile_id
        }),
    )
    .await;
    service
        .upsert_llm_factory_program_profile(recursive_profile(
            profile_id,
            &created.instance.instance_id,
            2,
            ApprovalClass::HumanRequired,
            false,
        ))
        .await
        .unwrap();

    let (address, handle) = spawn_mock_server(MockResponseKind::ApprovalBlocked).await;
    let provider = provider("provider:recursive-approval", &format!("http://{address}"));
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let blocked: FactoryProgramView = post_json(
        &app,
        &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
        &json!({
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:recursive-approval"),
            "max_cycles": 2
        }),
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

    let health: RecursiveFactoryHealthView =
        get_json(&app, "/api/llm-interface/recursive-factory-health").await;
    assert_eq!(health.approval_incident_count, 1);
    assert_eq!(health.model_driven_cycle_count, 1);

    let approval_id = approvals.approvals[0]
        .approval
        .model_approval_request_id
        .clone();
    let resolved: TurnGovernanceView = post_empty(
        &app,
        &format!("/api/llm-interface/model-approval-requests/{approval_id}/grant"),
    )
    .await;
    assert_eq!(
        resolved.approvals[0]
            .approval
            .latest_decision
            .as_ref()
            .unwrap()
            .decision,
        aiaf_v1::execution::ApprovalDecisionStatus::Granted
    );

    let after_grant: FactoryProgramView = get_json(
        &app,
        &format!("/api/programs/{}", created.instance.instance_id),
    )
    .await;
    assert_eq!(after_grant.instance.campaign_count, 1);
    assert_eq!(after_grant.model_factory_cycles.len(), 1);
    assert!(
        after_grant.model_factory_cycles[0]
            .cycle
            .tick_receipt_ref
            .is_some()
    );
    assert_eq!(
        after_grant.model_factory_cycles[0].cycle.outcome,
        RecursiveCycleOutcome::Adopted
    );
    assert_eq!(
        after_grant
            .recursive_lineage_execution
            .as_ref()
            .unwrap()
            .lineage
            .claim_posture,
        RecursionClaimPosture::GovernedBounded
    );

    let after_grant_health: RecursiveFactoryHealthView =
        get_json(&app, "/api/llm-interface/recursive-factory-health").await;
    assert_eq!(after_grant_health.model_driven_cycle_count, 1);
    assert_eq!(after_grant_health.adopted_count, 1);
    handle.abort();
}

#[tokio::test]
async fn denied_quarantined_and_failed_cycles_put_recursive_claims_on_hold() {
    for (label, kind, expected_outcome, expect_quarantine_profile) in [
        (
            "denied",
            MockResponseKind::UnsupportedTool,
            RecursiveCycleOutcome::Denied,
            false,
        ),
        (
            "quarantined",
            MockResponseKind::Quarantined,
            RecursiveCycleOutcome::Quarantined,
            true,
        ),
        (
            "failed",
            MockResponseKind::InvalidContract,
            RecursiveCycleOutcome::Failed,
            false,
        ),
    ] {
        let service = service(&format!("llm-recursive-factory-{label}")).await;
        let app = router(service.clone());
        let profile_id = format!("profile:recursive-{label}");
        let created: FactoryProgramView = post_json(
            &app,
            "/api/programs",
            &json!({
                "spec_id": format!("factory-program-spec:recursive-{label}"),
                "title": format!("Recursive {label} Program"),
                "root_factory_ref": "factory:root",
                "stable_interface_ref": "stable-interface:v1",
                "goal_refs": [format!("goal:recursive-{label}")],
                "workload_refs": [format!("workload:recursive-{label}")],
                "utility_metric_refs": [format!("metric:recursive-{label}")],
                "mutation_scope_refs": [format!("scope:recursive-{label}")],
                "promotion_gate_refs": [format!("promotion-gate:recursive-{label}")],
                "rollback_gate_refs": [format!("rollback-gate:recursive-{label}")],
                "recursion_budget": {
                    "recursion_budget_id": format!("recursion-budget:recursive-{label}"),
                    "max_depth": 3,
                    "max_campaigns": 3,
                    "risk_threshold_refs": [format!("risk-threshold:recursive-{label}")],
                    "exhaustion_policy": "stop"
                },
                "policy_ref": format!("policy:recursive-{label}"),
                "llm_driver_profile_ref": profile_id
            }),
        )
        .await;
        service
            .upsert_llm_factory_program_profile(recursive_profile(
                &profile_id,
                &created.instance.instance_id,
                3,
                ApprovalClass::SupervisorAllowed,
                false,
            ))
            .await
            .unwrap();

        let (seed_address, seed_handle) =
            spawn_mock_server(MockResponseKind::RecursiveAdoptingCycle).await;
        let seed_provider = provider(
            &format!("provider:recursive-seed:{label}"),
            &format!("http://{seed_address}"),
        );
        let _: InferenceProviderView =
            post_json(&app, "/api/llm-interface/providers", &seed_provider).await;
        let seeded: FactoryProgramView = post_json(
            &app,
            &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
            &json!({
                "provider_ref": seed_provider.provider_id,
                "model_ref": "gpt-5.4-mini",
                "generation_policy": generation_policy(&format!("policy:recursive-seed:{label}")),
                "max_cycles": 1
            }),
        )
        .await;
        assert_eq!(seeded.instance.campaign_count, 1);
        assert_eq!(seeded.model_factory_cycles.len(), 1);
        seed_handle.abort();

        if expect_quarantine_profile {
            service
                .upsert_llm_factory_program_profile(recursive_profile(
                    &profile_id,
                    &created.instance.instance_id,
                    3,
                    ApprovalClass::SupervisorAllowed,
                    true,
                ))
                .await
                .unwrap();
        }

        let (address, handle) = spawn_mock_server(kind).await;
        let provider = provider(
            &format!("provider:recursive-incident:{label}"),
            &format!("http://{address}"),
        );
        let _: InferenceProviderView =
            post_json(&app, "/api/llm-interface/providers", &provider).await;
        let incident: FactoryProgramView = post_json(
            &app,
            &format!("/api/programs/{}/llm-drive", created.instance.instance_id),
            &json!({
                "provider_ref": provider.provider_id,
                "model_ref": "gpt-5.4-mini",
                "generation_policy": generation_policy(&format!("policy:recursive-incident:{label}")),
                "max_cycles": 1
            }),
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

        let health: RecursiveFactoryHealthView =
            get_json(&app, "/api/llm-interface/recursive-factory-health").await;
        assert_eq!(health.model_driven_cycle_count, 2);
        match expected_outcome {
            RecursiveCycleOutcome::Denied => assert_eq!(health.denial_incident_count, 1),
            RecursiveCycleOutcome::Quarantined => {
                assert_eq!(health.quarantine_incident_count, 1);
                let cycle_ledger: ModelDrivenFactoryCycleLedgerView =
                    get_json(&app, "/api/llm-interface/model-factory-cycles").await;
                assert_eq!(
                    cycle_ledger.cycles[0].cycle.outcome,
                    RecursiveCycleOutcome::Quarantined
                );
                assert_eq!(
                    incident.model_factory_cycles[1].cycle.quarantine_refs.len(),
                    1
                );
                assert_eq!(
                    get_json::<ModelDrivenFactoryCycleLedgerView>(
                        &app,
                        "/api/llm-interface/model-factory-cycles"
                    )
                    .await
                    .cycles[0]
                        .cycle
                        .outcome,
                    RecursiveCycleOutcome::Quarantined
                );
            }
            RecursiveCycleOutcome::Failed => assert_eq!(health.failure_incident_count, 1),
            _ => unreachable!(),
        }

        if expected_outcome == RecursiveCycleOutcome::Quarantined {
            assert_eq!(
                incident.model_factory_cycles[1].cycle.quarantine_refs.len(),
                1
            );
            let quarantines: FactoryProgramView = get_json(
                &app,
                &format!("/api/programs/{}", created.instance.instance_id),
            )
            .await;
            assert_eq!(
                quarantines.model_factory_cycles[1].cycle.outcome,
                RecursiveCycleOutcome::Quarantined
            );
            assert_eq!(
                quarantines
                    .architectural_dependency_statement
                    .as_ref()
                    .unwrap()
                    .statement
                    .claim_posture,
                RecursionClaimPosture::GovernedBoundedOnHold
            );
        }

        handle.abort();
    }
}
