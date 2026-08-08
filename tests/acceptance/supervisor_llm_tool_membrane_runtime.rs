use crate::local_runtime_support::{
    get_json, post_empty, post_empty_response, post_json, reloaded_service_from_existing_workspace,
    router, service,
};
use aiaf_v1::execution::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityOperationApproval,
    CapabilityWorld, CapabilityWorldGrant, FactoryProgramSpec, InferenceGenerationPolicy,
    InferenceProviderMode, InferenceProviderModelEntry, InferenceProviderRegistryEntry,
    IsolationProfile, RecursionBudgetRecord, TurnPackageRole, TurnResponseSchemaFamily,
};
use aiaf_v1::local_runtime::{
    AuthorityDecisionLedgerView, CreateTurnPackageContextBudget, CreateTurnPackageRequest,
    CreateTurnPackageToolExecutionContext, FactoryProgramView, GovernanceHealthView,
    InferenceProviderView, ModelApprovalRequestLedgerView, ModelQuarantineLedgerView,
    OperatorOnlySurfaceRegistryView, ParsedTurnResultView, ParsedTurnToolExecutionView,
    ToolCatalogView, ToolExecutionLedgerView, ToolExecutionView, TurnCheckpointLedgerView,
    TurnGovernanceView, TurnMemoryUpdateLedgerView, TurnMemoryUpdateView, TurnPackageView,
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
    ContinuitySupervisor,
    MemoryUpdateSupervisor,
    MultiFamilySupervisor,
    WorkerEcology,
    ApprovalBlocked,
    ApprovalBlockedWithParsedApproval,
    UnsupportedTool,
    Quarantined,
    FencedContinuitySupervisor,
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
        policy_summary: "bounded runtime inference".to_string(),
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
        summary: "bounded membrane acceptance generation policy".to_string(),
    }
}

fn base_envelope(allowed_resource_scopes: Vec<String>) -> CapabilityEnvelope {
    CapabilityEnvelope {
        envelope_id: "envelope:tool-membrane".to_string(),
        actor_scope: "llm-turn".to_string(),
        world_grants: Vec::new(),
        authority_ceiling: AuthorityClass::PromotionControl,
        isolation_profile: IsolationProfile::SupervisorExclusive,
        allowed_resource_scopes,
        approval_overrides: Vec::new(),
        quota_policy: None,
        campaign_scope: Some("campaign:tool-membrane".to_string()),
        epoch_scope: Some("epoch:tool-membrane".to_string()),
    }
}

fn turn_package_request(
    turn_package_id: &str,
    role: TurnPackageRole,
    response_schema_family: TurnResponseSchemaFamily,
    tool_execution_context: CreateTurnPackageToolExecutionContext,
) -> CreateTurnPackageRequest {
    CreateTurnPackageRequest {
        turn_package_id: turn_package_id.to_string(),
        program_ref: "program:tool-membrane".to_string(),
        session_ref: "session:tool-membrane".to_string(),
        turn_ref: "turn:tool-membrane".to_string(),
        envelope_ref: tool_execution_context
            .capability_envelope
            .envelope_id
            .clone(),
        role,
        system_frame_ref: "system:tool-membrane".to_string(),
        system_frame_text: "You are the bounded Wasm-Biotic supervisor.".to_string(),
        program_frame_ref: "program-frame:tool-membrane".to_string(),
        program_frame_text: "Operate through the canonical tool membrane.".to_string(),
        capability_frame_ref: "capability-frame:tool-membrane".to_string(),
        capability_frame_text: "Do not exceed the active capability envelope.".to_string(),
        agenda_ref: "agenda:tool-membrane".to_string(),
        agenda_text: "Evaluate the next bounded turn.".to_string(),
        continuity_entries: vec![aiaf_v1::execution::TurnContinuityEntry {
            entry_ref: "continuity:critical".to_string(),
            text: "Critical continuity evidence.".to_string(),
            priority: aiaf_v1::execution::ContinuityEntryPriority::Critical,
        }],
        tool_execution_context,
        response_schema_family,
        context_budget: CreateTurnPackageContextBudget {
            context_budget_id: format!("context-budget:{turn_package_id}"),
            max_rendered_prompt_chars: 5_000,
            max_continuity_entries: 4,
        },
    }
}

async fn mock_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    let body = match state.response_kind {
        MockResponseKind::ContinuitySupervisor => json!({
            "id": "resp_tool_membrane_continuity",
            "output_parsed": {
                "summary": "continuity supervisor result",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "advance bounded work"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "continuity.retrieve",
                        "arguments": {
                            "bundle_class": "campaign_operating_notes",
                            "search_term": "continuity",
                            "max_bundle_refs": 1
                        }
                    }
                ],
                "stop_recommendation": "continue"
            },
            "usage": {"input_tokens": 60, "output_tokens": 18, "total_tokens": 78}
        }),
        MockResponseKind::MemoryUpdateSupervisor => json!({
            "id": "resp_tool_membrane_memory_update",
            "output_parsed": {
                "summary": "continuity update supervisor result",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "carry forward verified continuity"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "continuity.propose_update",
                        "arguments": {
                            "summary": "Persist the verified continuity update.",
                            "evidence_refs": ["artifact:evidence:1", "artifact:evidence:2"],
                            "verification_refs": ["review:verification:1"]
                        }
                    }
                ],
                "stop_recommendation": "continue"
            },
            "usage": {"input_tokens": 58, "output_tokens": 16, "total_tokens": 74}
        }),
        MockResponseKind::MultiFamilySupervisor => json!({
            "id": "resp_tool_membrane_multifamily",
            "output_parsed": {
                "summary": "multi-family supervisor result",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "keep bounded execution moving"}
                ],
                "tool_call_intents": [
                    {"tool_id": "program.inspect", "arguments": {}},
                    {
                        "tool_id": "validation.run_proving",
                        "arguments": {
                            "candidate_factory_ref": "factory:g1",
                            "proving_run_ref": "proving-run:g1",
                            "summary": "run proving"
                        }
                    },
                    {
                        "tool_id": "validation.compare_candidate",
                        "arguments": {
                            "comparison_id": "comparison:g1",
                            "candidate_factory_ref": "factory:g1",
                            "incumbent_factory_ref": "factory:root",
                            "summary": "compare candidate"
                        }
                    }
                ],
                "stop_recommendation": "continue"
            },
            "usage": {"input_tokens": 90, "output_tokens": 28, "total_tokens": 118}
        }),
        MockResponseKind::WorkerEcology => json!({
            "id": "resp_tool_membrane_worker",
            "output_parsed": {
                "summary": "worker ecology result",
                "tool_call_intents": [
                    {
                        "tool_id": "ecology.dispatch_worker",
                        "arguments": {
                            "worker_id": "worker:observer",
                            "worker_task_ref": "worker-task:1",
                            "task_kind": "observe",
                            "requested_capabilities": [
                                {
                                    "world": "workspace_observe",
                                    "operation": "search",
                                    "resource_scope": "task:tool-membrane"
                                }
                            ]
                        }
                    },
                    {
                        "tool_id": "ecology.collect_results",
                        "arguments": {
                            "dispatch_id": "dispatch:1",
                            "worker_id": "worker:observer",
                            "worker_task_ref": "worker-task:1",
                            "result_ref": "worker-result:1",
                            "summary": "worker finished"
                        }
                    }
                ]
            },
            "usage": {"input_tokens": 40, "output_tokens": 14, "total_tokens": 54}
        }),
        MockResponseKind::ApprovalBlocked => json!({
            "id": "resp_tool_membrane_approval",
            "output_parsed": {
                "summary": "approval-blocked supervisor result",
                "proposals": [
                    {"proposal_family": "approval_request", "summary": "request promotion approval"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "program.submit_cycle_decision",
                        "arguments": {
                            "candidate_factory_ref": "factory:g1",
                            "proving_refs": ["proving:g1"],
                            "observation_refs": ["observation:g1"],
                            "comparison_refs": ["comparison:g1"],
                            "risk_refs": ["risk:g1"],
                            "trend_refs": ["trend:g1"],
                            "rollback_refs": ["rollback:g1"],
                            "decision": "adopted",
                            "operator_note": "requires promotion approval"
                        }
                    }
                ],
                "stop_recommendation": "constrain"
            },
            "usage": {"input_tokens": 44, "output_tokens": 16, "total_tokens": 60}
        }),
        MockResponseKind::ApprovalBlockedWithParsedApproval => json!({
            "id": "resp_tool_membrane_approval_dedup",
            "output_parsed": {
                "summary": "approval-blocked supervisor result with explicit approval artifact",
                "proposals": [
                    {"proposal_family": "approval_request", "summary": "request promotion approval"}
                ],
                "approval_request": {
                    "summary": "request promotion approval",
                    "action_ref": "program.submit_cycle_decision",
                    "scope_ref": "task:tool-membrane",
                    "requested_authority_class": "promotion_control"
                },
                "tool_call_intents": [
                    {
                        "tool_id": "program.submit_cycle_decision",
                        "arguments": {
                            "candidate_factory_ref": "factory:g1",
                            "proving_refs": ["proving:g1"],
                            "observation_refs": ["observation:g1"],
                            "comparison_refs": ["comparison:g1"],
                            "risk_refs": ["risk:g1"],
                            "trend_refs": ["trend:g1"],
                            "rollback_refs": ["rollback:g1"],
                            "decision": "adopted",
                            "operator_note": "requires promotion approval"
                        }
                    }
                ],
                "stop_recommendation": "constrain"
            },
            "usage": {"input_tokens": 48, "output_tokens": 18, "total_tokens": 66}
        }),
        MockResponseKind::UnsupportedTool => json!({
            "id": "resp_tool_membrane_unsupported",
            "output_parsed": {
                "summary": "unsupported tool result",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "flag the unsupported tool request"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "unsupported.synthetic_tool",
                        "arguments": {"summary": "tool is outside the bounded membrane"}
                    }
                ],
                "stop_recommendation": "pause"
            },
            "usage": {"input_tokens": 32, "output_tokens": 12, "total_tokens": 44}
        }),
        MockResponseKind::Quarantined => json!({
            "id": "resp_tool_membrane_quarantine",
            "output_parsed": {
                "summary": "quarantine recommendation",
                "proposals": [
                    {"proposal_family": "halt_or_escalate", "summary": "halt bounded turn"}
                ],
                "tool_call_intents": [
                    {
                        "tool_id": "governance.recommend_quarantine",
                        "arguments": {
                            "reason_class": "policy_violation",
                            "affected_refs": ["factory:g1"],
                            "summary": "candidate widened scope"
                        }
                    }
                ],
                "stop_recommendation": "pause"
            },
            "usage": {"input_tokens": 48, "output_tokens": 18, "total_tokens": 66}
        }),
        MockResponseKind::FencedContinuitySupervisor => json!({
            "id": "resp_tool_membrane_fenced",
            "output_parsed": "```json\n{\"summary\":\"fenced continuity result\",\"proposals\":[{\"proposal_family\":\"task_update\",\"summary\":\"continue bounded continuity review\"}],\"tool_call_intents\":[{\"tool_id\":\"continuity.retrieve\",\"arguments\":{\"bundle_class\":\"campaign_operating_notes\",\"search_term\":\"continuity\",\"max_bundle_refs\":1}}],\"stop_recommendation\":\"continue\"}\n```",
            "usage": {"input_tokens": 36, "output_tokens": 11, "total_tokens": 47}
        }),
    };
    (
        StatusCode::OK,
        [("x-request-id".to_string(), "req_tool_membrane".to_string())],
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

fn program_spec(spec_id: &str) -> FactoryProgramSpec {
    FactoryProgramSpec {
        spec_id: spec_id.to_string(),
        title: "Membrane Acceptance Program".to_string(),
        root_factory_ref: "factory:root".to_string(),
        stable_interface_ref: "stable-interface:v1".to_string(),
        goal_refs: vec!["goal:1".to_string()],
        workload_refs: vec!["workload:1".to_string()],
        utility_metric_refs: vec!["metric:1".to_string()],
        mutation_scope_refs: vec!["factory-program-instance:scope".to_string()],
        promotion_gate_refs: vec!["promotion-gate:1".to_string()],
        rollback_gate_refs: vec!["rollback-gate:1".to_string()],
        recursion_budget: RecursionBudgetRecord {
            recursion_budget_id: format!("recursion-budget:{spec_id}"),
            max_depth: 2,
            max_campaigns: 3,
            risk_threshold_refs: vec!["risk-threshold:1".to_string()],
            exhaustion_policy: "stop".to_string(),
        },
        policy_ref: "policy:1".to_string(),
        llm_driver_profile_ref: None,
    }
}

#[tokio::test]
async fn canonical_catalog_and_operator_only_surfaces_survive_reload() {
    let service = service("llm-tool-membrane-catalog").await;
    let app = router(service.clone());

    let catalog: ToolCatalogView = get_json(&app, "/api/llm-interface/tool-catalog").await;
    assert!(
        catalog
            .definitions
            .iter()
            .any(|definition| definition.tool_id == "continuity.retrieve")
    );
    assert!(
        !catalog
            .definitions
            .iter()
            .any(|definition| definition.tool_id == "service:operator:raw-shell")
    );

    let operator_only: OperatorOnlySurfaceRegistryView =
        get_json(&app, "/api/llm-interface/operator-only-surfaces").await;
    assert!(
        operator_only
            .operator_only_surfaces
            .iter()
            .any(|surface| surface.internal_service_ref == "service:operator:raw-shell")
    );

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-tool-membrane-catalog-reload")
            .await;
    let reloaded_app = router(reloaded);
    let reloaded_catalog: ToolCatalogView =
        get_json(&reloaded_app, "/api/llm-interface/tool-catalog").await;
    assert_eq!(
        reloaded_catalog.catalog.tool_catalog_id,
        catalog.catalog.tool_catalog_id
    );
}

#[tokio::test]
async fn continuity_tool_execution_from_parsed_turn_persists_and_reloads() {
    let service = service("llm-tool-membrane-continuity").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::ContinuitySupervisor).await;
    let provider = provider(
        "provider:tool-membrane:continuity",
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let request = turn_package_request(
        "turn-package:tool-membrane:continuity",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:continuity".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::MemoryAccess,
                    allowed_operations: vec!["continuity.retrieve".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                ..base_envelope(vec!["pointer-index:tool-membrane".to_string()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: Some("pointer-index:tool-membrane".to_string()),
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView = post_json(&app, "/api/llm-interface/turn-packages", &request).await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:continuity/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:continuity",
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:continuity")
        }),
    )
    .await;
    let receipt: ParsedTurnToolExecutionView = post_empty(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}/execute-tools",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;

    assert_eq!(receipt.executions.len(), 1);
    assert_eq!(
        receipt.executions[0].execution.tool_id,
        "continuity.retrieve"
    );
    assert_eq!(
        receipt.executions[0].execution.decision,
        aiaf_v1::execution::ToolExecutionDecision::Allowed
    );

    let ledger: ToolExecutionLedgerView =
        get_json(&app, "/api/llm-interface/tool-executions").await;
    assert_eq!(ledger.tool_executions.len(), 1);

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-tool-membrane-continuity-reload")
            .await;
    let reloaded_app = router(reloaded);
    let detail: ToolExecutionView = get_json(
        &reloaded_app,
        &format!(
            "/api/llm-interface/tool-executions/{}",
            receipt.executions[0].execution.tool_execution_id
        ),
    )
    .await;
    assert_eq!(detail.execution.tool_id, "continuity.retrieve");

    handle.abort();
}

#[tokio::test]
async fn verified_turn_memory_update_is_persisted_after_continuity_writeback() {
    let service = service("llm-tool-membrane-memory-update").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::MemoryUpdateSupervisor).await;
    let provider = provider(
        "provider:tool-membrane:memory-update",
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let request = turn_package_request(
        "turn-package:tool-membrane:memory-update",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:memory-update".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::MemoryAccess,
                    allowed_operations: vec!["continuity.propose_update".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                ..base_envelope(vec!["pointer-index:memory-update".to_string()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: Some("pointer-index:memory-update".to_string()),
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView = post_json(&app, "/api/llm-interface/turn-packages", &request).await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:memory-update/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:memory-update",
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:memory-update")
        }),
    )
    .await;
    let receipt: ParsedTurnToolExecutionView = post_empty(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}/execute-tools",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;

    assert_eq!(receipt.executions.len(), 1);
    assert_eq!(
        receipt.executions[0].execution.tool_id,
        "continuity.propose_update"
    );

    let parsed_detail: ParsedTurnResultView = get_json(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;
    assert_eq!(parsed_detail.turn_memory_updates.len(), 1);
    assert_eq!(
        parsed_detail.turn_memory_updates[0]
            .update
            .tool_execution_ref,
        receipt.executions[0].execution.tool_execution_id
    );
    assert_eq!(
        parsed_detail.turn_memory_updates[0].update.proposed_summary,
        "Persist the verified continuity update."
    );

    let ledger: TurnMemoryUpdateLedgerView =
        get_json(&app, "/api/llm-interface/turn-memory-updates").await;
    assert_eq!(ledger.turn_memory_updates.len(), 1);

    let reloaded = reloaded_service_from_existing_workspace(
        &service,
        "llm-tool-membrane-memory-update-reload",
    )
    .await;
    let reloaded_app = router(reloaded);
    let detail: TurnMemoryUpdateView = get_json(
        &reloaded_app,
        &format!(
            "/api/llm-interface/turn-memory-updates/{}",
            ledger.turn_memory_updates[0].update.turn_memory_update_id
        ),
    )
    .await;
    assert_eq!(
        detail.update.output_bundle_ref,
        ledger.turn_memory_updates[0].update.output_bundle_ref
    );

    handle.abort();
}

#[tokio::test]
async fn supervisor_multi_family_execution_records_ordered_tool_runs() {
    let service = service("llm-tool-membrane-multifamily").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::MultiFamilySupervisor).await;
    let provider = provider(
        "provider:tool-membrane:multifamily",
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;
    let program: FactoryProgramView = service
        .create_factory_program(program_spec("factory-program-spec:membrane"))
        .await
        .unwrap();

    let request = turn_package_request(
        "turn-package:tool-membrane:multifamily",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:multifamily".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![
                    CapabilityWorldGrant {
                        world: CapabilityWorld::CampaignControl,
                        allowed_operations: vec!["program.inspect".to_string()],
                        default_authority_class: AuthorityClass::Observe,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: Vec::new(),
                    },
                    CapabilityWorldGrant {
                        world: CapabilityWorld::ServiceOrganelle,
                        allowed_operations: vec!["validation.run_proving".to_string()],
                        default_authority_class: AuthorityClass::CampaignControl,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: Vec::new(),
                    },
                    CapabilityWorldGrant {
                        world: CapabilityWorld::ReviewPromotion,
                        allowed_operations: vec!["validation.compare_candidate".to_string()],
                        default_authority_class: AuthorityClass::PromotionControl,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: Vec::new(),
                    },
                ],
                ..base_envelope(vec![
                    program.instance.instance_id.clone(),
                    "workspace:tool-membrane".to_string(),
                ])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: Some(program.instance.instance_id.clone()),
            workspace_scope_ref: Some("workspace:tool-membrane".to_string()),
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView = post_json(&app, "/api/llm-interface/turn-packages", &request).await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:multifamily/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:multifamily",
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:multifamily")
        }),
    )
    .await;
    let receipt: ParsedTurnToolExecutionView = post_empty(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}/execute-tools",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;

    let executed_tool_ids = receipt
        .executions
        .iter()
        .map(|execution| execution.execution.tool_id.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        executed_tool_ids,
        vec![
            "program.inspect".to_string(),
            "validation.run_proving".to_string(),
            "validation.compare_candidate".to_string(),
        ]
    );

    handle.abort();
}

#[tokio::test]
async fn worker_ecology_batch_executes_in_order() {
    let service = service("llm-tool-membrane-worker").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::WorkerEcology).await;
    let provider = provider(
        "provider:tool-membrane:worker",
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let request = turn_package_request(
        "turn-package:tool-membrane:worker",
        TurnPackageRole::Worker,
        TurnResponseSchemaFamily::WorkerTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:worker".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::WorkerMessaging,
                    allowed_operations: vec![
                        "ecology.dispatch_worker".to_string(),
                        "ecology.collect_results".to_string(),
                    ],
                    default_authority_class: AuthorityClass::CampaignControl,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                ..base_envelope(vec!["task:tool-membrane".to_string()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: Some("ecology-snapshot:tool-membrane".to_string()),
        },
    );
    let _: TurnPackageView = post_json(&app, "/api/llm-interface/turn-packages", &request).await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:worker/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:worker",
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:worker")
        }),
    )
    .await;
    let receipt: ParsedTurnToolExecutionView = post_empty(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}/execute-tools",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;

    assert_eq!(receipt.executions.len(), 2);
    assert_eq!(
        receipt.executions[0].execution.tool_id,
        "ecology.dispatch_worker"
    );
    assert_eq!(
        receipt.executions[1].execution.tool_id,
        "ecology.collect_results"
    );
    assert_eq!(
        receipt.receipt.terminal_decision,
        aiaf_v1::execution::ToolExecutionDecision::Allowed
    );

    handle.abort();
}

#[tokio::test]
async fn approval_blocked_turn_dedupes_matching_parsed_request_and_requires_explicit_grant() {
    let service = service("llm-tool-membrane-gated").await;
    let app = router(service.clone());

    let approval_program: FactoryProgramView = service
        .create_factory_program(program_spec("factory-program-spec:approval-blocked"))
        .await
        .unwrap();

    let (approval_address, approval_handle) =
        spawn_mock_server(MockResponseKind::ApprovalBlockedWithParsedApproval).await;
    let approval_provider = provider(
        "provider:tool-membrane:approval",
        &format!("http://{approval_address}"),
    );
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &approval_provider).await;
    let approval_request = turn_package_request(
        "turn-package:tool-membrane:approval",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:approval".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ReviewPromotion,
                    allowed_operations: vec!["program.submit_cycle_decision".to_string()],
                    default_authority_class: AuthorityClass::PromotionControl,
                    default_approval_class: ApprovalClass::HumanRequired,
                    operation_approval_overrides: Vec::new(),
                }],
                ..base_envelope(vec![approval_program.instance.instance_id.clone()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: Some(approval_program.instance.instance_id.clone()),
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView =
        post_json(&app, "/api/llm-interface/turn-packages", &approval_request).await;
    let approval_parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:approval/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:approval",
            "provider_ref": approval_provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:approval")
        }),
    )
    .await;
    let governance = approval_parsed
        .governance
        .clone()
        .expect("governance should be present for approval-blocked turns");
    assert_eq!(
        governance.authority_decision.decision,
        aiaf_v1::execution::ModelAuthorityDecisionKind::ApprovalBlock
    );
    assert!(approval_parsed.parsed_approval_request.is_some());
    assert_eq!(governance.approvals.len(), 1);
    assert_eq!(governance.pending_actions.len(), 1);
    assert_eq!(governance.checkpoints.len(), 1);
    assert!(governance.checkpoints[0].checkpoint.resumable);
    assert!(!governance.checkpoints[0].checkpoint.terminal);
    assert_eq!(
        governance.pending_actions[0].resolution_status,
        aiaf_v1::execution::PendingGovernedTurnActionStatus::PendingApproval
    );

    let authority_ledger: AuthorityDecisionLedgerView =
        get_json(&app, "/api/llm-interface/authority-decisions").await;
    assert_eq!(authority_ledger.decisions.len(), 1);
    assert_eq!(
        authority_ledger.decisions[0].decision.decision,
        aiaf_v1::execution::ModelAuthorityDecisionKind::ApprovalBlock
    );

    let approval_ledger: ModelApprovalRequestLedgerView =
        get_json(&app, "/api/llm-interface/model-approval-requests").await;
    assert_eq!(approval_ledger.approvals.len(), 1);
    assert!(approval_ledger.approvals[0].pending_action.is_some());

    let checkpoint_ledger: TurnCheckpointLedgerView =
        get_json(&app, "/api/llm-interface/turn-checkpoints").await;
    assert_eq!(checkpoint_ledger.checkpoints.len(), 1);
    assert!(checkpoint_ledger.checkpoints[0].checkpoint.resumable);

    let (status, body) = post_empty_response(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}/execute-tools",
            approval_parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("explicit approval release is required"));

    let approval_id = &governance.approvals[0].approval.model_approval_request_id;
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
    assert_eq!(
        resolved.pending_actions[0].resolution_status,
        aiaf_v1::execution::PendingGovernedTurnActionStatus::GrantedExecuted
    );

    let execution_ledger: ToolExecutionLedgerView =
        get_json(&app, "/api/llm-interface/tool-executions").await;
    assert_eq!(execution_ledger.tool_executions.len(), 1);
    assert_eq!(
        execution_ledger.tool_executions[0].execution.tool_id,
        "program.submit_cycle_decision"
    );
    approval_handle.abort();
}

#[tokio::test]
async fn approval_deny_expire_and_escalate_never_resume_stored_batch() {
    for (label, action_path, expected_status, expected_decision) in [
        (
            "deny",
            "deny",
            aiaf_v1::execution::PendingGovernedTurnActionStatus::Denied,
            aiaf_v1::execution::ApprovalDecisionStatus::Denied,
        ),
        (
            "expire",
            "expire",
            aiaf_v1::execution::PendingGovernedTurnActionStatus::Expired,
            aiaf_v1::execution::ApprovalDecisionStatus::Expired,
        ),
        (
            "escalate",
            "escalate",
            aiaf_v1::execution::PendingGovernedTurnActionStatus::Escalated,
            aiaf_v1::execution::ApprovalDecisionStatus::Superseded,
        ),
    ] {
        let service = service(&format!("llm-tool-membrane-approval-{label}")).await;
        let app = router(service.clone());
        let approval_program: FactoryProgramView = service
            .create_factory_program(program_spec(&format!(
                "factory-program-spec:approval-{label}"
            )))
            .await
            .unwrap();

        let (address, handle) = spawn_mock_server(MockResponseKind::ApprovalBlocked).await;
        let provider = provider(
            &format!("provider:tool-membrane:approval:{label}"),
            &format!("http://{address}"),
        );
        let _: InferenceProviderView =
            post_json(&app, "/api/llm-interface/providers", &provider).await;

        let request = turn_package_request(
            &format!("turn-package:tool-membrane:approval:{label}"),
            TurnPackageRole::Supervisor,
            TurnResponseSchemaFamily::SupervisorTurnV1,
            CreateTurnPackageToolExecutionContext {
                tool_execution_context_id: format!("tool-context:approval:{label}"),
                capability_envelope: CapabilityEnvelope {
                    world_grants: vec![CapabilityWorldGrant {
                        world: CapabilityWorld::ReviewPromotion,
                        allowed_operations: vec!["program.submit_cycle_decision".to_string()],
                        default_authority_class: AuthorityClass::PromotionControl,
                        default_approval_class: ApprovalClass::HumanRequired,
                        operation_approval_overrides: Vec::new(),
                    }],
                    ..base_envelope(vec![approval_program.instance.instance_id.clone()])
                },
                campaign_ref: Some("campaign:tool-membrane".to_string()),
                epoch_ref: Some("epoch:tool-membrane".to_string()),
                task_ref: Some("task:tool-membrane".to_string()),
                pointer_index_ref: None,
                factory_program_instance_ref: Some(approval_program.instance.instance_id.clone()),
                workspace_scope_ref: None,
                ecology_snapshot_ref: None,
            },
        );
        let _: TurnPackageView =
            post_json(&app, "/api/llm-interface/turn-packages", &request).await;
        let parsed: ParsedTurnResultView = post_json(
            &app,
            &format!(
                "/api/llm-interface/turn-packages/{}/execute",
                request.turn_package_id
            ),
            &json!({
                "turn_package_id": request.turn_package_id,
                "provider_ref": provider.provider_id,
                "model_ref": "gpt-5.4-mini",
                "generation_policy": generation_policy(&format!("policy:tool-membrane:{label}"))
            }),
        )
        .await;

        let approval_id = parsed.governance.as_ref().unwrap().approvals[0]
            .approval
            .model_approval_request_id
            .clone();
        let resolved: TurnGovernanceView = post_empty(
            &app,
            &format!("/api/llm-interface/model-approval-requests/{approval_id}/{action_path}"),
        )
        .await;
        assert_eq!(
            resolved.approvals[0]
                .approval
                .latest_decision
                .as_ref()
                .unwrap()
                .decision,
            expected_decision
        );
        assert_eq!(
            resolved.pending_actions[0].resolution_status,
            expected_status
        );

        let execution_ledger: ToolExecutionLedgerView =
            get_json(&app, "/api/llm-interface/tool-executions").await;
        assert!(execution_ledger.tool_executions.is_empty());
        handle.abort();
    }
}

#[tokio::test]
async fn unsupported_tool_use_becomes_deny_and_blocks_execution() {
    let service = service("llm-tool-membrane-deny").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::UnsupportedTool).await;
    let provider = provider("provider:tool-membrane:deny", &format!("http://{address}"));
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let request = turn_package_request(
        "turn-package:tool-membrane:deny",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:deny".to_string(),
            capability_envelope: base_envelope(vec!["task:tool-membrane".to_string()]),
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView = post_json(&app, "/api/llm-interface/turn-packages", &request).await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:deny/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:deny",
            "provider_ref": provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:deny")
        }),
    )
    .await;

    let governance = parsed.governance.unwrap();
    assert_eq!(
        governance.authority_decision.decision,
        aiaf_v1::execution::ModelAuthorityDecisionKind::Deny
    );
    assert!(governance.approvals.is_empty());
    assert!(governance.quarantines.is_empty());
    assert_eq!(governance.checkpoints.len(), 1);
    assert!(governance.checkpoints[0].checkpoint.terminal);
    assert!(!governance.checkpoints[0].checkpoint.resumable);

    let (status, body) = post_empty_response(
        &app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}/execute-tools",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body.contains("cannot proceed"));

    let checkpoint_ledger: TurnCheckpointLedgerView =
        get_json(&app, "/api/llm-interface/turn-checkpoints").await;
    assert_eq!(checkpoint_ledger.checkpoints.len(), 1);
    handle.abort();
}

#[tokio::test]
async fn authority_expanding_output_becomes_quarantine_and_prevents_execution() {
    let service = service("llm-tool-membrane-quarantine").await;
    let app = router(service.clone());
    let (quarantine_address, quarantine_handle) =
        spawn_mock_server(MockResponseKind::Quarantined).await;
    let quarantine_provider = provider(
        "provider:tool-membrane:quarantined",
        &format!("http://{quarantine_address}"),
    );
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &quarantine_provider).await;
    let quarantine_request = turn_package_request(
        "turn-package:tool-membrane:quarantined",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:quarantined".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ReviewPromotion,
                    allowed_operations: vec!["governance.recommend_quarantine".to_string()],
                    default_authority_class: AuthorityClass::PromotionControl,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: vec![CapabilityOperationApproval {
                        operation: "governance.recommend_quarantine".to_string(),
                        approval_class: ApprovalClass::QuarantineOnExpand,
                    }],
                }],
                ..base_envelope(vec!["task:tool-membrane".to_string()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &quarantine_request,
    )
    .await;
    let quarantine_parsed: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:quarantined/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:quarantined",
            "provider_ref": quarantine_provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:quarantined")
        }),
    )
    .await;

    let governance = quarantine_parsed.governance.unwrap();
    assert_eq!(
        governance.authority_decision.decision,
        aiaf_v1::execution::ModelAuthorityDecisionKind::Quarantine
    );
    assert_eq!(governance.quarantines.len(), 1);
    assert_eq!(
        governance.quarantines[0].quarantine.reason_class,
        aiaf_v1::execution::ModelOutputQuarantineReasonClass::AuthorityExpansion
    );
    assert!(governance.checkpoints[0].checkpoint.terminal);

    let quarantine_ledger: ModelQuarantineLedgerView =
        get_json(&app, "/api/llm-interface/model-quarantines").await;
    assert_eq!(quarantine_ledger.quarantines.len(), 1);

    let (status, _) = post_empty_response(
        &app,
        &format!(
            "/api/llm-interface/tool-intents/{}/execute",
            quarantine_parsed.parsed_tool_call_intents[0].parsed_tool_call_intent_id
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    quarantine_handle.abort();
}

#[tokio::test]
async fn governance_health_counts_interrupts_quarantines_denials_and_parse_repairs() {
    let service = service("llm-tool-membrane-governance-health").await;
    let app = router(service.clone());

    let approval_program: FactoryProgramView = service
        .create_factory_program(program_spec("factory-program-spec:governance-health"))
        .await
        .unwrap();

    let (approval_address, approval_handle) =
        spawn_mock_server(MockResponseKind::ApprovalBlocked).await;
    let approval_provider = provider(
        "provider:tool-membrane:health:approval",
        &format!("http://{approval_address}"),
    );
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &approval_provider).await;
    let approval_request = turn_package_request(
        "turn-package:tool-membrane:health:approval",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:health:approval".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ReviewPromotion,
                    allowed_operations: vec!["program.submit_cycle_decision".to_string()],
                    default_authority_class: AuthorityClass::PromotionControl,
                    default_approval_class: ApprovalClass::HumanRequired,
                    operation_approval_overrides: Vec::new(),
                }],
                ..base_envelope(vec![approval_program.instance.instance_id.clone()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: Some(approval_program.instance.instance_id.clone()),
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView =
        post_json(&app, "/api/llm-interface/turn-packages", &approval_request).await;
    let _: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:health:approval/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:health:approval",
            "provider_ref": approval_provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:health:approval")
        }),
    )
    .await;
    approval_handle.abort();

    let (deny_address, deny_handle) = spawn_mock_server(MockResponseKind::UnsupportedTool).await;
    let deny_provider = provider(
        "provider:tool-membrane:health:deny",
        &format!("http://{deny_address}"),
    );
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &deny_provider).await;
    let deny_request = turn_package_request(
        "turn-package:tool-membrane:health:deny",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:health:deny".to_string(),
            capability_envelope: base_envelope(vec!["task:tool-membrane".to_string()]),
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView =
        post_json(&app, "/api/llm-interface/turn-packages", &deny_request).await;
    let _: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:health:deny/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:health:deny",
            "provider_ref": deny_provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:health:deny")
        }),
    )
    .await;
    deny_handle.abort();

    let (quarantine_address, quarantine_handle) =
        spawn_mock_server(MockResponseKind::Quarantined).await;
    let quarantine_provider = provider(
        "provider:tool-membrane:health:quarantine",
        &format!("http://{quarantine_address}"),
    );
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &quarantine_provider).await;
    let quarantine_request = turn_package_request(
        "turn-package:tool-membrane:health:quarantine",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:health:quarantine".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::ReviewPromotion,
                    allowed_operations: vec!["governance.recommend_quarantine".to_string()],
                    default_authority_class: AuthorityClass::PromotionControl,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: vec![CapabilityOperationApproval {
                        operation: "governance.recommend_quarantine".to_string(),
                        approval_class: ApprovalClass::QuarantineOnExpand,
                    }],
                }],
                ..base_envelope(vec!["task:tool-membrane".to_string()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: None,
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &quarantine_request,
    )
    .await;
    let _: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:health:quarantine/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:health:quarantine",
            "provider_ref": quarantine_provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:health:quarantine")
        }),
    )
    .await;
    quarantine_handle.abort();

    let (repair_address, repair_handle) =
        spawn_mock_server(MockResponseKind::FencedContinuitySupervisor).await;
    let repair_provider = provider(
        "provider:tool-membrane:health:repair",
        &format!("http://{repair_address}"),
    );
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &repair_provider).await;
    let repair_request = turn_package_request(
        "turn-package:tool-membrane:health:repair",
        TurnPackageRole::Supervisor,
        TurnResponseSchemaFamily::SupervisorTurnV1,
        CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: "tool-context:health:repair".to_string(),
            capability_envelope: CapabilityEnvelope {
                world_grants: vec![CapabilityWorldGrant {
                    world: CapabilityWorld::MemoryAccess,
                    allowed_operations: vec!["continuity.retrieve".to_string()],
                    default_authority_class: AuthorityClass::Observe,
                    default_approval_class: ApprovalClass::SupervisorAllowed,
                    operation_approval_overrides: Vec::new(),
                }],
                ..base_envelope(vec!["pointer-index:tool-membrane".to_string()])
            },
            campaign_ref: Some("campaign:tool-membrane".to_string()),
            epoch_ref: Some("epoch:tool-membrane".to_string()),
            task_ref: Some("task:tool-membrane".to_string()),
            pointer_index_ref: Some("pointer-index:tool-membrane".to_string()),
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: None,
        },
    );
    let _: TurnPackageView =
        post_json(&app, "/api/llm-interface/turn-packages", &repair_request).await;
    let _: ParsedTurnResultView = post_json(
        &app,
        "/api/llm-interface/turn-packages/turn-package:tool-membrane:health:repair/execute",
        &json!({
            "turn_package_id": "turn-package:tool-membrane:health:repair",
            "provider_ref": repair_provider.provider_id,
            "model_ref": "gpt-5.4-mini",
            "generation_policy": generation_policy("policy:tool-membrane:health:repair")
        }),
    )
    .await;
    repair_handle.abort();

    let health: GovernanceHealthView = get_json(&app, "/api/llm-interface/governance-health").await;
    assert_eq!(health.total_turns, 4);
    assert_eq!(health.approval_block_count, 1);
    assert_eq!(health.deny_count, 1);
    assert_eq!(health.quarantine_count, 1);
    assert_eq!(health.allow_count, 1);
    assert_eq!(health.fail_count, 0);
    assert_eq!(health.approval_interrupt_count, 1);
    assert_eq!(health.quarantine_record_count, 1);
    assert_eq!(health.parse_repair_event_count, 1);
}
