use crate::local_runtime_support::{
    get_json, post_empty, post_json, reloaded_service_from_existing_workspace, router, service,
};
use aiaf_v1::execution::{
    ApprovalClass, AuthorityClass, CapabilityEnvelope, CapabilityWorld, CapabilityWorldGrant,
    InferenceProviderMode, InferenceProviderModelEntry, InferenceProviderRegistryEntry,
    IsolationProfile, StopConditionDecision, TurnPackageRole, TurnResponseSchemaFamily,
};
use aiaf_v1::local_runtime::{
    ContinuityBundleView, CreateTurnPackageContextBudget, CreateTurnPackageRequest,
    CreateTurnPackageToolExecutionContext, ExecuteTurnPackageRequest, InferenceProviderView,
    ParsedTurnResultLedgerView, ParsedTurnResultView, TurnGroundingLedgerView, TurnGroundingView,
    TurnPackageView,
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
    SupervisorSuccess,
    WorkerSuccess,
    FencedSupervisor,
    InvalidContract,
    OpenRouterSupervisorSuccess,
    OpenRouterFencedSupervisor,
    OpenRouterToolCallsOnly,
}

#[derive(Clone, Copy)]
struct MockState {
    response_kind: MockResponseKind,
}

fn provider(
    provider_id: &str,
    provider_mode: InferenceProviderMode,
    base_url: &str,
) -> InferenceProviderRegistryEntry {
    InferenceProviderRegistryEntry {
        provider_id: provider_id.to_string(),
        provider_mode,
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

fn supervisor_turn_package_request(turn_package_id: &str) -> CreateTurnPackageRequest {
    CreateTurnPackageRequest {
        turn_package_id: turn_package_id.to_string(),
        program_ref: "program:acceptance".to_string(),
        session_ref: "session:acceptance".to_string(),
        turn_ref: "turn:acceptance".to_string(),
        envelope_ref: "envelope:acceptance".to_string(),
        role: TurnPackageRole::Supervisor,
        system_frame_ref: "system:acceptance".to_string(),
        system_frame_text: "You are the bounded Wasm-Biotic supervisor.".to_string(),
        program_frame_ref: "program-frame:acceptance".to_string(),
        program_frame_text: "Advance the bounded NorthStar turn package.".to_string(),
        capability_frame_ref: "capability-frame:acceptance".to_string(),
        capability_frame_text: "Stay inside the active capability envelope.".to_string(),
        agenda_ref: "agenda:acceptance".to_string(),
        agenda_text: "Evaluate the next bounded lineage turn.".to_string(),
        continuity_entries: vec![
            aiaf_v1::execution::TurnContinuityEntry {
                entry_ref: "continuity:critical".to_string(),
                text: "Critical contradiction evidence.".to_string(),
                priority: aiaf_v1::execution::ContinuityEntryPriority::Critical,
            },
            aiaf_v1::execution::TurnContinuityEntry {
                entry_ref: "continuity:supporting".to_string(),
                text: "Supporting evidence that should be omitted by the bounded package."
                    .to_string(),
                priority: aiaf_v1::execution::ContinuityEntryPriority::Supporting,
            },
        ],
        tool_execution_context: CreateTurnPackageToolExecutionContext {
            tool_execution_context_id: format!("tool-context:{turn_package_id}"),
            capability_envelope: CapabilityEnvelope {
                envelope_id: "envelope:acceptance".to_string(),
                actor_scope: "llm-turn".to_string(),
                world_grants: vec![
                    CapabilityWorldGrant {
                        world: CapabilityWorld::MemoryAccess,
                        allowed_operations: vec!["continuity.retrieve".to_string()],
                        default_authority_class: AuthorityClass::Observe,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: Vec::new(),
                    },
                    CapabilityWorldGrant {
                        world: CapabilityWorld::WorkerMessaging,
                        allowed_operations: vec!["ecology.collect_results".to_string()],
                        default_authority_class: AuthorityClass::Observe,
                        default_approval_class: ApprovalClass::SupervisorAllowed,
                        operation_approval_overrides: Vec::new(),
                    },
                ],
                authority_ceiling: AuthorityClass::PromotionControl,
                isolation_profile: IsolationProfile::SupervisorExclusive,
                allowed_resource_scopes: vec![
                    "pointer-index:acceptance".to_string(),
                    "task:acceptance".to_string(),
                    "ecology-snapshot:acceptance".to_string(),
                ],
                approval_overrides: Vec::new(),
                quota_policy: None,
                campaign_scope: Some("campaign:acceptance".to_string()),
                epoch_scope: Some("epoch:acceptance".to_string()),
            },
            campaign_ref: Some("campaign:acceptance".to_string()),
            epoch_ref: Some("epoch:acceptance".to_string()),
            task_ref: Some("task:acceptance".to_string()),
            pointer_index_ref: Some("pointer-index:acceptance".to_string()),
            factory_program_instance_ref: None,
            workspace_scope_ref: None,
            ecology_snapshot_ref: Some("ecology-snapshot:acceptance".to_string()),
        },
        response_schema_family: TurnResponseSchemaFamily::SupervisorTurnV1,
        context_budget: CreateTurnPackageContextBudget {
            context_budget_id: format!("context-budget:{turn_package_id}"),
            max_rendered_prompt_chars: 5_000,
            max_continuity_entries: 1,
        },
    }
}

fn worker_turn_package_request(turn_package_id: &str) -> CreateTurnPackageRequest {
    let mut request = supervisor_turn_package_request(turn_package_id);
    request.role = TurnPackageRole::Worker;
    request.response_schema_family = TurnResponseSchemaFamily::WorkerTurnV1;
    request
}

fn execute_request(turn_package_id: &str, provider_ref: &str) -> ExecuteTurnPackageRequest {
    ExecuteTurnPackageRequest {
        turn_package_id: turn_package_id.to_string(),
        provider_ref: provider_ref.to_string(),
        model_ref: "gpt-5.4-mini".to_string(),
        generation_policy: aiaf_v1::execution::InferenceGenerationPolicy {
            generation_policy_id: format!("policy:{turn_package_id}"),
            max_output_tokens: 256,
            max_retries: 1,
            summary: "bounded acceptance generation policy".to_string(),
        },
    }
}

async fn mock_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    let body = match state.response_kind {
        MockResponseKind::SupervisorSuccess => json!({
            "id": "resp_supervisor_success",
            "output_parsed": {
                "summary": "bounded supervisor result",
                "proposals": [
                    {"proposal_family": "task_update", "summary": "advance the active task"}
                ],
                "tool_call_intents": [
                    {"tool_id": "continuity.retrieve", "arguments": {"pointer_index_ref": "pointer:1"}}
                ],
                "approval_request": {
                    "summary": "need approval",
                    "action_ref": "action:1",
                    "scope_ref": "scope:1",
                    "requested_authority_class": "observe"
                },
                "stop_recommendation": "continue"
            },
            "usage": {"input_tokens": 100, "output_tokens": 40, "total_tokens": 140}
        }),
        MockResponseKind::WorkerSuccess => json!({
            "id": "resp_worker_success",
            "output_parsed": {
                "summary": "worker result",
                "tool_call_intents": [
                    {"tool_id": "ecology.collect_results", "arguments": {"lease_ref": "lease:1"}}
                ]
            },
            "usage": {"input_tokens": 10, "output_tokens": 8, "total_tokens": 18}
        }),
        MockResponseKind::FencedSupervisor => json!({
            "id": "resp_supervisor_fenced",
            "output_parsed": "```json\n{\"summary\":\"bounded supervisor result\",\"proposals\":[{\"proposal_family\":\"task_update\",\"summary\":\"advance the active task\"}],\"stop_recommendation\":\"continue\"}\n```",
            "usage": {"input_tokens": 12, "output_tokens": 6, "total_tokens": 18}
        }),
        MockResponseKind::InvalidContract => json!({
            "id": "resp_invalid_contract",
            "output_parsed": {
                "summary": "missing required supervisor fields"
            },
            "usage": {"input_tokens": 12, "output_tokens": 4, "total_tokens": 16}
        }),
        MockResponseKind::OpenRouterSupervisorSuccess
        | MockResponseKind::OpenRouterFencedSupervisor
        | MockResponseKind::OpenRouterToolCallsOnly => json!({
            "error": {"message": "responses endpoint behavior mismatch"}
        }),
    };
    (
        StatusCode::OK,
        [("x-request-id".to_string(), "req_turn_package".to_string())],
        body.to_string(),
    )
}

async fn mock_chat_completions_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    let body = match state.response_kind {
        MockResponseKind::OpenRouterSupervisorSuccess => json!({
            "id": "chatcmpl_supervisor_success",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "{\"summary\":\"bounded supervisor result\",\"proposals\":[{\"proposal_family\":\"task_update\",\"summary\":\"advance the active task\"}],\"tool_call_intents\":[{\"tool_id\":\"continuity.retrieve\",\"arguments\":{\"pointer_index_ref\":\"pointer:1\"}}],\"approval_request\":{\"summary\":\"need approval\",\"action_ref\":\"action:1\",\"scope_ref\":\"scope:1\",\"requested_authority_class\":\"observe\"},\"stop_recommendation\":\"continue\"}"
                }
            }],
            "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140}
        }),
        MockResponseKind::OpenRouterFencedSupervisor => json!({
            "id": "chatcmpl_supervisor_fenced",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "```json\n{\"summary\":\"bounded supervisor result\",\"proposals\":[{\"proposal_family\":\"task_update\",\"summary\":\"advance the active task\"}],\"stop_recommendation\":\"continue\"}\n```"
                }
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 6, "total_tokens": 18}
        }),
        MockResponseKind::OpenRouterToolCallsOnly => json!({
            "id": "chatcmpl_tool_calls_only",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "continuity.retrieve",
                            "arguments": "{\"pointer_index_ref\":\"pointer:1\"}"
                        }
                    }]
                }
            }],
            "usage": {"prompt_tokens": 12, "completion_tokens": 4, "total_tokens": 16}
        }),
        MockResponseKind::SupervisorSuccess
        | MockResponseKind::WorkerSuccess
        | MockResponseKind::FencedSupervisor
        | MockResponseKind::InvalidContract => json!({
            "error": {"message": "chat completions endpoint behavior mismatch"}
        }),
    };
    (
        StatusCode::OK,
        [("x-request-id".to_string(), "req_turn_package".to_string())],
        body.to_string(),
    )
}

async fn spawn_mock_server(kind: MockResponseKind) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let app = AxumRouter::new()
        .route("/v1/responses", post(mock_handler))
        .route("/v1/chat/completions", post(mock_chat_completions_handler))
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
async fn turn_package_render_and_restart_replay() {
    let service = service("llm-turn-package-render").await;
    let app = router(service.clone());
    let turn_package_id = "turn-package:acceptance:render";

    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let rendered: TurnPackageView = post_empty(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/render"),
    )
    .await;

    assert!(rendered.latest_rendering.is_some());
    assert_eq!(rendered.prompt_layers.len(), 6);
    assert_eq!(
        rendered
            .latest_truncation
            .as_ref()
            .unwrap()
            .omitted_entry_refs,
        vec!["continuity:supporting".to_string()]
    );
    assert!(
        rendered
            .latest_rendering
            .as_ref()
            .unwrap()
            .rendered_prompt_text
            .contains("Missing context note:")
    );

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-turn-package-render-reload").await;
    let reloaded_app = router(reloaded);
    let detail: TurnPackageView = get_json(
        &reloaded_app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}"),
    )
    .await;
    assert!(detail.latest_rendering.is_some());
    assert_eq!(detail.prompt_layers.len(), 6);
}

#[tokio::test]
async fn turn_package_creation_persists_grounding_open_questions() {
    let service = service("llm-turn-package-grounding-open-questions").await;
    let app = router(service.clone());
    let turn_package_id = "turn-package:acceptance:grounding-open-questions";

    let created: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;

    let grounding = created.turn_grounding.as_ref().unwrap();
    assert!(!grounding.continuity_bundle.open_question_refs.is_empty());
    assert!(grounding.open_question_ledger.is_some());
    assert!(
        grounding
            .open_question_ledger
            .as_ref()
            .unwrap()
            .notes
            .iter()
            .any(|note| note.contains("No replayable runtime state matched session"))
    );

    let ledger: TurnGroundingLedgerView =
        get_json(&app, "/api/llm-interface/turn-groundings").await;
    assert_eq!(ledger.turn_groundings.len(), 1);

    let continuity_bundle: ContinuityBundleView = get_json(
        &app,
        &format!(
            "/api/llm-interface/continuity-bundles/{}",
            grounding.continuity_bundle.continuity_bundle_id
        ),
    )
    .await;
    assert_eq!(
        continuity_bundle.continuity_bundle.turn_package_ref,
        turn_package_id
    );

    let reloaded = reloaded_service_from_existing_workspace(
        &service,
        "llm-turn-package-grounding-open-questions-reload",
    )
    .await;
    let reloaded_app = router(reloaded);
    let detail: TurnGroundingView = get_json(
        &reloaded_app,
        &format!("/api/llm-interface/turn-groundings/{turn_package_id}"),
    )
    .await;
    assert_eq!(
        detail.turn_grounding_packet.turn_package_ref,
        turn_package_id
    );
}

#[tokio::test]
async fn turn_package_creation_attaches_runtime_and_lineage_grounding() {
    let service = service("llm-turn-package-grounding-evidence").await;
    let app = router(service.clone());

    let run = service
        .run_headless("supervisor-v4-live-shell-runner-path")
        .await
        .unwrap();
    let snapshots = service.run_snapshots(&run.summary.run_id).await.unwrap();
    let pointer_index_ref = snapshots.runtime_state.memory_store.pointer_indexes[0]
        .index_id
        .clone();
    let factory_program = service.drive_controlled_evolution().await.unwrap();

    let turn_package_id = "turn-package:acceptance:grounding-evidence";
    let mut request = supervisor_turn_package_request(turn_package_id);
    request.session_ref = run.summary.session_id.clone();
    request.turn_ref = format!("turn:grounding:{}", run.summary.run_id);
    request.agenda_ref = snapshots.runtime_state.root_task.task_id.clone();
    request.tool_execution_context.campaign_ref = Some(run.summary.campaign_id.clone());
    request.tool_execution_context.epoch_ref = Some(run.summary.epoch_id.clone());
    request.tool_execution_context.task_ref =
        Some(snapshots.runtime_state.root_task.task_id.clone());
    request.tool_execution_context.pointer_index_ref = Some(pointer_index_ref.clone());
    request.tool_execution_context.factory_program_instance_ref =
        Some(factory_program.instance.instance_id.clone());

    let created: TurnPackageView =
        post_json(&app, "/api/llm-interface/turn-packages", &request).await;
    let grounding = created.turn_grounding.as_ref().unwrap();

    assert!(
        grounding
            .continuity_bundle
            .pointer_index_refs
            .contains(&pointer_index_ref)
    );
    assert!(!grounding.retrieval_traces.is_empty());
    assert!(!grounding.continuity_bundle.lineage_receipt_refs.is_empty());
    assert!(
        grounding
            .turn_grounding_packet
            .selection_diagnostics
            .iter()
            .any(|note| note.contains("attached"))
    );

    let detail: TurnGroundingView = get_json(
        &app,
        &format!("/api/llm-interface/turn-groundings/{turn_package_id}"),
    )
    .await;
    assert_eq!(
        detail.continuity_bundle.continuity_bundle_id,
        grounding.continuity_bundle.continuity_bundle_id
    );
}

#[tokio::test]
async fn successful_supervisor_execution_and_parse_reloads_cleanly() {
    let service = service("llm-turn-package-supervisor").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::SupervisorSuccess).await;
    let provider = provider(
        "provider:turn-package:supervisor",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:supervisor-success";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::Parsed
    );
    assert_eq!(parsed.parsed_proposals.len(), 1);
    assert_eq!(parsed.parsed_tool_call_intents.len(), 1);
    assert!(parsed.parsed_approval_request.is_some());
    assert_eq!(
        parsed.parsed_result.stop_recommendation,
        Some(StopConditionDecision::Continue)
    );

    let ledger: ParsedTurnResultLedgerView =
        get_json(&app, "/api/llm-interface/parsed-turn-results").await;
    assert_eq!(ledger.parsed_turn_results.len(), 1);

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-turn-package-supervisor-reload")
            .await;
    let reloaded_app = router(reloaded);
    let detail: ParsedTurnResultView = get_json(
        &reloaded_app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;
    assert_eq!(
        detail.parsed_result.parsed_turn_result_id,
        parsed.parsed_result.parsed_turn_result_id
    );

    handle.abort();
}

#[tokio::test]
async fn worker_role_family_accepts_worker_specific_contract() {
    let service = service("llm-turn-package-worker").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::WorkerSuccess).await;
    let provider = provider(
        "provider:turn-package:worker",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:worker-success";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &worker_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::Parsed
    );
    assert_eq!(parsed.parsed_proposals.len(), 0);
    assert_eq!(parsed.parsed_tool_call_intents.len(), 1);
    assert_eq!(parsed.parsed_result.stop_recommendation, None);

    handle.abort();
}

#[tokio::test]
async fn parse_repair_path_records_explicit_repair_evidence() {
    let service = service("llm-turn-package-parse-repair").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::FencedSupervisor).await;
    let provider = provider(
        "provider:turn-package:repair",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:parse-repair";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::Parsed
    );
    assert_eq!(parsed.repair_records.len(), 1);
    assert_eq!(
        parsed.repair_records[0].repair_class,
        aiaf_v1::execution::ParseRepairClass::CodeFenceUnwrap
    );

    handle.abort();
}

#[tokio::test]
async fn rejected_contract_path_persists_failure_state_and_reloads() {
    let service = service("llm-turn-package-rejected-contract").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::InvalidContract).await;
    let provider = provider(
        "provider:turn-package:rejected",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:rejected-contract";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::RejectedContract
    );
    assert!(parsed.parsed_proposals.is_empty());
    assert!(parsed.parsed_tool_call_intents.is_empty());
    assert!(
        parsed
            .parsed_result
            .summary
            .contains("missing required field")
    );
    let governance = parsed
        .governance
        .as_ref()
        .expect("rejected contracts should still produce governance artifacts");
    assert_eq!(
        governance.authority_decision.decision,
        aiaf_v1::execution::ModelAuthorityDecisionKind::Fail
    );
    assert!(governance.approvals.is_empty());
    assert!(governance.quarantines.is_empty());
    assert_eq!(governance.checkpoints.len(), 1);
    assert!(governance.checkpoints[0].checkpoint.terminal);
    assert!(!governance.checkpoints[0].checkpoint.resumable);

    let reloaded = reloaded_service_from_existing_workspace(
        &service,
        "llm-turn-package-rejected-contract-reload",
    )
    .await;
    let reloaded_app = router(reloaded);
    let detail: ParsedTurnResultView = get_json(
        &reloaded_app,
        &format!(
            "/api/llm-interface/parsed-turn-results/{}",
            parsed.parsed_result.parsed_turn_result_id
        ),
    )
    .await;
    assert_eq!(
        detail.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::RejectedContract
    );
    assert_eq!(
        detail
            .governance
            .as_ref()
            .unwrap()
            .authority_decision
            .decision,
        aiaf_v1::execution::ModelAuthorityDecisionKind::Fail
    );

    handle.abort();
}

#[tokio::test]
async fn openrouter_supervisor_execution_parses_contract_from_assistant_content() {
    let service = service("llm-turn-package-openrouter-supervisor").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::OpenRouterSupervisorSuccess).await;
    let provider = provider(
        "provider:turn-package:openrouter-supervisor",
        InferenceProviderMode::OpenRouterChatCompletions,
        &format!("http://{address}/v1"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:openrouter-supervisor-success";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::Parsed
    );
    assert_eq!(parsed.parsed_proposals.len(), 1);
    assert_eq!(parsed.parsed_tool_call_intents.len(), 1);
    assert!(parsed.parsed_approval_request.is_some());
    assert_eq!(
        parsed.parsed_result.stop_recommendation,
        Some(StopConditionDecision::Continue)
    );

    handle.abort();
}

#[tokio::test]
async fn openrouter_parse_repair_path_unwraps_fenced_json_assistant_content() {
    let service = service("llm-turn-package-openrouter-parse-repair").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::OpenRouterFencedSupervisor).await;
    let provider = provider(
        "provider:turn-package:openrouter-repair",
        InferenceProviderMode::OpenRouterChatCompletions,
        &format!("http://{address}/v1"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:openrouter-parse-repair";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::Parsed
    );
    assert_eq!(parsed.repair_records.len(), 1);
    assert_eq!(
        parsed.repair_records[0].repair_class,
        aiaf_v1::execution::ParseRepairClass::CodeFenceUnwrap
    );

    handle.abort();
}

#[tokio::test]
async fn openrouter_native_tool_calls_without_contract_are_rejected_without_execution() {
    let service = service("llm-turn-package-openrouter-tool-calls-only").await;
    let app = router(service.clone());
    let (address, handle) = spawn_mock_server(MockResponseKind::OpenRouterToolCallsOnly).await;
    let provider = provider(
        "provider:turn-package:openrouter-tool-calls-only",
        InferenceProviderMode::OpenRouterChatCompletions,
        &format!("http://{address}/v1"),
    );
    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let turn_package_id = "turn-package:acceptance:openrouter-tool-calls-only";
    let _: TurnPackageView = post_json(
        &app,
        "/api/llm-interface/turn-packages",
        &supervisor_turn_package_request(turn_package_id),
    )
    .await;
    let parsed: ParsedTurnResultView = post_json(
        &app,
        &format!("/api/llm-interface/turn-packages/{turn_package_id}/execute"),
        &execute_request(turn_package_id, &provider.provider_id),
    )
    .await;

    assert_eq!(
        parsed.parsed_result.status,
        aiaf_v1::execution::ParsedTurnResultStatus::RejectedContract
    );
    assert!(parsed.parsed_proposals.is_empty());
    assert!(parsed.parsed_tool_call_intents.is_empty());
    assert!(parsed.tool_executions.is_empty());
    assert!(parsed.tool_execution_receipts.is_empty());
    assert!(
        parsed
            .parsed_result
            .summary
            .contains("did not yield a parseable contract result")
    );

    handle.abort();
}
