use crate::local_runtime_support::{
    get_json, post_json, reloaded_service_from_existing_workspace, router, service,
};
use aiaf_v1::execution::{
    InferenceFinishReason, InferenceProviderMode, InferenceProviderModelEntry,
    InferenceProviderRegistryEntry,
};
use aiaf_v1::local_runtime::{
    CreateInferenceTurnRequest, InferenceProviderRegistryView, InferenceProviderView,
    InferenceTurnLedgerView, InferenceTurnView,
};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::State;
use axum::http::{Method, Request, StatusCode};
use axum::routing::post;
use axum::{Json, Router as AxumRouter};
use serde::Serialize;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;
use tower::util::ServiceExt;

#[derive(Clone, Copy)]
enum MockBehavior {
    Success,
    Timeout,
}

#[derive(Clone)]
struct MockState {
    behavior: MockBehavior,
    attempts: Arc<AtomicUsize>,
}

fn provider(
    provider_id: &str,
    mode: InferenceProviderMode,
    base_url: &str,
    api_key_env_var: &str,
    request_timeout_ms: u64,
) -> InferenceProviderRegistryEntry {
    InferenceProviderRegistryEntry {
        provider_id: provider_id.to_string(),
        provider_mode: mode,
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
        api_key_env_var: api_key_env_var.to_string(),
        organization_env_var: None,
        project_env_var: None,
        request_timeout_ms,
    }
}

fn create_turn_request(turn_request_id: &str, provider_ref: &str) -> CreateInferenceTurnRequest {
    CreateInferenceTurnRequest {
        turn_request_id: turn_request_id.to_string(),
        provider_ref: provider_ref.to_string(),
        model_ref: "gpt-5.4-mini".to_string(),
        generation_policy: aiaf_v1::execution::InferenceGenerationPolicy {
            generation_policy_id: format!("policy:{turn_request_id}"),
            max_output_tokens: 256,
            max_retries: 1,
            summary: "bounded acceptance generation policy".to_string(),
        },
        rendered_prompt: "You are the Wasm-Biotic LLM interface adapter.".to_string(),
        tool_catalog_json: r#"[{"type":"function","name":"continuity.retrieve","description":"retrieve continuity","parameters":{"type":"object","properties":{},"additionalProperties":false}}]"#.to_string(),
        response_schema_json: r#"{"type":"json_schema","name":"turn_result","strict":true,"schema":{"type":"object","properties":{"turn_outcome":{"type":"string"}},"required":["turn_outcome"],"additionalProperties":false}}"#.to_string(),
    }
}

async fn mock_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    state.attempts.fetch_add(1, Ordering::SeqCst);
    match state.behavior {
        MockBehavior::Success => (
            StatusCode::OK,
            [("x-request-id".to_string(), "req_acceptance".to_string())],
            json!({
                "id": "resp_acceptance",
                "output_parsed": {"turn_outcome": "accepted", "summary": "success"},
                "usage": {"input_tokens": 100, "output_tokens": 40, "total_tokens": 140}
            })
            .to_string(),
        ),
        MockBehavior::Timeout => {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            (
                StatusCode::OK,
                [("x-request-id".to_string(), "req_timeout".to_string())],
                json!({
                    "id": "resp_timeout",
                    "output_parsed": {"turn_outcome": "late"},
                    "usage": {"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}
                })
                .to_string(),
            )
        }
    }
}

async fn mock_chat_completions_handler(
    State(state): State<MockState>,
    Json(_body): Json<Value>,
) -> (StatusCode, [(String, String); 1], String) {
    state.attempts.fetch_add(1, Ordering::SeqCst);
    match state.behavior {
        MockBehavior::Success => (
            StatusCode::OK,
            [("x-request-id".to_string(), "req_acceptance".to_string())],
            json!({
                "id": "chatcmpl_acceptance",
                "choices": [{
                    "message": {
                        "role": "assistant",
                        "content": "{\"turn_outcome\":\"accepted\",\"summary\":\"success\"}"
                    }
                }],
                "usage": {"prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140}
            })
            .to_string(),
        ),
        MockBehavior::Timeout => {
            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
            (
                StatusCode::OK,
                [("x-request-id".to_string(), "req_timeout".to_string())],
                json!({
                    "id": "chatcmpl_timeout",
                    "choices": [{
                        "message": {
                            "role": "assistant",
                            "content": "{\"turn_outcome\":\"late\"}"
                        }
                    }],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
                })
                .to_string(),
            )
        }
    }
}

async fn spawn_mock_server(
    behavior: MockBehavior,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let attempts = Arc::new(AtomicUsize::new(0));
    let app = AxumRouter::new()
        .route("/v1/responses", post(mock_handler))
        .route("/v1/chat/completions", post(mock_chat_completions_handler))
        .with_state(MockState {
            behavior,
            attempts: attempts.clone(),
        });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (address, attempts, handle)
}

async fn post_status<B: Serialize>(router: &Router, uri: &str, body: &B) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = String::from_utf8_lossy(&to_bytes(response.into_body(), usize::MAX).await.unwrap())
        .to_string();
    (status, body)
}

#[tokio::test]
async fn provider_registry_persists_across_runtime_restart() {
    let service = service("llm-interface-provider-persistence").await;
    let app = router(service.clone());
    let provider = provider(
        "provider:acceptance:persistent",
        InferenceProviderMode::OpenAiResponses,
        "http://127.0.0.1:1",
        "PATH",
        25,
    );

    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let registry: InferenceProviderRegistryView =
        get_json(&app, "/api/llm-interface/providers").await;
    assert_eq!(registry.providers.len(), 1);
    assert_eq!(registry.providers[0].provider, provider);

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-interface-provider-reload").await;
    let reloaded_app = router(reloaded);
    let reloaded_registry: InferenceProviderRegistryView =
        get_json(&reloaded_app, "/api/llm-interface/providers").await;
    assert_eq!(reloaded_registry.providers.len(), 1);
    assert_eq!(
        reloaded_registry.providers[0].provider.provider_id,
        "provider:acceptance:persistent"
    );
}

#[tokio::test]
async fn successful_inference_turn_is_recorded_and_ordered_newest_first() {
    let service = service("llm-interface-success").await;
    let app = router(service.clone());
    let (address, attempts, handle) = spawn_mock_server(MockBehavior::Success).await;
    let provider = provider(
        "provider:acceptance:success",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
        "PATH",
        50,
    );

    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let first: InferenceTurnView = post_json(
        &app,
        "/api/llm-interface/turns",
        &create_turn_request("turn:acceptance:first", &provider.provider_id),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    let second: InferenceTurnView = post_json(
        &app,
        "/api/llm-interface/turns",
        &create_turn_request("turn:acceptance:second", &provider.provider_id),
    )
    .await;

    assert_eq!(
        first.turn_result.finish_reason,
        InferenceFinishReason::Completed
    );
    assert!(first.parsed_output.is_some());
    assert_eq!(first.usage_record.input_tokens, 100);
    assert_eq!(first.usage_record.output_tokens, 40);
    assert!(first.usage_record.estimated_cost_microunits > 0);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    let ledger: InferenceTurnLedgerView = get_json(&app, "/api/llm-interface/turns").await;
    assert_eq!(ledger.turns.len(), 2);
    assert_eq!(
        ledger.turns[0].turn_result.turn_result_id,
        second.turn_result.turn_result_id
    );
    assert_eq!(
        ledger.turns[1].turn_result.turn_result_id,
        first.turn_result.turn_result_id
    );

    let detail: InferenceTurnView = get_json(
        &app,
        &format!(
            "/api/llm-interface/turns/{}",
            second.turn_result.turn_result_id
        ),
    )
    .await;
    assert_eq!(
        detail.turn_result.turn_result_id,
        second.turn_result.turn_result_id
    );

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-interface-success-reload").await;
    let reloaded_app = router(reloaded);
    let reloaded_detail: InferenceTurnView = get_json(
        &reloaded_app,
        &format!(
            "/api/llm-interface/turns/{}",
            second.turn_result.turn_result_id
        ),
    )
    .await;
    assert_eq!(
        reloaded_detail.turn_result.turn_result_id,
        second.turn_result.turn_result_id
    );

    handle.abort();
}

#[tokio::test]
async fn successful_openrouter_inference_turn_is_recorded() {
    let service = service("llm-interface-openrouter-success").await;
    let app = router(service.clone());
    let (address, attempts, handle) = spawn_mock_server(MockBehavior::Success).await;
    let provider = provider(
        "provider:acceptance:openrouter-success",
        InferenceProviderMode::OpenRouterChatCompletions,
        &format!("http://{address}/v1"),
        "PATH",
        50,
    );

    let _: InferenceProviderView = post_json(&app, "/api/llm-interface/providers", &provider).await;

    let view: InferenceTurnView = post_json(
        &app,
        "/api/llm-interface/turns",
        &create_turn_request("turn:acceptance:openrouter", &provider.provider_id),
    )
    .await;

    assert_eq!(
        view.turn_result.finish_reason,
        InferenceFinishReason::Completed
    );
    assert!(view.parsed_output.is_some());
    assert_eq!(view.usage_record.input_tokens, 100);
    assert_eq!(view.usage_record.output_tokens, 40);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    let detail: InferenceTurnView = get_json(
        &app,
        &format!(
            "/api/llm-interface/turns/{}",
            view.turn_result.turn_result_id
        ),
    )
    .await;
    assert_eq!(
        detail.turn_result.turn_result_id,
        view.turn_result.turn_result_id
    );

    handle.abort();
}

#[tokio::test]
async fn degraded_inference_turn_retries_and_persists_failure_state() {
    let service = service("llm-interface-degraded").await;
    let app = router(service.clone());
    let (address, attempts, handle) = spawn_mock_server(MockBehavior::Timeout).await;
    let timeout_provider = provider(
        "provider:acceptance:timeout",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
        "PATH",
        10,
    );

    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &timeout_provider).await;

    let mut request = create_turn_request("turn:acceptance:timeout", &timeout_provider.provider_id);
    request.generation_policy.max_retries = 2;
    let view: InferenceTurnView = post_json(&app, "/api/llm-interface/turns", &request).await;

    assert_eq!(
        view.turn_result.finish_reason,
        InferenceFinishReason::TimedOut
    );
    assert!(view.degradation_record.is_some());
    assert_eq!(view.attempts.len(), 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);

    let reloaded =
        reloaded_service_from_existing_workspace(&service, "llm-interface-timeout-reload").await;
    let reloaded_app = router(reloaded);
    let reloaded_view: InferenceTurnView = get_json(
        &reloaded_app,
        &format!(
            "/api/llm-interface/turns/{}",
            view.turn_result.turn_result_id
        ),
    )
    .await;
    assert_eq!(
        reloaded_view.turn_result.finish_reason,
        InferenceFinishReason::TimedOut
    );
    assert!(reloaded_view.degradation_record.is_some());

    let disabled_provider = InferenceProviderRegistryEntry {
        provider_id: "provider:acceptance:disabled".to_string(),
        provider_mode: InferenceProviderMode::Disabled,
        models: timeout_provider.models.clone(),
        capability_summary: timeout_provider.capability_summary.clone(),
        policy_summary: timeout_provider.policy_summary.clone(),
        active: true,
        api_base_url: timeout_provider.api_base_url.clone(),
        api_key_env_var: "PATH".to_string(),
        organization_env_var: None,
        project_env_var: None,
        request_timeout_ms: 25,
    };
    let _: InferenceProviderView =
        post_json(&app, "/api/llm-interface/providers", &disabled_provider).await;
    let (bad_status, _) = post_status(
        &app,
        "/api/llm-interface/turns",
        &create_turn_request("turn:acceptance:disabled", &disabled_provider.provider_id),
    )
    .await;
    assert_eq!(bad_status, StatusCode::BAD_REQUEST);

    let missing_secret_provider = provider(
        "provider:acceptance:missing-secret",
        InferenceProviderMode::OpenAiResponses,
        &format!("http://{address}"),
        "AIAF_MISSING_SECRET_DO_NOT_SET",
        25,
    );
    let _: InferenceProviderView = post_json(
        &app,
        "/api/llm-interface/providers",
        &missing_secret_provider,
    )
    .await;
    let (internal_status, _) = post_status(
        &app,
        "/api/llm-interface/turns",
        &create_turn_request(
            "turn:acceptance:missing-secret",
            &missing_secret_provider.provider_id,
        ),
    )
    .await;
    assert_eq!(internal_status, StatusCode::INTERNAL_SERVER_ERROR);

    handle.abort();
}
