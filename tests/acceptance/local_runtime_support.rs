use aiaf_v1::execution::Phase03ClosureReviewPacket;
use aiaf_v1::local_runtime::{
    LocalRunStatus, LocalRuntimeService, LocalRuntimeWorkspace, NorthStar07ClosureReviewView,
    RemediationPhase03ReproductionEcosystemClosureView, RemediationPhase04FinalClosureRereviewView,
    RunViewModel, build_router,
};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::http::{Method, Request, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tower::util::ServiceExt;

#[derive(Clone, Debug)]
pub struct PositiveClosureSeed {
    pub phase_d_run_id: String,
    pub rollback_ready_run_id: String,
}

#[derive(Clone, Debug)]
pub struct PositiveClosureTruth {
    pub phase03: RemediationPhase03ReproductionEcosystemClosureView,
    pub phase03_packet: Phase03ClosureReviewPacket,
    pub phase04: RemediationPhase04FinalClosureRereviewView,
    pub northstar07: NorthStar07ClosureReviewView,
}

pub fn temp_workspace_root(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    std::env::temp_dir().join(format!("aiaf-v15-{name}-{unique}"))
}

pub async fn service(name: &str) -> Arc<LocalRuntimeService> {
    let root = temp_workspace_root(name);
    let _ = fs::remove_dir_all(&root);
    let workspace = LocalRuntimeWorkspace::bootstrap(root).unwrap();
    Arc::new(LocalRuntimeService::new(workspace).await.unwrap())
}

pub async fn service_from_root(root: PathBuf) -> Arc<LocalRuntimeService> {
    let workspace = LocalRuntimeWorkspace::bootstrap(root).unwrap();
    Arc::new(LocalRuntimeService::new(workspace).await.unwrap())
}

pub fn router(service: Arc<LocalRuntimeService>) -> Router {
    build_router(service)
}

pub async fn seed_positive_closure_corpus(
    service: &LocalRuntimeService,
    router: &Router,
) -> PositiveClosureSeed {
    let mut phase_d_run_id = None;
    for scenario_id in [
        "supervisor-v4-live-shell-runner-path",
        "supervisor-northstar-live-persistent-shell-program",
        "supervisor-phase-b-live-factory-artifact-family",
        "supervisor-phase-c-live-bounded-factory-replication",
        "supervisor-phase-d-live-prefederation-exchange-contracts",
    ] {
        let run = service.run_headless(scenario_id).await.unwrap();
        if scenario_id == "supervisor-phase-d-live-prefederation-exchange-contracts" {
            phase_d_run_id = Some(run.summary.run_id);
        }
    }

    let expired: RunViewModel = post_json(
        router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::AwaitingApproval);
    let expired: RunViewModel = post_empty(
        router,
        &format!("/api/runs/{}/approval/expire", expired.summary.run_id),
    )
    .await;
    assert_eq!(expired.summary.status, LocalRunStatus::Failed);

    let escalated: RunViewModel = post_json(
        router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-durable-fixed-interface-continuous-self-hosting-program"
        }),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::AwaitingApproval);
    let escalated: RunViewModel = post_empty(
        router,
        &format!("/api/runs/{}/approval/escalate", escalated.summary.run_id),
    )
    .await;
    assert_eq!(escalated.summary.status, LocalRunStatus::Paused);

    let rollback_ready: RunViewModel = post_json(
        router,
        "/api/runs",
        &json!({
            "scenario_id": "supervisor-background-quarantine-rollback-control-loop"
        }),
    )
    .await;
    assert_eq!(
        rollback_ready.summary.status,
        LocalRunStatus::AwaitingRollback
    );

    PositiveClosureSeed {
        phase_d_run_id: phase_d_run_id.expect("phase D run should be seeded"),
        rollback_ready_run_id: rollback_ready.summary.run_id,
    }
}

pub async fn fetch_positive_closure_truth(router: &Router) -> PositiveClosureTruth {
    PositiveClosureTruth {
        phase03: get_json(
            router,
            "/api/remediation/phase-03/reproduction-ecosystem-closure",
        )
        .await,
        phase03_packet: get_json(router, "/api/remediation/phase-03/closure-review-packet").await,
        phase04: get_json(router, "/api/remediation/phase-04/final-closure-rereview").await,
        northstar07: get_json(router, "/api/northstar/07/closure-review").await,
    }
}

pub async fn reloaded_service_from_existing_workspace(
    source: &Arc<LocalRuntimeService>,
    name: &str,
) -> Arc<LocalRuntimeService> {
    let root = temp_workspace_root(name);
    let _ = fs::remove_dir_all(&root);
    copy_dir_all(source.workspace().root(), &root).unwrap();
    service_from_root(root).await
}

pub async fn get_json<T: DeserializeOwned>(router: &Router, uri: &str) -> T {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET {uri} returned {status} with body: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

pub async fn post_json<T: DeserializeOwned, B: Serialize>(
    router: &Router,
    uri: &str,
    body: &B,
) -> T {
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
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "POST {uri} returned {status} with body: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

pub async fn post_empty<T: DeserializeOwned>(router: &Router, uri: &str) -> T {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "POST {uri} returned {status} with body: {}",
        String::from_utf8_lossy(&bytes)
    );
    serde_json::from_slice(&bytes).unwrap()
}

pub async fn post_empty_response(router: &Router, uri: &str) -> (StatusCode, String) {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (status, String::from_utf8_lossy(&bytes).to_string())
}

pub async fn get_text(router: &Router, uri: &str) -> String {
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(
        status,
        StatusCode::OK,
        "GET {uri} returned {status} with body: {}",
        String::from_utf8_lossy(&bytes)
    );
    String::from_utf8_lossy(&bytes).to_string()
}

pub fn read_snapshot_json<T: DeserializeOwned>(export_root: &Path, relative_path: &str) -> T {
    let raw = fs::read_to_string(export_root.join(relative_path)).unwrap();
    serde_json::from_str(&raw).unwrap()
}

pub fn free_socket_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

pub fn wait_for_http(address: SocketAddr, path: &str) -> String {
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        address
    );

    for _ in 0..40 {
        if let Ok(mut stream) = TcpStream::connect(address) {
            stream.write_all(request.as_bytes()).unwrap();
            let mut raw = String::new();
            stream.read_to_string(&mut raw).unwrap();
            if let Some(separator) = raw.find("\r\n\r\n") {
                return raw[separator + 4..].to_string();
            }
            return raw;
        }
        thread::sleep(Duration::from_millis(25));
    }

    panic!("failed to connect to local console at {address}");
}

fn copy_dir_all(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::create_dir_all(target)?;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let entry_type = entry.file_type()?;
        let target_path = target.join(entry.file_name());
        if entry_type.is_dir() {
            copy_dir_all(&entry.path(), &target_path)?;
        } else {
            fs::copy(entry.path(), target_path)?;
        }
    }
    Ok(())
}
