use aiaf_v1::local_runtime::V2RetrievalProfileWorkspaceView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_retrieval_profile_query_classes_acceptance() {
    let service = service("v22-retrieval").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let retrieval: V2RetrievalProfileWorkspaceView =
        get_json(&router, "/api/v2/continuity/retrieval").await;

    assert!(retrieval.summary.contains("retrieval"));
    assert_eq!(retrieval.profiles.len(), 5);
    assert!(
        retrieval
            .profiles
            .iter()
            .any(|profile| profile.scope == "run")
    );
    assert!(
        retrieval
            .profiles
            .iter()
            .any(|profile| profile.scope == "campaign")
    );
    assert!(
        retrieval
            .profiles
            .iter()
            .any(|profile| profile.scope == "release")
    );
    assert!(
        retrieval
            .profiles
            .iter()
            .any(|profile| profile.scope == "pressure")
    );
    assert!(
        retrieval
            .profiles
            .iter()
            .any(|profile| profile.scope == "operator-context")
    );
}
