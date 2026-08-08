use aiaf_v1::local_runtime::V2ContradictionLineageWorkspaceView;

use crate::local_runtime_support::{get_json, post_json, router, service};

#[tokio::test]
async fn supervisor_v2_contradiction_lineage_query_services_acceptance() {
    let service = service("v22-lineage-services").await;
    let run = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service.clone());
    let _: aiaf_v1::local_runtime::V2TransitionPacket = post_json(
        &router,
        "/api/transition/v2/export",
        &aiaf_v1::local_runtime::V2TransitionPacketExportRequest {
            run_ids: vec![run.summary.run_id.clone()],
            title: Some("v22 lineage packet".to_string()),
            summary: None,
            next_v2_questions: vec![],
        },
    )
    .await;

    let lineage: V2ContradictionLineageWorkspaceView =
        get_json(&router, "/api/v2/continuity/lineage").await;
    assert!(lineage.summary.contains("lineage"));
    assert!(!lineage.lineage_queries.is_empty());
    assert!(
        lineage
            .lineage_queries
            .iter()
            .any(|query| query.scope == "contract-generation")
    );
    assert!(!lineage.guardrails.is_empty());
}
