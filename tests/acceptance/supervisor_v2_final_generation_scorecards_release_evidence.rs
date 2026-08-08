use aiaf_v1::local_runtime::V2FinalGenerationScorecardsView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_v2_final_generation_scorecards_release_evidence_acceptance() {
    let service = service("v29-scorecards").await;
    service
        .run_headless("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let router = router(service);
    let scorecards: V2FinalGenerationScorecardsView =
        get_json(&router, "/api/v2/convergence/scorecards").await;

    assert!(scorecards.summary.contains("first v2 phase"));
    assert!(scorecards.scorecards.len() >= 4);
    assert!(!scorecards.release_evidence.is_empty());
    assert!(!scorecards.adoption_evidence.is_empty());
    assert!(!scorecards.guardrails.is_empty());
}
