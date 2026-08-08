use aiaf_v1::local_runtime::PortfolioBoardView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_portfolio_board_release_train_governance_acceptance() {
    let service = service("portfolio-board-release-train").await;
    let _ = service
        .run_headless("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let _ = service
        .run_headless("supervisor-durable-fixed-interface-self-hosting-loop")
        .await
        .unwrap();

    let router = router(service.clone());
    let board: PortfolioBoardView = get_json(&router, "/api/convergence/portfolio-board").await;

    assert!(board.summary.contains("release train"));
    assert!(!board.release_board.is_empty());
    assert!(board.strongest_candidate.is_some());
    assert!(!board.intervention_law.is_empty());
    assert!(
        board
            .release_board
            .iter()
            .any(|entry| !entry.next_gate.trim().is_empty())
    );
}
