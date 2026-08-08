use std::fs;

use aiaf_v1::local_runtime::RunSummary;

use crate::local_runtime_support::service;

#[tokio::test]
async fn supervisor_local_runner_report_export_acceptance() {
    let service = service("report-export").await;
    let run = service
        .run_headless("supervisor-durable-fixed-interface-continuous-self-hosting-program")
        .await
        .unwrap();

    let export_root = service.export_run(&run.summary.run_id).await.unwrap();
    assert!(export_root.join("summary.json").exists());
    assert!(export_root.join("events.jsonl").exists());
    assert!(export_root.join("report.html").exists());
    assert!(export_root.join("snapshots/approvals.json").exists());
    assert!(export_root.join("snapshots/checkpoints.json").exists());
    assert!(export_root.join("snapshots/memory.json").exists());
    assert!(export_root.join("snapshots/promotion.json").exists());
    assert!(export_root.join("snapshots/runtime-state.json").exists());
    assert!(export_root.join("snapshots/factory.json").exists());
    assert!(export_root.join("snapshots/agents.json").exists());
    assert!(export_root.join("snapshots/attention.json").exists());
    assert!(export_root.join("snapshots/history.json").exists());
    assert!(
        export_root
            .join("snapshots/comparison-ledger.json")
            .exists()
    );
    assert!(export_root.join("snapshots/evidence.json").exists());
    assert!(export_root.join("snapshots/replay.json").exists());
    assert!(export_root.join("snapshots/portfolio.json").exists());
    assert!(export_root.join("snapshots/analytics.json").exists());
    assert!(export_root.join("snapshots/operator.json").exists());
    assert!(export_root.join("snapshots/context-packages.json").exists());
    assert!(export_root.join("snapshots/review-packets.json").exists());
    assert!(
        export_root
            .join("snapshots/experiment-ledger.json")
            .exists()
    );
    assert!(export_root.join("snapshots/portfolio-board.json").exists());
    assert!(
        export_root
            .join("snapshots/contract-pressure.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/convergence-scorecard.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/final-self-hosting-suite.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/v2-transition-workspace.json")
            .exists()
    );
    assert!(
        export_root
            .join("snapshots/v2-transition-packets.json")
            .exists()
    );
    assert!(export_root.join("snapshots/planning.json").exists());
    assert!(export_root.join("snapshots/scenario-studio.json").exists());
    assert!(export_root.join("snapshots/usecases.json").exists());
    assert!(
        export_root
            .join("snapshots/experiment-program.json")
            .exists()
    );

    let summary: RunSummary =
        serde_json::from_str(&fs::read_to_string(export_root.join("summary.json")).unwrap())
            .unwrap();
    assert_eq!(summary.run_id, run.summary.run_id);
    assert_eq!(
        summary.status,
        aiaf_v1::local_runtime::LocalRunStatus::Completed
    );
}
