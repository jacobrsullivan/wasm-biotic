use std::collections::BTreeSet;

use aiaf_v1::execution::{FactoryProgramSpec, FactoryProgramTickReceipt, RecursionBudgetRecord};
use aiaf_v1::local_runtime::{FactoryProgramView, GeneralAudienceHomeView, RunViewModel};
use serde_json::Value;

use crate::local_runtime_support::{get_json, post_empty, post_json, router, service};

fn test_program_spec() -> FactoryProgramSpec {
    FactoryProgramSpec {
        spec_id: "general-audience-home-spec".to_string(),
        title: "General Audience Home Program".to_string(),
        root_factory_ref: "factory:root".to_string(),
        stable_interface_ref: "contract:bounded-v1".to_string(),
        goal_refs: vec!["goal:home-view".to_string()],
        workload_refs: vec!["workload:home-view".to_string()],
        utility_metric_refs: vec!["metric:home-view".to_string()],
        mutation_scope_refs: vec!["scope:home-view".to_string()],
        promotion_gate_refs: vec!["gate:promotion".to_string()],
        rollback_gate_refs: vec!["gate:rollback".to_string()],
        recursion_budget: RecursionBudgetRecord {
            recursion_budget_id: "budget:general-audience-home".to_string(),
            max_depth: 2,
            max_campaigns: 3,
            risk_threshold_refs: vec!["risk-threshold:home-view".to_string()],
            exhaustion_policy: "stop".to_string(),
        },
        policy_ref: "policy:general-audience-home".to_string(),
        llm_driver_profile_ref: Some("profile:general-audience-home".to_string()),
    }
}

#[tokio::test]
async fn supervisor_general_audience_home_acceptance() {
    let service = service("general-audience-home").await;
    let router = router(service.clone());

    service
        .start_run("supervisor-promote-activate-successor-campaign")
        .await
        .unwrap();
    let approval_run = service
        .start_run("supervisor-approval-resume-worker-complete")
        .await
        .unwrap();
    let created_program = service
        .create_factory_program(test_program_spec())
        .await
        .unwrap();

    let home: GeneralAudienceHomeView = get_json(&router, "/api/home/general-audience").await;

    assert_eq!(home.introduction_paragraphs.len(), 3);
    assert!(
        home.introduction_paragraphs[0]
            .starts_with("AIAF is an AI system built on the idea that software should improve")
    );
    assert!(
        home.introduction_paragraphs[1]
            .starts_with("In its current form, AIAF acts as a local supervisory system")
    );
    assert!(
        home.introduction_paragraphs[2]
            .starts_with("AIAF is building workspace services for reading and changing code")
    );

    assert_eq!(home.current_snapshot.active_run_count, 1);
    assert_eq!(home.current_snapshot.pending_approval_count, 1);
    assert_eq!(
        home.current_snapshot
            .latest_active_run
            .as_ref()
            .map(|run| run.run_id.as_str()),
        Some(approval_run.summary.run_id.as_str())
    );
    assert_eq!(home.current_snapshot.expert_console_path, "/console");

    let groups = home
        .active_capability_groups
        .iter()
        .map(|group| group.title.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        groups,
        BTreeSet::from([
            "Workspace",
            "Execution",
            "Memory",
            "Worker Coordination",
            "Approval And Governance",
            "Review And Promotion",
            "Scheduling",
            "Infrastructure",
        ])
    );

    assert!(home.in_flight_capabilities.iter().any(|item| {
        item.run_id.as_deref() == Some(approval_run.summary.run_id.as_str())
            && item
                .governance_state
                .contains("Awaiting 1 governed approval decision")
    }));
    assert!(
        home.in_flight_capabilities
            .iter()
            .any(|item| item.program_instance_id.as_deref()
                == Some(created_program.instance.instance_id.as_str()))
    );

    assert!(!home.historical_timeline.is_empty());
    assert!(!home.future_roadmap.is_empty());
    assert!(home.future_roadmap.iter().all(|item| matches!(
        item.source_kind.as_str(),
        "progress_tracker" | "planning" | "transition" | "blocker"
    )));
    assert!(home.future_roadmap.iter().all(|item| matches!(
        item.status,
        aiaf_v1::local_runtime::ConsoleProgressStatus::LiveButBounded
            | aiaf_v1::local_runtime::ConsoleProgressStatus::NotYet
    )));

    let recommended = home
        .recommended_actions
        .iter()
        .find(|action| {
            action.scenario_id.as_deref() == Some("supervisor-approval-resume-worker-complete")
        })
        .expect("recommended approval scenario action should exist");
    let recommended_payload: Value = serde_json::from_str(
        recommended
            .payload_template
            .as_deref()
            .expect("recommended action should include a payload template"),
    )
    .unwrap();
    let started_from_home: RunViewModel =
        post_json(&router, &recommended.endpoint, &recommended_payload).await;
    assert_eq!(
        started_from_home.summary.scenario_id,
        "supervisor-approval-resume-worker-complete"
    );

    let grant_action = home
        .advanced_actions
        .run_controls
        .iter()
        .find(|action| {
            action.run_id.as_deref() == Some(approval_run.summary.run_id.as_str())
                && action.endpoint.ends_with("/approval/grant")
        })
        .expect("grant approval control should be surfaced");
    let granted_run: RunViewModel = post_empty(&router, &grant_action.endpoint).await;
    assert_eq!(granted_run.summary.run_id, approval_run.summary.run_id);
    assert_eq!(
        granted_run.summary.status,
        aiaf_v1::local_runtime::LocalRunStatus::Completed
    );

    let tick_action = home
        .advanced_actions
        .program_actions
        .iter()
        .find(|action| {
            action.program_instance_id.as_deref()
                == Some(created_program.instance.instance_id.as_str())
                && action.endpoint.ends_with("/tick")
        })
        .expect("program tick control should be surfaced");
    let tick_payload: Value = serde_json::from_str(
        tick_action
            .payload_template
            .as_deref()
            .expect("tick action should include a payload template"),
    )
    .unwrap();
    let tick_receipt: FactoryProgramTickReceipt =
        post_json(&router, &tick_action.endpoint, &tick_payload).await;
    assert_eq!(
        tick_receipt.instance_id,
        created_program.instance.instance_id
    );

    let drive_action = home
        .advanced_actions
        .program_actions
        .iter()
        .find(|action| action.endpoint == "/api/programs/controlled-evolution/drive")
        .expect("global controlled evolution drive should be surfaced");
    let driven_program: FactoryProgramView = post_empty(&router, &drive_action.endpoint).await;
    assert_eq!(
        driven_program.instance.program_state,
        aiaf_v1::execution::FactoryProgramState::Completed
    );

    let llm_drive_action = home
        .advanced_actions
        .program_actions
        .iter()
        .find(|action| {
            action.program_instance_id.as_deref()
                == Some(created_program.instance.instance_id.as_str())
                && action.endpoint.ends_with("/llm-drive")
        })
        .expect("program llm-drive control should be surfaced");
    let llm_payload: Value = serde_json::from_str(
        llm_drive_action
            .payload_template
            .as_deref()
            .expect("llm-drive action should include a payload template"),
    )
    .unwrap();
    assert_eq!(llm_payload["provider_ref"], "provider:configure-me");
    assert_eq!(llm_payload["model_ref"], "gpt-5.4-mini");
    assert_eq!(
        llm_payload["generation_policy"]["max_output_tokens"],
        Value::from(512)
    );
}
