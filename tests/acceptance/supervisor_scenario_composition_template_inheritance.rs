use aiaf_v1::local_runtime::ExperimentProgramView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_scenario_composition_template_inheritance_acceptance() {
    let service = service("scenario-composition").await;
    let router = router(service);

    let programs: ExperimentProgramView = get_json(&router, "/api/studio/experiment-program").await;
    assert!(programs.summary.contains("composition"));
    assert!(!programs.compositions.is_empty());

    let composition = programs
        .compositions
        .iter()
        .find(|composition| composition.composition_id == "composition-factory-approval-baseline")
        .expect("expected factory approval composition");
    assert_eq!(composition.template_id, "template-factory-approval-lane");
    assert!(
        composition
            .inherited_from
            .iter()
            .any(|item| item.contains("supervisor-approval-resume-worker-complete"))
    );
}
