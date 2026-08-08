use aiaf_v1::local_runtime::ExperimentProgramView;

use crate::local_runtime_support::{get_json, router, service};

#[tokio::test]
async fn supervisor_factory_agent_rehearsal_program_regression_pack_acceptance() {
    let service = service("rehearsal-programs").await;
    let router = router(service);

    let programs: ExperimentProgramView = get_json(&router, "/api/studio/experiment-program").await;
    assert!(!programs.rehearsal_programs.is_empty());
    assert!(!programs.regression_packs.is_empty());
    assert!(
        programs
            .rehearsal_programs
            .iter()
            .any(|program| program.kind == "Factory")
    );
    assert!(
        programs
            .rehearsal_programs
            .iter()
            .any(|program| program.kind == "Agent")
    );
}
