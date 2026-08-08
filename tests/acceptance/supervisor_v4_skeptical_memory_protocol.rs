use super::supervisor_v4_support::{run_full_v4_flow, temp_store_root};

#[test]
fn supervisor_v4_skeptical_memory_protocol_acceptance() {
    let artifacts = run_full_v4_flow(temp_store_root("skeptical-memory-protocol"));

    assert_eq!(artifacts.bundle.memory_retrieval_traces.len(), 1);
    assert_eq!(artifacts.bundle.verified_memory_updates.len(), 1);
    let continuity = artifacts.bundle.continuity_bundle.as_ref().unwrap();
    assert_eq!(continuity.retrieval_trace_refs.len(), 1);
    assert_eq!(continuity.verified_memory_refs.len(), 1);
    assert_eq!(
        continuity.contradiction_refs,
        vec!["contradiction-v4-1".to_string()]
    );
}
