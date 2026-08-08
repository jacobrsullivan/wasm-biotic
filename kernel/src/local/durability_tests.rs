use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};

const MIGRATION_COMPONENT: &[u8] = include_bytes!("../../fixtures/artifacts/task.wasm");
static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(point: DurabilityFaultPoint) -> Self {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-activation-durability-{point:?}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::SeqCst)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn graph_binding(digest: Sha256Digest) -> StoredRootBinding {
    StoredRootBinding {
        composed_root_digest: digest_hex(digest),
        source_component_digests: Vec::new(),
        execution_bindings: BTreeMap::new(),
        scoped_component_digests: Vec::new(),
        principals: BTreeMap::new(),
        invocation_targets: BTreeMap::new(),
        root_principal_seeds: Vec::new(),
        validation_report_digest: digest_hex(digest),
        release_certification_digest: digest_hex(digest),
    }
}

fn graph_binding_with_principal(
    digest: Sha256Digest,
    component: Sha256Digest,
    principal_seed: Sha256Digest,
    activation_import: bool,
) -> StoredRootBinding {
    let mut binding = graph_binding(digest);
    let host_imports = if activation_import {
        vec![StoredHostImport {
            alias: format!(
                "wasm-biotic:factory/host-{}@0.1.0",
                digest_hex(Sha256Digest::from_bytes(
                    format!("{}:{principal_seed}", digest_hex(digest)).as_bytes()
                ))
            ),
            source_import: "wasm-biotic:factory/activation@0.1.0".to_string(),
            capability: "activation".to_string(),
            scope: "switch".to_string(),
            constraint_digest: digest_hex(component),
        }]
    } else {
        Vec::new()
    };
    binding.principals.insert(
        digest_hex(principal_seed),
        StoredPrincipal {
            consumer: "principal-owner".to_string(),
            authority_component_digest: digest_hex(component),
            principal_seed: digest_hex(principal_seed),
            scoped_component_digest: digest_hex(component),
            host_imports,
        },
    );
    binding.root_principal_seeds = vec![digest_hex(principal_seed)];
    binding
}

fn atomic_points() -> [DurabilityFaultPoint; 8] {
    [
        DurabilityFaultPoint::BeforeTempWrite,
        DurabilityFaultPoint::AfterTempWrite,
        DurabilityFaultPoint::BeforeTempSync,
        DurabilityFaultPoint::AfterTempSync,
        DurabilityFaultPoint::BeforeRename,
        DurabilityFaultPoint::AfterRename,
        DurabilityFaultPoint::BeforeDirectorySync,
        DurabilityFaultPoint::AfterDirectorySync,
    ]
}

fn renamed(point: DurabilityFaultPoint) -> bool {
    matches!(
        point,
        DurabilityFaultPoint::AfterRename
            | DurabilityFaultPoint::BeforeDirectorySync
            | DurabilityFaultPoint::AfterDirectorySync
    )
}

fn assert_blob_option_eq(
    actual: Option<&foundation::BlobRef>,
    expected: Option<&foundation::BlobRef>,
    context: impl std::fmt::Display,
) {
    assert_eq!(
        blob_option_key(actual).unwrap(),
        blob_option_key(expected).unwrap(),
        "{context}"
    );
}

fn principal_test_scope(
    mechanisms: &mut LocalMechanisms,
    manifest: Sha256Digest,
    component: Sha256Digest,
) {
    mechanisms.graph_scope = Some(Arc::new(GraphScope {
        manifest_digest: manifest,
        source_components: BTreeSet::from([digest_hex(component)]),
        execution_bindings: BTreeMap::new(),
        principals: BTreeMap::new(),
        invocation_targets: BTreeMap::new(),
    }));
}

#[test]
fn r2_principal_handles_and_idempotency_remain_isolated_after_restart() {
    let directory = TestDirectory::new(DurabilityFaultPoint::BeforeTempWrite);
    let manifest = Sha256Digest::from_bytes(b"r2-owner-graph");
    let component = Sha256Digest::from_bytes(MIGRATION_COMPONENT);
    let principal_a = Sha256Digest::from_bytes(b"r2-principal-a");
    let principal_b = Sha256Digest::from_bytes(b"r2-principal-b");
    let mut mechanisms = LocalMechanisms::open(
        &directory.0,
        LocalConfig::default().with_max_blob_bytes(1024 * 1024),
    )
    .unwrap();
    mechanisms
        .admit_component(component, MIGRATION_COMPONENT)
        .unwrap();
    let incumbent_manifest = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            b"r2-owner-graph".to_vec(),
        )
        .unwrap();
    assert_eq!(
        validate_digest(&incumbent_manifest.content_digest).unwrap(),
        manifest
    );
    let successor_manifest = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            b"r2-successor-graph".to_vec(),
        )
        .unwrap();
    let successor = validate_digest(&successor_manifest.content_digest).unwrap();
    let missing_import_manifest = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            b"r2-missing-import-graph".to_vec(),
        )
        .unwrap();
    let missing_import = validate_digest(&missing_import_manifest.content_digest).unwrap();
    let wrong_seed_manifest = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            b"r2-wrong-seed-graph".to_vec(),
        )
        .unwrap();
    let wrong_seed = validate_digest(&wrong_seed_manifest.content_digest).unwrap();
    mechanisms
        .mutate_state("r2-handoff-bindings", |state| {
            for graph in [manifest, successor, missing_import, wrong_seed] {
                state.admitted_graphs.insert(digest_hex(graph));
            }
            state.root_bindings.insert(
                digest_hex(manifest),
                graph_binding_with_principal(manifest, component, principal_a, true),
            );
            state.root_bindings.insert(
                digest_hex(successor),
                graph_binding_with_principal(successor, component, principal_a, true),
            );
            state.root_bindings.insert(
                digest_hex(missing_import),
                graph_binding_with_principal(missing_import, component, principal_a, false),
            );
            state.root_bindings.insert(
                digest_hex(wrong_seed),
                graph_binding_with_principal(wrong_seed, component, principal_b, true),
            );
            state.active_manifest = Some(digest_value(manifest));
            Ok(())
        })
        .unwrap();
    principal_test_scope(&mut mechanisms, manifest, component);

    let wake = clock::WakeRequest {
        wake_id: "shared-wake-handle".to_string(),
        not_before_ms: mechanisms.now_ms(),
        target_component: digest_value(component),
        payload_digest: digest_value(Sha256Digest::from_bytes(b"wake-payload-a")),
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"shared-wake-key")),
    };
    mechanisms
        .schedule_for_principal(wake.clone(), Some(principal_a))
        .unwrap();
    assert_eq!(
        mechanisms
            .poll_scheduled_for_principal(wake.wake_id.clone(), Some(principal_b))
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        mechanisms
            .cancel_scheduled_for_principal(wake.wake_id.clone(), Some(principal_b))
            .unwrap_err()
            .code,
        "not-granted"
    );
    let mut conflicting = wake.clone();
    conflicting.payload_digest = digest_value(Sha256Digest::from_bytes(b"changed-payload"));
    assert_eq!(
        mechanisms
            .schedule_for_principal(conflicting, Some(principal_a))
            .unwrap_err()
            .code,
        "idempotency-conflict"
    );
    mechanisms
        .schedule_for_principal(wake.clone(), Some(principal_b))
        .unwrap();
    assert!(
        mechanisms
            .poll_scheduled_for_principal(wake.wake_id.clone(), Some(principal_b))
            .unwrap()
            .is_some()
    );

    let operation_key = digest_value(Sha256Digest::from_bytes(b"runner-operation-key"));
    let operation_scope = mechanisms
        .component_operation_scope(
            &validate_digest(&operation_key).unwrap().to_string(),
            Some(principal_a),
        )
        .unwrap();
    let operation_id = format!(
        "operation-{}",
        operation_scope.trim_start_matches("sha256:")
    );
    let request_digest = Sha256Digest::from_bytes(b"runner-request").to_string();
    mechanisms
        .record_run(
            operation_scope.clone(),
            StoredRun {
                request_digest: request_digest.clone(),
                operation_id: operation_id.clone(),
                completion: component_runner::RunCompletion {
                    run_id: "owned-run".to_string(),
                    outcome: foundation::TerminalOutcome::Rejected(failure(
                        "test-outcome",
                        "opaque test completion",
                    )),
                    receipt: mechanism_receipt(
                        Sha256Digest::from_bytes(b"runner-request"),
                        Sha256Digest::from_bytes(b"runner-outcome"),
                        1,
                        2,
                        0,
                    ),
                },
                provenance: Some(crate::root_runtime::ExecutionProvenance {
                    graph_manifest_digest: Some(manifest),
                    authority_component_digest: component,
                    executable_component_digest: component,
                    source_component_digests: vec![component],
                    caller_principal_seed: Some(principal_a),
                }),
                caller_principal_seed: Some(principal_a),
            },
        )
        .unwrap();
    assert!(
        mechanisms
            .poll_run_for_principal(&operation_id, Some(principal_a))
            .unwrap()
            .is_some()
    );
    let evidence_completion = mechanisms
        .execution_completion(&operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(evidence_completion.run_id, "owned-run");
    assert_eq!(
        component_runner::Host::poll(&mut mechanisms, operation_id.clone())
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        mechanisms
            .poll_run_for_principal(&operation_id, Some(principal_b))
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        mechanisms
            .cancel_run_for_principal(&operation_id, Some(principal_b))
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        mechanisms
            .existing_run(
                &operation_scope,
                &Sha256Digest::from_bytes(b"altered-request").to_string(),
                Some(manifest),
                Some(principal_a),
            )
            .unwrap_err()
            .code,
        "idempotency-conflict"
    );

    let missing_import_request = activation::ActivationRequest {
        activation_id: "missing-import-handle".to_string(),
        graph_manifest: missing_import_manifest,
        expected_active_graph: Some(digest_value(manifest)),
        expected_active_state: None,
        state_migration: None,
        migrated_state: None,
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"missing-import-key")),
    };
    mechanisms
        .stage_activation_for_principal(missing_import_request, Some(principal_a))
        .unwrap();
    assert_eq!(
        mechanisms
            .commit_activation_for_principal(
                "missing-import-handle".to_string(),
                Some(principal_a),
            )
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        validate_digest(
            &mechanisms
                .active_manifest_reference()
                .unwrap()
                .unwrap()
                .content_digest
        )
        .unwrap(),
        manifest
    );
    assert!(matches!(
        mechanisms
            .activation_status_for_principal(
                "missing-import-handle".to_string(),
                Some(principal_a),
            )
            .unwrap()
            .state,
        activation::ActivationState::Staged
    ));

    let wrong_seed_request = activation::ActivationRequest {
        activation_id: "wrong-destination-seed-handle".to_string(),
        graph_manifest: wrong_seed_manifest,
        expected_active_graph: Some(digest_value(manifest)),
        expected_active_state: None,
        state_migration: None,
        migrated_state: None,
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"wrong-destination-seed-key")),
    };
    mechanisms
        .stage_activation_for_principal(wrong_seed_request, Some(principal_a))
        .unwrap();
    assert_eq!(
        mechanisms
            .commit_activation_for_principal(
                "wrong-destination-seed-handle".to_string(),
                Some(principal_a),
            )
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        validate_digest(
            &mechanisms
                .active_manifest_reference()
                .unwrap()
                .unwrap()
                .content_digest
        )
        .unwrap(),
        manifest
    );
    assert!(matches!(
        mechanisms
            .activation_status_for_principal(
                "wrong-destination-seed-handle".to_string(),
                Some(principal_a),
            )
            .unwrap()
            .state,
        activation::ActivationState::Staged
    ));

    let activation_id = "shared-activation-handle";
    let activation_request = activation::ActivationRequest {
        activation_id: activation_id.to_string(),
        graph_manifest: successor_manifest,
        expected_active_graph: Some(digest_value(manifest)),
        expected_active_state: None,
        state_migration: None,
        migrated_state: None,
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"shared-activation-key")),
    };
    mechanisms
        .stage_activation_for_principal(activation_request.clone(), Some(principal_a))
        .unwrap();
    let committed = mechanisms
        .commit_activation_for_principal(activation_id.to_string(), Some(principal_a))
        .unwrap();
    assert!(matches!(
        committed.state,
        activation::ActivationState::Active
    ));
    assert_eq!(
        digest_option_key(committed.active_graph.as_ref()).unwrap(),
        Some(successor.to_string())
    );
    assert_eq!(
        mechanisms
            .activation_status_for_principal(activation_id.to_string(), Some(principal_a))
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        mechanisms
            .stage_activation_for_principal(activation_request.clone(), Some(principal_a))
            .unwrap_err()
            .code,
        "conflict"
    );
    let mut moved_owner_retry = activation_request;
    moved_owner_retry.expected_active_graph = Some(digest_value(successor));
    assert_eq!(
        mechanisms
            .stage_activation_for_principal(moved_owner_retry, Some(principal_a))
            .unwrap_err()
            .code,
        "not-granted"
    );

    let mut successor_scope = mechanisms.clone();
    principal_test_scope(&mut successor_scope, successor, component);
    assert!(matches!(
        successor_scope
            .activation_status_for_principal(activation_id.to_string(), Some(principal_a))
            .unwrap()
            .state,
        activation::ActivationState::Active
    ));
    assert_eq!(
        successor_scope
            .activation_status_for_principal(activation_id.to_string(), Some(principal_b))
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert_eq!(
        mechanisms
            .lock_state()
            .unwrap()
            .activations
            .values()
            .filter(|record| record.status.activation_id == activation_id)
            .count(),
        1
    );

    let rolled_back = successor_scope
        .rollback_activation_for_principal(
            activation_id.to_string(),
            digest_value(manifest),
            Some(principal_a),
        )
        .unwrap();
    assert!(matches!(
        rolled_back.state,
        activation::ActivationState::RolledBack
    ));
    assert_eq!(
        digest_option_key(rolled_back.active_graph.as_ref()).unwrap(),
        Some(manifest.to_string())
    );
    assert_eq!(
        successor_scope
            .activation_status_for_principal(activation_id.to_string(), Some(principal_a))
            .unwrap_err()
            .code,
        "not-granted"
    );
    assert!(matches!(
        mechanisms
            .activation_status_for_principal(activation_id.to_string(), Some(principal_a))
            .unwrap()
            .state,
        activation::ActivationState::RolledBack
    ));
    assert_eq!(
        mechanisms
            .lock_state()
            .unwrap()
            .activations
            .values()
            .filter(|record| record.status.activation_id == activation_id)
            .count(),
        1
    );

    drop(successor_scope);
    drop(mechanisms);
    let mut restarted = LocalMechanisms::open(
        &directory.0,
        LocalConfig::default().with_max_blob_bytes(1024 * 1024),
    )
    .unwrap();
    principal_test_scope(&mut restarted, manifest, component);
    assert!(
        restarted
            .poll_run_for_principal(&operation_id, Some(principal_a))
            .unwrap()
            .is_some()
    );
    assert_eq!(
        restarted
            .execution_completion(&operation_id)
            .unwrap()
            .unwrap()
            .run_id,
        "owned-run"
    );
    assert!(
        restarted
            .activation_status_for_principal(activation_id.to_string(), Some(principal_a))
            .is_ok()
    );
    assert!(
        restarted
            .poll_scheduled_for_principal(wake.wake_id, Some(principal_a))
            .unwrap()
            .is_some()
    );
}

#[test]
fn activation_commit_faults_never_mix_active_last_good_status_or_receipt() {
    let state_points = [
        DurabilityFaultPoint::BeforeStateChange,
        DurabilityFaultPoint::AfterStateChange,
        DurabilityFaultPoint::BeforeStateCommit,
        DurabilityFaultPoint::AfterStateCommit,
    ];
    for (point, operation, new_state_expected) in atomic_points()
        .into_iter()
        .map(|point| (point, "mechanism-state", renamed(point)))
        .chain(state_points.into_iter().map(|point| {
            (
                point,
                "activation-commit",
                point == DurabilityFaultPoint::AfterStateCommit,
            )
        }))
    {
        let directory = TestDirectory::new(point);
        let config = LocalConfig::default().with_max_blob_bytes(1024 * 1024);
        let initial = LocalMechanisms::open(&directory.0, config.clone()).unwrap();
        let old_graph = initial
            .put_blob(
                "application/vnd.wasm-biotic.graph+json".to_string(),
                b"old-graph".to_vec(),
            )
            .unwrap();
        let new_graph = initial
            .put_blob(
                "application/vnd.wasm-biotic.graph+json".to_string(),
                b"new-graph".to_vec(),
            )
            .unwrap();
        let old_state = initial
            .put_blob(
                "application/vnd.wasm-biotic.state+octets".to_string(),
                b"old-state".to_vec(),
            )
            .unwrap();
        let new_state = initial
            .put_blob(
                "application/vnd.wasm-biotic.state+octets".to_string(),
                b"new-state".to_vec(),
            )
            .unwrap();
        let migration_digest = Sha256Digest::from_bytes(MIGRATION_COMPONENT);
        initial
            .admit_component(migration_digest, MIGRATION_COMPONENT)
            .unwrap();
        let old_digest = validate_digest(&old_graph.content_digest).unwrap();
        let new_digest = validate_digest(&new_graph.content_digest).unwrap();
        initial
            .mutate_state("test-only-opaque-activation-fixture", |state| {
                state
                    .root_bindings
                    .insert(digest_hex(old_digest), graph_binding(old_digest));
                state
                    .root_bindings
                    .insert(digest_hex(new_digest), graph_binding(new_digest));
                state.active_manifest = Some(old_graph.content_digest.clone());
                state.active_state = Some(old_state.clone());
                Ok(())
            })
            .unwrap();
        drop(initial);

        let controller = DurabilityFaultController::default();
        let mut faulted = LocalMechanisms::open_with_fault_injection(
            &directory.0,
            config.clone(),
            Arc::new(SystemTimeSource),
            controller.clone(),
        )
        .unwrap();
        let request = activation::ActivationRequest {
            activation_id: "activation-under-fault".to_string(),
            graph_manifest: new_graph,
            expected_active_graph: Some(old_graph.content_digest.clone()),
            expected_active_state: Some(old_state.clone()),
            state_migration: Some(digest_value(migration_digest)),
            migrated_state: Some(new_state.clone()),
            idempotency_key: digest_value(Sha256Digest::from_bytes(b"activation-under-fault")),
        };
        activation::Host::stage(&mut faulted, request).unwrap();
        controller.arm(point, operation);
        assert!(
            activation::Host::commit(&mut faulted, "activation-under-fault".to_string()).is_err(),
            "{point:?}"
        );
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(faulted);

        let mut reopened = LocalMechanisms::open(&directory.0, config).unwrap();
        let active = reopened.active_manifest_digest().unwrap().unwrap();
        let active_state = reopened.active_state_reference().unwrap().unwrap();
        let (previous, previous_state) = {
            let state = reopened.inner.state.lock().unwrap();
            (
                state
                    .last_known_good_manifest
                    .as_ref()
                    .map(validate_digest)
                    .transpose()
                    .unwrap(),
                state.last_known_good_state.clone(),
            )
        };
        let status =
            activation::Host::status(&mut reopened, "activation-under-fault".to_string()).unwrap();
        if new_state_expected {
            assert_eq!(active, new_digest, "{point:?}");
            assert_eq!(previous, Some(old_digest), "{point:?}");
            assert_blob_option_eq(Some(&active_state), Some(&new_state), format!("{point:?}"));
            assert_blob_option_eq(
                previous_state.as_ref(),
                Some(&old_state),
                format!("{point:?}"),
            );
            assert!(
                matches!(status.state, activation::ActivationState::Active),
                "{point:?}"
            );
            assert_eq!(
                status
                    .active_graph
                    .as_ref()
                    .map(validate_digest)
                    .transpose()
                    .unwrap(),
                Some(new_digest),
                "{point:?}"
            );
            assert_blob_option_eq(
                status.active_state.as_ref(),
                Some(&new_state),
                format!("{point:?}"),
            );
            assert!(status.receipt.is_some(), "{point:?}");
        } else {
            assert_eq!(active, old_digest, "{point:?}");
            assert_eq!(previous, None, "{point:?}");
            assert_blob_option_eq(Some(&active_state), Some(&old_state), format!("{point:?}"));
            assert_blob_option_eq(previous_state.as_ref(), None, format!("{point:?}"));
            assert!(
                matches!(status.state, activation::ActivationState::Staged),
                "{point:?}"
            );
            assert_eq!(
                status
                    .active_graph
                    .as_ref()
                    .map(validate_digest)
                    .transpose()
                    .unwrap(),
                Some(new_digest),
                "{point:?}"
            );
            assert_blob_option_eq(
                status.active_state.as_ref(),
                Some(&new_state),
                format!("{point:?}"),
            );
            assert!(status.receipt.is_none(), "{point:?}");
        }

        let committed =
            activation::Host::commit(&mut reopened, "activation-under-fault".to_string()).unwrap();
        assert!(matches!(
            committed.state,
            activation::ActivationState::Active
        ));
        drop(reopened);

        let restarted = LocalMechanisms::open(
            &directory.0,
            LocalConfig::default().with_max_blob_bytes(1024 * 1024),
        )
        .unwrap();
        assert_eq!(
            restarted.active_manifest_digest().unwrap(),
            Some(new_digest),
            "{point:?}"
        );
        assert_eq!(
            restarted.last_known_good_manifest_digest().unwrap(),
            Some(old_digest),
            "{point:?}"
        );
        assert_blob_option_eq(
            restarted.active_state_reference().unwrap().as_ref(),
            Some(&new_state),
            format!("{point:?}"),
        );
        let restarted_previous_state = restarted
            .inner
            .state
            .lock()
            .unwrap()
            .last_known_good_state
            .clone();
        assert_blob_option_eq(
            restarted_previous_state.as_ref(),
            Some(&old_state),
            format!("{point:?}"),
        );
    }
}

#[test]
fn activation_stage_rejects_mismatched_partial_and_unstored_state_bindings() {
    let directory = TestDirectory::new(DurabilityFaultPoint::BeforeStateChange);
    let config = LocalConfig::default().with_max_blob_bytes(1024 * 1024);
    let mut mechanisms = LocalMechanisms::open(&directory.0, config).unwrap();
    let old_graph = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            b"negative-old-graph".to_vec(),
        )
        .unwrap();
    let new_graph = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.graph+json".to_string(),
            b"negative-new-graph".to_vec(),
        )
        .unwrap();
    let old_state = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.state+octets".to_string(),
            b"negative-old-state".to_vec(),
        )
        .unwrap();
    let wrong_state = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.state+octets".to_string(),
            b"negative-wrong-state".to_vec(),
        )
        .unwrap();
    let new_state = mechanisms
        .put_blob(
            "application/vnd.wasm-biotic.state+octets".to_string(),
            b"negative-new-state".to_vec(),
        )
        .unwrap();
    let old_digest = validate_digest(&old_graph.content_digest).unwrap();
    let new_digest = validate_digest(&new_graph.content_digest).unwrap();
    let migration_digest = Sha256Digest::from_bytes(MIGRATION_COMPONENT);
    mechanisms
        .admit_component(migration_digest, MIGRATION_COMPONENT)
        .unwrap();
    mechanisms
        .mutate_state("test-only-opaque-activation-negative-fixture", |state| {
            state
                .root_bindings
                .insert(digest_hex(old_digest), graph_binding(old_digest));
            state
                .root_bindings
                .insert(digest_hex(new_digest), graph_binding(new_digest));
            state.active_manifest = Some(old_graph.content_digest.clone());
            state.active_state = Some(old_state.clone());
            Ok(())
        })
        .unwrap();

    let base = activation::ActivationRequest {
        activation_id: "negative-activation".to_string(),
        graph_manifest: new_graph,
        expected_active_graph: Some(old_graph.content_digest.clone()),
        expected_active_state: Some(old_state.clone()),
        state_migration: Some(digest_value(migration_digest)),
        migrated_state: Some(new_state.clone()),
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"negative-activation")),
    };

    let mut mismatched = base.clone();
    mismatched.activation_id = "mismatched-state".to_string();
    mismatched.expected_active_state = Some(wrong_state);
    mismatched.idempotency_key = digest_value(Sha256Digest::from_bytes(b"mismatched-state"));
    assert_eq!(
        activation::Host::stage(&mut mechanisms, mismatched)
            .unwrap_err()
            .code,
        "conflict"
    );

    let mut missing_migrated_state = base.clone();
    missing_migrated_state.activation_id = "missing-migrated-state".to_string();
    missing_migrated_state.migrated_state = None;
    missing_migrated_state.idempotency_key =
        digest_value(Sha256Digest::from_bytes(b"missing-migrated-state"));
    assert_eq!(
        activation::Host::stage(&mut mechanisms, missing_migrated_state)
            .unwrap_err()
            .code,
        "incomplete-migration-binding"
    );

    let mut missing_migration_component = base.clone();
    missing_migration_component.activation_id = "missing-migration-component".to_string();
    missing_migration_component.state_migration = None;
    missing_migration_component.idempotency_key =
        digest_value(Sha256Digest::from_bytes(b"missing-migration-component"));
    assert_eq!(
        activation::Host::stage(&mut mechanisms, missing_migration_component)
            .unwrap_err()
            .code,
        "incomplete-migration-binding"
    );

    let mut unadmitted_migration = base.clone();
    unadmitted_migration.activation_id = "unadmitted-migration".to_string();
    unadmitted_migration.state_migration = Some(digest_value(Sha256Digest::from_bytes(
        b"unadmitted-migration-component",
    )));
    unadmitted_migration.idempotency_key =
        digest_value(Sha256Digest::from_bytes(b"unadmitted-migration"));
    assert_eq!(
        activation::Host::stage(&mut mechanisms, unadmitted_migration)
            .unwrap_err()
            .code,
        "not-admitted"
    );

    let mut unstored_state = base;
    unstored_state.activation_id = "unstored-migrated-state".to_string();
    unstored_state.migrated_state = Some(blob_reference(
        Sha256Digest::from_bytes(b"unstored-state"),
        u64::try_from(b"unstored-state".len()).unwrap(),
        "application/vnd.wasm-biotic.state+octets".to_string(),
    ));
    unstored_state.idempotency_key =
        digest_value(Sha256Digest::from_bytes(b"unstored-migrated-state"));
    assert_eq!(
        activation::Host::stage(&mut mechanisms, unstored_state)
            .unwrap_err()
            .code,
        "not-found"
    );

    assert_eq!(
        mechanisms.active_manifest_digest().unwrap(),
        Some(old_digest)
    );
    assert_blob_option_eq(
        mechanisms.active_state_reference().unwrap().as_ref(),
        Some(&old_state),
        "negative cases preserve active state",
    );
    let state = mechanisms.inner.state.lock().unwrap();
    assert!(state.activations.is_empty());
    assert!(state.last_known_good_manifest.is_none());
    assert!(state.last_known_good_state.is_none());
}

#[test]
fn activation_rollback_faults_never_mix_graph_and_opaque_state_pointers() {
    let state_points = [
        DurabilityFaultPoint::BeforeStateChange,
        DurabilityFaultPoint::AfterStateChange,
        DurabilityFaultPoint::BeforeStateCommit,
        DurabilityFaultPoint::AfterStateCommit,
    ];
    for (point, operation, rollback_committed) in atomic_points()
        .into_iter()
        .map(|point| (point, "mechanism-state", renamed(point)))
        .chain(state_points.into_iter().map(|point| {
            (
                point,
                "activation-rollback",
                point == DurabilityFaultPoint::AfterStateCommit,
            )
        }))
    {
        let directory = TestDirectory::new(point);
        let config = LocalConfig::default().with_max_blob_bytes(1024 * 1024);
        let mut initial = LocalMechanisms::open(&directory.0, config.clone()).unwrap();
        let old_graph = initial
            .put_blob(
                "application/vnd.wasm-biotic.graph+json".to_string(),
                format!("rollback-old-graph-{point:?}").into_bytes(),
            )
            .unwrap();
        let new_graph = initial
            .put_blob(
                "application/vnd.wasm-biotic.graph+json".to_string(),
                format!("rollback-new-graph-{point:?}").into_bytes(),
            )
            .unwrap();
        let old_state = initial
            .put_blob(
                "application/vnd.wasm-biotic.state+octets".to_string(),
                format!("rollback-old-state-{point:?}").into_bytes(),
            )
            .unwrap();
        let new_state = initial
            .put_blob(
                "application/vnd.wasm-biotic.state+octets".to_string(),
                format!("rollback-new-state-{point:?}").into_bytes(),
            )
            .unwrap();
        let old_digest = validate_digest(&old_graph.content_digest).unwrap();
        let new_digest = validate_digest(&new_graph.content_digest).unwrap();
        let migration_digest = Sha256Digest::from_bytes(MIGRATION_COMPONENT);
        initial
            .admit_component(migration_digest, MIGRATION_COMPONENT)
            .unwrap();
        initial
            .mutate_state("test-only-opaque-rollback-fixture", |state| {
                state
                    .root_bindings
                    .insert(digest_hex(old_digest), graph_binding(old_digest));
                state
                    .root_bindings
                    .insert(digest_hex(new_digest), graph_binding(new_digest));
                state.active_manifest = Some(old_graph.content_digest.clone());
                state.active_state = Some(old_state.clone());
                Ok(())
            })
            .unwrap();
        activation::Host::stage(
            &mut initial,
            activation::ActivationRequest {
                activation_id: "rollback-under-fault".to_string(),
                graph_manifest: new_graph,
                expected_active_graph: Some(old_graph.content_digest.clone()),
                expected_active_state: Some(old_state.clone()),
                state_migration: Some(digest_value(migration_digest)),
                migrated_state: Some(new_state.clone()),
                idempotency_key: digest_value(Sha256Digest::from_bytes(
                    format!("rollback-under-fault-{point:?}").as_bytes(),
                )),
            },
        )
        .unwrap();
        activation::Host::commit(&mut initial, "rollback-under-fault".to_string()).unwrap();
        drop(initial);

        let controller = DurabilityFaultController::default();
        let mut faulted = LocalMechanisms::open_with_fault_injection(
            &directory.0,
            config.clone(),
            Arc::new(SystemTimeSource),
            controller.clone(),
        )
        .unwrap();
        controller.arm(point, operation);
        assert!(
            activation::Host::rollback(
                &mut faulted,
                "rollback-under-fault".to_string(),
                old_graph.content_digest.clone(),
            )
            .is_err(),
            "{point:?}"
        );
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(faulted);

        let mut reopened = LocalMechanisms::open(&directory.0, config).unwrap();
        let active = reopened.active_manifest_digest().unwrap().unwrap();
        let active_state = reopened.active_state_reference().unwrap().unwrap();
        let (previous, previous_state) = {
            let state = reopened.inner.state.lock().unwrap();
            (
                state
                    .last_known_good_manifest
                    .as_ref()
                    .map(validate_digest)
                    .transpose()
                    .unwrap(),
                state.last_known_good_state.clone(),
            )
        };
        let status =
            activation::Host::status(&mut reopened, "rollback-under-fault".to_string()).unwrap();
        assert_eq!(previous, Some(old_digest), "{point:?}");
        assert_blob_option_eq(
            previous_state.as_ref(),
            Some(&old_state),
            format!("{point:?}"),
        );
        if rollback_committed {
            assert_eq!(active, old_digest, "{point:?}");
            assert_blob_option_eq(Some(&active_state), Some(&old_state), format!("{point:?}"));
            assert!(
                matches!(status.state, activation::ActivationState::RolledBack),
                "{point:?}"
            );
            assert_blob_option_eq(
                status.active_state.as_ref(),
                Some(&old_state),
                format!("{point:?}"),
            );
        } else {
            assert_eq!(active, new_digest, "{point:?}");
            assert_blob_option_eq(Some(&active_state), Some(&new_state), format!("{point:?}"));
            assert!(
                matches!(status.state, activation::ActivationState::Active),
                "{point:?}"
            );
            assert_blob_option_eq(
                status.active_state.as_ref(),
                Some(&new_state),
                format!("{point:?}"),
            );
        }

        let rolled_back = activation::Host::rollback(
            &mut reopened,
            "rollback-under-fault".to_string(),
            old_graph.content_digest.clone(),
        )
        .unwrap();
        assert!(matches!(
            rolled_back.state,
            activation::ActivationState::RolledBack
        ));
        assert_blob_option_eq(
            rolled_back.active_state.as_ref(),
            Some(&old_state),
            format!("{point:?}"),
        );
        drop(reopened);

        let restarted = LocalMechanisms::open(
            &directory.0,
            LocalConfig::default().with_max_blob_bytes(1024 * 1024),
        )
        .unwrap();
        assert_eq!(
            restarted.active_manifest_digest().unwrap(),
            Some(old_digest),
            "{point:?}"
        );
        assert_blob_option_eq(
            restarted.active_state_reference().unwrap().as_ref(),
            Some(&old_state),
            format!("{point:?}"),
        );
    }
}

#[test]
fn boot_recovery_faults_restore_graph_and_opaque_state_as_one_tuple() {
    let state_points = [
        DurabilityFaultPoint::BeforeStateChange,
        DurabilityFaultPoint::AfterStateChange,
        DurabilityFaultPoint::BeforeStateCommit,
        DurabilityFaultPoint::AfterStateCommit,
    ];
    for (point, operation, recovery_committed) in atomic_points()
        .into_iter()
        .map(|point| (point, "mechanism-state", renamed(point)))
        .chain(state_points.into_iter().map(|point| {
            (
                point,
                "restore-last-known-good",
                point == DurabilityFaultPoint::AfterStateCommit,
            )
        }))
    {
        let directory = TestDirectory::new(point);
        let config = LocalConfig::default().with_max_blob_bytes(1024 * 1024);
        let initial = LocalMechanisms::open(&directory.0, config.clone()).unwrap();
        let old_state = initial
            .put_blob(
                "application/vnd.wasm-biotic.state+octets".to_string(),
                format!("recovery-old-state-{point:?}").into_bytes(),
            )
            .unwrap();
        let new_state = initial
            .put_blob(
                "application/vnd.wasm-biotic.state+octets".to_string(),
                format!("recovery-new-state-{point:?}").into_bytes(),
            )
            .unwrap();
        let old_digest = Sha256Digest::from_bytes(format!("recovery-old-{point:?}").as_bytes());
        let new_digest = Sha256Digest::from_bytes(format!("recovery-new-{point:?}").as_bytes());
        initial
            .mutate_state("test-only-opaque-recovery-fixture", |state| {
                state
                    .root_bindings
                    .insert(digest_hex(old_digest), graph_binding(old_digest));
                state
                    .root_bindings
                    .insert(digest_hex(new_digest), graph_binding(new_digest));
                state.active_manifest = Some(digest_value(new_digest));
                state.active_state = Some(new_state.clone());
                state.last_known_good_manifest = Some(digest_value(old_digest));
                state.last_known_good_state = Some(old_state.clone());
                Ok(())
            })
            .unwrap();
        drop(initial);

        let controller = DurabilityFaultController::default();
        let faulted = LocalMechanisms::open_with_fault_injection(
            &directory.0,
            config.clone(),
            Arc::new(SystemTimeSource),
            controller.clone(),
        )
        .unwrap();
        controller.arm(point, operation);
        assert!(
            faulted
                .restore_last_known_good_manifest(new_digest)
                .is_err(),
            "{point:?}"
        );
        assert_eq!(controller.fired().len(), 1, "{point:?}");
        drop(faulted);

        let reopened = LocalMechanisms::open(&directory.0, config).unwrap();
        let active = reopened.active_manifest_digest().unwrap().unwrap();
        let active_state = reopened.active_state_reference().unwrap().unwrap();
        let (previous, previous_state) = {
            let state = reopened.inner.state.lock().unwrap();
            (
                state
                    .last_known_good_manifest
                    .as_ref()
                    .map(validate_digest)
                    .transpose()
                    .unwrap(),
                state.last_known_good_state.clone(),
            )
        };
        if recovery_committed {
            assert_eq!(active, old_digest, "{point:?}");
            assert_blob_option_eq(Some(&active_state), Some(&old_state), format!("{point:?}"));
            assert_eq!(previous, None, "{point:?}");
            assert_blob_option_eq(previous_state.as_ref(), None, format!("{point:?}"));
        } else {
            assert_eq!(active, new_digest, "{point:?}");
            assert_blob_option_eq(Some(&active_state), Some(&new_state), format!("{point:?}"));
            assert_eq!(previous, Some(old_digest), "{point:?}");
            assert_blob_option_eq(
                previous_state.as_ref(),
                Some(&old_state),
                format!("{point:?}"),
            );
            assert_eq!(
                reopened
                    .restore_last_known_good_manifest(new_digest)
                    .unwrap(),
                old_digest,
                "{point:?}"
            );
        }
        drop(reopened);

        let restarted = LocalMechanisms::open(
            &directory.0,
            LocalConfig::default().with_max_blob_bytes(1024 * 1024),
        )
        .unwrap();
        assert_eq!(
            restarted.active_manifest_digest().unwrap(),
            Some(old_digest),
            "{point:?}"
        );
        assert_blob_option_eq(
            restarted.active_state_reference().unwrap().as_ref(),
            Some(&old_state),
            format!("{point:?}"),
        );
        let state = restarted.inner.state.lock().unwrap();
        assert!(state.last_known_good_manifest.is_none(), "{point:?}");
        assert!(state.last_known_good_state.is_none(), "{point:?}");
    }
}
