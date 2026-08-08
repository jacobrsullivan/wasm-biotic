use aiaf_v1::execution::{
    ActorKind, AgendaItem, ApprovalClass, ApprovalDecision, AuthorityClass, CapabilityEnvelope,
    CapabilityWorld, CapabilityWorldGrant, ComponentBuildOutput, ComponentBuildRequest,
    ComponentExecutionContext, ComponentImportBinding, DurableArtifactStore, EventFamily,
    ExecutionEvent, ExecutionSession, ExecutionSessionHeader, FailureBudget, GenerationManifest,
    IsolationProfile, MemoryScope, MemoryStore, OwnershipBoundary, OwnershipMode, PointerIndex,
    ReplayableRuntimeState, ShellEvidencePacket, ShellSessionBundle, ShellWorkspaceView,
    TaskArtifact, TaskGraph, TaskState, TopicBundle, TopicBundleClass, TranscriptSlice,
    V4ShellEvidenceBundle, V4SupervisoryShellBundle, V4SupervisoryShellCompletionEvidence,
    V4SupervisoryShellCompletionGate, assemble_shell_evidence_packet, build_component_package,
    build_shell_workspace_view, complete_shell_orchestration, dispatch_shell_session,
    evaluate_v4_supervisory_shell_completion_gate, execute_active_shell_turn,
    finalize_shell_continuity_bundle, open_shell_session_bundle,
    record_shell_verified_memory_update, resume_shell_session_from_approval, start_shell_turn,
};
use std::env;
use std::path::PathBuf;
use std::process;

pub struct BuiltWorkerComponent {
    pub build: ComponentBuildOutput,
    pub context: ComponentExecutionContext,
}

pub struct FullV4FlowArtifacts {
    pub store: DurableArtifactStore,
    pub bundle: ShellSessionBundle,
    pub packet: ShellEvidencePacket,
    pub workspace: ShellWorkspaceView,
    pub evidence_bundle: V4ShellEvidenceBundle,
    pub final_bundle: V4SupervisoryShellBundle,
    pub gate: V4SupervisoryShellCompletionGate,
}

pub fn temp_store_root(suffix: &str) -> PathBuf {
    env::temp_dir().join(format!("aiaf-v4-{suffix}-{}", process::id()))
}

pub fn runtime_state() -> ReplayableRuntimeState {
    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: "session-v4-1".to_string(),
        actor_kind: ActorKind::Worker,
        actor_id: "worker-component-v4".to_string(),
        campaign_id: "campaign-v4-1".to_string(),
        epoch_id: "epoch-v4-1".to_string(),
        capability_envelope_ref: "envelope-v4-1".to_string(),
        parent_session_id: None,
    });
    aiaf_v1::execution::bind_session_ready(&mut session).unwrap();
    let task = TaskArtifact {
        state: TaskState::Ready,
        ..TaskArtifact::new("task-v4-1", "v4 shell root task")
    };
    let agenda_item = AgendaItem::new(
        "agenda-v4-1",
        "task-v4-1",
        "shell-task",
        Vec::new(),
        OwnershipBoundary {
            boundary_id: "boundary-v4-1".to_string(),
            resource_scope: "scope:shell".to_string(),
            mode: OwnershipMode::ExclusiveMutable,
            owner_actor_ref: "worker-component-v4".to_string(),
        },
    );
    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(PointerIndex {
        index_id: "pointer-index-v4-1".to_string(),
        scope: MemoryScope::Session("shell-session-v4-1".to_string()),
        entry_refs: vec!["bundle-v4-1".to_string()],
        contested_refs: Vec::new(),
        critical_refs: Vec::new(),
        governance_constraints: vec!["skeptical-memory".to_string()],
        open_task_refs: vec!["task-v4-1".to_string()],
        updated_at: "boot".to_string(),
    });
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: "bundle-v4-1".to_string(),
        bundle_class: TopicBundleClass::WorkspaceMap,
        scope: MemoryScope::Session("shell-session-v4-1".to_string()),
        summary: "workspace map".to_string(),
        evidence_refs: vec!["evidence:v4:workspace".to_string()],
        freshness_policy: "fresh".to_string(),
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-v4-1".to_string(),
        campaign_id: "campaign-v4-1".to_string(),
        epoch_id: "epoch-v4-1".to_string(),
        session_id: Some("session-v4-1".to_string()),
        task_id: Some("task-v4-1".to_string()),
        referenced_artifacts: vec!["bundle-v4-1".to_string()],
        summary: "memory retrieval slice".to_string(),
        excerpts: vec!["retrieve the bounded workspace map".to_string()],
    });
    ReplayableRuntimeState::new(
        session,
        task,
        TaskGraph::new("task-v4-1", vec![agenda_item]),
        memory_store,
        None,
        vec![ExecutionEvent::new(
            "event-v4-bootstrap",
            EventFamily::ShellSessionEvent,
            "campaign-v4-1",
            "epoch-v4-1",
            "session-v4-1",
            None,
            Some("task-v4-1".to_string()),
            "v4 shell runtime bootstrapped",
        )],
    )
}

fn manifest(build_id: &str) -> GenerationManifest {
    GenerationManifest::new(
        format!("generation-{build_id}"),
        None,
        "package:aiaf/supervisor@v4",
        "aiaf-supervisor-v4",
        vec![format!("src:{build_id}")],
        vec!["policy:bounded-single-factory".to_string()],
        vec![format!("input:{build_id}")],
        format!("manifest for {build_id}"),
    )
    .unwrap()
}

pub fn approval_component() -> BuiltWorkerComponent {
    let build = build_component_package(ComponentBuildRequest {
        build_id: "build-v4-approval".to_string(),
        manifest: manifest("approval"),
        wit_source:
            "world aiaf-supervisor-v4 { import approval-request: func(); export request-approval: func(); }"
                .to_string(),
        component_source: r#"
            (component
                (import "approval-request" (func $approval))
                (core func $approval-core (canon lower (func $approval)))
                (core module $m
                    (import "" "approval-request" (func $approval))
                    (func (export "request-approval")
                        call $approval))
                (core instance $i (instantiate $m
                    (with "" (instance
                        (export "approval-request" (func $approval-core))))))
                (func $request-approval (canon lift (core func $i "request-approval")))
                (export "request-approval" (func $request-approval)))
        "#.to_string(),
        required_capability_world_refs: vec!["world:approval".to_string()],
    })
    .unwrap();
    let context = ComponentExecutionContext {
        capability_envelope: CapabilityEnvelope {
            envelope_id: "envelope-v4-approval".to_string(),
            actor_scope: "worker-component-v4".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::ApprovalGateway,
                allowed_operations: vec!["request-approval".to_string()],
                default_authority_class: AuthorityClass::CampaignControl,
                default_approval_class: ApprovalClass::AutoAllowed,
                operation_approval_overrides: Vec::new(),
            }],
            authority_ceiling: AuthorityClass::CampaignControl,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec!["scope:approval".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: None,
            epoch_scope: None,
        },
        import_bindings: vec![ComponentImportBinding {
            import_name: "approval-request".to_string(),
            world: CapabilityWorld::ApprovalGateway,
            operation: "request-approval".to_string(),
            resource_scope: "scope:approval".to_string(),
            required_authority_class: AuthorityClass::CampaignControl,
        }],
    };
    BuiltWorkerComponent { build, context }
}

pub fn memory_component() -> BuiltWorkerComponent {
    let build = build_component_package(ComponentBuildRequest {
        build_id: "build-v4-memory".to_string(),
        manifest: manifest("memory"),
        wit_source:
            "world aiaf-supervisor-v4 { import memory-fetch: func(); export retrieve-memory: func(); }"
                .to_string(),
        component_source: r#"
            (component
                (import "memory-fetch" (func $memory))
                (core func $memory-core (canon lower (func $memory)))
                (core module $m
                    (import "" "memory-fetch" (func $memory))
                    (func (export "retrieve-memory")
                        call $memory))
                (core instance $i (instantiate $m
                    (with "" (instance
                        (export "memory-fetch" (func $memory-core))))))
                (func $retrieve-memory (canon lift (core func $i "retrieve-memory")))
                (export "retrieve-memory" (func $retrieve-memory)))
        "#.to_string(),
        required_capability_world_refs: vec!["world:memory".to_string()],
    })
    .unwrap();
    let context = ComponentExecutionContext {
        capability_envelope: CapabilityEnvelope {
            envelope_id: "envelope-v4-memory".to_string(),
            actor_scope: "worker-component-v4".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::MemoryAccess,
                allowed_operations: vec!["retrieve-topic".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::AutoAllowed,
                operation_approval_overrides: Vec::new(),
            }],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec!["pointer-index-v4-1".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: None,
            epoch_scope: None,
        },
        import_bindings: vec![ComponentImportBinding {
            import_name: "memory-fetch".to_string(),
            world: CapabilityWorld::MemoryAccess,
            operation: "retrieve-topic".to_string(),
            resource_scope: "pointer-index-v4-1".to_string(),
            required_authority_class: AuthorityClass::Observe,
        }],
    };
    BuiltWorkerComponent { build, context }
}

pub fn complete_component() -> BuiltWorkerComponent {
    let build = build_component_package(ComponentBuildRequest {
        build_id: "build-v4-complete".to_string(),
        manifest: manifest("complete"),
        wit_source:
            "world aiaf-supervisor-v4 { import task-complete: func(); export complete-task: func(); }"
                .to_string(),
        component_source: r#"
            (component
                (import "task-complete" (func $complete))
                (core func $complete-core (canon lower (func $complete)))
                (core module $m
                    (import "" "task-complete" (func $complete))
                    (func (export "complete-task")
                        call $complete))
                (core instance $i (instantiate $m
                    (with "" (instance
                        (export "task-complete" (func $complete-core))))))
                (func $complete-task (canon lift (core func $i "complete-task")))
                (export "complete-task" (func $complete-task)))
        "#.to_string(),
        required_capability_world_refs: vec!["world:task".to_string()],
    })
    .unwrap();
    let context = ComponentExecutionContext {
        capability_envelope: CapabilityEnvelope {
            envelope_id: "envelope-v4-task".to_string(),
            actor_scope: "worker-component-v4".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::CampaignControl,
                allowed_operations: vec!["complete-task".to_string()],
                default_authority_class: AuthorityClass::CampaignControl,
                default_approval_class: ApprovalClass::AutoAllowed,
                operation_approval_overrides: Vec::new(),
            }],
            authority_ceiling: AuthorityClass::CampaignControl,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec!["scope:task-v4-1".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: None,
            epoch_scope: None,
        },
        import_bindings: vec![ComponentImportBinding {
            import_name: "task-complete".to_string(),
            world: CapabilityWorld::CampaignControl,
            operation: "complete-task".to_string(),
            resource_scope: "scope:task-v4-1".to_string(),
            required_authority_class: AuthorityClass::CampaignControl,
        }],
    };
    BuiltWorkerComponent { build, context }
}

pub fn denied_component() -> BuiltWorkerComponent {
    let build = build_component_package(ComponentBuildRequest {
        build_id: "build-v4-denied".to_string(),
        manifest: manifest("denied"),
        wit_source:
            "world aiaf-supervisor-v4 { import memory-fetch: func(); export denied-memory: func(); }"
                .to_string(),
        component_source: r#"
            (component
                (import "memory-fetch" (func $memory))
                (core func $memory-core (canon lower (func $memory)))
                (core module $m
                    (import "" "memory-fetch" (func $memory))
                    (func (export "denied-memory")
                        call $memory))
                (core instance $i (instantiate $m
                    (with "" (instance
                        (export "memory-fetch" (func $memory-core))))))
                (func $denied-memory (canon lift (core func $i "denied-memory")))
                (export "denied-memory" (func $denied-memory)))
        "#.to_string(),
        required_capability_world_refs: vec!["world:memory".to_string()],
    })
    .unwrap();
    let context = ComponentExecutionContext {
        capability_envelope: CapabilityEnvelope {
            envelope_id: "envelope-v4-denied".to_string(),
            actor_scope: "worker-component-v4".to_string(),
            world_grants: vec![CapabilityWorldGrant {
                world: CapabilityWorld::MemoryAccess,
                allowed_operations: vec!["retrieve-topic".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::Forbidden,
                operation_approval_overrides: Vec::new(),
            }],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            allowed_resource_scopes: vec!["pointer-index-v4-1".to_string()],
            approval_overrides: Vec::new(),
            quota_policy: None,
            campaign_scope: None,
            epoch_scope: None,
        },
        import_bindings: vec![ComponentImportBinding {
            import_name: "memory-fetch".to_string(),
            world: CapabilityWorld::MemoryAccess,
            operation: "retrieve-topic".to_string(),
            resource_scope: "pointer-index-v4-1".to_string(),
            required_authority_class: AuthorityClass::Observe,
        }],
    };
    BuiltWorkerComponent { build, context }
}

pub fn run_full_v4_flow(root: PathBuf) -> FullV4FlowArtifacts {
    let store = DurableArtifactStore::bootstrap(root).unwrap();
    let approval = approval_component();
    let memory = memory_component();
    let complete = complete_component();

    let mut failure_budget = FailureBudget::default();
    let mut bundle = open_shell_session_bundle(
        "shell-session-v4-1",
        "worker-component-v4",
        Some("agenda-v4-1".to_string()),
        runtime_state(),
        &failure_budget,
    )
    .unwrap();
    dispatch_shell_session(&mut bundle, "agenda-v4-1").unwrap();

    start_shell_turn(&mut bundle, "shell-turn-v4-approval", "request-approval").unwrap();
    let approval_execution = execute_active_shell_turn(
        &mut bundle,
        &approval.build.component_bytes,
        &approval.context,
        &mut failure_budget,
    )
    .unwrap();
    let approval_request = approval_execution.approval_request.unwrap();
    resume_shell_session_from_approval(
        &mut bundle,
        &ApprovalDecision::granted(
            approval_request.approval_request_id.clone(),
            "campaign-v4-1",
            "epoch-v4-1",
            "session-v4-1",
            "task-v4-1",
            approval_request.action_ref.clone(),
            "operator-v4",
            approval_request.scope_ref.clone(),
            Some("resume shell".to_string()),
        ),
        "operator-v4",
    )
    .unwrap();

    start_shell_turn(&mut bundle, "shell-turn-v4-memory", "retrieve-memory").unwrap();
    execute_active_shell_turn(
        &mut bundle,
        &memory.build.component_bytes,
        &memory.context,
        &mut failure_budget,
    )
    .unwrap();
    let memory_trace = bundle
        .memory_retrieval_traces
        .last()
        .unwrap()
        .trace_id
        .clone();
    let contradiction = bundle.runtime_state.memory_store.register_contradiction(
        "contradiction-v4-1",
        vec![memory_trace.clone()],
        "shell-memory-verify",
        Some("pointer-index-v4-1"),
    );
    assert!(
        bundle
            .runtime_state
            .memory_store
            .resolve_contradiction(&contradiction.contradiction_id, Some("pointer-index-v4-1"))
    );
    record_shell_verified_memory_update(
        &mut bundle,
        "verified-memory-v4-1",
        "pointer-index-v4-1",
        TopicBundleClass::GovernanceNotes,
        "verified shell completion memory",
        vec![memory_trace],
        vec!["verification:v4:1".to_string()],
    )
    .unwrap();
    finalize_shell_continuity_bundle(
        &mut bundle,
        "continuity-v4-1",
        "pointer-index-v4-1",
        vec![contradiction.contradiction_id.clone()],
    )
    .unwrap();

    start_shell_turn(&mut bundle, "shell-turn-v4-complete", "complete-task").unwrap();
    execute_active_shell_turn(
        &mut bundle,
        &complete.build.component_bytes,
        &complete.context,
        &mut failure_budget,
    )
    .unwrap();
    complete_shell_orchestration(&mut bundle, "agenda-v4-1").unwrap();

    let packet = assemble_shell_evidence_packet(
        "packet-v4-1",
        bundle.shell_session.shell_session_id.clone(),
        &bundle,
    );
    let workspace = build_shell_workspace_view(&packet, &bundle);
    let evidence_bundle = V4ShellEvidenceBundle {
        shell_session_bundle: bundle.clone(),
        shell_evidence_packet: packet.clone(),
    };
    let gate = evaluate_v4_supervisory_shell_completion_gate(
        "gate-v4-1",
        V4SupervisoryShellCompletionEvidence {
            shell_session_bundle_ref: bundle.shell_session.shell_session_id.clone(),
            shell_evidence_packet_ref: packet.packet_id.clone(),
            shell_session_ref: bundle.shell_session.shell_session_id.clone(),
            pause_resume_refs: packet.pause_resume_refs.clone(),
            membrane_trace_refs: packet.membrane_trace_refs.clone(),
            memory_trace_refs: packet.memory_trace_refs.clone(),
            verified_memory_refs: packet.verified_memory_refs.clone(),
            orchestration_trace_refs: packet.orchestration_trace_refs.clone(),
        },
    );
    let final_bundle = V4SupervisoryShellBundle {
        shell_session_bundle: bundle.clone(),
        shell_evidence_packet: packet.clone(),
        completion_gate: gate.clone(),
    };

    store.persist_shell_session_bundle(&bundle).unwrap();
    store
        .persist_v4_shell_evidence_bundle(&evidence_bundle)
        .unwrap();
    store
        .persist_v4_supervisory_shell_bundle(&final_bundle)
        .unwrap();

    FullV4FlowArtifacts {
        store,
        bundle,
        packet,
        workspace,
        evidence_bundle,
        final_bundle,
        gate,
    }
}
