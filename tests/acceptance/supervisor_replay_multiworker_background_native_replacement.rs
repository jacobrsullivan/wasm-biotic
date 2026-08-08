use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;

use aiaf_v1::execution::{
    ActorKind, AgendaItem, AgendaStatus, AuditRecord, AuditRecordClass, AuthorityClass,
    BackgroundCampaign, CapabilityEnvelope, CapabilityImportTarget, CapabilityOperationRequest,
    CapabilityWorld, CapabilityWorldGrant, ConsolidationJob, ConsolidationJobStatus,
    DurableArtifactStore, EventFamily, ExecutionEvent, ExecutionSession, ExecutionSessionHeader,
    FailureBudget, GovernancePolicyClass, IsolationProfile, MemoryArtifact, MemoryScope,
    MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, MessageArtifact, MessageArtifactClass,
    MessageArtifactStatus, NativeReplacementTier, NativeSufficiencyGate, NormalizedProposal,
    OwnershipBoundary, OwnershipMode, PointerIndex, ProposalFamily, ReplayableRuntimeState,
    StopCondition, SynthesisClosureDecision, SynthesisHandoff, TaskArtifact, TaskGraph, TickSource,
    TopicBundle, TopicBundleClass, TranscriptSlice, TranscriptSliceQuery, WorkerCard,
    WorkerDispatch, WorkerDispatchCheckpointOutcome, WorkerRegistry, WorkerResult, WorkerRole,
    accept_worker_result, bind_session_ready, checkpointed_dispatch_to_worker,
    compare_transcript_retrieval, complete_task, conclude_turn_ready, create_rollback_handle,
    evaluate_native_sufficiency, execute_rollback, imported_transcript_retrieval_from_store,
    native_transcript_retrieval_from_memory, start_turn,
    validate_background_resume_with_runtime_state,
};

fn temp_store_root(name: &str) -> PathBuf {
    env::temp_dir().join(format!("rc02-aiaf-acceptance-{name}-{}", process::id()))
}

fn execution_event(
    event_id: &str,
    family: EventFamily,
    session: &ExecutionSession,
    task_id: Option<&str>,
    detail: &str,
) -> ExecutionEvent {
    ExecutionEvent::new(
        event_id,
        family,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        session
            .current_turn
            .as_ref()
            .map(|turn| turn.turn_id.clone()),
        task_id.map(str::to_string),
        detail.to_string(),
    )
}

fn capability_envelope(
    envelope_id: &str,
    actor_scope: &str,
    world_grants: Vec<CapabilityWorldGrant>,
    allowed_resource_scopes: Vec<&str>,
) -> CapabilityEnvelope {
    CapabilityEnvelope {
        envelope_id: envelope_id.to_string(),
        actor_scope: actor_scope.to_string(),
        world_grants,
        authority_ceiling: AuthorityClass::Observe,
        isolation_profile: IsolationProfile::ArtifactSandbox,
        allowed_resource_scopes: allowed_resource_scopes
            .into_iter()
            .map(str::to_string)
            .collect(),
        approval_overrides: Vec::new(),
        quota_policy: None,
        campaign_scope: Some("campaign-rc02".to_string()),
        epoch_scope: Some("epoch-1".to_string()),
    }
}

fn world_grant(world: CapabilityWorld, operations: Vec<&str>) -> CapabilityWorldGrant {
    CapabilityWorldGrant {
        world,
        allowed_operations: operations.into_iter().map(str::to_string).collect(),
        default_authority_class: AuthorityClass::Observe,
        default_approval_class: aiaf_v1::execution::ApprovalClass::AutoAllowed,
        operation_approval_overrides: Vec::new(),
    }
}

fn worker_card(
    worker_id: &str,
    worker_role: WorkerRole,
    task_kind: &str,
    required_worlds: Vec<CapabilityWorld>,
    result_contract: &str,
) -> WorkerCard {
    WorkerCard {
        worker_id: worker_id.to_string(),
        worker_role,
        supported_task_kinds: vec![task_kind.to_string()],
        required_worlds,
        authority_ceiling: AuthorityClass::Observe,
        isolation_profile: IsolationProfile::ArtifactSandbox,
        result_contract: result_contract.to_string(),
        max_concurrency: 1,
    }
}

fn worker_dispatch(
    session: &ExecutionSession,
    task_id: &str,
    worker_card: &WorkerCard,
    capability_envelope_ref: &str,
    dispatch_id: &str,
    worker_task_ref: &str,
    payload_summary: &str,
    requested_capabilities: Vec<CapabilityOperationRequest>,
    referenced_artifacts: Vec<String>,
) -> WorkerDispatch {
    WorkerDispatch {
        dispatch_id: dispatch_id.to_string(),
        task_id: task_id.to_string(),
        parent_session_id: session.header.session_id.clone(),
        worker_id: worker_card.worker_id.clone(),
        worker_task_ref: worker_task_ref.to_string(),
        capability_envelope_ref: capability_envelope_ref.to_string(),
        requested_capabilities,
        dispatch_message: MessageArtifact {
            message_id: format!("message-{dispatch_id}"),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task_id.to_string(),
            sender_actor_ref: session.header.session_id.clone(),
            receiver_actor_ref: worker_card.worker_id.clone(),
            message_class: MessageArtifactClass::DispatchMessage,
            payload_summary: payload_summary.to_string(),
            referenced_artifacts,
            status: MessageArtifactStatus::Sent,
        },
    }
}

fn worker_result(
    session: &ExecutionSession,
    task_id: &str,
    worker_card: &WorkerCard,
    dispatch: &WorkerDispatch,
    result_ref: &str,
    summary: &str,
) -> WorkerResult {
    WorkerResult {
        dispatch_id: dispatch.dispatch_id.clone(),
        worker_id: worker_card.worker_id.clone(),
        worker_task_ref: dispatch.worker_task_ref.clone(),
        result_ref: result_ref.to_string(),
        summary: summary.to_string(),
        result_message: MessageArtifact {
            message_id: format!("message-result-{result_ref}"),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task_id.to_string(),
            sender_actor_ref: worker_card.worker_id.clone(),
            receiver_actor_ref: session.header.session_id.clone(),
            message_class: MessageArtifactClass::ResultMessage,
            payload_summary: summary.to_string(),
            referenced_artifacts: vec![result_ref.to_string()],
            status: MessageArtifactStatus::Received,
        },
    }
}

#[test]
fn supervisor_replay_multiworker_background_native_replacement_acceptance() {
    let root = temp_store_root("multiworker");
    let _ = fs::remove_dir_all(&root);
    let store = DurableArtifactStore::bootstrap(&root).unwrap();

    let pointer_index_id = "pointer-index-rc02".to_string();
    let root_task_id = "task-root-rc02".to_string();
    let observe_task_id = "task-observe".to_string();
    let evaluate_task_id = "task-evaluate".to_string();
    let merge_task_id = "task-merge".to_string();

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(PointerIndex {
        index_id: pointer_index_id.clone(),
        scope: MemoryScope::Campaign("campaign-rc02".to_string()),
        entry_refs: vec![
            "bundle-legacy-operating-notes".to_string(),
            "transient:observe-tool-dump".to_string(),
        ],
        contested_refs: Vec::new(),
        critical_refs: vec!["bundle-legacy-operating-notes".to_string()],
        governance_constraints: vec![
            "scheduled resume requires checkpoint-backed state".to_string(),
            "consolidation trigger must stay inside campaign scope".to_string(),
        ],
        open_task_refs: vec![root_task_id.clone()],
        updated_at: "seed-load".to_string(),
    });
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: "bundle-legacy-operating-notes".to_string(),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: MemoryScope::Campaign("campaign-rc02".to_string()),
        summary: "Legacy operating note for bounded workspace review.".to_string(),
        evidence_refs: vec!["slice-legacy-observe".to_string()],
        freshness_policy: "carry-forward-until-verified".to_string(),
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-legacy-observe".to_string(),
        campaign_id: "campaign-rc02".to_string(),
        epoch_id: "epoch-1".to_string(),
        session_id: Some("session-supervisor-1".to_string()),
        task_id: Some(observe_task_id.clone()),
        referenced_artifacts: vec!["bundle-legacy-operating-notes".to_string()],
        summary: "Legacy workspace observe baseline".to_string(),
        excerpts: vec!["workspace observe baseline still applies".to_string()],
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-legacy-evaluate".to_string(),
        campaign_id: "campaign-rc02".to_string(),
        epoch_id: "epoch-1".to_string(),
        session_id: Some("session-supervisor-1".to_string()),
        task_id: Some(evaluate_task_id.clone()),
        referenced_artifacts: vec!["bundle-legacy-operating-notes".to_string()],
        summary: "Legacy history evaluation baseline".to_string(),
        excerpts: vec!["history evaluation baseline still applies".to_string()],
    });

    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: "session-supervisor-1".to_string(),
        actor_kind: ActorKind::Supervisor,
        actor_id: "supervisor-alpha".to_string(),
        campaign_id: "campaign-rc02".to_string(),
        epoch_id: "epoch-1".to_string(),
        capability_envelope_ref: "envelope-supervisor-root".to_string(),
        parent_session_id: None,
    });
    let mut task = TaskArtifact::new(
        root_task_id.clone(),
        "Replayable multi-worker governed RC02 campaign",
    );
    let mut task_graph = TaskGraph::new(
        root_task_id.clone(),
        vec![
            AgendaItem::new(
                "agenda-observe",
                observe_task_id.clone(),
                "workspace-observe",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-observe".to_string(),
                    resource_scope: "workspace-root".to_string(),
                    mode: OwnershipMode::ReadOnlyFanOut,
                    owner_actor_ref: session.header.session_id.clone(),
                },
            ),
            AgendaItem::new(
                "agenda-evaluate",
                evaluate_task_id.clone(),
                "history-evaluate",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-evaluate".to_string(),
                    resource_scope: "campaign-memory".to_string(),
                    mode: OwnershipMode::ReadOnlyFanOut,
                    owner_actor_ref: session.header.session_id.clone(),
                },
            ),
            AgendaItem::new(
                "agenda-merge",
                merge_task_id.clone(),
                "merge-findings",
                vec![observe_task_id.clone(), evaluate_task_id.clone()],
                OwnershipBoundary {
                    boundary_id: "boundary-merge".to_string(),
                    resource_scope: "campaign-memory".to_string(),
                    mode: OwnershipMode::MergeRequired,
                    owner_actor_ref: session.header.session_id.clone(),
                },
            ),
        ],
    );
    let mut event_log = Vec::new();
    let background_campaign = BackgroundCampaign {
        campaign_id: session.header.campaign_id.clone(),
        objective: "resume bounded replayable RC02 campaign".to_string(),
        authority_ceiling: AuthorityClass::Observe,
        allowed_tick_sources: vec![TickSource::ScheduledTimer, TickSource::ConsolidationTrigger],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
        audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
    };

    let observe_worker = worker_card(
        "worker-observer-1",
        WorkerRole::ObserverWorker,
        "workspace-observe",
        vec![
            CapabilityWorld::WorkspaceObserve,
            CapabilityWorld::MemoryAccess,
        ],
        "workspace-observe-result",
    );
    let evaluate_worker = worker_card(
        "worker-evaluator-1",
        WorkerRole::EvaluatorWorker,
        "history-evaluate",
        vec![CapabilityWorld::MemoryAccess],
        "history-evaluate-result",
    );
    let merge_worker = worker_card(
        "worker-consolidator-1",
        WorkerRole::ConsolidatorWorker,
        "merge-findings",
        vec![CapabilityWorld::MemoryAccess],
        "merge-findings-result",
    );
    let observe_envelope = capability_envelope(
        "envelope-worker-observe",
        "worker-observer-1",
        vec![
            world_grant(CapabilityWorld::WorkerMessaging, vec!["dispatch", "result"]),
            world_grant(
                CapabilityWorld::WorkspaceObserve,
                vec!["search", "read-file"],
            ),
            world_grant(
                CapabilityWorld::MemoryAccess,
                vec!["read-pointer-index", "read-transcript-slice"],
            ),
        ],
        vec!["worker-channel", "workspace-root", "pointer-index-store"],
    );
    let evaluate_envelope = capability_envelope(
        "envelope-worker-evaluate",
        "worker-evaluator-1",
        vec![
            world_grant(CapabilityWorld::WorkerMessaging, vec!["dispatch", "result"]),
            world_grant(
                CapabilityWorld::MemoryAccess,
                vec![
                    "read-pointer-index",
                    "read-transcript-slice",
                    "read-topic-bundle",
                ],
            ),
        ],
        vec!["worker-channel", "campaign-memory", "pointer-index-store"],
    );
    let merge_envelope = capability_envelope(
        "envelope-worker-merge",
        "worker-consolidator-1",
        vec![
            world_grant(CapabilityWorld::WorkerMessaging, vec!["dispatch", "result"]),
            world_grant(
                CapabilityWorld::MemoryAccess,
                vec!["read-transcript-slice", "read-topic-bundle"],
            ),
        ],
        vec!["worker-channel", "campaign-memory"],
    );

    let mut worker_registry = WorkerRegistry::default();
    worker_registry.register(observe_worker.clone());
    worker_registry.register(evaluate_worker.clone());
    worker_registry.register(merge_worker.clone());

    bind_session_ready(&mut session).unwrap();
    event_log.push(execution_event(
        "event-session-ready",
        EventFamily::SessionLifecycleEvent,
        &session,
        Some(&root_task_id),
        "session entered ready state for RC02 campaign",
    ));

    let _turn_one = start_turn(&mut session, &mut task, "turn-1").unwrap();
    let observe_route = worker_registry
        .select_worker(
            "workspace-observe",
            &observe_worker.required_worlds,
            &observe_worker.authority_ceiling,
            &observe_worker.isolation_profile,
        )
        .unwrap();
    assert_eq!(observe_route.worker_id, observe_worker.worker_id);
    task_graph
        .mark_dispatched("agenda-observe", observe_route.worker_id.clone())
        .unwrap();
    let observe_dispatch = worker_dispatch(
        &session,
        &observe_task_id,
        &observe_worker,
        &observe_envelope.envelope_id,
        "dispatch-observe-1",
        "worker-task-observe-1",
        "bounded workspace observe slice",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkspaceObserve,
                operation: "search".to_string(),
                resource_scope: "workspace-root".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-pointer-index".to_string(),
                resource_scope: "pointer-index-store".to_string(),
            },
        ],
        vec![pointer_index_id.clone()],
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(observe_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut session,
            &mut task,
            &observe_worker,
            &observe_envelope,
            &observe_dispatch,
            "checkpoint-observe-1",
            vec![
                NormalizedProposal::new(
                    ProposalFamily::SynthesisSummary,
                    "Observe workspace before evaluation".to_string(),
                    Some(observe_task_id.clone()),
                )
                .unwrap(),
            ],
            vec![pointer_index_id.clone()],
            FailureBudget::default().snapshot(),
            vec![observe_dispatch.dispatch_id.clone()],
        )
        .unwrap()
    else {
        panic!("observe dispatch should not require approval");
    };
    let observe_checkpoint_artifact_id = memory_store.persist_checkpoint_artifact(
        "memory-checkpoint-observe-1",
        observe_checkpoint.clone(),
        "observe worker checkpoint persisted",
    );
    event_log.push(execution_event(
        "event-observe-dispatch",
        EventFamily::WorkerDispatchEvent,
        &session,
        Some(&observe_task_id),
        "observe worker dispatched",
    ));
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(observe_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();

    let observe_result = worker_result(
        &session,
        &observe_task_id,
        &observe_worker,
        &observe_dispatch,
        "observe-result-1",
        "bounded observe result captured from workspace",
    );
    accept_worker_result(&mut session, &mut task, &observe_result).unwrap();
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-observe-result".to_string(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: Some(observe_task_id.clone()),
        referenced_artifacts: vec![
            observe_result.result_ref.clone(),
            observe_checkpoint_artifact_id.clone(),
        ],
        summary: observe_result.summary.clone(),
        excerpts: vec!["bounded observe result".to_string()],
    });

    let _turn_two = start_turn(&mut session, &mut task, "turn-2").unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-observe",
            &SynthesisHandoff {
                handoff_id: "handoff-observe-1".to_string(),
                task_id: observe_task_id.clone(),
                worker_output_refs: vec![observe_result.result_ref.clone()],
                supervisor_summary: "observe output accepted for replayable campaign".to_string(),
                next_action: "continue".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    task.record_output_ref(observe_result.result_ref.clone());
    conclude_turn_ready(&mut session, &mut task).unwrap();
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(observe_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();

    let replayed_state = store.load_runtime_state().unwrap();
    replayed_state.validate_replayability().unwrap();
    assert_eq!(
        replayed_state.session.state,
        aiaf_v1::execution::ExecutionSessionState::Ready
    );
    assert_eq!(
        replayed_state.count_events_in_family(EventFamily::WorkerDispatchEvent),
        1
    );
    assert_eq!(
        replayed_state
            .task_graph
            .agenda_item("agenda-observe")
            .unwrap()
            .status,
        AgendaStatus::Completed
    );
    assert_eq!(
        store
            .load_runtime_state_for_checkpoint("checkpoint-observe-1")
            .unwrap()
            .session
            .state,
        aiaf_v1::execution::ExecutionSessionState::AwaitingWorkerResult
    );
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ScheduledTimer,
        &replayed_state,
        &[],
        &[],
        &root_task_id,
    )
    .unwrap();

    session = replayed_state.session;
    task = replayed_state.root_task;
    task_graph = replayed_state.task_graph;
    memory_store = replayed_state.memory_store;
    event_log = replayed_state.event_log;
    let background_resume_audit = AuditRecord::new(
        "audit-background-resume-1",
        AuditRecordClass::GovernanceAuditRecord,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(root_task_id.clone()),
        "checkpoint-observe-1",
        "scheduled timer replay validated for RC02 continuation",
    );
    memory_store.append(MemoryArtifact::audit_record(
        "memory-audit-background-resume-1",
        background_resume_audit,
    ));
    event_log.push(execution_event(
        "event-background-resume",
        EventFamily::GovernanceDecisionEvent,
        &session,
        Some(&root_task_id),
        "scheduled timer replay validated",
    ));

    let _turn_three = start_turn(&mut session, &mut task, "turn-3").unwrap();
    let evaluate_route = worker_registry
        .select_worker(
            "history-evaluate",
            &evaluate_worker.required_worlds,
            &evaluate_worker.authority_ceiling,
            &evaluate_worker.isolation_profile,
        )
        .unwrap();
    assert_eq!(evaluate_route.worker_id, evaluate_worker.worker_id);
    task_graph
        .mark_dispatched("agenda-evaluate", evaluate_route.worker_id.clone())
        .unwrap();
    let evaluate_dispatch = worker_dispatch(
        &session,
        &evaluate_task_id,
        &evaluate_worker,
        &evaluate_envelope.envelope_id,
        "dispatch-evaluate-1",
        "worker-task-evaluate-1",
        "bounded history evaluation slice",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-transcript-slice".to_string(),
                resource_scope: "campaign-memory".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-pointer-index".to_string(),
                resource_scope: "pointer-index-store".to_string(),
            },
        ],
        vec![
            pointer_index_id.clone(),
            "slice-legacy-evaluate".to_string(),
        ],
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(evaluate_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut session,
            &mut task,
            &evaluate_worker,
            &evaluate_envelope,
            &evaluate_dispatch,
            "checkpoint-evaluate-1",
            Vec::new(),
            vec![pointer_index_id.clone()],
            FailureBudget::default().snapshot(),
            vec![evaluate_dispatch.dispatch_id.clone()],
        )
        .unwrap()
    else {
        panic!("evaluate dispatch should not require approval");
    };
    let evaluate_checkpoint_artifact_id = memory_store.persist_checkpoint_artifact(
        "memory-checkpoint-evaluate-1",
        evaluate_checkpoint.clone(),
        "evaluate worker checkpoint persisted",
    );
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(evaluate_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();
    let evaluate_snapshot_session = session.clone();
    let evaluate_snapshot_task = task.clone();
    let evaluate_snapshot_task_graph = task_graph.clone();
    let evaluate_snapshot_event_log = event_log.clone();

    let evaluate_result = worker_result(
        &session,
        &evaluate_task_id,
        &evaluate_worker,
        &evaluate_dispatch,
        "evaluate-result-1",
        "bounded evaluation result reconciled with prior context",
    );
    accept_worker_result(&mut session, &mut task, &evaluate_result).unwrap();
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-evaluate-result".to_string(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: Some(evaluate_task_id.clone()),
        referenced_artifacts: vec![
            evaluate_result.result_ref.clone(),
            evaluate_checkpoint_artifact_id.clone(),
        ],
        summary: evaluate_result.summary.clone(),
        excerpts: vec!["bounded evaluation result".to_string()],
    });

    let _turn_four = start_turn(&mut session, &mut task, "turn-4").unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-evaluate",
            &SynthesisHandoff {
                handoff_id: "handoff-evaluate-1".to_string(),
                task_id: evaluate_task_id.clone(),
                worker_output_refs: vec![evaluate_result.result_ref.clone()],
                supervisor_summary: "evaluation output accepted for merge".to_string(),
                next_action: "continue".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    task.record_output_ref(evaluate_result.result_ref.clone());
    let contradiction = memory_store.register_contradiction(
        "contradiction-1",
        vec![
            observe_result.result_ref.clone(),
            evaluate_result.result_ref.clone(),
        ],
        "resolve during merge synthesis",
        Some(&pointer_index_id),
    );
    assert_eq!(contradiction.contradiction_id, "contradiction-1");
    assert!(memory_store.resolve_contradiction("contradiction-1", Some(&pointer_index_id)));
    task_graph.refresh_ready_states(&[observe_task_id.clone(), evaluate_task_id.clone()]);
    assert_eq!(
        task_graph.agenda_item("agenda-merge").unwrap().status,
        AgendaStatus::Ready
    );
    conclude_turn_ready(&mut session, &mut task).unwrap();
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(evaluate_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();

    let _turn_five = start_turn(&mut session, &mut task, "turn-5").unwrap();
    let merge_route = worker_registry
        .select_worker(
            "merge-findings",
            &merge_worker.required_worlds,
            &merge_worker.authority_ceiling,
            &merge_worker.isolation_profile,
        )
        .unwrap();
    assert_eq!(merge_route.worker_id, merge_worker.worker_id);
    task_graph
        .mark_dispatched("agenda-merge", merge_route.worker_id.clone())
        .unwrap();
    let merge_dispatch = worker_dispatch(
        &session,
        &merge_task_id,
        &merge_worker,
        &merge_envelope.envelope_id,
        "dispatch-merge-1",
        "worker-task-merge-1",
        "bounded merge synthesis slice",
        vec![
            CapabilityOperationRequest {
                world: CapabilityWorld::WorkerMessaging,
                operation: "dispatch".to_string(),
                resource_scope: "worker-channel".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-topic-bundle".to_string(),
                resource_scope: "campaign-memory".to_string(),
            },
            CapabilityOperationRequest {
                world: CapabilityWorld::MemoryAccess,
                operation: "read-transcript-slice".to_string(),
                resource_scope: "campaign-memory".to_string(),
            },
        ],
        vec![
            "bundle-legacy-operating-notes".to_string(),
            "slice-observe-result".to_string(),
            "slice-evaluate-result".to_string(),
        ],
    );
    let WorkerDispatchCheckpointOutcome::Dispatched(merge_checkpoint) =
        checkpointed_dispatch_to_worker(
            &mut session,
            &mut task,
            &merge_worker,
            &merge_envelope,
            &merge_dispatch,
            "checkpoint-merge-1",
            Vec::new(),
            vec![pointer_index_id.clone()],
            FailureBudget::default().snapshot(),
            vec![merge_dispatch.dispatch_id.clone()],
        )
        .unwrap()
    else {
        panic!("merge dispatch should not require approval");
    };
    let merge_checkpoint_artifact_id = memory_store.persist_checkpoint_artifact(
        "memory-checkpoint-merge-1",
        merge_checkpoint.clone(),
        "merge worker checkpoint persisted",
    );
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(merge_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();

    let merge_result = worker_result(
        &session,
        &merge_task_id,
        &merge_worker,
        &merge_dispatch,
        "merge-result-1",
        "bounded merge result formed a single campaign summary",
    );
    accept_worker_result(&mut session, &mut task, &merge_result).unwrap();
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-merge-result".to_string(),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: Some(merge_task_id.clone()),
        referenced_artifacts: vec![
            merge_result.result_ref.clone(),
            merge_checkpoint_artifact_id.clone(),
        ],
        summary: merge_result.summary.clone(),
        excerpts: vec!["bounded merge result".to_string()],
    });

    let _turn_six = start_turn(&mut session, &mut task, "turn-6").unwrap();
    task_graph
        .apply_synthesis_handoff(
            "agenda-merge",
            &SynthesisHandoff {
                handoff_id: "handoff-merge-1".to_string(),
                task_id: merge_task_id.clone(),
                worker_output_refs: vec![merge_result.result_ref.clone()],
                supervisor_summary: "merge output accepted as campaign summary".to_string(),
                next_action: "complete-root-task".to_string(),
                closure_decision: SynthesisClosureDecision::Complete,
            },
        )
        .unwrap();
    task.record_output_ref(merge_result.result_ref.clone());
    memory_store.propose_memory_update(MemoryUpdateProposal {
        proposal_id: "memory-update-rc02-merge".to_string(),
        pointer_index_ref: Some(pointer_index_id.clone()),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        proposed_summary: "Merged observe and evaluate findings into a replayable operating note"
            .to_string(),
        evidence_refs: vec![
            observe_result.result_ref.clone(),
            evaluate_result.result_ref.clone(),
            merge_result.result_ref.clone(),
        ],
        verification_refs: vec![
            observe_checkpoint_artifact_id.clone(),
            evaluate_checkpoint_artifact_id.clone(),
            merge_checkpoint_artifact_id.clone(),
        ],
        status: MemoryUpdateStatus::Proposed,
    });
    let verified_bundle_id = memory_store
        .accept_memory_update(
            "memory-update-rc02-merge",
            "bundle-verified-merge-summary",
            "verified-by-three-checkpoints",
        )
        .unwrap();
    let consolidation_runtime_state = ReplayableRuntimeState::new(
        session.clone(),
        task.clone(),
        task_graph.clone(),
        memory_store.clone(),
        Some(merge_checkpoint.clone()),
        event_log.clone(),
    );
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ConsolidationTrigger,
        &consolidation_runtime_state,
        &[],
        &[],
        &root_task_id,
    )
    .unwrap();
    let consolidated_bundle_id = memory_store
        .run_consolidation_job(ConsolidationJob {
            job_id: "consolidation-1".to_string(),
            pointer_index_ref: pointer_index_id.clone(),
            input_bundle_refs: vec![
                "bundle-legacy-operating-notes".to_string(),
                verified_bundle_id.clone(),
            ],
            output_bundle_id: "bundle-consolidated-campaign-summary".to_string(),
            output_bundle_class: TopicBundleClass::CampaignOperatingNotes,
            output_scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
            output_summary: "Consolidated RC02 campaign summary bundle".to_string(),
            freshness_policy: "verified-replayable-summary".to_string(),
            status: ConsolidationJobStatus::Planned,
        })
        .unwrap();
    assert!(
        memory_store
            .load_pointer_index(&pointer_index_id)
            .unwrap()
            .critical_refs
            .iter()
            .any(|critical_ref| critical_ref == &merge_checkpoint_artifact_id)
    );
    task.record_output_ref(verified_bundle_id.clone());
    task.record_output_ref(consolidated_bundle_id.clone());
    complete_task(&mut session, &mut task).unwrap();
    event_log.push(execution_event(
        "event-task-complete",
        EventFamily::TaskLifecycleEvent,
        &session,
        Some(&root_task_id),
        "RC02 root task completed after merge synthesis",
    ));

    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(merge_checkpoint.clone()),
            event_log.clone(),
        ))
        .unwrap();

    let transcript_query = TranscriptSliceQuery {
        campaign_id: Some(session.header.campaign_id.clone()),
        search_term: Some("result".to_string()),
        ..TranscriptSliceQuery::default()
    };
    let imported = imported_transcript_retrieval_from_store(&store, &transcript_query).unwrap();
    let native = native_transcript_retrieval_from_memory(&memory_store, &transcript_query);
    let comparison = compare_transcript_retrieval(&imported, &native);
    let sufficiency_gate = NativeSufficiencyGate {
        target: CapabilityImportTarget::TranscriptRetrieval,
        required_tier: NativeReplacementTier::NativeCapabilitySurfaces,
        requires_exact_match: true,
    };
    assert!(
        comparison.matched,
        "native replacement comparison should match"
    );
    assert!(evaluate_native_sufficiency(&sufficiency_gate, &comparison));

    let native_replacement_audit = AuditRecord::new(
        "audit-native-replacement-1",
        AuditRecordClass::PromotionAuditRecord,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(root_task_id.clone()),
        "transcript-retrieval",
        "Native transcript retrieval matched imported durable retrieval",
    );
    memory_store.append(MemoryArtifact::audit_record(
        "memory-audit-native-replacement-1",
        native_replacement_audit,
    ));
    event_log.push(execution_event(
        "event-native-replacement",
        EventFamily::GovernanceDecisionEvent,
        &session,
        Some(&root_task_id),
        "native transcript retrieval passed shadow-match gate",
    ));
    let rollback_handle = create_rollback_handle(
        "rollback-evaluate-1",
        "campaign",
        "checkpoint-evaluate-1",
        vec!["reload evaluate checkpoint snapshot".to_string()],
        Vec::new(),
    );
    memory_store.append(MemoryArtifact::audit_record(
        "memory-audit-evaluate-checkpoint-rollback",
        AuditRecord::new(
            "audit-evaluate-checkpoint-rollback",
            AuditRecordClass::GovernanceAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(root_task_id.clone()),
            "checkpoint-evaluate-1",
            "evaluate checkpoint retained for rollback reconstruction",
        ),
    ));
    memory_store.append(MemoryArtifact::audit_record(
        "memory-audit-rollback-evaluate-1",
        AuditRecord::new(
            "audit-rollback-evaluate-1",
            AuditRecordClass::PromotionAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(root_task_id.clone()),
            rollback_handle.rollback_handle_id.clone(),
            "rollback handle retained for governed replay restoration",
        ),
    ));
    let evaluate_snapshot_path = root.join("snapshots/by-checkpoint/checkpoint-evaluate-1.json");
    let _ = fs::remove_file(&evaluate_snapshot_path);
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            evaluate_snapshot_session,
            evaluate_snapshot_task,
            evaluate_snapshot_task_graph,
            memory_store.clone(),
            Some(evaluate_checkpoint.clone()),
            evaluate_snapshot_event_log,
        ))
        .unwrap();
    store
        .persist_runtime_state(&ReplayableRuntimeState::new(
            session.clone(),
            task.clone(),
            task_graph.clone(),
            memory_store.clone(),
            Some(merge_checkpoint.clone()),
            event_log,
        ))
        .unwrap();
    let restored = execute_rollback(&rollback_handle, &store).unwrap();

    assert_eq!(
        session.state,
        aiaf_v1::execution::ExecutionSessionState::Completed
    );
    assert_eq!(task.state, aiaf_v1::execution::TaskState::Completed);
    assert_eq!(
        task_graph.agenda_item("agenda-merge").unwrap().status,
        AgendaStatus::Completed
    );
    assert!(
        memory_store
            .load_pointer_index(&pointer_index_id)
            .unwrap()
            .entry_refs
            .iter()
            .any(|entry_ref| entry_ref == &consolidated_bundle_id)
    );
    assert!(
        !memory_store
            .load_pointer_index(&pointer_index_id)
            .unwrap()
            .entry_refs
            .iter()
            .any(|entry_ref| entry_ref.starts_with("transient:"))
    );
    assert!(
        memory_store
            .consolidation_jobs
            .iter()
            .any(|job| job.job_id == "consolidation-1"
                && job.status == ConsolidationJobStatus::Completed)
    );
    assert_eq!(
        restored.session.state,
        aiaf_v1::execution::ExecutionSessionState::AwaitingWorkerResult
    );
    assert_eq!(
        restored
            .task_graph
            .agenda_item("agenda-observe")
            .unwrap()
            .status,
        AgendaStatus::Completed
    );
    assert_eq!(
        restored
            .task_graph
            .agenda_item("agenda-evaluate")
            .unwrap()
            .status,
        AgendaStatus::Dispatched
    );
    assert_eq!(
        restored
            .task_graph
            .agenda_item("agenda-merge")
            .unwrap()
            .status,
        AgendaStatus::PendingDependencies
    );
    let artifact_ids = store.artifact_ids().unwrap();
    assert!(
        artifact_ids
            .iter()
            .any(|artifact_id| artifact_id == "memory-checkpoint-observe-1")
    );
    assert!(
        artifact_ids
            .iter()
            .any(|artifact_id| artifact_id == "memory-checkpoint-evaluate-1")
    );
    assert!(
        artifact_ids
            .iter()
            .any(|artifact_id| artifact_id == "memory-checkpoint-merge-1")
    );
    assert!(
        artifact_ids
            .iter()
            .any(|artifact_id| artifact_id == "memory-audit-native-replacement-1")
    );
}
