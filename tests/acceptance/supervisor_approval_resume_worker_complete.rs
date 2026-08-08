use std::fs;
use std::path::PathBuf;

use aiaf_v1::execution::{
    ActorKind, AgendaItem, AgendaStatus, ApprovalClass, ApprovalDecision, AuditRecord,
    AuditRecordClass, AuthorityClass, BackgroundCampaign, CapabilityEnvelope,
    CapabilityOperationApproval, CapabilityOperationRequest, CapabilityWorld, CapabilityWorldGrant,
    EventFamily, ExecutionEvent, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState,
    FailureBudget, GovernancePolicyClass, IsolationProfile, MemoryArtifactClass, MemoryScope,
    MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus, MessageArtifact, MessageArtifactClass,
    MessageArtifactStatus, NormalizedProposal, OwnershipBoundary, OwnershipMode, PointerIndex,
    ProposalFamily, ReplayableRuntimeState, RunCheckpoint, StopCondition, SynthesisClosureDecision,
    SynthesisHandoff, TaskArtifact, TaskGraph, TaskState, TickSource, TopicBundleClass,
    TranscriptSlice, TranscriptSliceQuery, WorkerCard, WorkerDispatch, WorkerRegistry,
    WorkerResult, WorkerRole, accept_worker_result, apply_approval_decision, bind_session_ready,
    checkpointed_block_on_approval, checkpointed_dispatch_to_worker, complete_task,
    persist_approval_decision_bundle, persist_approval_request_bundle, start_turn,
    validate_background_resume_with_runtime_state, validate_ownership_boundary,
};
use serde::Deserialize;
use serde::de::DeserializeOwned;

#[derive(Deserialize)]
struct SessionFixture {
    session_id: String,
    actor_kind: String,
    actor_id: String,
    campaign_id: String,
    epoch_id: String,
    capability_envelope_ref: String,
    parent_session_id: Option<String>,
}

#[derive(Deserialize)]
struct TaskFixture {
    task_id: String,
    summary: String,
}

#[derive(Deserialize)]
struct PointerIndexFixture {
    artifact_id: String,
    critical_refs: Vec<String>,
    governance_constraints: Vec<String>,
}

#[derive(Deserialize)]
struct ApprovalRequestFixture {
    approval_request_id: String,
    summary: String,
    requested_action_ref: String,
    approval_class: String,
}

#[derive(Deserialize)]
struct ApprovalDecisionFixture {
    approval_request_id: String,
    decision: String,
    scope_ref: String,
    decided_by: String,
    notes: Option<String>,
}

#[derive(Deserialize)]
struct WorkerCardFixture {
    worker_id: String,
    worker_role: String,
    supported_task_kinds: Vec<String>,
    required_worlds: Vec<String>,
    authority_ceiling: String,
    isolation_profile: String,
    result_contract: String,
    max_concurrency: usize,
}

#[derive(Deserialize)]
struct CapabilityEnvelopeFixture {
    envelope_id: String,
    actor_scope: String,
    authority_ceiling: String,
    isolation_profile: String,
    allowed_resource_scopes: Vec<String>,
    campaign_scope: String,
    epoch_scope: String,
    world_grants: Vec<CapabilityWorldGrantFixture>,
}

#[derive(Deserialize)]
struct CapabilityWorldGrantFixture {
    world: String,
    allowed_operations: Vec<String>,
    default_authority_class: String,
    default_approval_class: String,
    operation_approval_overrides: Vec<CapabilityOperationApprovalFixture>,
}

#[derive(Deserialize)]
struct CapabilityOperationApprovalFixture {
    operation: String,
    approval_class: String,
}

#[derive(Deserialize)]
struct WorkerDispatchFixture {
    dispatch_id: String,
    worker_task_ref: String,
    capability_envelope_ref: String,
    payload_summary: String,
    requested_capabilities: Vec<CapabilityOperationRequestFixture>,
}

#[derive(Deserialize)]
struct CapabilityOperationRequestFixture {
    world: String,
    operation: String,
    resource_scope: String,
}

#[derive(Deserialize)]
struct WorkerResultFixture {
    worker_id: String,
    worker_task_ref: String,
    result_ref: String,
    summary: String,
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("artifacts/fixtures/supervisor-approval-resume-worker-complete")
}

fn load_fixture<T: DeserializeOwned>(name: &str) -> T {
    let path = fixture_root().join(name);
    let raw = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("failed to read fixture {}: {error}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|error| panic!("failed to parse fixture {}: {error}", path.display()))
}

fn actor_kind(raw: &str) -> ActorKind {
    match raw {
        "supervisor" => ActorKind::Supervisor,
        "worker" => ActorKind::Worker,
        other => panic!("unsupported actor kind fixture: {other}"),
    }
}

fn worker_role(raw: &str) -> WorkerRole {
    match raw {
        "observer-worker" => WorkerRole::ObserverWorker,
        "mutator-worker" => WorkerRole::MutatorWorker,
        "evaluator-worker" => WorkerRole::EvaluatorWorker,
        "reviewer-worker" => WorkerRole::ReviewerWorker,
        "consolidator-worker" => WorkerRole::ConsolidatorWorker,
        other => panic!("unsupported worker role fixture: {other}"),
    }
}

fn capability_world(raw: &str) -> CapabilityWorld {
    match raw {
        "workspace-observe" => CapabilityWorld::WorkspaceObserve,
        "workspace-mutate" => CapabilityWorld::WorkspaceMutate,
        "memory-access" => CapabilityWorld::MemoryAccess,
        "worker-messaging" => CapabilityWorld::WorkerMessaging,
        "campaign-control" => CapabilityWorld::CampaignControl,
        "approval-gateway" => CapabilityWorld::ApprovalGateway,
        "schedule-tick" => CapabilityWorld::ScheduleTick,
        "service-organelle" => CapabilityWorld::ServiceOrganelle,
        "review-promotion" => CapabilityWorld::ReviewPromotion,
        other => panic!("unsupported capability world fixture: {other}"),
    }
}

fn authority_class(raw: &str) -> AuthorityClass {
    match raw {
        "observe" => AuthorityClass::Observe,
        "local-mutate" => AuthorityClass::LocalMutate,
        "campaign-control" => AuthorityClass::CampaignControl,
        "external-interact" => AuthorityClass::ExternalInteract,
        "sensitive-access" => AuthorityClass::SensitiveAccess,
        "promotion-control" => AuthorityClass::PromotionControl,
        "automation-control" => AuthorityClass::AutomationControl,
        other => panic!("unsupported authority class fixture: {other}"),
    }
}

fn approval_class(raw: &str) -> ApprovalClass {
    match raw {
        "auto-allowed" => ApprovalClass::AutoAllowed,
        "supervisor-allowed" => ApprovalClass::SupervisorAllowed,
        "human-required" => ApprovalClass::HumanRequired,
        "quarantine-on-expand" => ApprovalClass::QuarantineOnExpand,
        "forbidden" => ApprovalClass::Forbidden,
        other => panic!("unsupported approval class fixture: {other}"),
    }
}

fn isolation_profile(raw: &str) -> IsolationProfile {
    match raw {
        "read-only-inspect" => IsolationProfile::ReadOnlyInspect,
        "disposable-worktree" => IsolationProfile::DisposableWorktree,
        "artifact-sandbox" => IsolationProfile::ArtifactSandbox,
        "isolated-service-namespace" => IsolationProfile::IsolatedServiceNamespace,
        "supervisor-exclusive" => IsolationProfile::SupervisorExclusive,
        other => panic!("unsupported isolation profile fixture: {other}"),
    }
}

#[test]
fn supervisor_approval_resume_worker_complete_acceptance() {
    let session_fixture: SessionFixture = load_fixture("session-context.json");
    let task_fixture: TaskFixture = load_fixture("task-artifact.json");
    let pointer_index: PointerIndexFixture = load_fixture("pointer-index.json");
    let approval_request: ApprovalRequestFixture = load_fixture("approval-request.json");
    let approval_decision: ApprovalDecisionFixture = load_fixture("approval-decision.json");
    let envelope_fixture: CapabilityEnvelopeFixture =
        load_fixture("worker-capability-envelope.json");
    let worker_card_fixture: WorkerCardFixture = load_fixture("worker-card.json");
    let worker_dispatch_fixture: WorkerDispatchFixture = load_fixture("worker-dispatch.json");
    let worker_result_fixture: WorkerResultFixture = load_fixture("worker-result.json");

    assert_eq!(approval_request.approval_class, "human-required");
    assert_eq!(approval_decision.decision, "granted");
    assert_eq!(
        approval_decision.scope_ref, approval_request.requested_action_ref,
        "approval scope must match the gated action"
    );
    assert!(
        pointer_index
            .governance_constraints
            .iter()
            .any(|constraint| constraint.contains("human approval")),
        "pointer index should surface the human approval constraint"
    );

    let worker_card = WorkerCard {
        worker_id: worker_card_fixture.worker_id.clone(),
        worker_role: worker_role(&worker_card_fixture.worker_role),
        supported_task_kinds: worker_card_fixture.supported_task_kinds.clone(),
        required_worlds: worker_card_fixture
            .required_worlds
            .iter()
            .map(|world| capability_world(world))
            .collect(),
        authority_ceiling: authority_class(&worker_card_fixture.authority_ceiling),
        isolation_profile: isolation_profile(&worker_card_fixture.isolation_profile),
        result_contract: worker_card_fixture.result_contract.clone(),
        max_concurrency: worker_card_fixture.max_concurrency,
    };
    let worker_envelope = CapabilityEnvelope {
        envelope_id: envelope_fixture.envelope_id.clone(),
        actor_scope: envelope_fixture.actor_scope.clone(),
        world_grants: envelope_fixture
            .world_grants
            .iter()
            .map(|grant| CapabilityWorldGrant {
                world: capability_world(&grant.world),
                allowed_operations: grant.allowed_operations.clone(),
                default_authority_class: authority_class(&grant.default_authority_class),
                default_approval_class: approval_class(&grant.default_approval_class),
                operation_approval_overrides: grant
                    .operation_approval_overrides
                    .iter()
                    .map(|override_rule| CapabilityOperationApproval {
                        operation: override_rule.operation.clone(),
                        approval_class: approval_class(&override_rule.approval_class),
                    })
                    .collect(),
            })
            .collect(),
        authority_ceiling: authority_class(&envelope_fixture.authority_ceiling),
        isolation_profile: isolation_profile(&envelope_fixture.isolation_profile),
        allowed_resource_scopes: envelope_fixture.allowed_resource_scopes.clone(),
        approval_overrides: Vec::new(),
        quota_policy: None,
        campaign_scope: Some(envelope_fixture.campaign_scope.clone()),
        epoch_scope: Some(envelope_fixture.epoch_scope.clone()),
    };

    assert!(worker_envelope.grants_world(&CapabilityWorld::WorkerMessaging));
    assert!(worker_envelope.authority_allows(&worker_card.authority_ceiling));
    assert!(worker_envelope.isolation_allows(&worker_card.isolation_profile));
    assert!(worker_envelope.scope_allows("workspace-root"));

    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(PointerIndex {
        index_id: pointer_index.artifact_id.clone(),
        scope: MemoryScope::Campaign(session_fixture.campaign_id.clone()),
        entry_refs: pointer_index.critical_refs.clone(),
        contested_refs: Vec::new(),
        critical_refs: pointer_index.critical_refs.clone(),
        governance_constraints: pointer_index.governance_constraints.clone(),
        open_task_refs: vec![task_fixture.task_id.clone()],
        updated_at: "fixture-load".to_string(),
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: "slice-approval-context".to_string(),
        campaign_id: session_fixture.campaign_id.clone(),
        epoch_id: session_fixture.epoch_id.clone(),
        session_id: Some(session_fixture.session_id.clone()),
        task_id: Some(task_fixture.task_id.clone()),
        referenced_artifacts: vec![pointer_index.artifact_id.clone()],
        summary: "Prior operating note: any workspace mutation requires human approval."
            .to_string(),
        excerpts: vec![
            "The operator required human approval before any workspace mutation.".to_string(),
        ],
    });
    let transcript_slice_id = {
        let transcript_slices = memory_store.retrieve_transcript_slices(&TranscriptSliceQuery {
            campaign_id: Some(session_fixture.campaign_id.clone()),
            task_id: Some(task_fixture.task_id.clone()),
            search_term: Some("human approval".to_string()),
            ..TranscriptSliceQuery::default()
        });
        assert_eq!(transcript_slices.len(), 1);
        transcript_slices[0].slice_id.clone()
    };

    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: session_fixture.session_id.clone(),
        actor_kind: actor_kind(&session_fixture.actor_kind),
        actor_id: session_fixture.actor_id.clone(),
        campaign_id: session_fixture.campaign_id.clone(),
        epoch_id: session_fixture.epoch_id.clone(),
        capability_envelope_ref: session_fixture.capability_envelope_ref.clone(),
        parent_session_id: session_fixture.parent_session_id.clone(),
    });
    let mut task = TaskArtifact::new(task_fixture.task_id.clone(), task_fixture.summary);
    let ownership_boundary = OwnershipBoundary {
        boundary_id: "ownership-boundary-root".to_string(),
        resource_scope: "workspace-root".to_string(),
        mode: OwnershipMode::ExclusiveMutable,
        owner_actor_ref: session.header.session_id.clone(),
    };
    validate_ownership_boundary(&[], &ownership_boundary).unwrap();
    let mut task_graph = TaskGraph::new(
        task.task_id.clone(),
        vec![AgendaItem::new(
            "agenda-root",
            task.task_id.clone(),
            "bounded-analysis",
            Vec::new(),
            ownership_boundary.clone(),
        )],
    );
    let mut worker_registry = WorkerRegistry::default();
    worker_registry.register(worker_card.clone());
    let mut events = Vec::new();

    bind_session_ready(&mut session).unwrap();
    events.push(ExecutionEvent::new(
        "event-session-ready",
        EventFamily::SessionLifecycleEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        None,
        None,
        "session entered ready state",
    ));

    let turn_one = start_turn(&mut session, &mut task, "turn-1").unwrap();
    events.push(ExecutionEvent::new(
        "event-turn-1-open",
        EventFamily::TurnLifecycleEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        "first turn opened",
    ));
    events.push(ExecutionEvent::new(
        "event-pointer-index-load",
        EventFamily::MemoryInteractionEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        format!("pointer index {} loaded", pointer_index.artifact_id),
    ));
    events.push(ExecutionEvent::new(
        "event-transcript-slice-load",
        EventFamily::MemoryInteractionEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        format!("retrieved transcript slice {}", transcript_slice_id),
    ));

    let approval_proposal = NormalizedProposal::new(
        ProposalFamily::ApprovalRequest,
        approval_request.summary.clone(),
        Some(approval_request.requested_action_ref.clone()),
    )
    .unwrap();
    events.push(ExecutionEvent::new(
        "event-approval-proposal",
        EventFamily::ActionProposalEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        approval_request.summary.clone(),
    ));

    let checkpoint: RunCheckpoint = checkpointed_block_on_approval(
        &mut session,
        &mut task,
        approval_request.approval_request_id.clone(),
        approval_request.summary.clone(),
        "checkpoint-1",
        vec![approval_proposal],
        vec![pointer_index.artifact_id.clone()],
        FailureBudget::default().snapshot(),
        vec![approval_request.requested_action_ref.clone()],
    )
    .unwrap();
    let approval_checkpoint_artifact_id = memory_store.persist_checkpoint_artifact(
        "memory-checkpoint-approval-1",
        checkpoint.clone(),
        "approval-block checkpoint persisted for bounded resume",
    );
    let approval_request_record = aiaf_v1::execution::ApprovalRequest::requested(
        approval_request.approval_request_id.clone(),
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        task.task_id.clone(),
        approval_request.requested_action_ref.clone(),
        approval_request.requested_action_ref.clone(),
        AuthorityClass::Observe,
    );
    let approval_memory_write =
        persist_approval_request_bundle(&mut memory_store, &approval_request_record, &checkpoint);

    events.push(ExecutionEvent::new(
        "event-approval-blocked",
        EventFamily::ApprovalStateEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        "session blocked on approval",
    ));
    events.push(ExecutionEvent::new(
        "event-checkpoint-1",
        EventFamily::CheckpointEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        checkpoint.checkpoint_id.clone(),
    ));

    assert_eq!(session.state, ExecutionSessionState::AwaitingApproval);
    assert_eq!(task.state, TaskState::BlockedOnApproval);
    assert_eq!(
        checkpoint.pending_approval_refs,
        vec![approval_request.approval_request_id.clone()]
    );
    assert_eq!(
        checkpoint.memory_artifact_refs,
        vec![pointer_index.artifact_id.clone()]
    );
    assert_eq!(
        memory_store
            .get(&approval_memory_write.approval_request_artifact_id)
            .expect("approval request memory artifact should exist")
            .class,
        MemoryArtifactClass::ApprovalRequestArtifact
    );
    assert_eq!(
        memory_store
            .get(&approval_checkpoint_artifact_id)
            .expect("approval checkpoint memory artifact should exist")
            .class,
        MemoryArtifactClass::CheckpointArtifact
    );
    assert!(
        pointer_index
            .critical_refs
            .iter()
            .any(|reference| reference == &task.task_id)
    );

    let approval_decision = ApprovalDecision::granted(
        approval_decision.approval_request_id.clone(),
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        task.task_id.clone(),
        approval_request.requested_action_ref.clone(),
        approval_decision.decided_by.clone(),
        approval_decision.scope_ref.clone(),
        approval_decision.notes.clone(),
    );
    assert!(approval_request_record.matches_decision(&approval_decision));
    assert!(approval_decision.matches_request(&approval_request_record));
    let background_campaign = BackgroundCampaign {
        campaign_id: session.header.campaign_id.clone(),
        objective: "resume approval-blocked bounded flow".to_string(),
        authority_ceiling: AuthorityClass::Observe,
        allowed_tick_sources: vec![TickSource::ApprovalResponse],
        max_concurrent_sessions: 1,
        stop_conditions: vec![StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
        audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
    };
    let background_runtime_state = ReplayableRuntimeState::new(
        session.clone(),
        task.clone(),
        task_graph.clone(),
        memory_store.clone(),
        Some(checkpoint.clone()),
        events.clone(),
    );
    validate_background_resume_with_runtime_state(
        &background_campaign,
        &TickSource::ApprovalResponse,
        &background_runtime_state,
        &[approval_decision.clone()],
        &[],
        &task.task_id,
    )
    .unwrap();
    apply_approval_decision(&mut session, &mut task, &approval_decision).unwrap();
    events.push(ExecutionEvent::new(
        "event-approval-granted",
        EventFamily::GovernanceDecisionEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        "approval granted and consumed for bounded continuation",
    ));
    events.push(ExecutionEvent::new(
        "event-background-resume-validated",
        EventFamily::GovernanceDecisionEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_one.turn_id.clone()),
        Some(task.task_id.clone()),
        "approval-response tick validated for bounded background resume",
    ));

    let turn_two = start_turn(&mut session, &mut task, "turn-2").unwrap();
    let routing_decision = worker_registry
        .select_worker(
            "bounded-analysis",
            &worker_card.required_worlds,
            &worker_card.authority_ceiling,
            &worker_card.isolation_profile,
        )
        .unwrap();
    assert_eq!(routing_decision.worker_id, worker_card.worker_id);

    let worker_dispatch = WorkerDispatch {
        dispatch_id: worker_dispatch_fixture.dispatch_id.clone(),
        task_id: task.task_id.clone(),
        parent_session_id: session.header.session_id.clone(),
        worker_id: worker_card.worker_id.clone(),
        worker_task_ref: worker_dispatch_fixture.worker_task_ref.clone(),
        capability_envelope_ref: worker_dispatch_fixture.capability_envelope_ref.clone(),
        requested_capabilities: worker_dispatch_fixture
            .requested_capabilities
            .iter()
            .map(|request| CapabilityOperationRequest {
                world: capability_world(&request.world),
                operation: request.operation.clone(),
                resource_scope: request.resource_scope.clone(),
            })
            .collect(),
        dispatch_message: MessageArtifact {
            message_id: "message-dispatch-rc01".to_string(),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task.task_id.clone(),
            sender_actor_ref: session.header.session_id.clone(),
            receiver_actor_ref: worker_card.worker_id.clone(),
            message_class: MessageArtifactClass::DispatchMessage,
            payload_summary: worker_dispatch_fixture.payload_summary.clone(),
            referenced_artifacts: vec![task.task_id.clone(), pointer_index.artifact_id.clone()],
            status: MessageArtifactStatus::Sent,
        },
    };

    let worker_dispatch_outcome = checkpointed_dispatch_to_worker(
        &mut session,
        &mut task,
        &worker_card,
        &worker_envelope,
        &worker_dispatch,
        "checkpoint-2",
        Vec::new(),
        vec![pointer_index.artifact_id.clone()],
        FailureBudget::default().snapshot(),
        vec![worker_dispatch.dispatch_id.clone()],
    )
    .unwrap();
    let aiaf_v1::execution::WorkerDispatchCheckpointOutcome::Dispatched(worker_checkpoint) =
        worker_dispatch_outcome
    else {
        panic!("expected worker dispatch to proceed without approval");
    };
    task_graph
        .mark_dispatched("agenda-root", routing_decision.worker_id.clone())
        .unwrap();
    let worker_checkpoint_artifact_id = memory_store.persist_checkpoint_artifact(
        "memory-checkpoint-worker-1",
        worker_checkpoint.clone(),
        "worker dispatch checkpoint persisted for bounded orchestration",
    );

    events.push(ExecutionEvent::new(
        "event-worker-dispatch",
        EventFamily::WorkerDispatchEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_two.turn_id.clone()),
        Some(task.task_id.clone()),
        format!(
            "dispatch {} to {} for {}",
            worker_dispatch.dispatch_id, worker_dispatch.worker_id, worker_dispatch.worker_task_ref
        ),
    ));

    assert_eq!(session.state, ExecutionSessionState::AwaitingWorkerResult);
    assert_eq!(task.state, TaskState::BlockedOnWorker);
    assert_eq!(
        worker_checkpoint.outstanding_worker_refs,
        vec![worker_card.worker_id.clone()]
    );

    let worker_result = WorkerResult {
        dispatch_id: worker_dispatch.dispatch_id.clone(),
        worker_id: worker_result_fixture.worker_id.clone(),
        worker_task_ref: worker_result_fixture.worker_task_ref.clone(),
        result_ref: worker_result_fixture.result_ref.clone(),
        summary: worker_result_fixture.summary.clone(),
        result_message: MessageArtifact {
            message_id: "message-result-rc01".to_string(),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task.task_id.clone(),
            sender_actor_ref: worker_card.worker_id.clone(),
            receiver_actor_ref: session.header.session_id.clone(),
            message_class: MessageArtifactClass::ResultMessage,
            payload_summary: worker_result_fixture.summary.clone(),
            referenced_artifacts: vec![worker_result_fixture.result_ref.clone()],
            status: MessageArtifactStatus::Received,
        },
    };

    accept_worker_result(&mut session, &mut task, &worker_result).unwrap();

    let turn_three = start_turn(&mut session, &mut task, "turn-3").unwrap();
    let synthesis_handoff = SynthesisHandoff {
        handoff_id: "handoff-rc01".to_string(),
        task_id: task.task_id.clone(),
        worker_output_refs: vec![worker_result.result_ref.clone()],
        supervisor_summary: worker_result.summary.clone(),
        next_action: "complete-task".to_string(),
        closure_decision: SynthesisClosureDecision::Complete,
    };
    task_graph
        .apply_synthesis_handoff("agenda-root", &synthesis_handoff)
        .unwrap();
    task.record_output_ref(worker_result.result_ref.clone());
    let synthesis = NormalizedProposal::new(
        ProposalFamily::SynthesisSummary,
        format!(
            "{} ({})",
            synthesis_handoff.supervisor_summary, worker_result.result_ref
        ),
        None,
    )
    .unwrap();
    memory_store.propose_memory_update(MemoryUpdateProposal {
        proposal_id: "memory-update-rc01".to_string(),
        pointer_index_ref: Some(pointer_index.artifact_id.clone()),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: MemoryScope::Task(task.task_id.clone()),
        proposed_summary: synthesis_handoff.supervisor_summary.clone(),
        evidence_refs: vec![worker_result.result_ref.clone()],
        verification_refs: vec![
            worker_checkpoint_artifact_id.clone(),
            approval_memory_write.audit_artifact_id.clone(),
        ],
        status: MemoryUpdateStatus::Proposed,
    });
    let verified_memory_bundle_id = memory_store
        .accept_memory_update(
            "memory-update-rc01",
            "bundle-rc01-worker-flow",
            "verified-by-checkpoint-and-audit",
        )
        .unwrap();
    task.record_output_ref(verified_memory_bundle_id.clone());
    events.push(ExecutionEvent::new(
        "event-synthesis-summary",
        EventFamily::ActionProposalEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_three.turn_id.clone()),
        Some(task.task_id.clone()),
        synthesis.summary.clone(),
    ));
    events.push(ExecutionEvent::new(
        "event-memory-write-verified",
        EventFamily::MemoryInteractionEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_three.turn_id.clone()),
        Some(task.task_id.clone()),
        format!(
            "verified memory bundle {} accepted",
            verified_memory_bundle_id
        ),
    ));

    complete_task(&mut session, &mut task).unwrap();
    events.push(ExecutionEvent::new(
        "event-task-completed",
        EventFamily::TaskLifecycleEvent,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        Some(turn_three.turn_id.clone()),
        Some(task.task_id.clone()),
        "task completed through supervisor synthesis",
    ));

    let audit_records = vec![
        AuditRecord::new(
            "audit-approval-1",
            AuditRecordClass::ApprovalAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(task.task_id.clone()),
            approval_decision.approval_request_id.clone(),
            "approval decision recorded for bounded continuation",
        ),
        AuditRecord::new(
            "audit-governance-1",
            AuditRecordClass::GovernanceAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(task.task_id.clone()),
            approval_decision.scope_ref.clone(),
            "governance approved the scoped workspace mutation",
        ),
        AuditRecord::new(
            "audit-execution-1",
            AuditRecordClass::ExecutionAuditRecord,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            Some(task.task_id.clone()),
            worker_dispatch.dispatch_id.clone(),
            "worker dispatch and synthesis completed in bounded scope",
        ),
    ];
    let decision_memory_write =
        persist_approval_decision_bundle(&mut memory_store, &approval_decision, &audit_records);
    let approval_lineage = memory_store.approval_lineage(&approval_request.approval_request_id);
    let checkpoint_lineage = memory_store.checkpoint_lineage(&checkpoint.checkpoint_id);

    let approval_granted_index = events
        .iter()
        .position(|event| event.event_id == "event-approval-granted")
        .unwrap();
    let worker_dispatch_index = events
        .iter()
        .position(|event| event.event_id == "event-worker-dispatch")
        .unwrap();

    assert!(worker_dispatch_index > approval_granted_index);
    assert_eq!(turn_one.turn_index, 1);
    assert_eq!(turn_three.turn_index, 3);
    assert_eq!(session.state, ExecutionSessionState::Completed);
    assert_eq!(task.state, TaskState::Completed);
    assert!(
        events
            .iter()
            .any(|event| matches!(event.family, EventFamily::CheckpointEvent))
    );
    assert!(
        approval_lineage
            .iter()
            .any(|artifact| { artifact.class == MemoryArtifactClass::ApprovalRequestArtifact })
    );
    assert!(
        approval_lineage
            .iter()
            .any(|artifact| { artifact.class == MemoryArtifactClass::ApprovalDecisionArtifact })
    );
    assert!(
        approval_lineage
            .iter()
            .any(|artifact| { artifact.class == MemoryArtifactClass::AuditRecordArtifact })
    );
    assert!(
        checkpoint_lineage
            .iter()
            .any(|artifact| { artifact.class == MemoryArtifactClass::CheckpointArtifact })
    );
    assert!(
        checkpoint_lineage
            .iter()
            .any(|artifact| { artifact.class == MemoryArtifactClass::AuditRecordArtifact })
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event.family, EventFamily::WorkerDispatchEvent))
    );
    assert!(
        events
            .iter()
            .any(|event| matches!(event.family, EventFamily::MemoryInteractionEvent))
    );
    assert_eq!(worker_dispatch.worker_id, worker_card.worker_id);
    assert_eq!(
        worker_dispatch.capability_envelope_ref,
        worker_envelope.envelope_id
    );
    assert_eq!(worker_result.dispatch_id, worker_dispatch.dispatch_id);
    assert!(
        audit_records
            .iter()
            .any(|record| matches!(record.class, AuditRecordClass::ApprovalAuditRecord))
    );
    assert!(
        audit_records
            .iter()
            .any(|record| matches!(record.class, AuditRecordClass::ExecutionAuditRecord))
    );
    assert_eq!(
        task_graph.agenda_item("agenda-root").unwrap().status,
        AgendaStatus::Completed
    );
    assert!(
        task_graph
            .agenda_item("agenda-root")
            .unwrap()
            .output_refs
            .iter()
            .any(|output_ref| output_ref == &worker_result.result_ref)
    );
    assert!(
        task.output_refs
            .iter()
            .any(|output_ref| output_ref == &verified_memory_bundle_id)
    );
    assert!(
        memory_store
            .load_pointer_index(&pointer_index.artifact_id)
            .unwrap()
            .entry_refs
            .iter()
            .any(|entry_ref| entry_ref == &verified_memory_bundle_id)
    );
    assert_eq!(
        memory_store
            .get(&worker_checkpoint_artifact_id)
            .expect("worker checkpoint artifact should exist")
            .class,
        MemoryArtifactClass::CheckpointArtifact
    );
    assert_eq!(
        memory_store
            .get(&decision_memory_write.approval_decision_artifact_id)
            .expect("approval decision memory artifact should exist")
            .class,
        MemoryArtifactClass::ApprovalDecisionArtifact
    );
    assert_eq!(
        decision_memory_write.audit_artifact_ids.len(),
        audit_records.len() + 1
    );
    assert!(
        memory_store
            .artifacts_for_related_ref(&format!(
                "approval-transport:{}",
                approval_request.approval_request_id
            ))
            .iter()
            .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
    );
    assert!(
        memory_store
            .artifacts_for_task(&task.task_id)
            .iter()
            .any(|artifact| matches!(artifact.class, MemoryArtifactClass::AuditRecordArtifact))
    );
}
