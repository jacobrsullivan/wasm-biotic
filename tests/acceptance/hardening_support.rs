use aiaf_v1::execution::{
    ActorKind, AgendaItem, ApprovalClass, ApprovalDecision, ApprovalRequest, AuditRecord,
    AuditRecordClass, AuthorityClass, BackgroundCampaign, BlockedReason, BlockedReasonKind,
    CapabilityClosureEntry, CapabilityClosureStatus, CapabilityDependencyMode, CapabilityEnvelope,
    CapabilityImportTarget, CapabilityOperationApproval, CapabilityOperationRequest,
    CapabilityWorld, CapabilityWorldGrant, ClosureInventory, DimensionVerdict, EvaluationDimension,
    EvaluationDimensionScore, ExecutionSession, ExecutionSessionHeader, ExecutionSessionState,
    FailureBudget, GovernancePolicyClass, IsolationProfile, MemoryArtifact, MemoryScope,
    MemoryStore, OwnershipBoundary, OwnershipMode, PointerIndex, ReplayableRuntimeState,
    RunCheckpoint, TaskArtifact, TaskGraph, TaskState, TickSource, TopicBundle, TopicBundleClass,
    TranscriptSlice, WorkerCard, WorkerDispatch, WorkerRole, build_closure_inventory,
};
use std::env;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn ready_session(
    session_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    envelope_id: &str,
) -> ExecutionSession {
    let mut session = ExecutionSession::new(ExecutionSessionHeader {
        session_id: session_id.to_string(),
        actor_kind: ActorKind::Supervisor,
        actor_id: "supervisor-alpha".to_string(),
        campaign_id: campaign_id.to_string(),
        epoch_id: epoch_id.to_string(),
        capability_envelope_ref: envelope_id.to_string(),
        parent_session_id: None,
    });
    session.state = ExecutionSessionState::Ready;
    session
}

pub fn root_task(task_id: &str, summary: &str) -> TaskArtifact {
    let mut task = TaskArtifact::new(task_id, summary);
    task.state = TaskState::Ready;
    task
}

pub fn root_pointer_index(
    pointer_index_id: &str,
    campaign_id: &str,
    task_id: &str,
) -> PointerIndex {
    PointerIndex {
        index_id: pointer_index_id.to_string(),
        scope: MemoryScope::Campaign(campaign_id.to_string()),
        entry_refs: vec![task_id.to_string()],
        contested_refs: Vec::new(),
        critical_refs: vec![task_id.to_string()],
        governance_constraints: vec!["human approval required".to_string()],
        open_task_refs: vec![task_id.to_string()],
        updated_at: "t0".to_string(),
    }
}

pub fn worker_card(worker_id: &str) -> WorkerCard {
    WorkerCard {
        worker_id: worker_id.to_string(),
        worker_role: WorkerRole::EvaluatorWorker,
        supported_task_kinds: vec!["bounded-analysis".to_string()],
        required_worlds: vec![
            CapabilityWorld::WorkspaceObserve,
            CapabilityWorld::MemoryAccess,
        ],
        authority_ceiling: AuthorityClass::Observe,
        isolation_profile: IsolationProfile::ArtifactSandbox,
        result_contract: "bounded-result".to_string(),
        max_concurrency: 1,
    }
}

pub fn worker_envelope(
    envelope_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    approval_class: ApprovalClass,
) -> CapabilityEnvelope {
    CapabilityEnvelope {
        envelope_id: envelope_id.to_string(),
        actor_scope: "worker-evaluator-1".to_string(),
        world_grants: vec![
            CapabilityWorldGrant {
                world: CapabilityWorld::WorkspaceObserve,
                allowed_operations: vec!["search".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: approval_class.clone(),
                operation_approval_overrides: vec![CapabilityOperationApproval {
                    operation: "search".to_string(),
                    approval_class,
                }],
            },
            CapabilityWorldGrant {
                world: CapabilityWorld::MemoryAccess,
                allowed_operations: vec!["retrieve".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::SupervisorAllowed,
                operation_approval_overrides: Vec::new(),
            },
            CapabilityWorldGrant {
                world: CapabilityWorld::WorkerMessaging,
                allowed_operations: vec!["dispatch".to_string()],
                default_authority_class: AuthorityClass::Observe,
                default_approval_class: ApprovalClass::SupervisorAllowed,
                operation_approval_overrides: Vec::new(),
            },
        ],
        authority_ceiling: AuthorityClass::Observe,
        isolation_profile: IsolationProfile::ArtifactSandbox,
        allowed_resource_scopes: vec!["workspace-root".to_string(), "pointer-index-1".to_string()],
        approval_overrides: Vec::new(),
        quota_policy: None,
        campaign_scope: Some(campaign_id.to_string()),
        epoch_scope: Some(epoch_id.to_string()),
    }
}

pub fn worker_dispatch(
    dispatch_id: &str,
    session: &ExecutionSession,
    task_id: &str,
    worker_id: &str,
    envelope_id: &str,
) -> WorkerDispatch {
    WorkerDispatch {
        dispatch_id: dispatch_id.to_string(),
        task_id: task_id.to_string(),
        parent_session_id: session.header.session_id.clone(),
        worker_id: worker_id.to_string(),
        worker_task_ref: format!("worker-task-{dispatch_id}"),
        capability_envelope_ref: envelope_id.to_string(),
        requested_capabilities: vec![CapabilityOperationRequest {
            world: CapabilityWorld::WorkspaceObserve,
            operation: "search".to_string(),
            resource_scope: "workspace-root".to_string(),
        }],
        dispatch_message: aiaf_v1::execution::MessageArtifact {
            message_id: format!("dispatch-message-{dispatch_id}"),
            campaign_id: session.header.campaign_id.clone(),
            epoch_id: session.header.epoch_id.clone(),
            task_id: task_id.to_string(),
            sender_actor_ref: session.header.session_id.clone(),
            receiver_actor_ref: worker_id.to_string(),
            message_class: aiaf_v1::execution::MessageArtifactClass::DispatchMessage,
            payload_summary: format!("dispatch {dispatch_id}"),
            referenced_artifacts: Vec::new(),
            status: aiaf_v1::execution::MessageArtifactStatus::Prepared,
        },
    }
}

pub fn checkpoint(
    checkpoint_id: &str,
    session: &ExecutionSession,
    task: Option<&TaskArtifact>,
    memory_artifact_refs: Vec<String>,
    idempotency_markers: Vec<String>,
) -> RunCheckpoint {
    RunCheckpoint::capture(
        checkpoint_id,
        session,
        task,
        Vec::new(),
        memory_artifact_refs,
        FailureBudget::default().snapshot(),
        idempotency_markers,
    )
}

pub fn persist_checkpoint_lineage(
    memory_store: &mut MemoryStore,
    checkpoint: &RunCheckpoint,
    audit_suffix: &str,
    summary: &str,
) {
    memory_store.persist_checkpoint_artifact(
        format!("memory-checkpoint-{}", checkpoint.checkpoint_id),
        checkpoint.clone(),
        format!("checkpoint {} persisted", checkpoint.checkpoint_id),
    );
    memory_store.append(MemoryArtifact::audit_record(
        format!("memory-audit-checkpoint-{audit_suffix}"),
        AuditRecord::new(
            format!("audit-checkpoint-{audit_suffix}"),
            AuditRecordClass::GovernanceAuditRecord,
            checkpoint.session_header.campaign_id.clone(),
            checkpoint.session_header.epoch_id.clone(),
            checkpoint.session_header.session_id.clone(),
            checkpoint.active_task_refs.first().cloned(),
            checkpoint.checkpoint_id.clone(),
            summary,
        ),
    ));
}

pub fn append_audit(
    memory_store: &mut MemoryStore,
    artifact_id: &str,
    audit_record_id: &str,
    class: AuditRecordClass,
    session: &ExecutionSession,
    task_id: Option<&str>,
    related_ref: &str,
    summary: &str,
) {
    memory_store.append(MemoryArtifact::audit_record(
        artifact_id.to_string(),
        AuditRecord::new(
            audit_record_id.to_string(),
            class,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            task_id.map(str::to_string),
            related_ref.to_string(),
            summary.to_string(),
        ),
    ));
}

pub fn append_named_related_audit(
    memory_store: &mut MemoryStore,
    session: &ExecutionSession,
    task_id: Option<&str>,
    related_ref: &str,
    audit_record_id: &str,
    class: AuditRecordClass,
    summary: &str,
) {
    append_audit(
        memory_store,
        &format!("memory-audit-{audit_record_id}"),
        audit_record_id,
        class,
        session,
        task_id,
        related_ref,
        summary,
    );
}

pub fn append_inventory_audits(
    memory_store: &mut MemoryStore,
    session: &ExecutionSession,
    task_id: Option<&str>,
    inventory: &ClosureInventory,
) {
    for entry in &inventory.entries {
        if let Some(audit_ref) = entry.audit_ref.as_deref() {
            append_named_related_audit(
                memory_store,
                session,
                task_id,
                audit_ref,
                audit_ref,
                AuditRecordClass::GovernanceAuditRecord,
                "service inventory audit remained reconstructable",
            );
        }
    }
}

pub fn append_v14_program_evidence(
    memory_store: &mut MemoryStore,
    session: &ExecutionSession,
    task_id: Option<&str>,
    label: &str,
    review_artifact_refs: &[String],
) {
    let portfolio_ref = format!("portfolio:{label}");
    let budget_ref = format!("budget:{label}");
    let intervention_ref = format!("intervention:{label}");
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: portfolio_ref.clone(),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "campaign portfolio and budget continuity remained reconstructable".to_string(),
        evidence_refs: vec![
            portfolio_ref.clone(),
            budget_ref.clone(),
            intervention_ref.clone(),
        ],
        freshness_policy: "retain-until-program-close".to_string(),
    });

    let review_bundle_ref = format!("review:{label}");
    let canary_ref = format!("canary:{label}");
    let release_ref = format!("release:{label}");
    let rejection_ref = format!("rejection:{label}");
    let mut review_evidence_refs = review_artifact_refs.to_vec();
    review_evidence_refs.extend([
        review_bundle_ref.clone(),
        canary_ref.clone(),
        release_ref.clone(),
        rejection_ref.clone(),
    ]);
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: review_bundle_ref.clone(),
        bundle_class: TopicBundleClass::GovernanceNotes,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "review, canary, release, and rejection evidence remained reconstructable"
            .to_string(),
        evidence_refs: review_evidence_refs,
        freshness_policy: "retain-until-adoption-close".to_string(),
    });

    let program_memory_ref = format!("program-memory:{label}");
    let plan_ref = format!("plan-carry-forward:{label}");
    let reprioritization_ref = format!("reprioritization:{label}");
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: program_memory_ref.clone(),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "program memory continuity remained reconstructable".to_string(),
        evidence_refs: vec![
            program_memory_ref.clone(),
            plan_ref.clone(),
            reprioritization_ref.clone(),
        ],
        freshness_policy: "carry-forward-across-cycles".to_string(),
    });
    memory_store.add_transcript_slice(TranscriptSlice {
        slice_id: format!("program-transcript:{label}"),
        campaign_id: session.header.campaign_id.clone(),
        epoch_id: session.header.epoch_id.clone(),
        session_id: Some(session.header.session_id.clone()),
        task_id: task_id.map(str::to_string),
        referenced_artifacts: vec![
            review_bundle_ref.clone(),
            plan_ref.clone(),
            reprioritization_ref.clone(),
        ],
        summary: "carry-forward and reprioritization remained transcript-backed".to_string(),
        excerpts: vec!["reprioritized under bounded review load".to_string()],
    });

    let contention_ref = format!("contention:{label}");
    let fairness_ref = format!("fairness:{label}");
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: contention_ref.clone(),
        bundle_class: TopicBundleClass::CampaignOperatingNotes,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "contention and fairness control remained reconstructable".to_string(),
        evidence_refs: vec![contention_ref.clone(), fairness_ref.clone()],
        freshness_policy: "retain-until-contention-cleared".to_string(),
    });

    let steering_ref = format!("steering:{label}");
    let rollback_rehearsal_ref = format!("rollback-rehearsal:{label}");
    let adoption_safety_ref = format!("adoption-safety:{label}");
    memory_store.add_topic_bundle(TopicBundle {
        bundle_id: steering_ref.clone(),
        bundle_class: TopicBundleClass::ArchitectureDecision,
        scope: MemoryScope::Campaign(session.header.campaign_id.clone()),
        summary: "operator steering and adoption safety remained reconstructable".to_string(),
        evidence_refs: vec![
            steering_ref.clone(),
            rollback_rehearsal_ref.clone(),
            adoption_safety_ref.clone(),
        ],
        freshness_policy: "retain-through-reversal-window".to_string(),
    });

    let pointer_index_ref = memory_store
        .pointer_indexes
        .first()
        .map(|pointer_index| pointer_index.index_id.clone());
    let contradiction_ref = format!("contradiction:{label}");
    memory_store.register_contradiction(
        contradiction_ref.clone(),
        vec![plan_ref.clone(), reprioritization_ref.clone()],
        "reconcile plan carry-forward with reprioritized work",
        pointer_index_ref.as_deref(),
    );
    memory_store.resolve_contradiction(&contradiction_ref, pointer_index_ref.as_deref());

    for (related_ref, audit_record_id, class, summary) in [
        (
            portfolio_ref.as_str(),
            "audit-portfolio",
            AuditRecordClass::GovernanceAuditRecord,
            "campaign portfolio remained reconstructable",
        ),
        (
            budget_ref.as_str(),
            "audit-budget",
            AuditRecordClass::GovernanceAuditRecord,
            "budget continuity remained reconstructable",
        ),
        (
            intervention_ref.as_str(),
            "audit-intervention",
            AuditRecordClass::GovernanceAuditRecord,
            "intervention evidence remained reconstructable",
        ),
        (
            canary_ref.as_str(),
            "audit-canary",
            AuditRecordClass::PromotionAuditRecord,
            "canary evidence remained reconstructable",
        ),
        (
            release_ref.as_str(),
            "audit-release",
            AuditRecordClass::PromotionAuditRecord,
            "release evidence remained reconstructable",
        ),
        (
            rejection_ref.as_str(),
            "audit-rejection",
            AuditRecordClass::GovernanceAuditRecord,
            "rejection evidence remained reconstructable",
        ),
        (
            program_memory_ref.as_str(),
            "audit-program-memory",
            AuditRecordClass::GovernanceAuditRecord,
            "program memory evidence remained reconstructable",
        ),
        (
            plan_ref.as_str(),
            "audit-plan-carry-forward",
            AuditRecordClass::GovernanceAuditRecord,
            "plan carry-forward remained reconstructable",
        ),
        (
            reprioritization_ref.as_str(),
            "audit-reprioritization",
            AuditRecordClass::GovernanceAuditRecord,
            "reprioritization remained reconstructable",
        ),
        (
            contention_ref.as_str(),
            "audit-contention",
            AuditRecordClass::GovernanceAuditRecord,
            "contention evidence remained reconstructable",
        ),
        (
            fairness_ref.as_str(),
            "audit-fairness",
            AuditRecordClass::GovernanceAuditRecord,
            "fairness evidence remained reconstructable",
        ),
        (
            steering_ref.as_str(),
            "audit-steering",
            AuditRecordClass::GovernanceAuditRecord,
            "operator steering remained reconstructable",
        ),
        (
            rollback_rehearsal_ref.as_str(),
            "audit-rollback-rehearsal",
            AuditRecordClass::PromotionAuditRecord,
            "rollback rehearsal remained reconstructable",
        ),
        (
            adoption_safety_ref.as_str(),
            "audit-adoption-safety",
            AuditRecordClass::PromotionAuditRecord,
            "adoption safety remained reconstructable",
        ),
    ] {
        append_named_related_audit(
            memory_store,
            session,
            task_id,
            related_ref,
            &format!("{audit_record_id}-{label}"),
            class,
            summary,
        );
    }
}

pub fn approval_blocked_runtime_state(
    memory_store: MemoryStore,
    approval_request_id: &str,
    checkpoint_id: &str,
    task_id: &str,
) -> ReplayableRuntimeState {
    let mut session = ready_session("session-1", "campaign-1", "epoch-1", "envelope-1");
    session.state = ExecutionSessionState::AwaitingApproval;
    session.active_task_id = Some(task_id.to_string());
    session.pending_approval_refs = vec![approval_request_id.to_string()];
    session.blocked_reason = Some(BlockedReason::new(
        BlockedReasonKind::Approval,
        "approval required for bounded continuation",
    ));

    let mut task = root_task(task_id, "bounded hardening task");
    task.state = TaskState::BlockedOnApproval;
    task.owner_session_id = Some(session.header.session_id.clone());
    task.blocked_reason = session.blocked_reason.clone();

    let checkpoint = RunCheckpoint::capture(
        checkpoint_id,
        &session,
        Some(&task),
        Vec::new(),
        vec!["pointer-index-1".to_string()],
        FailureBudget::default().snapshot(),
        vec![approval_request_id.to_string()],
    );
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());

    ReplayableRuntimeState::new(
        session,
        task,
        TaskGraph::new(
            task_id,
            vec![AgendaItem::new(
                "agenda-root",
                task_id,
                "bounded-analysis",
                Vec::new(),
                OwnershipBoundary {
                    boundary_id: "boundary-root".to_string(),
                    resource_scope: "workspace-root".to_string(),
                    mode: OwnershipMode::ExclusiveMutable,
                    owner_actor_ref: "supervisor-alpha".to_string(),
                },
            )],
        ),
        memory_store,
        Some(checkpoint),
        vec![aiaf_v1::execution::ExecutionEvent::new(
            "event-checkpoint-1",
            aiaf_v1::execution::EventFamily::CheckpointEvent,
            "campaign-1",
            "epoch-1",
            "session-1",
            None,
            Some(task_id.to_string()),
            "approval checkpoint captured",
        )],
    )
}

pub fn background_campaign(campaign_id: &str) -> BackgroundCampaign {
    BackgroundCampaign {
        campaign_id: campaign_id.to_string(),
        objective: "resume governed bounded flow".to_string(),
        authority_ceiling: AuthorityClass::Observe,
        allowed_tick_sources: vec![TickSource::ApprovalResponse],
        max_concurrent_sessions: 1,
        stop_conditions: vec![aiaf_v1::execution::StopCondition::ExplicitTaskCompletion],
        approval_policy: GovernancePolicyClass::BackgroundAutonomyPolicy,
        audit_policy: GovernancePolicyClass::ExecutionSafetyPolicy,
    }
}

pub fn supervisor_dimension_scores(
    incumbent_label: &str,
    challenger_label: &str,
) -> Vec<EvaluationDimensionScore> {
    vec![
        EvaluationDimensionScore {
            dimension: EvaluationDimension::SemanticCorrectness,
            verdict: DimensionVerdict::Equivalent,
            incumbent_summary: format!("{incumbent_label} remained semantically correct"),
            challenger_summary: format!("{challenger_label} remained semantically correct"),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::GovernanceFidelity,
            verdict: DimensionVerdict::Equivalent,
            incumbent_summary: format!("{incumbent_label} remained governed"),
            challenger_summary: format!("{challenger_label} remained governed"),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::Replayability,
            verdict: DimensionVerdict::Equivalent,
            incumbent_summary: format!("{incumbent_label} remained replayable"),
            challenger_summary: format!("{challenger_label} remained replayable"),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::OperatorBurden,
            verdict: DimensionVerdict::Equivalent,
            incumbent_summary: format!("{incumbent_label} kept operator review bounded"),
            challenger_summary: format!("{challenger_label} kept operator review bounded"),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::BoundaryCost,
            verdict: DimensionVerdict::Equivalent,
            incumbent_summary: format!("{incumbent_label} preserved bounded worker costs"),
            challenger_summary: format!("{challenger_label} preserved bounded worker costs"),
        },
        EvaluationDimensionScore {
            dimension: EvaluationDimension::ReplacementSafety,
            verdict: DimensionVerdict::Equivalent,
            incumbent_summary: format!("{incumbent_label} remained reversible"),
            challenger_summary: format!("{challenger_label} remained reversible"),
        },
    ]
}

pub fn full_closure_inventory(inventory_id: &str) -> ClosureInventory {
    build_closure_inventory(
        inventory_id,
        vec![
            CapabilityClosureEntry {
                target: CapabilityImportTarget::TranscriptRetrieval,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:memory-access".to_string()),
                audit_ref: Some("audit-memory-access".to_string()),
                rationale: "skeptical transcript retrieval is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::CampaignControl,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:campaign-control".to_string()),
                audit_ref: Some("audit-campaign-control".to_string()),
                rationale: "campaign control is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ApprovalGateway,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:approval-gateway".to_string()),
                audit_ref: Some("audit-approval-gateway".to_string()),
                rationale: "approval gateway is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ReviewPromotion,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:review-promotion".to_string()),
                audit_ref: Some("audit-review-promotion".to_string()),
                rationale: "review and promotion flow is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ScheduleTick,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:schedule-tick".to_string()),
                audit_ref: Some("audit-schedule-tick".to_string()),
                rationale: "schedule tick handling is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ModelHosting,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:model-hosting-adapter".to_string()),
                audit_ref: Some("audit-model-hosting".to_string()),
                rationale: "model hosting remains an explicit carried import".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::WorktreeHostAdapter,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:worktree-host-adapter".to_string()),
                audit_ref: Some("audit-worktree-host-adapter".to_string()),
                rationale: "worktree host access remains an explicit carried import".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::EnvironmentBridge,
                current_mode: CapabilityDependencyMode::ImportedBaseline,
                closure_status: CapabilityClosureStatus::CarriedImportApproved,
                capability_world_ref: Some("world:environment-bridge".to_string()),
                audit_ref: Some("audit-environment-bridge".to_string()),
                rationale: "environment bridge remains an explicit carried import".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::SemanticValidation,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:semantic-validation".to_string()),
                audit_ref: Some("audit-semantic-validation".to_string()),
                rationale: "semantic validation is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::ArtifactPackaging,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:artifact-packaging".to_string()),
                audit_ref: Some("audit-artifact-packaging".to_string()),
                rationale: "artifact packaging is native".to_string(),
            },
            CapabilityClosureEntry {
                target: CapabilityImportTarget::NativeSupervisorChallenger,
                current_mode: CapabilityDependencyMode::Native,
                closure_status: CapabilityClosureStatus::NativeClosed,
                capability_world_ref: Some("world:native-supervisor-challenger".to_string()),
                audit_ref: Some("audit-native-supervisor-challenger".to_string()),
                rationale: "native supervisor challenger evaluation is closed".to_string(),
            },
        ],
        Vec::new(),
        "full fixed-interface self-hosting closure inventory",
    )
}

pub fn runtime_state_with_checkpoint(
    mut session: ExecutionSession,
    task: TaskArtifact,
    task_graph: TaskGraph,
    memory_store: MemoryStore,
    checkpoint: RunCheckpoint,
    event_id: &str,
    detail: &str,
) -> ReplayableRuntimeState {
    session.latest_checkpoint_ref = Some(checkpoint.checkpoint_id.clone());
    ReplayableRuntimeState::new(
        session.clone(),
        task.clone(),
        task_graph,
        memory_store,
        Some(checkpoint),
        vec![aiaf_v1::execution::ExecutionEvent::new(
            event_id,
            aiaf_v1::execution::EventFamily::CheckpointEvent,
            session.header.campaign_id.clone(),
            session.header.epoch_id.clone(),
            session.header.session_id.clone(),
            None,
            Some(task.task_id.clone()),
            detail,
        )],
    )
}

pub fn completed_runtime_state(
    session_id: &str,
    campaign_id: &str,
    epoch_id: &str,
    task_id: &str,
    checkpoint_id: &str,
    output_refs: Vec<String>,
    detail: &str,
) -> ReplayableRuntimeState {
    let mut session = ready_session(session_id, campaign_id, epoch_id, "envelope-root");
    session.state = ExecutionSessionState::Completed;

    let mut task = root_task(task_id, detail);
    task.state = TaskState::Completed;
    task.owner_session_id = Some(session.header.session_id.clone());
    for output_ref in output_refs {
        task.record_output_ref(output_ref);
    }

    let pointer_index_id = format!("pointer-index-{task_id}");
    let mut memory_store = MemoryStore::default();
    memory_store.insert_pointer_index(root_pointer_index(
        &pointer_index_id,
        &session.header.campaign_id,
        &task.task_id,
    ));
    let checkpoint = checkpoint(
        checkpoint_id,
        &session,
        Some(&task),
        vec![pointer_index_id],
        Vec::new(),
    );
    persist_checkpoint_lineage(
        &mut memory_store,
        &checkpoint,
        checkpoint_id,
        "completed runtime checkpoint remained reconstructable",
    );

    runtime_state_with_checkpoint(
        session,
        task,
        TaskGraph::new(task_id, Vec::new()),
        memory_store,
        checkpoint,
        &format!("event-{session_id}"),
        detail,
    )
}

pub fn request_for_dispatch(
    approval_request_id: &str,
    session: &ExecutionSession,
    task_id: &str,
) -> ApprovalRequest {
    ApprovalRequest::requested(
        approval_request_id,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        task_id.to_string(),
        "dispatch:dispatch-1:WorkspaceObserve:search",
        "workspace-root",
        AuthorityClass::Observe,
    )
}

pub fn granted_dispatch_decision(
    approval_request_id: &str,
    session: &ExecutionSession,
    task_id: &str,
) -> ApprovalDecision {
    ApprovalDecision::granted(
        approval_request_id,
        session.header.campaign_id.clone(),
        session.header.epoch_id.clone(),
        session.header.session_id.clone(),
        task_id.to_string(),
        "dispatch:dispatch-1:WorkspaceObserve:search",
        "operator-1",
        "workspace-root",
        Some("approved bounded dispatch".to_string()),
    )
}

pub fn temp_store_root(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after unix epoch")
        .as_nanos();
    env::temp_dir().join(format!("aiaf-v1-{name}-{}-{nanos}", process::id()))
}
