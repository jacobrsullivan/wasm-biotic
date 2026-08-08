use crate::execution::capability::{AuthorityClass, CapabilityWorld, IsolationProfile};
use crate::execution::failure_budget::{
    FailureBudget, FailureBudgetSnapshot, RetryClass, StopCondition,
};
use crate::execution::worker::{MessageArtifact, MessageArtifactClass};
use crate::execution::worker::{SynthesisClosureDecision, SynthesisHandoff, WorkerCard};
use crate::execution::{AgendaItemId, TaskId, WorkerId};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OwnershipMode {
    ReadOnlyFanOut,
    ExclusiveMutable,
    MergeRequired,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnershipBoundary {
    pub boundary_id: String,
    pub resource_scope: String,
    pub mode: OwnershipMode,
    pub owner_actor_ref: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgendaStatus {
    PendingDependencies,
    Ready,
    Dispatched,
    AwaitingSynthesis,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgendaItem {
    pub agenda_item_id: AgendaItemId,
    pub task_id: TaskId,
    pub task_kind: String,
    pub dependency_refs: Vec<TaskId>,
    pub assigned_worker_id: Option<WorkerId>,
    pub status: AgendaStatus,
    pub ownership_boundary: OwnershipBoundary,
    pub output_refs: Vec<String>,
}

impl AgendaItem {
    pub fn new(
        agenda_item_id: impl Into<AgendaItemId>,
        task_id: impl Into<TaskId>,
        task_kind: impl Into<String>,
        dependency_refs: Vec<TaskId>,
        ownership_boundary: OwnershipBoundary,
    ) -> Self {
        let dependency_refs = dependency_refs;
        let status = if dependency_refs.is_empty() {
            AgendaStatus::Ready
        } else {
            AgendaStatus::PendingDependencies
        };

        Self {
            agenda_item_id: agenda_item_id.into(),
            task_id: task_id.into(),
            task_kind: task_kind.into(),
            dependency_refs,
            assigned_worker_id: None,
            status,
            ownership_boundary,
            output_refs: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskGraph {
    pub root_task_id: TaskId,
    pub agenda_items: Vec<AgendaItem>,
}

impl TaskGraph {
    pub fn new(root_task_id: impl Into<TaskId>, agenda_items: Vec<AgendaItem>) -> Self {
        Self {
            root_task_id: root_task_id.into(),
            agenda_items,
        }
    }

    pub fn refresh_ready_states(&mut self, completed_task_refs: &[TaskId]) {
        let completed: HashSet<&str> = completed_task_refs.iter().map(String::as_str).collect();

        for agenda_item in &mut self.agenda_items {
            if agenda_item.status == AgendaStatus::PendingDependencies
                && agenda_item
                    .dependency_refs
                    .iter()
                    .all(|dependency| completed.contains(dependency.as_str()))
            {
                agenda_item.status = AgendaStatus::Ready;
            }
        }
    }

    pub fn agenda_item(&self, agenda_item_id: &str) -> Option<&AgendaItem> {
        self.agenda_items
            .iter()
            .find(|agenda_item| agenda_item.agenda_item_id == agenda_item_id)
    }

    fn agenda_item_mut(&mut self, agenda_item_id: &str) -> Option<&mut AgendaItem> {
        self.agenda_items
            .iter_mut()
            .find(|agenda_item| agenda_item.agenda_item_id == agenda_item_id)
    }

    pub fn mark_dispatched(
        &mut self,
        agenda_item_id: &str,
        worker_id: impl Into<WorkerId>,
    ) -> Result<(), OrchestrationError> {
        let agenda_item = self.agenda_item_mut(agenda_item_id).ok_or_else(|| {
            OrchestrationError::AgendaItemNotFound {
                agenda_item_id: agenda_item_id.to_string(),
            }
        })?;

        if agenda_item.status != AgendaStatus::Ready {
            return Err(OrchestrationError::TaskNotReady {
                task_id: agenda_item.task_id.clone(),
            });
        }

        agenda_item.status = AgendaStatus::Dispatched;
        agenda_item.assigned_worker_id = Some(worker_id.into());
        Ok(())
    }

    pub fn apply_synthesis_handoff(
        &mut self,
        agenda_item_id: &str,
        synthesis_handoff: &SynthesisHandoff,
    ) -> Result<(), OrchestrationError> {
        let agenda_item = self.agenda_item_mut(agenda_item_id).ok_or_else(|| {
            OrchestrationError::AgendaItemNotFound {
                agenda_item_id: agenda_item_id.to_string(),
            }
        })?;

        if agenda_item.status != AgendaStatus::Dispatched {
            return Err(OrchestrationError::SynthesisWithoutDispatch {
                task_id: agenda_item.task_id.clone(),
            });
        }

        agenda_item.status = AgendaStatus::AwaitingSynthesis;
        agenda_item
            .output_refs
            .extend(synthesis_handoff.worker_output_refs.clone());

        agenda_item.status = match synthesis_handoff.closure_decision {
            SynthesisClosureDecision::Continue => AgendaStatus::Ready,
            SynthesisClosureDecision::Escalate | SynthesisClosureDecision::Fail => {
                AgendaStatus::Failed
            }
            SynthesisClosureDecision::Complete => AgendaStatus::Completed,
        };

        Ok(())
    }

    pub fn recover_orphaned_dispatches(
        &mut self,
        live_worker_ids: &[WorkerId],
    ) -> Vec<AgendaItemId> {
        let live_worker_ids: HashSet<&str> = live_worker_ids.iter().map(String::as_str).collect();
        let mut recovered = Vec::new();

        for agenda_item in &mut self.agenda_items {
            let worker_is_live = agenda_item
                .assigned_worker_id
                .as_deref()
                .is_some_and(|worker_id| live_worker_ids.contains(worker_id));

            match agenda_item.status {
                AgendaStatus::Dispatched if !worker_is_live => {
                    agenda_item.status = AgendaStatus::Ready;
                    agenda_item.assigned_worker_id = None;
                    recovered.push(agenda_item.agenda_item_id.clone());
                }
                AgendaStatus::AwaitingSynthesis if !worker_is_live => {
                    agenda_item.assigned_worker_id = None;
                    recovered.push(agenda_item.agenda_item_id.clone());
                }
                _ => {}
            }
        }

        recovered
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerRegistry {
    pub worker_cards: Vec<WorkerCard>,
}

impl WorkerRegistry {
    pub fn register(&mut self, worker_card: WorkerCard) {
        self.worker_cards.push(worker_card);
    }

    pub fn select_worker(
        &self,
        task_kind: &str,
        required_worlds: &[CapabilityWorld],
        required_authority: &AuthorityClass,
        required_isolation: &IsolationProfile,
    ) -> Result<RoutingDecision, OrchestrationError> {
        let worker_card = self
            .worker_cards
            .iter()
            .find(|worker_card| {
                worker_card
                    .supported_task_kinds
                    .iter()
                    .any(|supported| supported == task_kind)
                    && required_worlds
                        .iter()
                        .all(|required| worker_card.required_worlds.contains(required))
                    && &worker_card.authority_ceiling >= required_authority
                    && worker_card.isolation_profile.satisfies(required_isolation)
            })
            .ok_or_else(|| OrchestrationError::NoWorkerFound {
                task_kind: task_kind.to_string(),
            })?;

        Ok(RoutingDecision {
            worker_id: worker_card.worker_id.clone(),
            task_kind: task_kind.to_string(),
            rationale: format!(
                "worker {} matched task kind {} with required worlds {:?}",
                worker_card.worker_id, task_kind, required_worlds
            ),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoutingDecision {
    pub worker_id: WorkerId,
    pub task_kind: String,
    pub rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellOrchestrationRecord {
    pub orchestration_id: String,
    pub shell_session_id: String,
    pub agenda_item_id: AgendaItemId,
    pub worker_id: WorkerId,
    pub status: AgendaStatus,
    pub ownership_scope: String,
    pub retry_budget: FailureBudgetSnapshot,
    pub synthesis_handoff_ref: Option<String>,
    pub output_refs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrchestrationError {
    AgendaItemNotFound {
        agenda_item_id: AgendaItemId,
    },
    TaskNotReady {
        task_id: TaskId,
    },
    NoWorkerFound {
        task_kind: String,
    },
    OwnershipConflict {
        resource_scope: String,
        existing_owner: String,
        requested_owner: String,
    },
    SynthesisWithoutDispatch {
        task_id: TaskId,
    },
}

pub fn validate_ownership_boundary(
    existing_boundaries: &[OwnershipBoundary],
    candidate_boundary: &OwnershipBoundary,
) -> Result<(), OrchestrationError> {
    for existing_boundary in existing_boundaries {
        let same_scope = existing_boundary.resource_scope == candidate_boundary.resource_scope;
        let same_owner = existing_boundary.owner_actor_ref == candidate_boundary.owner_actor_ref;
        let all_read_only = existing_boundary.mode == OwnershipMode::ReadOnlyFanOut
            && candidate_boundary.mode == OwnershipMode::ReadOnlyFanOut;

        if same_scope && !same_owner && !all_read_only {
            return Err(OrchestrationError::OwnershipConflict {
                resource_scope: candidate_boundary.resource_scope.clone(),
                existing_owner: existing_boundary.owner_actor_ref.clone(),
                requested_owner: candidate_boundary.owner_actor_ref.clone(),
            });
        }
    }

    Ok(())
}

pub fn dispatch_shell_session_to_agenda_item(
    task_graph: &mut TaskGraph,
    agenda_item_id: &str,
    shell_session_id: impl Into<String>,
    worker_id: impl Into<WorkerId>,
    retry_budget: FailureBudgetSnapshot,
) -> Result<ShellOrchestrationRecord, OrchestrationError> {
    let worker_id = worker_id.into();
    task_graph.mark_dispatched(agenda_item_id, worker_id.clone())?;
    let agenda_item = task_graph
        .agenda_item(agenda_item_id)
        .expect("agenda item must exist after dispatch");
    Ok(ShellOrchestrationRecord {
        orchestration_id: format!("shell-orchestration-{agenda_item_id}-dispatch"),
        shell_session_id: shell_session_id.into(),
        agenda_item_id: agenda_item_id.to_string(),
        worker_id,
        status: agenda_item.status.clone(),
        ownership_scope: agenda_item.ownership_boundary.resource_scope.clone(),
        retry_budget,
        synthesis_handoff_ref: None,
        output_refs: agenda_item.output_refs.clone(),
    })
}

pub fn complete_shell_session_agenda_item(
    task_graph: &mut TaskGraph,
    agenda_item_id: &str,
    shell_session_id: impl Into<String>,
    worker_id: impl Into<WorkerId>,
    retry_budget: FailureBudgetSnapshot,
    synthesis_handoff: &SynthesisHandoff,
) -> Result<ShellOrchestrationRecord, OrchestrationError> {
    let worker_id = worker_id.into();
    task_graph.apply_synthesis_handoff(agenda_item_id, synthesis_handoff)?;
    let agenda_item = task_graph
        .agenda_item(agenda_item_id)
        .expect("agenda item must exist after synthesis");
    Ok(ShellOrchestrationRecord {
        orchestration_id: format!("shell-orchestration-{agenda_item_id}-complete"),
        shell_session_id: shell_session_id.into(),
        agenda_item_id: agenda_item_id.to_string(),
        worker_id,
        status: agenda_item.status.clone(),
        ownership_scope: agenda_item.ownership_boundary.resource_scope.clone(),
        retry_budget,
        synthesis_handoff_ref: Some(synthesis_handoff.handoff_id.clone()),
        output_refs: agenda_item.output_refs.clone(),
    })
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
enum WorkerRecoveryDisposition {
    Requeued,
    AwaitingSynthesis,
    Contained,
    HardStop(StopCondition),
}

#[allow(dead_code)]
fn recover_failed_agenda_item(
    task_graph: &mut TaskGraph,
    agenda_item_id: &str,
    failure_message: &MessageArtifact,
    failure_budget: &mut FailureBudget,
) -> Result<WorkerRecoveryDisposition, OrchestrationError> {
    let agenda_item = task_graph.agenda_item_mut(agenda_item_id).ok_or_else(|| {
        OrchestrationError::AgendaItemNotFound {
            agenda_item_id: agenda_item_id.to_string(),
        }
    })?;
    agenda_item.assigned_worker_id = None;

    match failure_message.message_class {
        MessageArtifactClass::ExceptionMessage => {
            if !agenda_item.output_refs.is_empty() {
                let stop_condition = failure_budget.note_no_progress();
                if let Some(stop_condition) = stop_condition {
                    agenda_item.status = AgendaStatus::Failed;
                    return Ok(WorkerRecoveryDisposition::HardStop(stop_condition));
                }

                agenda_item.status = AgendaStatus::AwaitingSynthesis;
                Ok(WorkerRecoveryDisposition::AwaitingSynthesis)
            } else if let Some(stop_condition) =
                failure_budget.record_failure(RetryClass::TransientWorker)
            {
                agenda_item.status = AgendaStatus::Failed;
                Ok(WorkerRecoveryDisposition::HardStop(stop_condition))
            } else {
                agenda_item.status = AgendaStatus::Ready;
                Ok(WorkerRecoveryDisposition::Requeued)
            }
        }
        MessageArtifactClass::RiskMessage => {
            let stop_condition = failure_budget
                .record_failure(RetryClass::PolicyNonRetryable)
                .unwrap_or(StopCondition::GovernanceHardStop);
            agenda_item.status = AgendaStatus::Failed;
            Ok(WorkerRecoveryDisposition::HardStop(stop_condition))
        }
        _ => {
            let stop_condition = failure_budget
                .record_failure(RetryClass::StructuralNonRetryable)
                .unwrap_or(StopCondition::StructuralValidationFailure);
            agenda_item.status = AgendaStatus::Failed;
            Ok(WorkerRecoveryDisposition::HardStop(stop_condition))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::execution::capability::{AuthorityClass, CapabilityWorld, IsolationProfile};
    use crate::execution::failure_budget::{FailureBudget, RetryClass, StopCondition};
    use crate::execution::worker::{
        MessageArtifact, MessageArtifactClass, MessageArtifactStatus, SynthesisClosureDecision,
        SynthesisHandoff, WorkerCard, WorkerRole,
    };

    use super::{
        AgendaItem, AgendaStatus, OrchestrationError, OwnershipBoundary, OwnershipMode, TaskGraph,
        WorkerRecoveryDisposition, WorkerRegistry, recover_failed_agenda_item,
        validate_ownership_boundary,
    };

    fn worker_card() -> WorkerCard {
        WorkerCard {
            worker_id: "worker-evaluator-1".to_string(),
            worker_role: WorkerRole::EvaluatorWorker,
            supported_task_kinds: vec!["bounded-analysis".to_string()],
            required_worlds: vec![
                CapabilityWorld::WorkspaceObserve,
                CapabilityWorld::MemoryAccess,
            ],
            authority_ceiling: AuthorityClass::Observe,
            isolation_profile: IsolationProfile::ArtifactSandbox,
            result_contract: "bounded-evaluation-result".to_string(),
            max_concurrency: 1,
        }
    }

    fn mutable_boundary(owner_actor_ref: &str) -> OwnershipBoundary {
        OwnershipBoundary {
            boundary_id: format!("boundary-{owner_actor_ref}"),
            resource_scope: "workspace-root".to_string(),
            mode: OwnershipMode::ExclusiveMutable,
            owner_actor_ref: owner_actor_ref.to_string(),
        }
    }

    fn failure_message(message_class: MessageArtifactClass) -> MessageArtifact {
        MessageArtifact {
            message_id: format!("message-{message_class:?}"),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            task_id: "task-parent".to_string(),
            sender_actor_ref: "worker-evaluator-1".to_string(),
            receiver_actor_ref: "session-1".to_string(),
            message_class,
            payload_summary: "worker failure signal".to_string(),
            referenced_artifacts: Vec::new(),
            status: MessageArtifactStatus::Received,
        }
    }

    #[test]
    fn task_graph_dependency_gates_agenda_readiness() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![
                AgendaItem::new(
                    "agenda-parent",
                    "task-parent",
                    "bounded-analysis",
                    Vec::new(),
                    mutable_boundary("supervisor-1"),
                ),
                AgendaItem::new(
                    "agenda-child",
                    "task-child",
                    "bounded-analysis",
                    vec!["task-parent".to_string()],
                    mutable_boundary("supervisor-1"),
                ),
            ],
        );

        assert_eq!(
            task_graph.agenda_item("agenda-parent").unwrap().status,
            AgendaStatus::Ready
        );
        assert_eq!(
            task_graph.agenda_item("agenda-child").unwrap().status,
            AgendaStatus::PendingDependencies
        );

        task_graph.refresh_ready_states(&["task-parent".to_string()]);

        assert_eq!(
            task_graph.agenda_item("agenda-child").unwrap().status,
            AgendaStatus::Ready
        );
    }

    #[test]
    fn worker_registry_routes_to_matching_worker_card() {
        let mut registry = WorkerRegistry::default();
        registry.register(worker_card());

        let decision = registry
            .select_worker(
                "bounded-analysis",
                &[
                    CapabilityWorld::WorkspaceObserve,
                    CapabilityWorld::MemoryAccess,
                ],
                &AuthorityClass::Observe,
                &IsolationProfile::ReadOnlyInspect,
            )
            .unwrap();

        assert_eq!(decision.worker_id, "worker-evaluator-1");
    }

    #[test]
    fn exclusive_mutable_ownership_conflicts_are_rejected() {
        let existing_boundaries = vec![mutable_boundary("worker-1")];
        let error =
            validate_ownership_boundary(&existing_boundaries, &mutable_boundary("worker-2"))
                .unwrap_err();

        assert_eq!(
            error,
            OrchestrationError::OwnershipConflict {
                resource_scope: "workspace-root".to_string(),
                existing_owner: "worker-1".to_string(),
                requested_owner: "worker-2".to_string(),
            }
        );
    }

    #[test]
    fn synthesis_handoff_closes_dispatched_agenda_item() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();

        let synthesis_handoff = SynthesisHandoff {
            handoff_id: "handoff-1".to_string(),
            task_id: "task-parent".to_string(),
            worker_output_refs: vec!["worker-result-1".to_string()],
            supervisor_summary: "bounded result accepted".to_string(),
            next_action: "complete-task".to_string(),
            closure_decision: SynthesisClosureDecision::Complete,
        };

        task_graph
            .apply_synthesis_handoff("agenda-parent", &synthesis_handoff)
            .unwrap();

        let agenda_item = task_graph.agenda_item("agenda-parent").unwrap();
        assert_eq!(agenda_item.status, AgendaStatus::Completed);
        assert_eq!(agenda_item.output_refs, vec!["worker-result-1".to_string()]);
    }

    #[test]
    fn merge_task_becomes_ready_after_two_worker_agenda_items_complete() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![
                AgendaItem::new(
                    "agenda-observe",
                    "task-observe",
                    "workspace-observe",
                    Vec::new(),
                    OwnershipBoundary {
                        boundary_id: "boundary-observe".to_string(),
                        resource_scope: "workspace-root".to_string(),
                        mode: OwnershipMode::ReadOnlyFanOut,
                        owner_actor_ref: "supervisor-1".to_string(),
                    },
                ),
                AgendaItem::new(
                    "agenda-evaluate",
                    "task-evaluate",
                    "history-evaluate",
                    Vec::new(),
                    OwnershipBoundary {
                        boundary_id: "boundary-evaluate".to_string(),
                        resource_scope: "pointer-index".to_string(),
                        mode: OwnershipMode::ReadOnlyFanOut,
                        owner_actor_ref: "supervisor-1".to_string(),
                    },
                ),
                AgendaItem::new(
                    "agenda-merge",
                    "task-merge",
                    "merge-findings",
                    vec!["task-observe".to_string(), "task-evaluate".to_string()],
                    OwnershipBoundary {
                        boundary_id: "boundary-merge".to_string(),
                        resource_scope: "workspace-root".to_string(),
                        mode: OwnershipMode::MergeRequired,
                        owner_actor_ref: "supervisor-1".to_string(),
                    },
                ),
            ],
        );

        task_graph
            .mark_dispatched("agenda-observe", "worker-observer-1")
            .unwrap();
        task_graph
            .apply_synthesis_handoff(
                "agenda-observe",
                &SynthesisHandoff {
                    handoff_id: "handoff-observe".to_string(),
                    task_id: "task-observe".to_string(),
                    worker_output_refs: vec!["observe-result".to_string()],
                    supervisor_summary: "observe complete".to_string(),
                    next_action: "continue".to_string(),
                    closure_decision: SynthesisClosureDecision::Complete,
                },
            )
            .unwrap();
        task_graph
            .mark_dispatched("agenda-evaluate", "worker-evaluator-1")
            .unwrap();
        task_graph
            .apply_synthesis_handoff(
                "agenda-evaluate",
                &SynthesisHandoff {
                    handoff_id: "handoff-evaluate".to_string(),
                    task_id: "task-evaluate".to_string(),
                    worker_output_refs: vec!["evaluate-result".to_string()],
                    supervisor_summary: "evaluation complete".to_string(),
                    next_action: "continue".to_string(),
                    closure_decision: SynthesisClosureDecision::Complete,
                },
            )
            .unwrap();

        task_graph.refresh_ready_states(&["task-observe".to_string(), "task-evaluate".to_string()]);

        assert_eq!(
            task_graph.agenda_item("agenda-merge").unwrap().status,
            AgendaStatus::Ready
        );
    }

    #[test]
    fn orphaned_dispatch_recovery_requeues_dispatched_agenda_item() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();

        let recovered = task_graph.recover_orphaned_dispatches(&[]);

        assert_eq!(recovered, vec!["agenda-parent".to_string()]);
        let agenda_item = task_graph.agenda_item("agenda-parent").unwrap();
        assert_eq!(agenda_item.status, AgendaStatus::Ready);
        assert_eq!(agenda_item.assigned_worker_id, None);
    }

    #[test]
    fn orphaned_dispatch_recovery_preserves_awaiting_synthesis_outputs() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();
        task_graph
            .apply_synthesis_handoff(
                "agenda-parent",
                &SynthesisHandoff {
                    handoff_id: "handoff-1".to_string(),
                    task_id: "task-parent".to_string(),
                    worker_output_refs: vec!["worker-result-1".to_string()],
                    supervisor_summary: "bounded result accepted".to_string(),
                    next_action: "continue".to_string(),
                    closure_decision: SynthesisClosureDecision::Continue,
                },
            )
            .unwrap();
        let agenda_item = task_graph
            .agenda_items
            .iter_mut()
            .find(|agenda_item| agenda_item.agenda_item_id == "agenda-parent")
            .unwrap();
        agenda_item.status = AgendaStatus::AwaitingSynthesis;

        let recovered = task_graph.recover_orphaned_dispatches(&[]);

        assert_eq!(recovered, vec!["agenda-parent".to_string()]);
        let agenda_item = task_graph.agenda_item("agenda-parent").unwrap();
        assert_eq!(agenda_item.status, AgendaStatus::AwaitingSynthesis);
        assert_eq!(agenda_item.assigned_worker_id, None);
        assert_eq!(agenda_item.output_refs, vec!["worker-result-1".to_string()]);
    }

    #[test]
    fn failed_worker_is_requeued_when_budget_allows_retry() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();
        let mut failure_budget = FailureBudget::default();

        let disposition = recover_failed_agenda_item(
            &mut task_graph,
            "agenda-parent",
            &failure_message(MessageArtifactClass::ExceptionMessage),
            &mut failure_budget,
        )
        .unwrap();

        assert_eq!(disposition, WorkerRecoveryDisposition::Requeued);
        assert_eq!(
            task_graph.agenda_item("agenda-parent").unwrap().status,
            AgendaStatus::Ready
        );
        assert_eq!(failure_budget.session_failures, 1);
        assert_eq!(failure_budget.task_failures, 1);
    }

    #[test]
    fn failed_worker_hard_stops_when_budget_is_exhausted() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();
        let mut failure_budget = FailureBudget {
            max_session_failures: 1,
            max_task_failures: 1,
            ..FailureBudget::default()
        };

        let disposition = recover_failed_agenda_item(
            &mut task_graph,
            "agenda-parent",
            &failure_message(MessageArtifactClass::ExceptionMessage),
            &mut failure_budget,
        )
        .unwrap();

        assert_eq!(
            disposition,
            WorkerRecoveryDisposition::HardStop(StopCondition::FailureBudgetExhausted)
        );
        assert_eq!(
            task_graph.agenda_item("agenda-parent").unwrap().status,
            AgendaStatus::Failed
        );
    }

    #[test]
    fn failed_worker_with_outputs_requires_supervisor_synthesis() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();
        task_graph
            .agenda_items
            .iter_mut()
            .find(|agenda_item| agenda_item.agenda_item_id == "agenda-parent")
            .unwrap()
            .output_refs
            .push("worker-partial-output-1".to_string());
        let mut failure_budget = FailureBudget::default();

        let disposition = recover_failed_agenda_item(
            &mut task_graph,
            "agenda-parent",
            &failure_message(MessageArtifactClass::ExceptionMessage),
            &mut failure_budget,
        )
        .unwrap();

        assert_eq!(disposition, WorkerRecoveryDisposition::AwaitingSynthesis);
        assert_eq!(
            task_graph.agenda_item("agenda-parent").unwrap().status,
            AgendaStatus::AwaitingSynthesis
        );
        assert_eq!(failure_budget.no_progress_turns, 1);
    }

    #[test]
    fn risk_message_is_policy_non_retryable_hard_stop() {
        let mut task_graph = TaskGraph::new(
            "task-root",
            vec![AgendaItem::new(
                "agenda-parent",
                "task-parent",
                "bounded-analysis",
                Vec::new(),
                mutable_boundary("supervisor-1"),
            )],
        );
        task_graph
            .mark_dispatched("agenda-parent", "worker-evaluator-1")
            .unwrap();
        let mut failure_budget = FailureBudget::default();

        let disposition = recover_failed_agenda_item(
            &mut task_graph,
            "agenda-parent",
            &failure_message(MessageArtifactClass::RiskMessage),
            &mut failure_budget,
        )
        .unwrap();

        assert_eq!(
            disposition,
            WorkerRecoveryDisposition::HardStop(StopCondition::GovernanceHardStop)
        );
        assert_eq!(
            failure_budget.record_failure(RetryClass::PolicyNonRetryable),
            Some(StopCondition::GovernanceHardStop)
        );
    }
}
