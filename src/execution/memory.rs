use crate::execution::checkpoint::RunCheckpoint;
use crate::execution::governance::{ApprovalDecision, ApprovalRequest, AuditRecord};
use crate::execution::{
    CampaignId, ContradictionId, EpochId, MemoryArtifactId, MemoryUpdateProposalId, PointerIndexId,
    SessionId, TaskId, TopicBundleId, TranscriptSliceId,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryArtifactClass {
    PointerIndexArtifact,
    TopicBundleArtifact,
    TranscriptSliceArtifact,
    ContradictionRecordArtifact,
    MemoryUpdateProposalArtifact,
    ApprovalRequestArtifact,
    ApprovalDecisionArtifact,
    AuditRecordArtifact,
    CheckpointArtifact,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryScope {
    Global,
    Campaign(CampaignId),
    Epoch(EpochId),
    Session(SessionId),
    Task(TaskId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TopicBundleClass {
    WorkspaceMap,
    ArchitectureDecision,
    CampaignOperatingNotes,
    CapabilityNotes,
    GovernanceNotes,
    OpenTechnicalRisks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompactionStage {
    ToolResultBudgeting,
    SnipCompaction,
    Microcompact,
    ContextCollapse,
    AutoCompact,
    ReactiveCompact,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContradictionResolutionState {
    Unresolved,
    Verifying,
    Resolved,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryUpdateStatus {
    Proposed,
    VerifiedAccepted,
    Rejected,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsolidationJobStatus {
    Planned,
    Completed,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerIndex {
    pub index_id: PointerIndexId,
    pub scope: MemoryScope,
    pub entry_refs: Vec<String>,
    pub contested_refs: Vec<ContradictionId>,
    pub critical_refs: Vec<String>,
    pub governance_constraints: Vec<String>,
    pub open_task_refs: Vec<TaskId>,
    pub updated_at: String,
}

impl PointerIndex {
    pub fn compact(&self, stage: CompactionStage) -> Self {
        let mut compacted = self.clone();

        if !matches!(stage, CompactionStage::ToolResultBudgeting) {
            compacted.entry_refs.retain(|entry_ref| {
                self.critical_refs
                    .iter()
                    .any(|critical| critical == entry_ref)
                    || self
                        .open_task_refs
                        .iter()
                        .any(|task_id| task_id == entry_ref)
                    || !entry_ref.starts_with("transient:")
            });
        }

        compacted.entry_refs.sort();
        compacted.entry_refs.dedup();
        compacted
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopicBundle {
    pub bundle_id: TopicBundleId,
    pub bundle_class: TopicBundleClass,
    pub scope: MemoryScope,
    pub summary: String,
    pub evidence_refs: Vec<String>,
    pub freshness_policy: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSlice {
    pub slice_id: TranscriptSliceId,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    pub referenced_artifacts: Vec<String>,
    pub summary: String,
    pub excerpts: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptSliceQuery {
    pub campaign_id: Option<CampaignId>,
    pub epoch_id: Option<EpochId>,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    pub artifact_ref: Option<String>,
    pub search_term: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContradictionRecord {
    pub contradiction_id: ContradictionId,
    pub claim_refs: Vec<String>,
    pub resolution_state: ContradictionResolutionState,
    pub resolution_path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryUpdateProposal {
    pub proposal_id: MemoryUpdateProposalId,
    pub pointer_index_ref: Option<PointerIndexId>,
    pub bundle_class: TopicBundleClass,
    pub scope: MemoryScope,
    pub proposed_summary: String,
    pub evidence_refs: Vec<String>,
    pub verification_refs: Vec<String>,
    pub status: MemoryUpdateStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsolidationJob {
    pub job_id: String,
    pub pointer_index_ref: PointerIndexId,
    pub input_bundle_refs: Vec<TopicBundleId>,
    pub output_bundle_id: TopicBundleId,
    pub output_bundle_class: TopicBundleClass,
    pub output_scope: MemoryScope,
    pub output_summary: String,
    pub freshness_policy: String,
    pub status: ConsolidationJobStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryArtifactPayload {
    PointerIndex(PointerIndex),
    TopicBundle(TopicBundle),
    TranscriptSlice(TranscriptSlice),
    ContradictionRecord(ContradictionRecord),
    MemoryUpdateProposal(MemoryUpdateProposal),
    ApprovalRequest(ApprovalRequest),
    ApprovalDecision(ApprovalDecision),
    AuditRecord(AuditRecord),
    Checkpoint(RunCheckpoint),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryArtifact {
    pub artifact_id: MemoryArtifactId,
    pub class: MemoryArtifactClass,
    pub campaign_id: CampaignId,
    pub epoch_id: EpochId,
    pub session_id: SessionId,
    pub task_id: Option<TaskId>,
    pub related_ref: String,
    pub summary: String,
    pub payload: MemoryArtifactPayload,
}

impl MemoryArtifact {
    pub fn approval_request(
        artifact_id: impl Into<MemoryArtifactId>,
        approval_request: ApprovalRequest,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            class: MemoryArtifactClass::ApprovalRequestArtifact,
            campaign_id: approval_request.campaign_id.clone(),
            epoch_id: approval_request.epoch_id.clone(),
            session_id: approval_request.session_id.clone(),
            task_id: Some(approval_request.task_id.clone()),
            related_ref: approval_request.approval_request_id.clone(),
            summary: summary.into(),
            payload: MemoryArtifactPayload::ApprovalRequest(approval_request),
        }
    }

    pub fn approval_decision(
        artifact_id: impl Into<MemoryArtifactId>,
        approval_decision: ApprovalDecision,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            class: MemoryArtifactClass::ApprovalDecisionArtifact,
            campaign_id: approval_decision.campaign_id.clone(),
            epoch_id: approval_decision.epoch_id.clone(),
            session_id: approval_decision.session_id.clone(),
            task_id: Some(approval_decision.task_id.clone()),
            related_ref: approval_decision.approval_request_id.clone(),
            summary: summary.into(),
            payload: MemoryArtifactPayload::ApprovalDecision(approval_decision),
        }
    }

    pub fn audit_record(
        artifact_id: impl Into<MemoryArtifactId>,
        audit_record: AuditRecord,
    ) -> Self {
        let summary = audit_record.summary.clone();
        Self {
            artifact_id: artifact_id.into(),
            class: MemoryArtifactClass::AuditRecordArtifact,
            campaign_id: audit_record.campaign_id.clone(),
            epoch_id: audit_record.epoch_id.clone(),
            session_id: audit_record.session_id.clone(),
            task_id: audit_record.task_id.clone(),
            related_ref: audit_record.related_ref.clone(),
            summary,
            payload: MemoryArtifactPayload::AuditRecord(audit_record),
        }
    }

    pub fn checkpoint(
        artifact_id: impl Into<MemoryArtifactId>,
        checkpoint: RunCheckpoint,
        summary: impl Into<String>,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            class: MemoryArtifactClass::CheckpointArtifact,
            campaign_id: checkpoint.session_header.campaign_id.clone(),
            epoch_id: checkpoint.session_header.epoch_id.clone(),
            session_id: checkpoint.session_header.session_id.clone(),
            task_id: checkpoint.active_task_refs.first().cloned(),
            related_ref: checkpoint.checkpoint_id.clone(),
            summary: summary.into(),
            payload: MemoryArtifactPayload::Checkpoint(checkpoint),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryWriteError {
    PointerIndexNotFound { pointer_index_id: PointerIndexId },
    UpdateProposalNotFound { proposal_id: MemoryUpdateProposalId },
    UpdateProposalUnverified { proposal_id: MemoryUpdateProposalId },
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryStore {
    pub artifacts: Vec<MemoryArtifact>,
    pub pointer_indexes: Vec<PointerIndex>,
    pub topic_bundles: Vec<TopicBundle>,
    pub transcript_slices: Vec<TranscriptSlice>,
    pub contradiction_records: Vec<ContradictionRecord>,
    pub memory_update_proposals: Vec<MemoryUpdateProposal>,
    pub consolidation_jobs: Vec<ConsolidationJob>,
}

impl MemoryStore {
    pub fn append(&mut self, artifact: MemoryArtifact) -> MemoryArtifactId {
        let artifact_id = artifact.artifact_id.clone();
        self.artifacts.push(artifact);
        artifact_id
    }

    pub fn get(&self, artifact_id: &str) -> Option<&MemoryArtifact> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == artifact_id)
    }

    pub fn artifacts_for_task(&self, task_id: &str) -> Vec<&MemoryArtifact> {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.task_id.as_deref() == Some(task_id))
            .collect()
    }

    pub fn artifacts_for_related_ref(&self, related_ref: &str) -> Vec<&MemoryArtifact> {
        self.artifacts
            .iter()
            .filter(|artifact| artifact.related_ref == related_ref)
            .collect()
    }

    pub fn approval_lineage(&self, approval_request_id: &str) -> Vec<&MemoryArtifact> {
        let mut lineage: Vec<&MemoryArtifact> = self
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.related_ref == approval_request_id
                    && matches!(
                        artifact.class,
                        MemoryArtifactClass::ApprovalRequestArtifact
                            | MemoryArtifactClass::ApprovalDecisionArtifact
                            | MemoryArtifactClass::AuditRecordArtifact
                    )
            })
            .collect();
        lineage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        lineage
    }

    pub fn checkpoint_lineage(&self, checkpoint_id: &str) -> Vec<&MemoryArtifact> {
        let mut lineage: Vec<&MemoryArtifact> = self
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.related_ref == checkpoint_id
                    && matches!(
                        artifact.class,
                        MemoryArtifactClass::CheckpointArtifact
                            | MemoryArtifactClass::AuditRecordArtifact
                    )
            })
            .collect();
        lineage.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
        lineage
    }

    pub(crate) fn has_ref_prefix(&self, prefix: &str) -> bool {
        self.artifacts.iter().any(|artifact| {
            artifact.artifact_id.starts_with(prefix)
                || artifact.related_ref.starts_with(prefix)
                || matches!(
                    artifact.payload,
                    MemoryArtifactPayload::AuditRecord(ref audit_record)
                        if audit_record.audit_record_id.starts_with(prefix)
                            || audit_record.related_ref.starts_with(prefix)
                )
        }) || self.topic_bundles.iter().any(|bundle| {
            bundle.bundle_id.starts_with(prefix)
                || bundle
                    .evidence_refs
                    .iter()
                    .any(|evidence_ref| evidence_ref.starts_with(prefix))
        }) || self.transcript_slices.iter().any(|slice| {
            slice.slice_id.starts_with(prefix)
                || slice
                    .referenced_artifacts
                    .iter()
                    .any(|reference| reference.starts_with(prefix))
        }) || self.pointer_indexes.iter().any(|pointer_index| {
            pointer_index
                .entry_refs
                .iter()
                .any(|reference| reference.starts_with(prefix))
                || pointer_index
                    .critical_refs
                    .iter()
                    .any(|reference| reference.starts_with(prefix))
        }) || self.memory_update_proposals.iter().any(|proposal| {
            proposal
                .evidence_refs
                .iter()
                .any(|reference| reference.starts_with(prefix))
                || proposal
                    .verification_refs
                    .iter()
                    .any(|reference| reference.starts_with(prefix))
        }) || self.consolidation_jobs.iter().any(|job| {
            job.job_id.starts_with(prefix)
                || job.output_bundle_id.starts_with(prefix)
                || job
                    .input_bundle_refs
                    .iter()
                    .any(|reference| reference.starts_with(prefix))
        })
    }

    pub(crate) fn has_bundle_with_evidence_prefixes(
        &self,
        bundle_class: TopicBundleClass,
        prefixes: &[&str],
    ) -> bool {
        self.topic_bundles.iter().any(|bundle| {
            bundle.bundle_class == bundle_class
                && prefixes.iter().all(|prefix| {
                    bundle.bundle_id.starts_with(prefix)
                        || bundle
                            .evidence_refs
                            .iter()
                            .any(|evidence_ref| evidence_ref.starts_with(prefix))
                })
        })
    }

    pub(crate) fn has_transcript_references_with_prefixes(&self, prefixes: &[&str]) -> bool {
        self.transcript_slices.iter().any(|slice| {
            prefixes.iter().all(|prefix| {
                slice
                    .referenced_artifacts
                    .iter()
                    .any(|reference| reference.starts_with(prefix))
            })
        })
    }

    pub(crate) fn has_resolved_contradiction(&self) -> bool {
        self.contradiction_records
            .iter()
            .any(|record| record.resolution_state == ContradictionResolutionState::Resolved)
    }

    pub fn insert_pointer_index(&mut self, pointer_index: PointerIndex) {
        self.pointer_indexes.push(pointer_index);
    }

    pub fn load_pointer_index(&self, pointer_index_id: &str) -> Option<&PointerIndex> {
        self.pointer_indexes
            .iter()
            .find(|pointer_index| pointer_index.index_id == pointer_index_id)
    }

    pub fn pointer_index_mut(&mut self, pointer_index_id: &str) -> Option<&mut PointerIndex> {
        self.pointer_indexes
            .iter_mut()
            .find(|pointer_index| pointer_index.index_id == pointer_index_id)
    }

    pub fn add_topic_bundle(&mut self, topic_bundle: TopicBundle) {
        self.topic_bundles.push(topic_bundle);
    }

    pub fn topic_bundle(&self, bundle_id: &str) -> Option<&TopicBundle> {
        self.topic_bundles
            .iter()
            .find(|topic_bundle| topic_bundle.bundle_id == bundle_id)
    }

    pub fn add_transcript_slice(&mut self, transcript_slice: TranscriptSlice) {
        self.transcript_slices.push(transcript_slice);
    }

    pub fn retrieve_transcript_slices(
        &self,
        query: &TranscriptSliceQuery,
    ) -> Vec<&TranscriptSlice> {
        self.transcript_slices
            .iter()
            .filter(|transcript_slice| {
                query
                    .campaign_id
                    .as_ref()
                    .is_none_or(|campaign_id| &transcript_slice.campaign_id == campaign_id)
                    && query
                        .epoch_id
                        .as_ref()
                        .is_none_or(|epoch_id| &transcript_slice.epoch_id == epoch_id)
                    && query.session_id.as_ref().is_none_or(|session_id| {
                        transcript_slice.session_id.as_ref() == Some(session_id)
                    })
                    && query
                        .task_id
                        .as_ref()
                        .is_none_or(|task_id| transcript_slice.task_id.as_ref() == Some(task_id))
                    && query.artifact_ref.as_ref().is_none_or(|artifact_ref| {
                        transcript_slice
                            .referenced_artifacts
                            .iter()
                            .any(|candidate| candidate == artifact_ref)
                    })
                    && query.search_term.as_ref().is_none_or(|search_term| {
                        transcript_slice.summary.contains(search_term)
                            || transcript_slice
                                .excerpts
                                .iter()
                                .any(|excerpt| excerpt.contains(search_term))
                    })
            })
            .collect()
    }

    pub fn propose_memory_update(&mut self, proposal: MemoryUpdateProposal) {
        self.memory_update_proposals.push(proposal);
    }

    pub fn accept_memory_update(
        &mut self,
        proposal_id: &str,
        bundle_id: impl Into<TopicBundleId>,
        freshness_policy: impl Into<String>,
    ) -> Result<TopicBundleId, MemoryWriteError> {
        let proposal_index = self
            .memory_update_proposals
            .iter()
            .position(|proposal| proposal.proposal_id == proposal_id)
            .ok_or_else(|| MemoryWriteError::UpdateProposalNotFound {
                proposal_id: proposal_id.to_string(),
            })?;

        if self.memory_update_proposals[proposal_index]
            .verification_refs
            .is_empty()
        {
            return Err(MemoryWriteError::UpdateProposalUnverified {
                proposal_id: proposal_id.to_string(),
            });
        }

        self.memory_update_proposals[proposal_index].status = MemoryUpdateStatus::VerifiedAccepted;
        let proposal = self.memory_update_proposals[proposal_index].clone();
        let bundle_id = bundle_id.into();
        let mut evidence_refs = proposal.evidence_refs.clone();
        evidence_refs.extend(proposal.verification_refs.clone());

        self.topic_bundles.push(TopicBundle {
            bundle_id: bundle_id.clone(),
            bundle_class: proposal.bundle_class,
            scope: proposal.scope.clone(),
            summary: proposal.proposed_summary.clone(),
            evidence_refs,
            freshness_policy: freshness_policy.into(),
        });

        if let Some(pointer_index_ref) = proposal.pointer_index_ref {
            let pointer_index = self.pointer_index_mut(&pointer_index_ref).ok_or(
                MemoryWriteError::PointerIndexNotFound {
                    pointer_index_id: pointer_index_ref,
                },
            )?;
            if !pointer_index
                .entry_refs
                .iter()
                .any(|entry| entry == &bundle_id)
            {
                pointer_index.entry_refs.push(bundle_id.clone());
            }
            pointer_index.updated_at = format!("verified:{proposal_id}");
        }

        if let Some(pointer_index_ref) = self.memory_update_proposals[proposal_index]
            .pointer_index_ref
            .clone()
        {
            self.compact_pointer_index_preserving_evidence(
                &pointer_index_ref,
                CompactionStage::ReactiveCompact,
            )?;
        }

        Ok(bundle_id)
    }

    pub fn register_contradiction(
        &mut self,
        contradiction_id: impl Into<ContradictionId>,
        claim_refs: Vec<String>,
        resolution_path: impl Into<String>,
        pointer_index_ref: Option<&str>,
    ) -> ContradictionRecord {
        let contradiction_record = ContradictionRecord {
            contradiction_id: contradiction_id.into(),
            claim_refs,
            resolution_state: ContradictionResolutionState::Unresolved,
            resolution_path: resolution_path.into(),
        };

        if let Some(pointer_index_ref) = pointer_index_ref {
            if let Some(pointer_index) = self.pointer_index_mut(pointer_index_ref) {
                pointer_index
                    .contested_refs
                    .push(contradiction_record.contradiction_id.clone());
            }
        }

        self.contradiction_records
            .push(contradiction_record.clone());
        contradiction_record
    }

    pub fn resolve_contradiction(
        &mut self,
        contradiction_id: &str,
        pointer_index_ref: Option<&str>,
    ) -> bool {
        let Some(contradiction_record) = self
            .contradiction_records
            .iter_mut()
            .find(|contradiction_record| contradiction_record.contradiction_id == contradiction_id)
        else {
            return false;
        };

        contradiction_record.resolution_state = ContradictionResolutionState::Resolved;

        if let Some(pointer_index_ref) = pointer_index_ref {
            if let Some(pointer_index) = self.pointer_index_mut(pointer_index_ref) {
                pointer_index
                    .contested_refs
                    .retain(|contested_ref| contested_ref != contradiction_id);
            }
        }

        true
    }

    pub fn run_consolidation_job(
        &mut self,
        mut consolidation_job: ConsolidationJob,
    ) -> Result<TopicBundleId, MemoryWriteError> {
        let mut evidence_refs = Vec::new();
        for input_bundle_ref in &consolidation_job.input_bundle_refs {
            if let Some(topic_bundle) = self.topic_bundle(input_bundle_ref) {
                evidence_refs.extend(topic_bundle.evidence_refs.clone());
            }
        }

        let output_bundle_id = consolidation_job.output_bundle_id.clone();
        self.topic_bundles.push(TopicBundle {
            bundle_id: output_bundle_id.clone(),
            bundle_class: consolidation_job.output_bundle_class,
            scope: consolidation_job.output_scope.clone(),
            summary: consolidation_job.output_summary.clone(),
            evidence_refs,
            freshness_policy: consolidation_job.freshness_policy.clone(),
        });

        let pointer_index = self
            .pointer_index_mut(&consolidation_job.pointer_index_ref)
            .ok_or_else(|| MemoryWriteError::PointerIndexNotFound {
                pointer_index_id: consolidation_job.pointer_index_ref.clone(),
            })?;

        pointer_index
            .entry_refs
            .retain(|entry_ref| !consolidation_job.input_bundle_refs.contains(entry_ref));
        if !pointer_index
            .entry_refs
            .iter()
            .any(|entry_ref| entry_ref == &output_bundle_id)
        {
            pointer_index.entry_refs.push(output_bundle_id.clone());
        }
        pointer_index.updated_at = format!("consolidated:{}", consolidation_job.job_id);

        consolidation_job.status = ConsolidationJobStatus::Completed;
        let pointer_index_ref = consolidation_job.pointer_index_ref.clone();
        self.consolidation_jobs.push(consolidation_job);
        self.compact_pointer_index_preserving_evidence(
            &pointer_index_ref,
            CompactionStage::ContextCollapse,
        )?;

        Ok(output_bundle_id)
    }

    pub fn persist_checkpoint_artifact(
        &mut self,
        artifact_id: impl Into<MemoryArtifactId>,
        checkpoint: RunCheckpoint,
        summary: impl Into<String>,
    ) -> MemoryArtifactId {
        self.append(MemoryArtifact::checkpoint(artifact_id, checkpoint, summary))
    }

    fn compact_pointer_index_preserving_evidence(
        &mut self,
        pointer_index_ref: &str,
        stage: CompactionStage,
    ) -> Result<(), MemoryWriteError> {
        let evidence_refs = self.lineage_critical_refs();
        let pointer_index = self.pointer_index_mut(pointer_index_ref).ok_or_else(|| {
            MemoryWriteError::PointerIndexNotFound {
                pointer_index_id: pointer_index_ref.to_string(),
            }
        })?;

        pointer_index.critical_refs.extend(evidence_refs);
        pointer_index.critical_refs.sort();
        pointer_index.critical_refs.dedup();

        let compacted = pointer_index.compact(stage);
        *pointer_index = compacted;

        Ok(())
    }

    fn lineage_critical_refs(&self) -> Vec<String> {
        let mut refs = HashSet::new();

        for artifact in &self.artifacts {
            if matches!(
                artifact.class,
                MemoryArtifactClass::CheckpointArtifact
                    | MemoryArtifactClass::ApprovalRequestArtifact
                    | MemoryArtifactClass::ApprovalDecisionArtifact
                    | MemoryArtifactClass::AuditRecordArtifact
            ) {
                refs.insert(artifact.artifact_id.clone());
                refs.insert(artifact.related_ref.clone());
            }
        }

        for contradiction_record in &self.contradiction_records {
            refs.insert(contradiction_record.contradiction_id.clone());
            for claim_ref in &contradiction_record.claim_refs {
                refs.insert(claim_ref.clone());
            }
        }

        for transcript_slice in &self.transcript_slices {
            for artifact_ref in &transcript_slice.referenced_artifacts {
                refs.insert(artifact_ref.clone());
            }
        }

        for topic_bundle in &self.topic_bundles {
            for evidence_ref in &topic_bundle.evidence_refs {
                refs.insert(evidence_ref.clone());
            }
        }

        let mut refs = refs.into_iter().collect::<Vec<_>>();
        refs.sort();
        refs
    }
}

#[cfg(test)]
mod tests {
    use crate::execution::AuthorityClass;
    use crate::execution::checkpoint::RunCheckpoint;
    use crate::execution::failure_budget::FailureBudget;
    use crate::execution::governance::{
        ApprovalDecision, ApprovalRequest, AuditRecord, AuditRecordClass,
    };
    use crate::execution::session::{ActorKind, ExecutionSession, ExecutionSessionHeader};

    use super::{
        CompactionStage, ConsolidationJob, ConsolidationJobStatus, MemoryArtifact,
        MemoryArtifactClass, MemoryScope, MemoryStore, MemoryUpdateProposal, MemoryUpdateStatus,
        MemoryWriteError, PointerIndex, TopicBundle, TopicBundleClass, TranscriptSlice,
        TranscriptSliceQuery,
    };

    fn checkpoint() -> RunCheckpoint {
        let session = ExecutionSession::new(ExecutionSessionHeader {
            session_id: "session-1".to_string(),
            actor_kind: ActorKind::Supervisor,
            actor_id: "supervisor-alpha".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            capability_envelope_ref: "envelope-1".to_string(),
            parent_session_id: None,
        });

        RunCheckpoint::capture(
            "checkpoint-1",
            &session,
            None,
            Vec::new(),
            vec!["pointer-index-1".to_string()],
            FailureBudget::default().snapshot(),
            Vec::new(),
        )
    }

    #[test]
    fn pointer_index_compaction_preserves_governance_and_open_tasks() {
        let pointer_index = PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec![
                "transient:large-tool-output".to_string(),
                "task-1".to_string(),
                "bundle-architecture".to_string(),
            ],
            contested_refs: vec!["contradiction-1".to_string()],
            critical_refs: vec!["bundle-architecture".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        };

        let compacted = pointer_index.compact(CompactionStage::ContextCollapse);

        assert!(
            !compacted
                .entry_refs
                .iter()
                .any(|entry_ref| entry_ref == "transient:large-tool-output")
        );
        assert!(
            compacted
                .entry_refs
                .iter()
                .any(|entry_ref| entry_ref == "task-1")
        );
        assert!(
            compacted
                .governance_constraints
                .iter()
                .any(|constraint| constraint.contains("human approval"))
        );
    }

    #[test]
    fn transcript_slice_retrieval_is_targeted() {
        let mut memory_store = MemoryStore::default();
        memory_store.add_transcript_slice(TranscriptSlice {
            slice_id: "slice-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            referenced_artifacts: vec!["worker-result-1".to_string()],
            summary: "worker returned bounded result".to_string(),
            excerpts: vec!["bounded result accepted".to_string()],
        });
        memory_store.add_transcript_slice(TranscriptSlice {
            slice_id: "slice-2".to_string(),
            campaign_id: "campaign-2".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("session-2".to_string()),
            task_id: Some("task-2".to_string()),
            referenced_artifacts: vec!["worker-result-2".to_string()],
            summary: "unrelated campaign".to_string(),
            excerpts: vec!["ignore me".to_string()],
        });

        let slices = memory_store.retrieve_transcript_slices(&TranscriptSliceQuery {
            campaign_id: Some("campaign-1".to_string()),
            task_id: Some("task-1".to_string()),
            search_term: Some("bounded".to_string()),
            ..TranscriptSliceQuery::default()
        });

        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].slice_id, "slice-1");
    }

    #[test]
    fn verified_memory_write_updates_pointer_index() {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec!["bundle-existing".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["bundle-existing".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });
        memory_store.propose_memory_update(MemoryUpdateProposal {
            proposal_id: "memory-proposal-1".to_string(),
            pointer_index_ref: Some("pointer-index-1".to_string()),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Task("task-1".to_string()),
            proposed_summary: "bounded worker flow completed successfully".to_string(),
            evidence_refs: vec!["worker-result-1".to_string()],
            verification_refs: vec!["checkpoint-1".to_string()],
            status: MemoryUpdateStatus::Proposed,
        });

        let bundle_id = memory_store
            .accept_memory_update(
                "memory-proposal-1",
                "bundle-worker-flow",
                "verified-by-checkpoint",
            )
            .unwrap();

        assert_eq!(bundle_id, "bundle-worker-flow");
        assert!(
            memory_store
                .load_pointer_index("pointer-index-1")
                .unwrap()
                .entry_refs
                .iter()
                .any(|entry_ref| entry_ref == "bundle-worker-flow")
        );
        assert!(
            memory_store
                .load_pointer_index("pointer-index-1")
                .unwrap()
                .critical_refs
                .iter()
                .any(|critical_ref| critical_ref == "worker-result-1")
        );
        assert!(
            memory_store
                .load_pointer_index("pointer-index-1")
                .unwrap()
                .critical_refs
                .iter()
                .any(|critical_ref| critical_ref == "checkpoint-1")
        );
    }

    #[test]
    fn unverified_memory_write_is_rejected() {
        let mut memory_store = MemoryStore::default();
        memory_store.propose_memory_update(MemoryUpdateProposal {
            proposal_id: "memory-proposal-1".to_string(),
            pointer_index_ref: None,
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Task("task-1".to_string()),
            proposed_summary: "unverified claim".to_string(),
            evidence_refs: vec!["worker-result-1".to_string()],
            verification_refs: Vec::new(),
            status: MemoryUpdateStatus::Proposed,
        });

        let error = memory_store
            .accept_memory_update(
                "memory-proposal-1",
                "bundle-worker-flow",
                "verified-by-checkpoint",
            )
            .unwrap_err();

        assert_eq!(
            error,
            MemoryWriteError::UpdateProposalUnverified {
                proposal_id: "memory-proposal-1".to_string()
            }
        );
    }

    #[test]
    fn contradiction_registration_updates_pointer_index() {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec!["bundle-existing".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["bundle-existing".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });

        let contradiction = memory_store.register_contradiction(
            "contradiction-1",
            vec!["claim-a".to_string(), "claim-b".to_string()],
            "verify against checkpoint and worker result",
            Some("pointer-index-1"),
        );

        assert_eq!(contradiction.contradiction_id, "contradiction-1");
        assert!(
            memory_store
                .load_pointer_index("pointer-index-1")
                .unwrap()
                .contested_refs
                .iter()
                .any(|contested_ref| contested_ref == "contradiction-1")
        );
    }

    #[test]
    fn resolved_contradiction_is_removed_from_pointer_index() {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec!["bundle-existing".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["bundle-existing".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });
        memory_store.register_contradiction(
            "contradiction-1",
            vec!["claim-a".to_string(), "claim-b".to_string()],
            "verify against checkpoint and worker result",
            Some("pointer-index-1"),
        );

        assert!(memory_store.resolve_contradiction("contradiction-1", Some("pointer-index-1")));
        assert!(
            memory_store
                .load_pointer_index("pointer-index-1")
                .unwrap()
                .contested_refs
                .is_empty()
        );
    }

    #[test]
    fn consolidation_job_merges_bundle_refs_and_updates_pointer_index() {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec![
                "bundle-legacy".to_string(),
                "bundle-worker-flow".to_string(),
            ],
            contested_refs: Vec::new(),
            critical_refs: vec!["bundle-legacy".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });
        memory_store.add_topic_bundle(TopicBundle {
            bundle_id: "bundle-legacy".to_string(),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            summary: "legacy context".to_string(),
            evidence_refs: vec!["checkpoint-legacy".to_string()],
            freshness_policy: "manual".to_string(),
        });
        memory_store.add_topic_bundle(TopicBundle {
            bundle_id: "bundle-worker-flow".to_string(),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Task("task-1".to_string()),
            summary: "worker flow".to_string(),
            evidence_refs: vec!["checkpoint-worker".to_string()],
            freshness_policy: "verified".to_string(),
        });

        let bundle_id = memory_store
            .run_consolidation_job(ConsolidationJob {
                job_id: "consolidation-1".to_string(),
                pointer_index_ref: "pointer-index-1".to_string(),
                input_bundle_refs: vec![
                    "bundle-legacy".to_string(),
                    "bundle-worker-flow".to_string(),
                ],
                output_bundle_id: "bundle-campaign-summary".to_string(),
                output_bundle_class: TopicBundleClass::CampaignOperatingNotes,
                output_scope: MemoryScope::Campaign("campaign-1".to_string()),
                output_summary: "campaign summary".to_string(),
                freshness_policy: "consolidated".to_string(),
                status: ConsolidationJobStatus::Planned,
            })
            .unwrap();

        assert_eq!(bundle_id, "bundle-campaign-summary");
        assert!(
            memory_store
                .load_pointer_index("pointer-index-1")
                .unwrap()
                .entry_refs
                .iter()
                .any(|entry_ref| entry_ref == "bundle-campaign-summary")
        );
        assert_eq!(
            memory_store.consolidation_jobs[0].status,
            ConsolidationJobStatus::Completed
        );
    }

    #[test]
    fn evidence_preserving_consolidation_keeps_lineage_critical_refs() {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec![
                "transient:debug-dump".to_string(),
                "bundle-legacy".to_string(),
            ],
            contested_refs: vec!["contradiction-1".to_string()],
            critical_refs: vec!["bundle-legacy".to_string()],
            governance_constraints: vec!["preserve rollback evidence".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });
        let checkpoint = checkpoint();
        let checkpoint_artifact_id = memory_store.persist_checkpoint_artifact(
            "memory-checkpoint-1",
            checkpoint.clone(),
            "checkpoint persisted for rollback review",
        );
        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "dispatch:dispatch-1:WorkspaceObserve:search",
            "workspace-root",
            AuthorityClass::Observe,
        );
        memory_store.append(MemoryArtifact::approval_request(
            "memory-approval-request-1",
            approval_request.clone(),
            "approval persisted",
        ));
        memory_store.append(MemoryArtifact::approval_decision(
            "memory-approval-decision-1",
            ApprovalDecision::granted(
                approval_request.approval_request_id.clone(),
                approval_request.campaign_id.clone(),
                approval_request.epoch_id.clone(),
                approval_request.session_id.clone(),
                approval_request.task_id.clone(),
                approval_request.action_ref.clone(),
                "operator-1",
                approval_request.scope_ref.clone(),
                Some("approved".to_string()),
            ),
            "approval decision persisted",
        ));
        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-rollback-1",
            AuditRecord::new(
                "audit-rollback-1",
                AuditRecordClass::PromotionAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "rollback-1",
                "rollback evidence recorded",
            ),
        ));
        memory_store.add_transcript_slice(TranscriptSlice {
            slice_id: "slice-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            referenced_artifacts: vec![checkpoint_artifact_id.clone(), "rollback-1".to_string()],
            summary: "rollback transcript".to_string(),
            excerpts: vec!["rollback reviewed".to_string()],
        });
        memory_store.add_topic_bundle(TopicBundle {
            bundle_id: "bundle-legacy".to_string(),
            bundle_class: TopicBundleClass::GovernanceNotes,
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            summary: "legacy governance bundle".to_string(),
            evidence_refs: vec!["rollback-1".to_string(), checkpoint_artifact_id.clone()],
            freshness_policy: "carry-forward".to_string(),
        });
        memory_store.register_contradiction(
            "contradiction-1",
            vec!["rollback-1".to_string()],
            "review rollback evidence",
            Some("pointer-index-1"),
        );

        memory_store
            .run_consolidation_job(ConsolidationJob {
                job_id: "consolidation-rollback".to_string(),
                pointer_index_ref: "pointer-index-1".to_string(),
                input_bundle_refs: vec!["bundle-legacy".to_string()],
                output_bundle_id: "bundle-governance-consolidated".to_string(),
                output_bundle_class: TopicBundleClass::GovernanceNotes,
                output_scope: MemoryScope::Campaign("campaign-1".to_string()),
                output_summary: "consolidated governance evidence".to_string(),
                freshness_policy: "evidence-preserved".to_string(),
                status: ConsolidationJobStatus::Planned,
            })
            .unwrap();

        let pointer_index = memory_store.load_pointer_index("pointer-index-1").unwrap();
        assert!(
            !pointer_index
                .entry_refs
                .iter()
                .any(|entry_ref| entry_ref == "transient:debug-dump")
        );
        assert!(
            pointer_index
                .critical_refs
                .iter()
                .any(|critical_ref| critical_ref == "memory-checkpoint-1")
        );
        assert!(
            pointer_index
                .critical_refs
                .iter()
                .any(|critical_ref| critical_ref == "rollback-1")
        );
        assert!(
            pointer_index
                .critical_refs
                .iter()
                .any(|critical_ref| critical_ref == "contradiction-1")
        );
    }

    #[test]
    fn related_ref_queries_reconstruct_background_and_rollback_audits() {
        let mut memory_store = MemoryStore::default();
        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-background-1",
            AuditRecord::new(
                "audit-background-1",
                AuditRecordClass::GovernanceAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "background:campaign-1:ScheduledTimer:checkpoint-1",
                "background resume validated",
            ),
        ));
        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-rollback-1",
            AuditRecord::new(
                "audit-rollback-1",
                AuditRecordClass::PromotionAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "rollback-1",
                "rollback executed",
            ),
        ));
        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-quarantine-1",
            AuditRecord::new(
                "audit-quarantine-1",
                AuditRecordClass::GovernanceAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "quarantine-1",
                "quarantine opened",
            ),
        ));

        assert_eq!(
            memory_store
                .artifacts_for_related_ref("background:campaign-1:ScheduledTimer:checkpoint-1")
                .len(),
            1
        );
        assert!(
            memory_store
                .artifacts_for_related_ref("rollback-1")
                .iter()
                .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
        );
        assert!(
            memory_store
                .artifacts_for_related_ref("quarantine-1")
                .iter()
                .any(|artifact| artifact.class == MemoryArtifactClass::AuditRecordArtifact)
        );
    }

    #[test]
    fn checkpoint_artifact_is_persisted_for_traceability() {
        let mut memory_store = MemoryStore::default();
        let artifact_id = memory_store.persist_checkpoint_artifact(
            "memory-checkpoint-1",
            checkpoint(),
            "checkpoint persisted for approval resume",
        );

        assert_eq!(artifact_id, "memory-checkpoint-1");
        assert!(
            memory_store
                .get(&artifact_id)
                .expect("checkpoint artifact should exist")
                .summary
                .contains("approval resume")
        );
    }

    #[test]
    fn approval_and_checkpoint_lineage_are_reconstructable() {
        let mut memory_store = MemoryStore::default();
        let checkpoint = checkpoint();
        memory_store.persist_checkpoint_artifact(
            "memory-checkpoint-1",
            checkpoint.clone(),
            "checkpoint persisted for approval lineage",
        );

        let approval_request = ApprovalRequest::requested(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "dispatch:worker-1",
            "workspace-root",
            AuthorityClass::Observe,
        );
        memory_store.append(MemoryArtifact::approval_request(
            "memory-approval-request-1",
            approval_request.clone(),
            "approval request persisted",
        ));

        let approval_decision = ApprovalDecision::granted(
            "approval-1",
            "campaign-1",
            "epoch-1",
            "session-1",
            "task-1",
            "dispatch:worker-1",
            "operator-1",
            "workspace-root",
            Some("approved after review".to_string()),
        );
        memory_store.append(MemoryArtifact::approval_decision(
            "memory-approval-decision-1",
            approval_decision,
            "approval decision persisted",
        ));

        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-checkpoint-1",
            AuditRecord::new(
                "audit-checkpoint-1",
                AuditRecordClass::ApprovalAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                checkpoint.checkpoint_id.clone(),
                "checkpoint audit",
            ),
        ));
        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-approval-1",
            AuditRecord::new(
                "audit-approval-1",
                AuditRecordClass::ApprovalAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                approval_request.approval_request_id.clone(),
                "approval lineage audit",
            ),
        ));

        let checkpoint_lineage = memory_store.checkpoint_lineage(&checkpoint.checkpoint_id);
        assert_eq!(checkpoint_lineage.len(), 2);
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

        let approval_lineage = memory_store.approval_lineage(&approval_request.approval_request_id);
        assert_eq!(approval_lineage.len(), 3);
        assert!(
            approval_lineage
                .iter()
                .any(|artifact| { artifact.class == MemoryArtifactClass::ApprovalRequestArtifact })
        );
        assert!(
            approval_lineage.iter().any(|artifact| {
                artifact.class == MemoryArtifactClass::ApprovalDecisionArtifact
            })
        );
        assert!(
            approval_lineage
                .iter()
                .any(|artifact| { artifact.class == MemoryArtifactClass::AuditRecordArtifact })
        );
    }

    #[test]
    fn ref_prefix_queries_cover_bundles_transcripts_and_audits() {
        let mut memory_store = MemoryStore::default();
        memory_store.add_topic_bundle(TopicBundle {
            bundle_id: "portfolio:campaign-1".to_string(),
            bundle_class: TopicBundleClass::CampaignOperatingNotes,
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            summary: "campaign portfolio".to_string(),
            evidence_refs: vec![
                "budget:campaign-1".to_string(),
                "intervention:campaign-1".to_string(),
            ],
            freshness_policy: "retain-until-close".to_string(),
        });
        memory_store.add_transcript_slice(TranscriptSlice {
            slice_id: "program-transcript:campaign-1".to_string(),
            campaign_id: "campaign-1".to_string(),
            epoch_id: "epoch-1".to_string(),
            session_id: Some("session-1".to_string()),
            task_id: Some("task-1".to_string()),
            referenced_artifacts: vec![
                "plan-carry-forward:campaign-1".to_string(),
                "reprioritization:campaign-1".to_string(),
            ],
            summary: "program continuity".to_string(),
            excerpts: vec!["reprioritized after review".to_string()],
        });
        memory_store.append(MemoryArtifact::audit_record(
            "memory-audit-canary-campaign-1",
            AuditRecord::new(
                "audit-canary-campaign-1",
                AuditRecordClass::GovernanceAuditRecord,
                "campaign-1",
                "epoch-1",
                "session-1",
                Some("task-1".to_string()),
                "canary:campaign-1",
                "canary evidence persisted",
            ),
        ));

        assert!(memory_store.has_ref_prefix("portfolio:"));
        assert!(memory_store.has_ref_prefix("budget:"));
        assert!(memory_store.has_ref_prefix("intervention:"));
        assert!(memory_store.has_ref_prefix("canary:"));
        assert!(memory_store.has_bundle_with_evidence_prefixes(
            TopicBundleClass::CampaignOperatingNotes,
            &["portfolio:", "budget:", "intervention:"]
        ));
        assert!(memory_store.has_transcript_references_with_prefixes(&[
            "plan-carry-forward:",
            "reprioritization:",
        ]));
    }

    #[test]
    fn resolved_contradiction_is_detectable_for_program_continuity() {
        let mut memory_store = MemoryStore::default();
        memory_store.insert_pointer_index(PointerIndex {
            index_id: "pointer-index-1".to_string(),
            scope: MemoryScope::Campaign("campaign-1".to_string()),
            entry_refs: vec!["program-memory:campaign-1".to_string()],
            contested_refs: Vec::new(),
            critical_refs: vec!["program-memory:campaign-1".to_string()],
            governance_constraints: vec!["human approval required".to_string()],
            open_task_refs: vec!["task-1".to_string()],
            updated_at: "t0".to_string(),
        });
        memory_store.register_contradiction(
            "contradiction:campaign-1",
            vec![
                "plan-carry-forward:campaign-1".to_string(),
                "reprioritization:campaign-1".to_string(),
            ],
            "reconcile carry-forward with reprioritized queue",
            Some("pointer-index-1"),
        );
        assert!(!memory_store.has_resolved_contradiction());

        assert!(
            memory_store.resolve_contradiction("contradiction:campaign-1", Some("pointer-index-1"))
        );
        assert!(memory_store.has_resolved_contradiction());
    }
}
