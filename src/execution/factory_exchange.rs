use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryExchangePacketClass {
    LineageImport,
    EvidenceExchange,
    CompatibilityStatement,
    MemoryExchange,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryCompatibilityVerdict {
    Compatible,
    Incompatible,
    RequiresReview,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FactoryExchangeDecisionKind {
    AcceptToQuarantine,
    Reject,
    AcceptForReview,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryIdentityManifest {
    pub factory_identity_id: String,
    pub factory_ref: String,
    pub contract_refs: Vec<String>,
    pub service_closure_refs: Vec<String>,
    pub governance_policy_refs: Vec<String>,
    pub lineage_root_ref: String,
    pub claim_boundary: String,
    pub summary: String,
}

impl FactoryIdentityManifest {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.factory_identity_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingFactoryIdentityId);
        }
        if self.factory_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingFactoryRef);
        }
        validate_ref_list(
            &self.contract_refs,
            FactoryExchangeError::MissingContractRefs,
        )?;
        validate_ref_list(
            &self.service_closure_refs,
            FactoryExchangeError::MissingServiceClosureRefs,
        )?;
        validate_ref_list(
            &self.governance_policy_refs,
            FactoryExchangeError::MissingGovernancePolicyRefs,
        )?;
        if self.lineage_root_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingLineageRootRef);
        }
        if self.claim_boundary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingClaimBoundary);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryExchangeEnvelope {
    pub exchange_id: String,
    pub sender_factory_ref: String,
    pub receiver_scope_ref: String,
    pub packet_class: FactoryExchangePacketClass,
    pub payload_refs: Vec<String>,
    pub trust_requirements: Vec<String>,
    pub rollback_requirements: Vec<String>,
}

impl FactoryExchangeEnvelope {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.exchange_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingExchangeId);
        }
        if self.sender_factory_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSenderFactoryRef);
        }
        if self.receiver_scope_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingReceiverScopeRef);
        }
        validate_ref_list(&self.payload_refs, FactoryExchangeError::MissingPayloadRefs)?;
        validate_ref_list(
            &self.trust_requirements,
            FactoryExchangeError::MissingTrustRequirements,
        )?;
        validate_ref_list(
            &self.rollback_requirements,
            FactoryExchangeError::MissingRollbackRequirements,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactoryCompatibilityDecision {
    pub decision_id: String,
    pub exchange_ref: String,
    pub contract_compatibility: FactoryCompatibilityVerdict,
    pub service_compatibility: FactoryCompatibilityVerdict,
    pub governance_compatibility: FactoryCompatibilityVerdict,
    pub decision: FactoryExchangeDecisionKind,
    pub summary: String,
}

impl FactoryCompatibilityDecision {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.decision_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingDecisionId);
        }
        if self.exchange_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingExchangeRef);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportedArtifactQuarantinePacket {
    pub quarantine_packet_id: String,
    pub exchange_ref: String,
    pub affected_refs: Vec<String>,
    pub review_requirements: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub summary: String,
}

impl ImportedArtifactQuarantinePacket {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.quarantine_packet_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingQuarantinePacketId);
        }
        if self.exchange_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingExchangeRef);
        }
        validate_ref_list(
            &self.affected_refs,
            FactoryExchangeError::MissingAffectedRefs,
        )?;
        validate_ref_list(
            &self.review_requirements,
            FactoryExchangeError::MissingReviewRequirements,
        )?;
        validate_ref_list(
            &self.rollback_refs,
            FactoryExchangeError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFactoryLineageImportRecord {
    pub lineage_import_id: String,
    pub sender_factory_ref: String,
    pub receiver_factory_ref: String,
    pub imported_lineage_refs: Vec<String>,
    pub compatibility_ref: String,
    pub summary: String,
}

impl CrossFactoryLineageImportRecord {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.lineage_import_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingLineageImportId);
        }
        if self.sender_factory_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSenderFactoryRef);
        }
        if self.receiver_factory_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingReceiverFactoryRef);
        }
        validate_ref_list(
            &self.imported_lineage_refs,
            FactoryExchangeError::MissingImportedLineageRefs,
        )?;
        if self.compatibility_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingCompatibilityRef);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryExchangePacket {
    pub memory_exchange_id: String,
    pub sender_factory_ref: String,
    pub pointer_refs: Vec<String>,
    pub contradiction_refs: Vec<String>,
    pub freshness_policy: String,
    pub summary: String,
}

impl MemoryExchangePacket {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.memory_exchange_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingMemoryExchangeId);
        }
        if self.sender_factory_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSenderFactoryRef);
        }
        validate_ref_list(&self.pointer_refs, FactoryExchangeError::MissingPointerRefs)?;
        if self
            .contradiction_refs
            .iter()
            .any(|reference| reference.trim().is_empty())
        {
            return Err(FactoryExchangeError::MissingContradictionRefs);
        }
        if self.freshness_policy.trim().is_empty() {
            return Err(FactoryExchangeError::MissingFreshnessPolicy);
        }
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuarantineFirstImportStateKind {
    Received,
    Quarantined,
    Evaluated,
    Rejected,
    Retained,
    Admitted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportDispositionKind {
    Reject,
    Discard,
    RetainForReview,
    AdmitLocalOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineFirstImportStateRecord {
    pub import_state_id: String,
    pub exchange_ref: String,
    pub current_state: QuarantineFirstImportStateKind,
    pub review_refs: Vec<String>,
    pub rollback_or_discard_refs: Vec<String>,
    pub summary: String,
}

impl QuarantineFirstImportStateRecord {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.import_state_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingImportStateId);
        }
        if self.exchange_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingExchangeRef);
        }
        validate_ref_list(&self.review_refs, FactoryExchangeError::MissingReviewRefs)?;
        validate_ref_list(
            &self.rollback_or_discard_refs,
            FactoryExchangeError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImportDispositionRecord {
    pub disposition_id: String,
    pub exchange_ref: String,
    pub import_state_ref: String,
    pub disposition: ImportDispositionKind,
    pub rollback_refs: Vec<String>,
    pub summary: String,
}

impl ImportDispositionRecord {
    pub fn validate(&self) -> Result<(), FactoryExchangeError> {
        if self.disposition_id.trim().is_empty() {
            return Err(FactoryExchangeError::MissingDispositionId);
        }
        if self.exchange_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingExchangeRef);
        }
        if self.import_state_ref.trim().is_empty() {
            return Err(FactoryExchangeError::MissingImportStateRef);
        }
        validate_ref_list(
            &self.rollback_refs,
            FactoryExchangeError::MissingRollbackRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(FactoryExchangeError::MissingSummary);
        }
        Ok(())
    }
}

pub fn evaluate_factory_exchange_compatibility(
    decision_id: impl Into<String>,
    envelope: &FactoryExchangeEnvelope,
    contract_compatibility: FactoryCompatibilityVerdict,
    service_compatibility: FactoryCompatibilityVerdict,
    governance_compatibility: FactoryCompatibilityVerdict,
    decision: FactoryExchangeDecisionKind,
    summary: impl Into<String>,
) -> Result<FactoryCompatibilityDecision, FactoryExchangeError> {
    envelope.validate()?;
    let has_incompatible = [
        contract_compatibility,
        service_compatibility,
        governance_compatibility,
    ]
    .into_iter()
    .any(|verdict| verdict == FactoryCompatibilityVerdict::Incompatible);
    if has_incompatible && decision != FactoryExchangeDecisionKind::Reject {
        return Err(FactoryExchangeError::IncompatibleExchangeMustReject);
    }

    let record = FactoryCompatibilityDecision {
        decision_id: decision_id.into(),
        exchange_ref: envelope.exchange_id.clone(),
        contract_compatibility,
        service_compatibility,
        governance_compatibility,
        decision,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

pub fn issue_import_quarantine_packet(
    quarantine_packet_id: impl Into<String>,
    envelope: &FactoryExchangeEnvelope,
    affected_refs: Vec<String>,
    review_requirements: Vec<String>,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<ImportedArtifactQuarantinePacket, FactoryExchangeError> {
    envelope.validate()?;
    let packet = ImportedArtifactQuarantinePacket {
        quarantine_packet_id: quarantine_packet_id.into(),
        exchange_ref: envelope.exchange_id.clone(),
        affected_refs,
        review_requirements,
        rollback_refs,
        summary: summary.into(),
    };
    packet.validate()?;
    Ok(packet)
}

pub fn record_cross_factory_lineage_import(
    lineage_import_id: impl Into<String>,
    sender_factory_ref: impl Into<String>,
    receiver_factory_ref: impl Into<String>,
    imported_lineage_refs: Vec<String>,
    compatibility_ref: impl Into<String>,
    summary: impl Into<String>,
) -> Result<CrossFactoryLineageImportRecord, FactoryExchangeError> {
    let record = CrossFactoryLineageImportRecord {
        lineage_import_id: lineage_import_id.into(),
        sender_factory_ref: sender_factory_ref.into(),
        receiver_factory_ref: receiver_factory_ref.into(),
        imported_lineage_refs,
        compatibility_ref: compatibility_ref.into(),
        summary: summary.into(),
    };
    record.validate()?;
    if record.sender_factory_ref == record.receiver_factory_ref {
        return Err(FactoryExchangeError::SenderReceiverMustDiffer);
    }
    Ok(record)
}

pub fn record_quarantine_first_import_state(
    import_state_id: impl Into<String>,
    envelope: &FactoryExchangeEnvelope,
    current_state: QuarantineFirstImportStateKind,
    review_refs: Vec<String>,
    rollback_or_discard_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<QuarantineFirstImportStateRecord, FactoryExchangeError> {
    envelope.validate()?;
    let record = QuarantineFirstImportStateRecord {
        import_state_id: import_state_id.into(),
        exchange_ref: envelope.exchange_id.clone(),
        current_state,
        review_refs,
        rollback_or_discard_refs,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

pub fn record_import_disposition(
    disposition_id: impl Into<String>,
    envelope: &FactoryExchangeEnvelope,
    import_state: &QuarantineFirstImportStateRecord,
    disposition: ImportDispositionKind,
    rollback_refs: Vec<String>,
    summary: impl Into<String>,
) -> Result<ImportDispositionRecord, FactoryExchangeError> {
    envelope.validate()?;
    import_state.validate()?;
    if import_state.exchange_ref != envelope.exchange_id {
        return Err(FactoryExchangeError::ImportStateEnvelopeMismatch);
    }
    let record = ImportDispositionRecord {
        disposition_id: disposition_id.into(),
        exchange_ref: envelope.exchange_id.clone(),
        import_state_ref: import_state.import_state_id.clone(),
        disposition,
        rollback_refs,
        summary: summary.into(),
    };
    record.validate()?;
    Ok(record)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FactoryExchangeError {
    MissingFactoryIdentityId,
    MissingFactoryRef,
    MissingContractRefs,
    MissingServiceClosureRefs,
    MissingGovernancePolicyRefs,
    MissingLineageRootRef,
    MissingClaimBoundary,
    MissingExchangeId,
    MissingSenderFactoryRef,
    MissingReceiverFactoryRef,
    MissingReceiverScopeRef,
    MissingPayloadRefs,
    MissingTrustRequirements,
    MissingRollbackRequirements,
    MissingDecisionId,
    MissingImportStateId,
    MissingImportStateRef,
    MissingDispositionId,
    MissingExchangeRef,
    MissingQuarantinePacketId,
    MissingAffectedRefs,
    MissingReviewRequirements,
    MissingReviewRefs,
    MissingLineageImportId,
    MissingImportedLineageRefs,
    MissingCompatibilityRef,
    MissingMemoryExchangeId,
    MissingPointerRefs,
    MissingContradictionRefs,
    MissingFreshnessPolicy,
    MissingRollbackRefs,
    MissingSummary,
    IncompatibleExchangeMustReject,
    ImportStateEnvelopeMismatch,
    SenderReceiverMustDiffer,
}

impl Display for FactoryExchangeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingFactoryIdentityId => {
                write!(f, "factory identity manifest requires an identity id")
            }
            Self::MissingFactoryRef => {
                write!(f, "factory identity manifest requires a factory ref")
            }
            Self::MissingContractRefs => {
                write!(f, "factory identity manifest requires contract refs")
            }
            Self::MissingServiceClosureRefs => {
                write!(f, "factory identity manifest requires service closure refs")
            }
            Self::MissingGovernancePolicyRefs => {
                write!(
                    f,
                    "factory identity manifest requires governance policy refs"
                )
            }
            Self::MissingLineageRootRef => {
                write!(f, "factory identity manifest requires a lineage root ref")
            }
            Self::MissingClaimBoundary => {
                write!(f, "factory identity manifest requires a claim boundary")
            }
            Self::MissingExchangeId => write!(f, "factory exchange envelope requires an id"),
            Self::MissingSenderFactoryRef => {
                write!(f, "factory exchange record requires a sender factory ref")
            }
            Self::MissingReceiverFactoryRef => {
                write!(f, "factory lineage import requires a receiver factory ref")
            }
            Self::MissingReceiverScopeRef => {
                write!(f, "factory exchange envelope requires a receiver scope ref")
            }
            Self::MissingPayloadRefs => {
                write!(f, "factory exchange envelope requires payload refs")
            }
            Self::MissingTrustRequirements => {
                write!(f, "factory exchange envelope requires trust requirements")
            }
            Self::MissingRollbackRequirements => {
                write!(
                    f,
                    "factory exchange envelope requires rollback requirements"
                )
            }
            Self::MissingDecisionId => {
                write!(f, "factory compatibility decision requires an id")
            }
            Self::MissingImportStateId => {
                write!(f, "quarantine-first import state requires an id")
            }
            Self::MissingImportStateRef => {
                write!(f, "import disposition requires an import state ref")
            }
            Self::MissingDispositionId => {
                write!(f, "import disposition requires an id")
            }
            Self::MissingExchangeRef => {
                write!(f, "factory exchange record requires an exchange ref")
            }
            Self::MissingQuarantinePacketId => {
                write!(f, "import quarantine packet requires an id")
            }
            Self::MissingAffectedRefs => {
                write!(f, "import quarantine packet requires affected refs")
            }
            Self::MissingReviewRequirements => {
                write!(f, "import quarantine packet requires review requirements")
            }
            Self::MissingReviewRefs => {
                write!(f, "quarantine-first import state requires review refs")
            }
            Self::MissingLineageImportId => {
                write!(f, "cross-factory lineage import requires an id")
            }
            Self::MissingImportedLineageRefs => {
                write!(
                    f,
                    "cross-factory lineage import requires imported lineage refs"
                )
            }
            Self::MissingCompatibilityRef => {
                write!(
                    f,
                    "cross-factory lineage import requires a compatibility ref"
                )
            }
            Self::MissingMemoryExchangeId => write!(f, "memory exchange packet requires an id"),
            Self::MissingPointerRefs => write!(f, "memory exchange packet requires pointer refs"),
            Self::MissingContradictionRefs => {
                write!(
                    f,
                    "memory exchange contradiction refs cannot contain blanks"
                )
            }
            Self::MissingFreshnessPolicy => {
                write!(f, "memory exchange packet requires a freshness policy")
            }
            Self::MissingRollbackRefs => {
                write!(f, "exchange record requires rollback refs")
            }
            Self::MissingSummary => write!(f, "exchange record requires a summary"),
            Self::IncompatibleExchangeMustReject => {
                write!(f, "an incompatible factory exchange must be rejected")
            }
            Self::ImportStateEnvelopeMismatch => {
                write!(
                    f,
                    "import disposition must reference the same exchange as the import state"
                )
            }
            Self::SenderReceiverMustDiffer => write!(
                f,
                "cross-factory lineage import requires distinct sender and receiver factories"
            ),
        }
    }
}

impl Error for FactoryExchangeError {}

fn validate_ref_list(
    refs: &[String],
    error: FactoryExchangeError,
) -> Result<(), FactoryExchangeError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incompatible_exchange_must_reject() {
        let envelope = FactoryExchangeEnvelope {
            exchange_id: "exchange-1".to_string(),
            sender_factory_ref: "factory-sender".to_string(),
            receiver_scope_ref: "factory-receiver".to_string(),
            packet_class: FactoryExchangePacketClass::LineageImport,
            payload_refs: vec!["payload:lineage-1".to_string()],
            trust_requirements: vec!["trust:local-review".to_string()],
            rollback_requirements: vec!["rollback:discard-import".to_string()],
        };

        let error = evaluate_factory_exchange_compatibility(
            "decision-1",
            &envelope,
            FactoryCompatibilityVerdict::Compatible,
            FactoryCompatibilityVerdict::Incompatible,
            FactoryCompatibilityVerdict::Compatible,
            FactoryExchangeDecisionKind::AcceptToQuarantine,
            "attempted incompatible import",
        )
        .unwrap_err();
        assert_eq!(error, FactoryExchangeError::IncompatibleExchangeMustReject);
    }

    #[test]
    fn identity_manifest_requires_claim_boundary() {
        let manifest = FactoryIdentityManifest {
            factory_identity_id: "identity-1".to_string(),
            factory_ref: "factory-1".to_string(),
            contract_refs: vec!["contract:v1".to_string()],
            service_closure_refs: vec!["service:v4-shell".to_string()],
            governance_policy_refs: vec!["governance:bounded-adoption".to_string()],
            lineage_root_ref: "lineage-root:1".to_string(),
            claim_boundary: String::new(),
            summary: "identity manifest".to_string(),
        };

        let error = manifest.validate().unwrap_err();
        assert_eq!(error, FactoryExchangeError::MissingClaimBoundary);
    }

    #[test]
    fn quarantine_first_import_state_and_disposition_roundtrip() {
        let envelope = FactoryExchangeEnvelope {
            exchange_id: "exchange-2".to_string(),
            sender_factory_ref: "factory-sender".to_string(),
            receiver_scope_ref: "factory-receiver".to_string(),
            packet_class: FactoryExchangePacketClass::LineageImport,
            payload_refs: vec!["payload:lineage-2".to_string()],
            trust_requirements: vec!["trust:local-review".to_string()],
            rollback_requirements: vec!["rollback:discard-import".to_string()],
        };

        let state = record_quarantine_first_import_state(
            "import-state-1",
            &envelope,
            QuarantineFirstImportStateKind::Quarantined,
            vec!["review:compatibility".to_string()],
            vec!["rollback:discard-import".to_string()],
            "quarantine-first import state",
        )
        .unwrap();
        assert_eq!(
            state.current_state,
            QuarantineFirstImportStateKind::Quarantined
        );

        let disposition = record_import_disposition(
            "import-disposition-1",
            &envelope,
            &state,
            ImportDispositionKind::RetainForReview,
            vec!["rollback:discard-import".to_string()],
            "retain import for local review",
        )
        .unwrap();
        assert_eq!(disposition.import_state_ref, state.import_state_id);
    }
}
