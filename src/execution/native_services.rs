use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeServiceFamily {
    Build,
    Validation,
    Review,
    Packaging,
    Continuity,
    Scheduling,
    Operations,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceFamilyClassification {
    Mandatory,
    Optional,
    Transitional,
    Deprecated,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeWorkflowKind {
    Build,
    Validation,
    Packaging,
    Review,
    Scheduling,
    Continuity,
    OperationalAttestation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceClosureState {
    Open,
    Transitional,
    Closed,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowClosureStatus {
    Open,
    Bounded,
    ClosureGrade,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceAttestationDecision {
    Closed,
    Transitional,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceFamilyManifest {
    pub service_manifest_id: String,
    pub service_family: NativeServiceFamily,
    pub classification: ServiceFamilyClassification,
    pub world_ref: String,
    pub handle_schema_ref: String,
    pub authority_requirements: Vec<String>,
    pub workflow_coverage_refs: Vec<String>,
    pub closure_criteria_refs: Vec<String>,
    pub attestation_policy_ref: String,
    pub closure_policy_ref: String,
    pub closure_state: ServiceClosureState,
}

impl ServiceFamilyManifest {
    pub fn validate(&self) -> Result<(), NativeServicesError> {
        if self.service_manifest_id.trim().is_empty() {
            return Err(NativeServicesError::MissingServiceManifestId);
        }
        if self.world_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingWorldRef);
        }
        if self.handle_schema_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingHandleSchemaRef);
        }
        validate_ref_list(
            &self.authority_requirements,
            NativeServicesError::MissingAuthorityRequirements,
        )?;
        validate_ref_list(
            &self.workflow_coverage_refs,
            NativeServicesError::MissingWorkflowCoverageRefs,
        )?;
        validate_ref_list(
            &self.closure_criteria_refs,
            NativeServicesError::MissingClosureCriteriaRefs,
        )?;
        if self.attestation_policy_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingAttestationPolicyRef);
        }
        if self.closure_policy_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingClosurePolicyRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceHandleLease {
    pub service_handle_id: String,
    pub service_manifest_ref: String,
    pub owner_ref: String,
    pub authority_ref: String,
    pub workflow_ref: String,
    pub lease_policy_ref: String,
    pub effect_refs: Vec<String>,
    pub audit_refs: Vec<String>,
}

impl ServiceHandleLease {
    pub fn validate(&self) -> Result<(), NativeServicesError> {
        if self.service_handle_id.trim().is_empty() {
            return Err(NativeServicesError::MissingServiceHandleId);
        }
        if self.service_manifest_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingServiceManifestRef);
        }
        if self.owner_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingOwnerRef);
        }
        if self.authority_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingAuthorityRef);
        }
        if self.workflow_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingWorkflowRef);
        }
        if self.lease_policy_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingLeasePolicyRef);
        }
        validate_ref_list(&self.effect_refs, NativeServicesError::MissingEffectRefs)?;
        validate_ref_list(&self.audit_refs, NativeServicesError::MissingAuditRefs)?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAttestationBundle {
    pub attestation_id: String,
    pub service_manifest_ref: String,
    pub workflow_ref: String,
    pub handle_ref: String,
    pub effect_ref: String,
    pub authority_ref: String,
    pub compatibility_refs: Vec<String>,
    pub review_refs: Vec<String>,
    pub rollback_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub decision: ServiceAttestationDecision,
}

impl ServiceAttestationBundle {
    pub fn validate(&self) -> Result<(), NativeServicesError> {
        if self.attestation_id.trim().is_empty() {
            return Err(NativeServicesError::MissingAttestationId);
        }
        if self.service_manifest_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingServiceManifestRef);
        }
        if self.workflow_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingWorkflowRef);
        }
        if self.handle_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingHandleRef);
        }
        if self.effect_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingEffectRef);
        }
        if self.authority_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingAuthorityRef);
        }
        validate_ref_list(
            &self.compatibility_refs,
            NativeServicesError::MissingCompatibilityRefs,
        )?;
        validate_ref_list(&self.review_refs, NativeServicesError::MissingReviewRefs)?;
        validate_ref_list(
            &self.rollback_refs,
            NativeServicesError::MissingRollbackRefs,
        )?;
        validate_ref_list(
            &self.evidence_refs,
            NativeServicesError::MissingEvidenceRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceClosureDossier {
    pub closure_dossier_id: String,
    pub service_family: NativeServiceFamily,
    pub required_refs: Vec<String>,
    pub gap_refs: Vec<String>,
    pub decision_ref: String,
    pub claim_boundary: String,
}

impl ServiceClosureDossier {
    pub fn validate(&self) -> Result<(), NativeServicesError> {
        if self.closure_dossier_id.trim().is_empty() {
            return Err(NativeServicesError::MissingClosureDossierId);
        }
        validate_ref_list(
            &self.required_refs,
            NativeServicesError::MissingRequiredRefs,
        )?;
        if self.decision_ref.trim().is_empty() {
            return Err(NativeServicesError::MissingDecisionRef);
        }
        if self.claim_boundary.trim().is_empty() {
            return Err(NativeServicesError::MissingClaimBoundary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowSufficiencyRecord {
    pub workflow_sufficiency_id: String,
    pub workflow_kind: NativeWorkflowKind,
    pub required_service_refs: Vec<String>,
    pub present_service_refs: Vec<String>,
    pub transitional_gap_refs: Vec<String>,
    pub closure_status: WorkflowClosureStatus,
    pub supporting_run_refs: Vec<String>,
    pub summary: String,
}

impl WorkflowSufficiencyRecord {
    pub fn validate(&self) -> Result<(), NativeServicesError> {
        if self.workflow_sufficiency_id.trim().is_empty() {
            return Err(NativeServicesError::MissingWorkflowSufficiencyId);
        }
        validate_ref_list(
            &self.required_service_refs,
            NativeServicesError::MissingRequiredServiceRefs,
        )?;
        validate_ref_list(
            &self.present_service_refs,
            NativeServicesError::MissingPresentServiceRefs,
        )?;
        validate_ref_list(
            &self.supporting_run_refs,
            NativeServicesError::MissingSupportingRunRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(NativeServicesError::MissingSummary);
        }
        if self.closure_status == WorkflowClosureStatus::ClosureGrade
            && self
                .transitional_gap_refs
                .iter()
                .any(|reference| reference.trim().is_empty())
        {
            return Err(NativeServicesError::InvalidTransitionalGapRefs);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowServiceClosureDossier {
    pub workflow_dossier_id: String,
    pub workflow_kind: NativeWorkflowKind,
    pub required_service_refs: Vec<String>,
    pub service_handle_refs: Vec<String>,
    pub attestation_refs: Vec<String>,
    pub transitional_gap_refs: Vec<String>,
    pub closure_status: WorkflowClosureStatus,
    pub claim_boundary: String,
    pub summary: String,
}

impl WorkflowServiceClosureDossier {
    pub fn validate(&self) -> Result<(), NativeServicesError> {
        if self.workflow_dossier_id.trim().is_empty() {
            return Err(NativeServicesError::MissingWorkflowDossierId);
        }
        validate_ref_list(
            &self.required_service_refs,
            NativeServicesError::MissingRequiredServiceRefs,
        )?;
        validate_ref_list(
            &self.service_handle_refs,
            NativeServicesError::MissingServiceHandleRefs,
        )?;
        validate_ref_list(
            &self.attestation_refs,
            NativeServicesError::MissingAttestationRefs,
        )?;
        if self.claim_boundary.trim().is_empty() {
            return Err(NativeServicesError::MissingClaimBoundary);
        }
        if self.summary.trim().is_empty() {
            return Err(NativeServicesError::MissingSummary);
        }
        if self.closure_status == WorkflowClosureStatus::ClosureGrade
            && !self.transitional_gap_refs.is_empty()
        {
            return Err(NativeServicesError::InvalidTransitionalGapRefs);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeServicesError {
    MissingServiceManifestId,
    MissingWorldRef,
    MissingHandleSchemaRef,
    MissingAuthorityRequirements,
    MissingWorkflowCoverageRefs,
    MissingClosureCriteriaRefs,
    MissingAttestationPolicyRef,
    MissingClosurePolicyRef,
    MissingServiceHandleId,
    MissingServiceManifestRef,
    MissingOwnerRef,
    MissingAuthorityRef,
    MissingWorkflowRef,
    MissingLeasePolicyRef,
    MissingEffectRefs,
    MissingAuditRefs,
    MissingAttestationId,
    MissingHandleRef,
    MissingEffectRef,
    MissingCompatibilityRefs,
    MissingReviewRefs,
    MissingRollbackRefs,
    MissingEvidenceRefs,
    MissingClosureDossierId,
    MissingRequiredRefs,
    MissingDecisionRef,
    MissingClaimBoundary,
    MissingWorkflowSufficiencyId,
    MissingRequiredServiceRefs,
    MissingPresentServiceRefs,
    MissingSupportingRunRefs,
    InvalidTransitionalGapRefs,
    MissingSummary,
    MissingWorkflowDossierId,
    MissingServiceHandleRefs,
    MissingAttestationRefs,
}

impl Display for NativeServicesError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for NativeServicesError {}

fn validate_ref_list(
    refs: &[String],
    error: NativeServicesError,
) -> Result<(), NativeServicesError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        NativeServiceFamily, NativeWorkflowKind, ServiceAttestationBundle,
        ServiceAttestationDecision, ServiceClosureDossier, ServiceClosureState,
        ServiceFamilyClassification, ServiceFamilyManifest, ServiceHandleLease,
        WorkflowClosureStatus, WorkflowServiceClosureDossier, WorkflowSufficiencyRecord,
    };

    #[test]
    fn workflow_closure_records_validate() {
        let manifest = ServiceFamilyManifest {
            service_manifest_id: "manifest-build".to_string(),
            service_family: NativeServiceFamily::Build,
            classification: ServiceFamilyClassification::Mandatory,
            world_ref: "world:component-build".to_string(),
            handle_schema_ref: "schema:build".to_string(),
            authority_requirements: vec!["authority:bounded".to_string()],
            workflow_coverage_refs: vec!["workflow:build".to_string()],
            closure_criteria_refs: vec!["criteria:build".to_string()],
            attestation_policy_ref: "policy:attest".to_string(),
            closure_policy_ref: "policy:close".to_string(),
            closure_state: ServiceClosureState::Closed,
        };
        manifest.validate().unwrap();

        let handle = ServiceHandleLease {
            service_handle_id: "handle-build".to_string(),
            service_manifest_ref: manifest.service_manifest_id.clone(),
            owner_ref: "worker:builder".to_string(),
            authority_ref: "authority:bounded".to_string(),
            workflow_ref: "workflow:build".to_string(),
            lease_policy_ref: "policy:lease".to_string(),
            effect_refs: vec!["effect:build-artifact".to_string()],
            audit_refs: vec!["audit:build".to_string()],
        };
        handle.validate().unwrap();

        let attestation = ServiceAttestationBundle {
            attestation_id: "attestation-build".to_string(),
            service_manifest_ref: manifest.service_manifest_id.clone(),
            workflow_ref: "workflow:build".to_string(),
            handle_ref: handle.service_handle_id.clone(),
            effect_ref: "effect:build-artifact".to_string(),
            authority_ref: "authority:bounded".to_string(),
            compatibility_refs: vec!["compatibility:build".to_string()],
            review_refs: vec!["review:build".to_string()],
            rollback_refs: vec!["rollback:build".to_string()],
            evidence_refs: vec!["evidence:build".to_string()],
            decision: ServiceAttestationDecision::Closed,
        };
        attestation.validate().unwrap();

        let family_dossier = ServiceClosureDossier {
            closure_dossier_id: "family-dossier-build".to_string(),
            service_family: NativeServiceFamily::Build,
            required_refs: vec![
                manifest.service_manifest_id.clone(),
                handle.service_handle_id.clone(),
                attestation.attestation_id.clone(),
            ],
            gap_refs: Vec::new(),
            decision_ref: attestation.attestation_id.clone(),
            claim_boundary: "bounded family closure".to_string(),
        };
        family_dossier.validate().unwrap();

        let sufficiency = WorkflowSufficiencyRecord {
            workflow_sufficiency_id: "workflow-sufficiency-build".to_string(),
            workflow_kind: NativeWorkflowKind::Build,
            required_service_refs: vec![manifest.service_manifest_id.clone()],
            present_service_refs: vec![manifest.service_manifest_id.clone()],
            transitional_gap_refs: Vec::new(),
            closure_status: WorkflowClosureStatus::ClosureGrade,
            supporting_run_refs: vec!["run:phase-b".to_string()],
            summary: "build workflow is closed".to_string(),
        };
        sufficiency.validate().unwrap();

        let dossier = WorkflowServiceClosureDossier {
            workflow_dossier_id: "workflow-dossier-build".to_string(),
            workflow_kind: NativeWorkflowKind::Build,
            required_service_refs: vec![manifest.service_manifest_id],
            service_handle_refs: vec![handle.service_handle_id],
            attestation_refs: vec![attestation.attestation_id],
            transitional_gap_refs: Vec::new(),
            closure_status: WorkflowClosureStatus::ClosureGrade,
            claim_boundary: "build workflow stays bounded and governed".to_string(),
            summary: "build workflow closure grade".to_string(),
        };
        dossier.validate().unwrap();
    }
}
