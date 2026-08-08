use super::artifact::{ContentDigest, digest_json_content};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const ACTIVE_TRUTH_CLAIM_CATALOG_SCHEMA: &str = "wasm-biotic.claim-catalog.v1";
pub const ACTIVE_TRUTH_CLAIM_CATALOG_VERSION: &str = "1.0.0";
const ACTIVE_TRUTH_CLAIM_CATALOG_DOMAIN: &str = "wasm-biotic:m7-claim-catalog:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosureCriterionStatus {
    Passed,
    Caveated,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NorthStarClosureDecision {
    Closed,
    ClosedWithCaveats,
    NotYet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActiveTruthClaimIdV1 {
    #[serde(rename = "historical_phase_04_record_completeness")]
    HistoricalPhase04RecordCompleteness,
    #[serde(rename = "historical_phase_04_lineage_decision")]
    HistoricalPhase04LineageDecision,
    #[serde(rename = "operational_decision_not_yet")]
    OperationalDecisionNotYet,
    #[serde(rename = "roadmap_governs_capability_maturity")]
    RoadmapGovernsCapabilityMaturity,
    #[serde(rename = "north_star_reached")]
    NorthStarReached,
    #[serde(rename = "self_sustaining_wasm_biotic_world")]
    SelfSustainingWasmBioticWorld,
    #[serde(rename = "historical_phase_04_as_operational_decision")]
    HistoricalPhase04AsOperationalDecision,
    #[serde(rename = "operational_decision_closed_without_m7")]
    OperationalDecisionClosedWithoutM7,
    #[serde(rename = "historical_phase_04_as_current_capability_maturity")]
    HistoricalPhase04AsCurrentCapabilityMaturity,
    #[serde(rename = "historical_phase_04_as_current_m7_evidence")]
    HistoricalPhase04AsCurrentM7Evidence,
    #[serde(rename = "historical_decision_without_required_caveats")]
    HistoricalDecisionWithoutRequiredCaveats,
    #[serde(rename = "universal_shell_across_every_curated_path")]
    UniversalShellAcrossEveryCuratedPath,
    #[serde(rename = "public_federation")]
    PublicFederation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveTruthClaimStatementV1 {
    pub claim_id: ActiveTruthClaimIdV1,
    pub statement: String,
}

pub fn active_truth_allowed_claims() -> Vec<ActiveTruthClaimStatementV1> {
    vec![
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::HistoricalPhase04RecordCompleteness,
            statement: "Phase 04 is a historical record-completeness rereview.".to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::HistoricalPhase04LineageDecision,
            statement: "Its archived lineage decision is Closed.".to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::OperationalDecisionNotYet,
            statement: "The current operational North Star decision remains NotYet.".to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::RoadmapGovernsCapabilityMaturity,
            statement: "Current capability maturity is governed by notes/ROADMAP.md, not by Phase 04 status records."
                .to_string(),
        },
    ]
}

pub fn active_truth_forbidden_claims() -> Vec<ActiveTruthClaimStatementV1> {
    vec![
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::NorthStarReached,
            statement: "The North Star has been reached.".to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::SelfSustainingWasmBioticWorld,
            statement: "The system is a self-sustaining Wasm-Biotic world.".to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::HistoricalPhase04AsOperationalDecision,
            statement: "The historical Phase 04 decision is the current operational decision."
                .to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::OperationalDecisionClosedWithoutM7,
            statement:
                "The current operational North Star decision is Closed or ClosedWithCaveats."
                    .to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::HistoricalPhase04AsCurrentCapabilityMaturity,
            statement: "Phase 04 closure-grade status establishes current capability maturity."
                .to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::HistoricalPhase04AsCurrentM7Evidence,
            statement:
                "The Phase 04 bundle is a current M7 proof run, source capture, or independent review."
                    .to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::HistoricalDecisionWithoutRequiredCaveats,
            statement: "The historical decision may be published without its historical scope, operational NotYet status, status authority, and required caveats."
                .to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::UniversalShellAcrossEveryCuratedPath,
            statement: "Universal shell-first execution is complete across every curated path."
                .to_string(),
        },
        ActiveTruthClaimStatementV1 {
            claim_id: ActiveTruthClaimIdV1::PublicFederation,
            statement: "The ecosystem is an open-ended autonomous multi-factory federation."
                .to_string(),
        },
    ]
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveTruthClaimCatalogV1 {
    pub schema: String,
    pub catalog_version: String,
    pub allowed_claims: Vec<ActiveTruthClaimStatementV1>,
    pub forbidden_claims: Vec<ActiveTruthClaimStatementV1>,
    pub catalog_digest: ContentDigest,
}

impl ActiveTruthClaimCatalogV1 {
    pub fn bounded_local_first() -> Result<Self, ClosureReviewError> {
        let mut value = Self {
            schema: ACTIVE_TRUTH_CLAIM_CATALOG_SCHEMA.to_string(),
            catalog_version: ACTIVE_TRUTH_CLAIM_CATALOG_VERSION.to_string(),
            allowed_claims: active_truth_allowed_claims(),
            forbidden_claims: active_truth_forbidden_claims(),
            catalog_digest: ContentDigest::from_bytes(&[]),
        };
        value.catalog_digest = value.expected_digest()?;
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        let allowed = self
            .allowed_claims
            .iter()
            .map(|claim| claim.claim_id)
            .collect::<BTreeSet<_>>();
        let forbidden = self
            .forbidden_claims
            .iter()
            .map(|claim| claim.claim_id)
            .collect::<BTreeSet<_>>();
        if self.schema != ACTIVE_TRUTH_CLAIM_CATALOG_SCHEMA
            || self.catalog_version != ACTIVE_TRUTH_CLAIM_CATALOG_VERSION
            || self.allowed_claims != active_truth_allowed_claims()
            || self.forbidden_claims != active_truth_forbidden_claims()
            || allowed.len() != self.allowed_claims.len()
            || forbidden.len() != self.forbidden_claims.len()
            || !allowed.is_disjoint(&forbidden)
            || self.catalog_digest != self.expected_digest()?
        {
            return Err(ClosureReviewError::InvalidActiveTruthClaimCatalog);
        }
        Ok(())
    }

    pub fn allowed_claim_ids(&self) -> Vec<ActiveTruthClaimIdV1> {
        self.allowed_claims
            .iter()
            .map(|claim| claim.claim_id)
            .collect()
    }

    pub fn forbidden_claim_ids(&self) -> Vec<ActiveTruthClaimIdV1> {
        self.forbidden_claims
            .iter()
            .map(|claim| claim.claim_id)
            .collect()
    }

    pub fn allowed_claim_statements(&self) -> Vec<String> {
        self.allowed_claims
            .iter()
            .map(|claim| claim.statement.clone())
            .collect()
    }

    pub fn forbidden_claim_statements(&self) -> Vec<String> {
        self.forbidden_claims
            .iter()
            .map(|claim| claim.statement.clone())
            .collect()
    }

    pub fn allowed_claims_digest(&self) -> Result<ContentDigest, ClosureReviewError> {
        digest_json_content(&(
            ACTIVE_TRUTH_CLAIM_CATALOG_DOMAIN,
            "allowed",
            &self.catalog_version,
            &self.allowed_claims,
        ))
        .map_err(|_| ClosureReviewError::InvalidActiveTruthClaimCatalog)
    }

    pub fn forbidden_claims_digest(&self) -> Result<ContentDigest, ClosureReviewError> {
        digest_json_content(&(
            ACTIVE_TRUTH_CLAIM_CATALOG_DOMAIN,
            "forbidden",
            &self.catalog_version,
            &self.forbidden_claims,
        ))
        .map_err(|_| ClosureReviewError::InvalidActiveTruthClaimCatalog)
    }

    pub fn expected_digest(&self) -> Result<ContentDigest, ClosureReviewError> {
        digest_json_content(&(
            ACTIVE_TRUTH_CLAIM_CATALOG_DOMAIN,
            ACTIVE_TRUTH_CLAIM_CATALOG_SCHEMA,
            &self.catalog_version,
            &self.allowed_claims,
            &self.forbidden_claims,
        ))
        .map_err(|_| ClosureReviewError::InvalidActiveTruthClaimCatalog)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ActiveTruthPublicationControlV1 {
    #[serde(rename = "redact_secrets")]
    RedactSecrets,
    #[serde(rename = "label_historical_phase_04")]
    LabelHistoricalPhase04,
    #[serde(rename = "outcome_neutral_before_closure")]
    OutcomeNeutralBeforeClosure,
    #[serde(rename = "preserve_bounded_local_first_scope")]
    PreserveBoundedLocalFirstScope,
}

pub fn active_truth_publication_controls() -> BTreeSet<ActiveTruthPublicationControlV1> {
    BTreeSet::from([
        ActiveTruthPublicationControlV1::RedactSecrets,
        ActiveTruthPublicationControlV1::LabelHistoricalPhase04,
        ActiveTruthPublicationControlV1::OutcomeNeutralBeforeClosure,
        ActiveTruthPublicationControlV1::PreserveBoundedLocalFirstScope,
    ])
}

pub fn active_truth_required_publication_caveats() -> BTreeSet<String> {
    BTreeSet::from([
        "secrets:redacted".to_string(),
        "scope:historical-record-completeness-only".to_string(),
        "operational-decision:NotYet".to_string(),
        "scope:bounded-local-first-no-public-federation".to_string(),
        "status-authority:notes/ROADMAP.md".to_string(),
        "m7-authority:notes/M7-CLOSURE-OPERATIONS.md".to_string(),
        "phase04-is-not-current-m7-source-capture-or-independent-review".to_string(),
    ])
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResidualRiskClass {
    Rollback,
    Quarantine,
    Legibility,
    Autonomy,
    Stability,
    EcosystemTrust,
    ServiceClosure,
    ShellUniversality,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskSeverity {
    Low,
    Moderate,
    High,
    Blocking,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClosureEffect {
    Acceptable,
    Caveated,
    BlocksClosure,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureCriterionRecord {
    pub criterion_id: String,
    pub title: String,
    pub status: ClosureCriterionStatus,
    pub evidence_refs: Vec<String>,
    pub phase_evidence_refs: Vec<String>,
    pub delta_crosswalk_refs: Vec<String>,
    pub gap_refs: Vec<String>,
    pub summary: String,
}

impl ClosureCriterionRecord {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.criterion_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingCriterionId);
        }
        if self.title.trim().is_empty() {
            return Err(ClosureReviewError::MissingTitle);
        }
        validate_ref_list(&self.evidence_refs, ClosureReviewError::MissingEvidenceRefs)?;
        validate_ref_list(
            &self.phase_evidence_refs,
            ClosureReviewError::MissingPhaseEvidenceRefs,
        )?;
        validate_ref_list(
            &self.delta_crosswalk_refs,
            ClosureReviewError::MissingDeltaCrosswalkRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(ClosureReviewError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureCriteriaMatrix {
    pub criteria_matrix_id: String,
    pub criterion_refs: Vec<String>,
    pub status: ClosureCriterionStatus,
    pub evidence_refs: Vec<String>,
    pub phase_evidence_refs: Vec<String>,
    pub delta_crosswalk_refs: Vec<String>,
    pub gap_refs: Vec<String>,
    pub review_status: String,
}

impl ClosureCriteriaMatrix {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.criteria_matrix_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingCriteriaMatrixId);
        }
        validate_ref_list(
            &self.criterion_refs,
            ClosureReviewError::MissingCriterionRefs,
        )?;
        validate_ref_list(&self.evidence_refs, ClosureReviewError::MissingEvidenceRefs)?;
        validate_ref_list(
            &self.phase_evidence_refs,
            ClosureReviewError::MissingPhaseEvidenceRefs,
        )?;
        validate_ref_list(
            &self.delta_crosswalk_refs,
            ClosureReviewError::MissingDeltaCrosswalkRefs,
        )?;
        if self.review_status.trim().is_empty() {
            return Err(ClosureReviewError::MissingReviewStatus);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceInventoryPacket {
    pub inventory_packet_id: String,
    pub northstar_refs: Vec<String>,
    pub operator_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub phase_01_refs: Vec<String>,
    pub phase_02_refs: Vec<String>,
    pub phase_03_refs: Vec<String>,
    pub phase_04_refs: Vec<String>,
    pub summary: String,
}

impl EvidenceInventoryPacket {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.inventory_packet_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingInventoryPacketId);
        }
        validate_ref_list(
            &self.northstar_refs,
            ClosureReviewError::MissingNorthStarRefs,
        )?;
        validate_ref_list(&self.operator_refs, ClosureReviewError::MissingOperatorRefs)?;
        validate_ref_list(&self.risk_refs, ClosureReviewError::MissingRiskRefs)?;
        validate_ref_list(&self.phase_01_refs, ClosureReviewError::MissingPhase01Refs)?;
        validate_ref_list(&self.phase_02_refs, ClosureReviewError::MissingPhase02Refs)?;
        validate_ref_list(&self.phase_03_refs, ClosureReviewError::MissingPhase03Refs)?;
        validate_ref_list(&self.phase_04_refs, ClosureReviewError::MissingPhase04Refs)?;
        if self.summary.trim().is_empty() {
            return Err(ClosureReviewError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversarialReviewRecord {
    pub adversarial_review_id: String,
    pub scenario_refs: Vec<String>,
    pub criterion_refs: Vec<String>,
    pub criteria_matrix_ref: String,
    pub failure_refs: Vec<String>,
    pub counter_evidence_refs: Vec<String>,
    pub risk_refs: Vec<String>,
    pub challenge_outcome_refs: Vec<String>,
    pub recommendation_ref: String,
    pub summary: String,
}

impl AdversarialReviewRecord {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.adversarial_review_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingAdversarialReviewId);
        }
        validate_ref_list(&self.scenario_refs, ClosureReviewError::MissingScenarioRefs)?;
        validate_ref_list(
            &self.criterion_refs,
            ClosureReviewError::MissingCriterionRefs,
        )?;
        if self.criteria_matrix_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingCriteriaMatrixRef);
        }
        validate_ref_list(&self.failure_refs, ClosureReviewError::MissingFailureRefs)?;
        validate_ref_list(
            &self.counter_evidence_refs,
            ClosureReviewError::MissingCounterEvidenceRefs,
        )?;
        validate_ref_list(&self.risk_refs, ClosureReviewError::MissingRiskRefs)?;
        validate_ref_list(
            &self.challenge_outcome_refs,
            ClosureReviewError::MissingChallengeOutcomeRefs,
        )?;
        if self.recommendation_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingRecommendationRef);
        }
        if self.summary.trim().is_empty() {
            return Err(ClosureReviewError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidualRiskRecord {
    pub risk_record_id: String,
    pub risk_class: ResidualRiskClass,
    pub supporting_refs: Vec<String>,
    pub severity: RiskSeverity,
    pub closure_effect: ClosureEffect,
    pub summary: String,
}

impl ResidualRiskRecord {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.risk_record_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingRiskRecordId);
        }
        validate_ref_list(
            &self.supporting_refs,
            ClosureReviewError::MissingSupportingRefs,
        )?;
        if self.summary.trim().is_empty() {
            return Err(ClosureReviewError::MissingSummary);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureDossier {
    pub closure_dossier_id: String,
    pub criteria_matrix_ref: String,
    pub inventory_ref: String,
    pub adversarial_review_ref: String,
    pub claim_boundary_ref: String,
    pub risk_refs: Vec<String>,
    pub recommendation_ref: String,
}

impl ClosureDossier {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.closure_dossier_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingClosureDossierId);
        }
        if self.criteria_matrix_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingCriteriaMatrixRef);
        }
        if self.inventory_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingInventoryRef);
        }
        if self.adversarial_review_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingAdversarialReviewRef);
        }
        if self.claim_boundary_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingClaimBoundaryRef);
        }
        validate_ref_list(&self.risk_refs, ClosureReviewError::MissingRiskRefs)?;
        if self.recommendation_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingRecommendationRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimBoundaryReviewPacket {
    pub claim_review_id: String,
    pub claim_catalog: ActiveTruthClaimCatalogV1,
    pub allowed_claims: Vec<String>,
    pub forbidden_claims: Vec<String>,
    pub caveat_refs: Vec<String>,
    pub supporting_refs: Vec<String>,
    pub supporting_evidence_refs: Vec<String>,
    pub counter_evidence_refs: Vec<String>,
    pub publication_risk_refs: Vec<String>,
}

impl ClaimBoundaryReviewPacket {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.claim_review_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingClaimReviewId);
        }
        self.claim_catalog.validate()?;
        validate_ref_list(
            &self.allowed_claims,
            ClosureReviewError::MissingAllowedClaims,
        )?;
        validate_ref_list(
            &self.forbidden_claims,
            ClosureReviewError::MissingForbiddenClaims,
        )?;
        if self.allowed_claims != self.claim_catalog.allowed_claim_statements()
            || self.forbidden_claims != self.claim_catalog.forbidden_claim_statements()
        {
            return Err(ClosureReviewError::InvalidActiveTruthClaimMapping);
        }
        validate_ref_list(
            &self.supporting_refs,
            ClosureReviewError::MissingSupportingRefs,
        )?;
        validate_ref_list(
            &self.supporting_evidence_refs,
            ClosureReviewError::MissingSupportingEvidenceRefs,
        )?;
        validate_ref_list(
            &self.counter_evidence_refs,
            ClosureReviewError::MissingCounterEvidenceRefs,
        )?;
        validate_ref_list(
            &self.publication_risk_refs,
            ClosureReviewError::MissingPublicationRiskRefs,
        )?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClosureDecisionRecord {
    pub closure_decision_id: String,
    pub decision: NorthStarClosureDecision,
    pub rationale: String,
    pub required_followups: Vec<String>,
    pub publication_policy_ref: String,
    pub supersedes_ref: String,
}

impl ClosureDecisionRecord {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.closure_decision_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingClosureDecisionId);
        }
        if self.rationale.trim().is_empty() {
            return Err(ClosureReviewError::MissingRationale);
        }
        validate_ref_list(
            &self.required_followups,
            ClosureReviewError::MissingRequiredFollowups,
        )?;
        if self.publication_policy_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingPublicationPolicyRef);
        }
        if self.supersedes_ref.trim().is_empty() {
            return Err(ClosureReviewError::MissingSupersedesRef);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicationPolicyRecord {
    pub publication_policy_id: String,
    pub claim_catalog: ActiveTruthClaimCatalogV1,
    pub publication_controls: BTreeSet<ActiveTruthPublicationControlV1>,
    pub allowed_claims: Vec<String>,
    pub required_caveats: Vec<String>,
    pub forbidden_claims: Vec<String>,
    pub source_refs: Vec<String>,
    pub audience_note: String,
}

impl PublicationPolicyRecord {
    pub fn validate(&self) -> Result<(), ClosureReviewError> {
        if self.publication_policy_id.trim().is_empty() {
            return Err(ClosureReviewError::MissingPublicationPolicyId);
        }
        self.claim_catalog.validate()?;
        if self.publication_controls != active_truth_publication_controls() {
            return Err(ClosureReviewError::InvalidActiveTruthPublicationControls);
        }
        validate_ref_list(
            &self.allowed_claims,
            ClosureReviewError::MissingAllowedClaims,
        )?;
        validate_ref_list(
            &self.forbidden_claims,
            ClosureReviewError::MissingForbiddenClaims,
        )?;
        if self.allowed_claims != self.claim_catalog.allowed_claim_statements()
            || self.forbidden_claims != self.claim_catalog.forbidden_claim_statements()
        {
            return Err(ClosureReviewError::InvalidActiveTruthClaimMapping);
        }
        validate_ref_list(
            &self.required_caveats,
            ClosureReviewError::MissingRequiredCaveats,
        )?;
        let caveats = self
            .required_caveats
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        if caveats.len() != self.required_caveats.len()
            || !active_truth_required_publication_caveats().is_subset(&caveats)
        {
            return Err(ClosureReviewError::MissingRequiredCaveats);
        }
        validate_ref_list(&self.source_refs, ClosureReviewError::MissingSourceRefs)?;
        if self.audience_note.trim().is_empty() {
            return Err(ClosureReviewError::MissingAudienceNote);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClosureReviewError {
    MissingCriterionId,
    MissingTitle,
    MissingCriteriaMatrixId,
    MissingCriterionRefs,
    MissingEvidenceRefs,
    MissingPhaseEvidenceRefs,
    MissingDeltaCrosswalkRefs,
    MissingReviewStatus,
    MissingInventoryPacketId,
    MissingNorthStarRefs,
    MissingOperatorRefs,
    MissingPhase01Refs,
    MissingPhase02Refs,
    MissingPhase03Refs,
    MissingPhase04Refs,
    MissingAdversarialReviewId,
    MissingScenarioRefs,
    MissingFailureRefs,
    MissingCounterEvidenceRefs,
    MissingChallengeOutcomeRefs,
    MissingRecommendationRef,
    MissingRiskRecordId,
    MissingSupportingRefs,
    MissingSupportingEvidenceRefs,
    MissingPublicationRiskRefs,
    MissingClosureDossierId,
    MissingCriteriaMatrixRef,
    MissingInventoryRef,
    MissingAdversarialReviewRef,
    MissingClaimBoundaryRef,
    MissingRiskRefs,
    MissingClaimReviewId,
    MissingAllowedClaims,
    MissingForbiddenClaims,
    MissingClosureDecisionId,
    MissingRationale,
    MissingRequiredFollowups,
    MissingPublicationPolicyRef,
    MissingSupersedesRef,
    MissingPublicationPolicyId,
    MissingRequiredCaveats,
    MissingSourceRefs,
    MissingAudienceNote,
    MissingSummary,
    InvalidActiveTruthClaimCatalog,
    InvalidActiveTruthClaimMapping,
    InvalidActiveTruthPublicationControls,
}

impl Display for ClosureReviewError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for ClosureReviewError {}

fn validate_ref_list(refs: &[String], error: ClosureReviewError) -> Result<(), ClosureReviewError> {
    if refs.is_empty() || refs.iter().any(|reference| reference.trim().is_empty()) {
        return Err(error);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remediated_closure_review_records_validate() {
        let criterion = ClosureCriterionRecord {
            criterion_id: "criterion:1".to_string(),
            title: "Criterion".to_string(),
            status: ClosureCriterionStatus::Passed,
            evidence_refs: vec!["evidence:1".to_string()],
            phase_evidence_refs: vec!["phase:01".to_string()],
            delta_crosswalk_refs: vec!["delta:criterion".to_string()],
            gap_refs: Vec::new(),
            summary: "criterion summary".to_string(),
        };
        criterion.validate().unwrap();

        let matrix = ClosureCriteriaMatrix {
            criteria_matrix_id: "matrix:1".to_string(),
            criterion_refs: vec![criterion.criterion_id.clone()],
            status: ClosureCriterionStatus::Passed,
            evidence_refs: criterion.evidence_refs.clone(),
            phase_evidence_refs: criterion.phase_evidence_refs.clone(),
            delta_crosswalk_refs: criterion.delta_crosswalk_refs.clone(),
            gap_refs: Vec::new(),
            review_status: "remediated_current_review".to_string(),
        };
        matrix.validate().unwrap();

        let inventory = EvidenceInventoryPacket {
            inventory_packet_id: "inventory:1".to_string(),
            northstar_refs: vec!["northstar:1".to_string()],
            operator_refs: vec!["operator:1".to_string()],
            risk_refs: vec!["risk:1".to_string()],
            phase_01_refs: vec!["phase01:1".to_string()],
            phase_02_refs: vec!["phase02:1".to_string()],
            phase_03_refs: vec!["phase03:1".to_string()],
            phase_04_refs: vec!["phase04:1".to_string()],
            summary: "inventory summary".to_string(),
        };
        inventory.validate().unwrap();

        let adversarial = AdversarialReviewRecord {
            adversarial_review_id: "adversarial:1".to_string(),
            scenario_refs: vec!["scenario:1".to_string()],
            criterion_refs: vec![criterion.criterion_id.clone()],
            criteria_matrix_ref: matrix.criteria_matrix_id.clone(),
            failure_refs: vec!["gap:1".to_string()],
            counter_evidence_refs: vec!["counter:1".to_string()],
            risk_refs: vec!["risk:1".to_string()],
            challenge_outcome_refs: vec!["outcome:1".to_string()],
            recommendation_ref: "decision:1".to_string(),
            summary: "adversarial summary".to_string(),
        };
        adversarial.validate().unwrap();

        let claim_catalog =
            ActiveTruthClaimCatalogV1::bounded_local_first().expect("active claim catalog");
        let claim_boundary = ClaimBoundaryReviewPacket {
            claim_review_id: "claim:1".to_string(),
            claim_catalog: claim_catalog.clone(),
            allowed_claims: claim_catalog.allowed_claim_statements(),
            forbidden_claims: claim_catalog.forbidden_claim_statements(),
            caveat_refs: vec!["risk:1".to_string()],
            supporting_refs: vec!["matrix:1".to_string()],
            supporting_evidence_refs: vec!["evidence:1".to_string()],
            counter_evidence_refs: vec!["counter:1".to_string()],
            publication_risk_refs: vec!["risk:1".to_string()],
        };
        claim_boundary.validate().unwrap();

        let dossier = ClosureDossier {
            closure_dossier_id: "dossier:1".to_string(),
            criteria_matrix_ref: matrix.criteria_matrix_id.clone(),
            inventory_ref: inventory.inventory_packet_id.clone(),
            adversarial_review_ref: adversarial.adversarial_review_id.clone(),
            claim_boundary_ref: claim_boundary.claim_review_id.clone(),
            risk_refs: vec!["risk:1".to_string()],
            recommendation_ref: "decision:1".to_string(),
        };
        dossier.validate().unwrap();

        let policy = PublicationPolicyRecord {
            publication_policy_id: "policy:1".to_string(),
            claim_catalog: claim_catalog.clone(),
            publication_controls: active_truth_publication_controls(),
            allowed_claims: claim_catalog.allowed_claim_statements(),
            required_caveats: active_truth_required_publication_caveats()
                .into_iter()
                .collect(),
            forbidden_claims: claim_catalog.forbidden_claim_statements(),
            source_refs: vec!["source:1".to_string()],
            audience_note: "audience note".to_string(),
        };
        policy.validate().unwrap();

        let decision = ClosureDecisionRecord {
            closure_decision_id: "decision:1".to_string(),
            decision: NorthStarClosureDecision::NotYet,
            rationale: "not yet".to_string(),
            required_followups: vec!["followup:1".to_string()],
            publication_policy_ref: policy.publication_policy_id.clone(),
            supersedes_ref: "lineage:root".to_string(),
        };
        decision.validate().unwrap();
    }

    #[test]
    fn active_truth_publication_policy_rejects_empty_required_caveats() {
        let claim_catalog =
            ActiveTruthClaimCatalogV1::bounded_local_first().expect("active claim catalog");
        let policy = PublicationPolicyRecord {
            publication_policy_id: "policy:closed".to_string(),
            claim_catalog: claim_catalog.clone(),
            publication_controls: active_truth_publication_controls(),
            allowed_claims: claim_catalog.allowed_claim_statements(),
            required_caveats: Vec::new(),
            forbidden_claims: claim_catalog.forbidden_claim_statements(),
            source_refs: vec!["source:1".to_string()],
            audience_note: "closed posture".to_string(),
        };

        assert_eq!(
            policy.validate(),
            Err(ClosureReviewError::MissingRequiredCaveats)
        );
    }

    #[test]
    fn active_truth_publication_policy_requires_each_unique_structured_caveat() {
        let claim_catalog =
            ActiveTruthClaimCatalogV1::bounded_local_first().expect("active claim catalog");
        let mut required_caveats = active_truth_required_publication_caveats()
            .into_iter()
            .collect::<Vec<_>>();
        required_caveats.retain(|caveat| caveat != "operational-decision:NotYet");
        let mut policy = PublicationPolicyRecord {
            publication_policy_id: "policy:missing-caveat".to_string(),
            claim_catalog: claim_catalog.clone(),
            publication_controls: active_truth_publication_controls(),
            allowed_claims: claim_catalog.allowed_claim_statements(),
            required_caveats,
            forbidden_claims: claim_catalog.forbidden_claim_statements(),
            source_refs: vec!["source:1".to_string()],
            audience_note: "bounded active-truth publication policy".to_string(),
        };
        assert_eq!(
            policy.validate(),
            Err(ClosureReviewError::MissingRequiredCaveats)
        );

        policy.required_caveats = active_truth_required_publication_caveats()
            .into_iter()
            .collect();
        policy
            .required_caveats
            .push("operational-decision:NotYet".to_string());
        assert_eq!(
            policy.validate(),
            Err(ClosureReviewError::MissingRequiredCaveats)
        );
    }

    #[test]
    fn active_truth_catalog_rejects_a_statement_substitution_even_with_a_fresh_digest() {
        let mut claim_catalog =
            ActiveTruthClaimCatalogV1::bounded_local_first().expect("active claim catalog");
        claim_catalog.allowed_claims[0].statement =
            "Caller-supplied replacement for the historical Phase 04 claim.".to_string();
        claim_catalog.catalog_digest = claim_catalog
            .expected_digest()
            .expect("digest substituted catalog");

        assert_eq!(
            claim_catalog.validate(),
            Err(ClosureReviewError::InvalidActiveTruthClaimCatalog)
        );
    }
}
