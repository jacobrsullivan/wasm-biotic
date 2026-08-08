//! Persistable typed proving and comparison evidence for the bounded M1 path.
//!
//! The entry point in this module accepts exact component bytes, executes every
//! case through the bounded typed Wasmtime API, and records either the returned
//! trace or a classified pre-execution rejection. Callers cannot provide scores,
//! pass flags, comparison deltas, or a promotion verdict; all of those values are
//! derived here from the suite and execution evidence.
//!
//! Two content identities are retained:
//!
//! - semantic digests bind the component, suite, expected outcome, and observed
//!   output/trap/limit/rejection class while excluding human diagnostic text;
//! - record digests additionally bind the complete Wasmtime traces, including
//!   configured limits, fuel consumption, imports, and diagnostics.
//!
//! These digests make local records reproducible and tamper-evident. They are not
//! signatures and do not, by themselves, authenticate who produced a record.

use crate::execution::artifact::{ArtifactError, ContentDigest, digest_json_content};
use crate::execution::component::{
    ComponentBuildError, ComponentExecutionFailurePhase, ComponentExecutionLimitKind,
    ComponentExecutionLimits, ComponentI32ExecutionTrace, execute_component_i32_export,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{Display, Formatter};

pub const VALIDATION_SUITE_SCHEMA: &str = "wasm-biotic.m1-validation-suite.v1";
pub const PROVING_RECORD_SCHEMA: &str = "wasm-biotic.m1-proving-record.v1";
pub const COMPARISON_RECORD_SCHEMA: &str = "wasm-biotic.m1-comparison-record.v1";
pub const MAX_VALIDATION_CASES: usize = 1_024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationSuite {
    pub suite_id: String,
    pub export_name: String,
    pub cases: Vec<ValidationCase>,
    pub limits: ComponentExecutionLimits,
}

impl ValidationSuite {
    pub fn new(
        suite_id: impl Into<String>,
        export_name: impl Into<String>,
        cases: Vec<ValidationCase>,
        limits: ComponentExecutionLimits,
    ) -> Result<Self, ValidationError> {
        let suite = Self {
            suite_id: suite_id.into(),
            export_name: export_name.into(),
            cases,
            limits,
        };
        suite.validate()?;
        Ok(suite)
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_identifier("suite_id", &self.suite_id)?;
        validate_identifier("export_name", &self.export_name)?;
        if self.cases.is_empty() {
            return Err(ValidationError::InvalidSuite(
                "a proving suite must contain at least one case".to_string(),
            ));
        }
        if self.cases.len() > MAX_VALIDATION_CASES {
            return Err(ValidationError::InvalidSuite(format!(
                "a proving suite may contain at most {MAX_VALIDATION_CASES} cases"
            )));
        }
        validate_limits(&self.limits)?;

        let mut case_ids = BTreeSet::new();
        let mut inputs = BTreeSet::new();
        for case in &self.cases {
            validate_identifier("case_id", &case.case_id)?;
            if !case_ids.insert(case.case_id.clone()) {
                return Err(ValidationError::DuplicateCaseId(case.case_id.clone()));
            }
            if !inputs.insert(case.input) {
                return Err(ValidationError::DuplicateCaseInput(case.input));
            }
        }
        Ok(())
    }

    pub fn suite_digest(&self) -> Result<ContentDigest, ValidationError> {
        self.validate()?;
        Ok(digest_json_content(&SuiteDigestMaterial {
            schema: VALIDATION_SUITE_SCHEMA,
            suite: self,
        })?)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationCase {
    pub case_id: String,
    pub input: i32,
    pub expected: ExpectedI32Outcome,
}

impl ValidationCase {
    pub fn returns(case_id: impl Into<String>, input: i32, output: i32) -> Self {
        Self {
            case_id: case_id.into(),
            input,
            expected: ExpectedI32Outcome::Returned(output),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum ExpectedI32Outcome {
    Returned(i32),
    GuestTrap,
    LimitExhausted(ComponentExecutionLimitKind),
    ExecutionRejected(ExecutionRejectionKind),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ObservedI32Outcome {
    Returned {
        value: i32,
    },
    GuestTrap {
        phase: ComponentExecutionFailurePhase,
    },
    LimitExhausted {
        phase: ComponentExecutionFailurePhase,
        limit: ComponentExecutionLimitKind,
    },
    ExecutionRejected {
        rejection: ExecutionRejectionKind,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionRejectionKind {
    InvalidComponent,
    CoreModuleInsteadOfComponent,
    MissingExport,
    UnsupportedImports,
    InvalidLimits,
    IncompatibleTypedExportOrRuntime,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionRejection {
    pub kind: ExecutionRejectionKind,
    pub diagnostic: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "evidence")]
pub enum CaseExecutionEvidence {
    Trace { trace: ComponentI32ExecutionTrace },
    Rejected { rejection: ExecutionRejection },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationCaseResult {
    pub case_id: String,
    pub input: i32,
    pub expected: ExpectedI32Outcome,
    pub observed: ObservedI32Outcome,
    pub satisfied: bool,
    pub execution: CaseExecutionEvidence,
    pub semantic_digest: ContentDigest,
    pub record_digest: ContentDigest,
}

impl ValidationCaseResult {
    pub fn trace(&self) -> Option<&ComponentI32ExecutionTrace> {
        match &self.execution {
            CaseExecutionEvidence::Trace { trace } => Some(trace),
            CaseExecutionEvidence::Rejected { .. } => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvingSummary {
    pub case_count: usize,
    pub satisfied_count: usize,
    pub returned_count: usize,
    pub guest_trap_count: usize,
    pub limit_exhausted_count: usize,
    pub execution_rejected_count: usize,
    pub all_satisfied: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvingRecord {
    pub schema: String,
    pub suite_id: String,
    pub suite_digest: ContentDigest,
    pub component_digest: ContentDigest,
    pub export_name: String,
    pub limits: ComponentExecutionLimits,
    pub results: Vec<ValidationCaseResult>,
    pub summary: ProvingSummary,
    pub semantic_digest: ContentDigest,
    pub record_digest: ContentDigest,
}

/// Executes every suite case against the exact supplied bytes.
///
/// Guest traps and resource-limit terminations are successful calls to this
/// function and are represented by typed traces. Invalid component bytes,
/// missing exports, incompatible typed signatures, and runtime setup failures
/// are represented by classified rejection evidence rather than discarded.
pub fn prove_component_i32(
    suite: &ValidationSuite,
    component_bytes: &[u8],
) -> Result<ProvingRecord, ValidationError> {
    let suite_digest = suite.suite_digest()?;
    let component_digest = ContentDigest::from_bytes(component_bytes);
    let mut results = Vec::with_capacity(suite.cases.len());

    for case in &suite.cases {
        let execution = match execute_component_i32_export(
            component_bytes,
            suite.export_name.clone(),
            case.input,
            &suite.limits,
        ) {
            Ok(trace) => CaseExecutionEvidence::Trace { trace },
            Err(error) => CaseExecutionEvidence::Rejected {
                rejection: ExecutionRejection {
                    kind: classify_execution_rejection(&error),
                    diagnostic: error.to_string(),
                },
            },
        };
        results.push(build_case_result(
            &suite_digest,
            &component_digest,
            &suite.export_name,
            &suite.limits,
            case,
            execution,
        )?);
    }

    let summary = derive_proving_summary(&results);
    let semantic_digest = proving_semantic_digest(
        &suite_digest,
        &component_digest,
        &suite.export_name,
        &suite.limits,
        &results,
        &summary,
    )?;
    let record_digest = proving_record_digest(
        &suite.suite_id,
        &suite_digest,
        &component_digest,
        &suite.export_name,
        &suite.limits,
        &results,
        &summary,
        &semantic_digest,
    )?;
    let record = ProvingRecord {
        schema: PROVING_RECORD_SCHEMA.to_string(),
        suite_id: suite.suite_id.clone(),
        suite_digest,
        component_digest,
        export_name: suite.export_name.clone(),
        limits: suite.limits.clone(),
        results,
        summary,
        semantic_digest,
        record_digest,
    };
    validate_proving_record(suite, &record)?;
    Ok(record)
}

/// Re-derives all redundant fields and digests in a persisted proving record.
///
/// This establishes internal consistency and content identity. It cannot prove
/// provenance without an external signature or trusted storage boundary.
pub fn validate_proving_record(
    suite: &ValidationSuite,
    record: &ProvingRecord,
) -> Result<(), ValidationError> {
    let expected_suite_digest = suite.suite_digest()?;
    if record.schema != PROVING_RECORD_SCHEMA {
        return Err(proving_invariant("unexpected proving-record schema"));
    }
    if record.suite_id != suite.suite_id
        || record.suite_digest != expected_suite_digest
        || record.export_name != suite.export_name
        || record.limits != suite.limits
    {
        return Err(proving_invariant(
            "record is not bound to the supplied validation suite",
        ));
    }
    if record.results.len() != suite.cases.len() {
        return Err(proving_invariant(
            "result count does not match the validation suite",
        ));
    }

    for (case, result) in suite.cases.iter().zip(&record.results) {
        validate_case_result(
            &record.suite_digest,
            &record.component_digest,
            &record.export_name,
            &record.limits,
            case,
            result,
        )?;
    }

    let expected_summary = derive_proving_summary(&record.results);
    if record.summary != expected_summary {
        return Err(proving_invariant(
            "proving summary does not match the case results",
        ));
    }
    let expected_semantic_digest = proving_semantic_digest(
        &record.suite_digest,
        &record.component_digest,
        &record.export_name,
        &record.limits,
        &record.results,
        &record.summary,
    )?;
    if record.semantic_digest != expected_semantic_digest {
        return Err(proving_invariant(
            "proving semantic digest does not match derived semantics",
        ));
    }
    let expected_record_digest = proving_record_digest(
        &record.suite_id,
        &record.suite_digest,
        &record.component_digest,
        &record.export_name,
        &record.limits,
        &record.results,
        &record.summary,
        &record.semantic_digest,
    )?;
    if record.record_digest != expected_record_digest {
        return Err(proving_invariant(
            "proving record digest does not match complete evidence",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaseComparisonDelta {
    Improved,
    Regressed,
    SemanticallyEquivalent,
    ChangedWithoutScoreDelta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseComparison {
    pub case_id: String,
    pub incumbent_observed: ObservedI32Outcome,
    pub challenger_observed: ObservedI32Outcome,
    pub incumbent_satisfied: bool,
    pub challenger_satisfied: bool,
    pub delta: CaseComparisonDelta,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonSummary {
    pub case_count: usize,
    pub improved_count: usize,
    pub regressed_count: usize,
    pub semantically_equivalent_count: usize,
    pub changed_without_score_delta_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonDecision {
    ChallengerPreferred,
    SemanticallyEquivalent,
    IncumbentRetained,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComparisonRecord {
    pub schema: String,
    pub suite_id: String,
    pub suite_digest: ContentDigest,
    pub incumbent_component_digest: ContentDigest,
    pub challenger_component_digest: ContentDigest,
    pub incumbent_proving_digest: ContentDigest,
    pub challenger_proving_digest: ContentDigest,
    pub cases: Vec<CaseComparison>,
    pub summary: ComparisonSummary,
    pub decision: ComparisonDecision,
    pub eligible_for_activation: bool,
    pub rationale: String,
    pub semantic_digest: ContentDigest,
    pub record_digest: ContentDigest,
}

/// Derives a comparison solely from validated incumbent and challenger records.
///
/// A challenger is eligible only when it satisfies the complete suite and the
/// incumbent does not. Passing but behaviorally indistinguishable artifacts are
/// equivalent for this suite; partial improvements never authorize activation.
pub fn compare_proving_records(
    suite: &ValidationSuite,
    incumbent: &ProvingRecord,
    challenger: &ProvingRecord,
) -> Result<ComparisonRecord, ValidationError> {
    validate_proving_record(suite, incumbent)?;
    validate_proving_record(suite, challenger)?;
    derive_comparison_record(suite, incumbent, challenger)
}

/// Validates a persisted comparison by deriving the only admissible record.
pub fn validate_comparison_record(
    suite: &ValidationSuite,
    incumbent: &ProvingRecord,
    challenger: &ProvingRecord,
    comparison: &ComparisonRecord,
) -> Result<(), ValidationError> {
    validate_proving_record(suite, incumbent)?;
    validate_proving_record(suite, challenger)?;
    let expected = derive_comparison_record(suite, incumbent, challenger)?;
    if comparison != &expected {
        return Err(ValidationError::ComparisonInvariant(
            "persisted comparison differs from the derived comparison".to_string(),
        ));
    }
    Ok(())
}

fn derive_comparison_record(
    suite: &ValidationSuite,
    incumbent: &ProvingRecord,
    challenger: &ProvingRecord,
) -> Result<ComparisonRecord, ValidationError> {
    if incumbent.suite_digest != challenger.suite_digest {
        return Err(ValidationError::ComparisonInvariant(
            "incumbent and challenger records use different suites".to_string(),
        ));
    }

    let cases = incumbent
        .results
        .iter()
        .zip(&challenger.results)
        .map(|(incumbent_result, challenger_result)| {
            let delta = if !incumbent_result.satisfied && challenger_result.satisfied {
                CaseComparisonDelta::Improved
            } else if incumbent_result.satisfied && !challenger_result.satisfied {
                CaseComparisonDelta::Regressed
            } else if incumbent_result.observed == challenger_result.observed {
                CaseComparisonDelta::SemanticallyEquivalent
            } else {
                CaseComparisonDelta::ChangedWithoutScoreDelta
            };
            CaseComparison {
                case_id: incumbent_result.case_id.clone(),
                incumbent_observed: incumbent_result.observed.clone(),
                challenger_observed: challenger_result.observed.clone(),
                incumbent_satisfied: incumbent_result.satisfied,
                challenger_satisfied: challenger_result.satisfied,
                delta,
            }
        })
        .collect::<Vec<_>>();
    let summary = derive_comparison_summary(&cases);

    let decision = if challenger.summary.all_satisfied && !incumbent.summary.all_satisfied {
        ComparisonDecision::ChallengerPreferred
    } else if summary.semantically_equivalent_count == summary.case_count {
        ComparisonDecision::SemanticallyEquivalent
    } else {
        ComparisonDecision::IncumbentRetained
    };
    let eligible_for_activation = decision == ComparisonDecision::ChallengerPreferred;
    let rationale = match decision {
        ComparisonDecision::ChallengerPreferred => format!(
            "challenger satisfies all {} cases; incumbent satisfies {}/{}",
            challenger.summary.case_count,
            incumbent.summary.satisfied_count,
            incumbent.summary.case_count
        ),
        ComparisonDecision::SemanticallyEquivalent => format!(
            "incumbent and challenger have the same observed outcome for all {} cases",
            summary.case_count
        ),
        ComparisonDecision::IncumbentRetained => format!(
            "challenger is not a complete-suite improvement: {} improved, {} regressed, {}/{} satisfied",
            summary.improved_count,
            summary.regressed_count,
            challenger.summary.satisfied_count,
            challenger.summary.case_count
        ),
    };
    let semantic_digest = comparison_semantic_digest(
        &incumbent.suite_digest,
        incumbent,
        challenger,
        &cases,
        &summary,
        &decision,
        eligible_for_activation,
    )?;
    let record_digest = comparison_record_digest(
        &suite.suite_id,
        &incumbent.suite_digest,
        incumbent,
        challenger,
        &cases,
        &summary,
        &decision,
        eligible_for_activation,
        &rationale,
        &semantic_digest,
    )?;
    Ok(ComparisonRecord {
        schema: COMPARISON_RECORD_SCHEMA.to_string(),
        suite_id: suite.suite_id.clone(),
        suite_digest: incumbent.suite_digest.clone(),
        incumbent_component_digest: incumbent.component_digest.clone(),
        challenger_component_digest: challenger.component_digest.clone(),
        incumbent_proving_digest: incumbent.record_digest.clone(),
        challenger_proving_digest: challenger.record_digest.clone(),
        cases,
        summary,
        decision,
        eligible_for_activation,
        rationale,
        semantic_digest,
        record_digest,
    })
}

fn build_case_result(
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    export_name: &str,
    limits: &ComponentExecutionLimits,
    case: &ValidationCase,
    execution: CaseExecutionEvidence,
) -> Result<ValidationCaseResult, ValidationError> {
    let observed = observed_from_execution(
        component_digest,
        export_name,
        limits,
        case.input,
        &execution,
    )?;
    let satisfied = expected_matches_observed(&case.expected, &observed);
    let semantic_digest =
        case_semantic_digest(suite_digest, component_digest, case, &observed, satisfied)?;
    let record_digest = case_record_digest(
        suite_digest,
        component_digest,
        case,
        &observed,
        satisfied,
        &execution,
        &semantic_digest,
    )?;
    Ok(ValidationCaseResult {
        case_id: case.case_id.clone(),
        input: case.input,
        expected: case.expected.clone(),
        observed,
        satisfied,
        execution,
        semantic_digest,
        record_digest,
    })
}

fn validate_case_result(
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    export_name: &str,
    limits: &ComponentExecutionLimits,
    case: &ValidationCase,
    result: &ValidationCaseResult,
) -> Result<(), ValidationError> {
    if result.case_id != case.case_id
        || result.input != case.input
        || result.expected != case.expected
    {
        return Err(proving_invariant(
            "case result is not bound to its suite case",
        ));
    }
    let observed = observed_from_execution(
        component_digest,
        export_name,
        limits,
        case.input,
        &result.execution,
    )?;
    if result.observed != observed {
        return Err(proving_invariant(
            "recorded outcome does not match execution evidence",
        ));
    }
    let satisfied = expected_matches_observed(&case.expected, &observed);
    if result.satisfied != satisfied {
        return Err(proving_invariant(
            "recorded satisfaction flag does not match the expected and observed outcomes",
        ));
    }
    let semantic_digest =
        case_semantic_digest(suite_digest, component_digest, case, &observed, satisfied)?;
    if result.semantic_digest != semantic_digest {
        return Err(proving_invariant(
            "case semantic digest does not match derived semantics",
        ));
    }
    let record_digest = case_record_digest(
        suite_digest,
        component_digest,
        case,
        &observed,
        satisfied,
        &result.execution,
        &semantic_digest,
    )?;
    if result.record_digest != record_digest {
        return Err(proving_invariant(
            "case record digest does not match complete execution evidence",
        ));
    }
    Ok(())
}

fn observed_from_execution(
    component_digest: &ContentDigest,
    export_name: &str,
    limits: &ComponentExecutionLimits,
    input: i32,
    execution: &CaseExecutionEvidence,
) -> Result<ObservedI32Outcome, ValidationError> {
    match execution {
        CaseExecutionEvidence::Rejected { rejection } => {
            if rejection.diagnostic.trim().is_empty() {
                return Err(proving_invariant(
                    "execution rejection must retain a diagnostic",
                ));
            }
            Ok(ObservedI32Outcome::ExecutionRejected {
                rejection: rejection.kind.clone(),
            })
        }
        CaseExecutionEvidence::Trace { trace } => {
            if trace.component_digest != *component_digest
                || trace.export_name != export_name
                || trace.input != input
                || trace.limits != *limits
            {
                return Err(proving_invariant(
                    "Wasmtime trace is not bound to the component, export, input, and limits",
                ));
            }
            if trace.fuel_consumed > limits.fuel {
                return Err(proving_invariant(
                    "Wasmtime trace consumed more fuel than the configured limit",
                ));
            }
            if !trace.trapped {
                if trace.failure_phase.is_some()
                    || trace.limit_exhausted.is_some()
                    || trace.output.is_none()
                {
                    return Err(proving_invariant(
                        "successful Wasmtime trace has contradictory failure fields",
                    ));
                }
                return Ok(ObservedI32Outcome::Returned {
                    value: trace.output.expect("output checked above"),
                });
            }
            if trace.output.is_some() {
                return Err(proving_invariant(
                    "trapped Wasmtime trace cannot also contain an output",
                ));
            }
            let phase = trace.failure_phase.clone().ok_or_else(|| {
                proving_invariant("trapped Wasmtime trace must identify its failure phase")
            })?;
            match &trace.limit_exhausted {
                Some(limit) => Ok(ObservedI32Outcome::LimitExhausted {
                    phase,
                    limit: limit.clone(),
                }),
                None => Ok(ObservedI32Outcome::GuestTrap { phase }),
            }
        }
    }
}

fn expected_matches_observed(expected: &ExpectedI32Outcome, observed: &ObservedI32Outcome) -> bool {
    match (expected, observed) {
        (
            ExpectedI32Outcome::Returned(expected),
            ObservedI32Outcome::Returned { value: actual },
        ) => expected == actual,
        (ExpectedI32Outcome::GuestTrap, ObservedI32Outcome::GuestTrap { .. }) => true,
        (
            ExpectedI32Outcome::LimitExhausted(expected),
            ObservedI32Outcome::LimitExhausted { limit: actual, .. },
        ) => expected == actual,
        (
            ExpectedI32Outcome::ExecutionRejected(expected),
            ObservedI32Outcome::ExecutionRejected { rejection: actual },
        ) => expected == actual,
        _ => false,
    }
}

fn derive_proving_summary(results: &[ValidationCaseResult]) -> ProvingSummary {
    let mut summary = ProvingSummary {
        case_count: results.len(),
        satisfied_count: 0,
        returned_count: 0,
        guest_trap_count: 0,
        limit_exhausted_count: 0,
        execution_rejected_count: 0,
        all_satisfied: false,
    };
    for result in results {
        if result.satisfied {
            summary.satisfied_count += 1;
        }
        match result.observed {
            ObservedI32Outcome::Returned { .. } => summary.returned_count += 1,
            ObservedI32Outcome::GuestTrap { .. } => summary.guest_trap_count += 1,
            ObservedI32Outcome::LimitExhausted { .. } => {
                summary.limit_exhausted_count += 1;
            }
            ObservedI32Outcome::ExecutionRejected { .. } => {
                summary.execution_rejected_count += 1;
            }
        }
    }
    summary.all_satisfied = !results.is_empty() && summary.satisfied_count == summary.case_count;
    summary
}

fn derive_comparison_summary(cases: &[CaseComparison]) -> ComparisonSummary {
    let mut summary = ComparisonSummary {
        case_count: cases.len(),
        improved_count: 0,
        regressed_count: 0,
        semantically_equivalent_count: 0,
        changed_without_score_delta_count: 0,
    };
    for case in cases {
        match case.delta {
            CaseComparisonDelta::Improved => summary.improved_count += 1,
            CaseComparisonDelta::Regressed => summary.regressed_count += 1,
            CaseComparisonDelta::SemanticallyEquivalent => {
                summary.semantically_equivalent_count += 1;
            }
            CaseComparisonDelta::ChangedWithoutScoreDelta => {
                summary.changed_without_score_delta_count += 1;
            }
        }
    }
    summary
}

fn classify_execution_rejection(error: &ComponentBuildError) -> ExecutionRejectionKind {
    match error {
        ComponentBuildError::InvalidComponentEncoding
        | ComponentBuildError::WasmParse(_)
        | ComponentBuildError::WatParse(_) => ExecutionRejectionKind::InvalidComponent,
        ComponentBuildError::CoreWasmModuleRejected => {
            ExecutionRejectionKind::CoreModuleInsteadOfComponent
        }
        ComponentBuildError::MissingComponentExport(_) => ExecutionRejectionKind::MissingExport,
        ComponentBuildError::UnsupportedImports(_)
        | ComponentBuildError::UnboundComponentImport { .. }
        | ComponentBuildError::UnusedImportBinding { .. }
        | ComponentBuildError::DuplicateImportBinding { .. }
        | ComponentBuildError::MalformedImportBinding { .. }
        | ComponentBuildError::ImportCapabilityWorldMissing { .. }
        | ComponentBuildError::ImportResourceScopeNotAllowed { .. }
        | ComponentBuildError::ImportOperationNotAllowed { .. }
        | ComponentBuildError::ImportAuthorityExceedsEnvelope { .. }
        | ComponentBuildError::ImportApprovalBlocked { .. } => {
            ExecutionRejectionKind::UnsupportedImports
        }
        ComponentBuildError::InvalidExecutionLimit { .. }
        | ComponentBuildError::ExecutionLimitOutOfRange { .. } => {
            ExecutionRejectionKind::InvalidLimits
        }
        ComponentBuildError::MissingBuildId
        | ComponentBuildError::MissingWitWorld
        | ComponentBuildError::MissingComponentSource
        | ComponentBuildError::MissingCapabilityWorlds
        | ComponentBuildError::ComponentExportMismatch { .. }
        | ComponentBuildError::ComponentImportMismatch { .. }
        | ComponentBuildError::WitWorldMismatch { .. }
        | ComponentBuildError::WitParse(_)
        | ComponentBuildError::Wasmtime(_)
        | ComponentBuildError::Artifact(_)
        | ComponentBuildError::Serialization(_) => {
            ExecutionRejectionKind::IncompatibleTypedExportOrRuntime
        }
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.trim() != value || value.chars().any(char::is_control) {
        return Err(ValidationError::InvalidSuite(format!(
            "{field} must be a non-empty, trimmed, printable string"
        )));
    }
    Ok(())
}

fn validate_limits(limits: &ComponentExecutionLimits) -> Result<(), ValidationError> {
    let configured = [
        ("fuel", limits.fuel),
        ("max_memory_bytes", limits.max_memory_bytes),
        ("max_instances", u64::from(limits.max_instances)),
        ("max_memories", u64::from(limits.max_memories)),
        ("max_tables", u64::from(limits.max_tables)),
        ("max_table_elements", u64::from(limits.max_table_elements)),
    ];
    if let Some((name, _)) = configured.into_iter().find(|(_, value)| *value == 0) {
        return Err(ValidationError::InvalidSuite(format!(
            "execution limit {name} must be non-zero"
        )));
    }
    usize::try_from(limits.max_memory_bytes).map_err(|_| {
        ValidationError::InvalidSuite(
            "max_memory_bytes cannot be represented on this host".to_string(),
        )
    })?;
    Ok(())
}

#[derive(Serialize)]
struct SuiteDigestMaterial<'a> {
    schema: &'static str,
    suite: &'a ValidationSuite,
}

#[derive(Serialize)]
struct CaseSemanticDigestMaterial<'a> {
    schema: &'static str,
    suite_digest: &'a ContentDigest,
    component_digest: &'a ContentDigest,
    case_id: &'a str,
    input: i32,
    expected: &'a ExpectedI32Outcome,
    observed: &'a ObservedI32Outcome,
    satisfied: bool,
}

fn case_semantic_digest(
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    case: &ValidationCase,
    observed: &ObservedI32Outcome,
    satisfied: bool,
) -> Result<ContentDigest, ValidationError> {
    Ok(digest_json_content(&CaseSemanticDigestMaterial {
        schema: "wasm-biotic.m1-case-semantic.v1",
        suite_digest,
        component_digest,
        case_id: &case.case_id,
        input: case.input,
        expected: &case.expected,
        observed,
        satisfied,
    })?)
}

#[derive(Serialize)]
struct CaseRecordDigestMaterial<'a> {
    schema: &'static str,
    suite_digest: &'a ContentDigest,
    component_digest: &'a ContentDigest,
    case_id: &'a str,
    input: i32,
    expected: &'a ExpectedI32Outcome,
    observed: &'a ObservedI32Outcome,
    satisfied: bool,
    execution: &'a CaseExecutionEvidence,
    semantic_digest: &'a ContentDigest,
}

#[allow(clippy::too_many_arguments)]
fn case_record_digest(
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    case: &ValidationCase,
    observed: &ObservedI32Outcome,
    satisfied: bool,
    execution: &CaseExecutionEvidence,
    semantic_digest: &ContentDigest,
) -> Result<ContentDigest, ValidationError> {
    Ok(digest_json_content(&CaseRecordDigestMaterial {
        schema: "wasm-biotic.m1-case-record.v1",
        suite_digest,
        component_digest,
        case_id: &case.case_id,
        input: case.input,
        expected: &case.expected,
        observed,
        satisfied,
        execution,
        semantic_digest,
    })?)
}

#[derive(Serialize)]
struct ProvingSemanticDigestMaterial<'a> {
    schema: &'static str,
    suite_digest: &'a ContentDigest,
    component_digest: &'a ContentDigest,
    export_name: &'a str,
    limits: &'a ComponentExecutionLimits,
    result_semantic_digests: Vec<&'a ContentDigest>,
    summary: &'a ProvingSummary,
}

fn proving_semantic_digest(
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    export_name: &str,
    limits: &ComponentExecutionLimits,
    results: &[ValidationCaseResult],
    summary: &ProvingSummary,
) -> Result<ContentDigest, ValidationError> {
    Ok(digest_json_content(&ProvingSemanticDigestMaterial {
        schema: "wasm-biotic.m1-proving-semantic.v1",
        suite_digest,
        component_digest,
        export_name,
        limits,
        result_semantic_digests: results
            .iter()
            .map(|result| &result.semantic_digest)
            .collect(),
        summary,
    })?)
}

#[derive(Serialize)]
struct ProvingRecordDigestMaterial<'a> {
    schema: &'static str,
    suite_id: &'a str,
    suite_digest: &'a ContentDigest,
    component_digest: &'a ContentDigest,
    export_name: &'a str,
    limits: &'a ComponentExecutionLimits,
    results: &'a [ValidationCaseResult],
    summary: &'a ProvingSummary,
    semantic_digest: &'a ContentDigest,
}

#[allow(clippy::too_many_arguments)]
fn proving_record_digest(
    suite_id: &str,
    suite_digest: &ContentDigest,
    component_digest: &ContentDigest,
    export_name: &str,
    limits: &ComponentExecutionLimits,
    results: &[ValidationCaseResult],
    summary: &ProvingSummary,
    semantic_digest: &ContentDigest,
) -> Result<ContentDigest, ValidationError> {
    Ok(digest_json_content(&ProvingRecordDigestMaterial {
        schema: PROVING_RECORD_SCHEMA,
        suite_id,
        suite_digest,
        component_digest,
        export_name,
        limits,
        results,
        summary,
        semantic_digest,
    })?)
}

#[derive(Serialize)]
struct ComparisonSemanticDigestMaterial<'a> {
    schema: &'static str,
    suite_digest: &'a ContentDigest,
    incumbent_component_digest: &'a ContentDigest,
    challenger_component_digest: &'a ContentDigest,
    incumbent_proving_semantic_digest: &'a ContentDigest,
    challenger_proving_semantic_digest: &'a ContentDigest,
    cases: &'a [CaseComparison],
    summary: &'a ComparisonSummary,
    decision: &'a ComparisonDecision,
    eligible_for_activation: bool,
}

#[allow(clippy::too_many_arguments)]
fn comparison_semantic_digest(
    suite_digest: &ContentDigest,
    incumbent: &ProvingRecord,
    challenger: &ProvingRecord,
    cases: &[CaseComparison],
    summary: &ComparisonSummary,
    decision: &ComparisonDecision,
    eligible_for_activation: bool,
) -> Result<ContentDigest, ValidationError> {
    Ok(digest_json_content(&ComparisonSemanticDigestMaterial {
        schema: "wasm-biotic.m1-comparison-semantic.v1",
        suite_digest,
        incumbent_component_digest: &incumbent.component_digest,
        challenger_component_digest: &challenger.component_digest,
        incumbent_proving_semantic_digest: &incumbent.semantic_digest,
        challenger_proving_semantic_digest: &challenger.semantic_digest,
        cases,
        summary,
        decision,
        eligible_for_activation,
    })?)
}

#[derive(Serialize)]
struct ComparisonRecordDigestMaterial<'a> {
    schema: &'static str,
    suite_id: &'a str,
    suite_digest: &'a ContentDigest,
    incumbent_component_digest: &'a ContentDigest,
    challenger_component_digest: &'a ContentDigest,
    incumbent_proving_digest: &'a ContentDigest,
    challenger_proving_digest: &'a ContentDigest,
    cases: &'a [CaseComparison],
    summary: &'a ComparisonSummary,
    decision: &'a ComparisonDecision,
    eligible_for_activation: bool,
    rationale: &'a str,
    semantic_digest: &'a ContentDigest,
}

#[allow(clippy::too_many_arguments)]
fn comparison_record_digest(
    suite_id: &str,
    suite_digest: &ContentDigest,
    incumbent: &ProvingRecord,
    challenger: &ProvingRecord,
    cases: &[CaseComparison],
    summary: &ComparisonSummary,
    decision: &ComparisonDecision,
    eligible_for_activation: bool,
    rationale: &str,
    semantic_digest: &ContentDigest,
) -> Result<ContentDigest, ValidationError> {
    Ok(digest_json_content(&ComparisonRecordDigestMaterial {
        schema: COMPARISON_RECORD_SCHEMA,
        suite_id,
        suite_digest,
        incumbent_component_digest: &incumbent.component_digest,
        challenger_component_digest: &challenger.component_digest,
        incumbent_proving_digest: &incumbent.record_digest,
        challenger_proving_digest: &challenger.record_digest,
        cases,
        summary,
        decision,
        eligible_for_activation,
        rationale,
        semantic_digest,
    })?)
}

fn proving_invariant(detail: impl Into<String>) -> ValidationError {
    ValidationError::ProvingInvariant(detail.into())
}

#[derive(Debug)]
pub enum ValidationError {
    InvalidSuite(String),
    DuplicateCaseId(String),
    DuplicateCaseInput(i32),
    ProvingInvariant(String),
    ComparisonInvariant(String),
    Artifact(ArtifactError),
}

impl From<ArtifactError> for ValidationError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}

impl Display for ValidationError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSuite(detail) => write!(formatter, "invalid validation suite: {detail}"),
            Self::DuplicateCaseId(case_id) => {
                write!(formatter, "duplicate validation case id: {case_id}")
            }
            Self::DuplicateCaseInput(input) => {
                write!(formatter, "duplicate validation case input: {input}")
            }
            Self::ProvingInvariant(detail) => {
                write!(formatter, "proving-record invariant failed: {detail}")
            }
            Self::ComparisonInvariant(detail) => {
                write!(formatter, "comparison-record invariant failed: {detail}")
            }
            Self::Artifact(error) => write!(formatter, "validation artifact error: {error}"),
        }
    }
}

impl Error for ValidationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Artifact(source) => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaseComparisonDelta, CaseExecutionEvidence, ComparisonDecision, ExecutionRejectionKind,
        ExpectedI32Outcome, ObservedI32Outcome, ValidationCase, ValidationError, ValidationSuite,
        compare_proving_records, prove_component_i32, validate_comparison_record,
        validate_proving_record,
    };
    use crate::execution::component::{
        ComponentExecutionFailurePhase, ComponentExecutionLimitKind, ComponentExecutionLimits,
    };

    fn suite(cases: Vec<ValidationCase>, limits: ComponentExecutionLimits) -> ValidationSuite {
        ValidationSuite::new("m1-transform-v1", "transform", cases, limits)
            .expect("valid test suite")
    }

    fn increment_suite() -> ValidationSuite {
        suite(
            [(-1, 0), (0, 1), (41, 42)]
                .into_iter()
                .enumerate()
                .map(|(index, (input, output))| {
                    ValidationCase::returns(format!("case-{}", index + 1), input, output)
                })
                .collect(),
            ComponentExecutionLimits {
                fuel: 1_000_000,
                ..ComponentExecutionLimits::default()
            },
        )
    }

    fn component_bytes(core_body: &str) -> Vec<u8> {
        wat::parse_str(format!(
            r#"
                (component
                    (core module $m
                        (func (export "transform") (param i32) (result i32)
                            {core_body}))
                    (core instance $i (instantiate $m))
                    (func (export "transform") (param "input" s32) (result s32)
                        (canon lift (core func $i "transform"))))
            "#
        ))
        .expect("valid component fixture")
    }

    fn identity_component() -> Vec<u8> {
        component_bytes("local.get 0")
    }

    fn increment_component() -> Vec<u8> {
        component_bytes("local.get 0 i32.const 1 i32.add")
    }

    #[test]
    fn real_outputs_drive_scores_and_challenger_preference() {
        let suite = increment_suite();
        let incumbent =
            prove_component_i32(&suite, &identity_component()).expect("prove incumbent");
        let challenger =
            prove_component_i32(&suite, &increment_component()).expect("prove challenger");
        let comparison =
            compare_proving_records(&suite, &incumbent, &challenger).expect("compare records");

        assert_eq!(incumbent.summary.satisfied_count, 0);
        assert_eq!(challenger.summary.satisfied_count, 3);
        assert!(challenger.summary.all_satisfied);
        assert_eq!(
            challenger
                .results
                .iter()
                .map(|result| &result.observed)
                .collect::<Vec<_>>(),
            vec![
                &ObservedI32Outcome::Returned { value: 0 },
                &ObservedI32Outcome::Returned { value: 1 },
                &ObservedI32Outcome::Returned { value: 42 },
            ]
        );
        for result in &challenger.results {
            let trace = result.trace().expect("successful execution trace");
            assert!(trace.fuel_consumed > 0);
            assert_eq!(trace.limits, suite.limits);
            assert!(!trace.trapped);
        }
        assert_eq!(comparison.decision, ComparisonDecision::ChallengerPreferred);
        assert!(comparison.eligible_for_activation);
        assert!(
            comparison
                .cases
                .iter()
                .all(|case| case.delta == CaseComparisonDelta::Improved)
        );
    }

    #[test]
    fn semantic_and_record_digests_are_reproducible_and_serializable() {
        let suite = increment_suite();
        let component = increment_component();
        let first = prove_component_i32(&suite, &component).expect("first proving run");
        let second = prove_component_i32(&suite, &component).expect("second proving run");

        assert_eq!(first.semantic_digest, second.semantic_digest);
        assert_eq!(first.record_digest, second.record_digest);
        assert_eq!(
            first
                .results
                .iter()
                .map(|result| &result.semantic_digest)
                .collect::<Vec<_>>(),
            second
                .results
                .iter()
                .map(|result| &result.semantic_digest)
                .collect::<Vec<_>>()
        );

        let encoded = serde_json::to_vec(&first).expect("serialize proving record");
        let decoded = serde_json::from_slice(&encoded).expect("deserialize proving record");
        assert_eq!(first, decoded);
        validate_proving_record(&suite, &decoded).expect("validate persisted record");

        let comparison =
            compare_proving_records(&suite, &first, &second).expect("compare equivalent records");
        assert_eq!(
            comparison.decision,
            ComparisonDecision::SemanticallyEquivalent
        );
        assert!(!comparison.eligible_for_activation);
        let encoded = serde_json::to_vec(&comparison).expect("serialize comparison");
        let decoded = serde_json::from_slice(&encoded).expect("deserialize comparison");
        assert_eq!(comparison, decoded);
        validate_comparison_record(&suite, &first, &second, &decoded)
            .expect("validate persisted comparison");
    }

    #[test]
    fn guest_traps_are_typed_evidence_not_transport_errors() {
        let suite = suite(
            vec![ValidationCase {
                case_id: "trap".to_string(),
                input: 7,
                expected: ExpectedI32Outcome::GuestTrap,
            }],
            ComponentExecutionLimits::default(),
        );
        let record =
            prove_component_i32(&suite, &component_bytes("unreachable")).expect("prove trap");
        let result = &record.results[0];

        assert!(result.satisfied);
        assert_eq!(
            result.observed,
            ObservedI32Outcome::GuestTrap {
                phase: ComponentExecutionFailurePhase::Invocation
            }
        );
        let trace = result.trace().expect("trap trace");
        assert!(trace.trapped);
        assert_eq!(trace.output, None);
        assert_eq!(trace.limit_exhausted, None);
        assert!(trace.fuel_consumed > 0);
    }

    #[test]
    fn infinite_guest_is_stopped_and_recorded_at_the_fuel_boundary() {
        let limits = ComponentExecutionLimits {
            fuel: 50,
            ..ComponentExecutionLimits::default()
        };
        let suite = suite(
            vec![ValidationCase {
                case_id: "fuel".to_string(),
                input: 7,
                expected: ExpectedI32Outcome::LimitExhausted(ComponentExecutionLimitKind::Fuel),
            }],
            limits.clone(),
        );
        let component = component_bytes("(loop $spin br $spin) local.get 0");
        let record = prove_component_i32(&suite, &component).expect("prove bounded loop");
        let result = &record.results[0];

        assert!(result.satisfied);
        assert_eq!(
            result.observed,
            ObservedI32Outcome::LimitExhausted {
                phase: ComponentExecutionFailurePhase::Invocation,
                limit: ComponentExecutionLimitKind::Fuel,
            }
        );
        let trace = result.trace().expect("fuel trace");
        assert!(trace.trapped);
        assert_eq!(trace.fuel_consumed, limits.fuel);
        assert_eq!(
            trace.limit_exhausted,
            Some(ComponentExecutionLimitKind::Fuel)
        );
    }

    #[test]
    fn invalid_component_bytes_produce_persistable_rejection_evidence() {
        let suite = suite(
            vec![ValidationCase {
                case_id: "invalid".to_string(),
                input: 7,
                expected: ExpectedI32Outcome::ExecutionRejected(
                    ExecutionRejectionKind::InvalidComponent,
                ),
            }],
            ComponentExecutionLimits::default(),
        );
        let record = prove_component_i32(&suite, b"not wasm").expect("record invalid bytes");
        let result = &record.results[0];

        assert!(result.satisfied);
        assert_eq!(record.summary.execution_rejected_count, 1);
        assert_eq!(
            result.observed,
            ObservedI32Outcome::ExecutionRejected {
                rejection: ExecutionRejectionKind::InvalidComponent
            }
        );
        assert!(matches!(
            &result.execution,
            CaseExecutionEvidence::Rejected { rejection }
                if !rejection.diagnostic.is_empty()
        ));
        assert!(result.trace().is_none());
        validate_proving_record(&suite, &record).expect("validate rejection record");
    }

    #[test]
    fn tampered_scores_traces_and_verdicts_are_rejected() {
        let suite = increment_suite();
        let incumbent =
            prove_component_i32(&suite, &identity_component()).expect("prove incumbent");
        let challenger =
            prove_component_i32(&suite, &increment_component()).expect("prove challenger");

        let mut tampered_score = challenger.clone();
        tampered_score.summary.satisfied_count = 0;
        assert!(matches!(
            validate_proving_record(&suite, &tampered_score),
            Err(ValidationError::ProvingInvariant(_))
        ));

        let mut tampered_trace = challenger.clone();
        match &mut tampered_trace.results[0].execution {
            CaseExecutionEvidence::Trace { trace } => trace.fuel_consumed = 0,
            CaseExecutionEvidence::Rejected { .. } => panic!("expected trace"),
        }
        assert!(matches!(
            validate_proving_record(&suite, &tampered_trace),
            Err(ValidationError::ProvingInvariant(_))
        ));

        let comparison =
            compare_proving_records(&suite, &incumbent, &challenger).expect("compare records");
        let mut invented_verdict = comparison.clone();
        invented_verdict.decision = ComparisonDecision::IncumbentRetained;
        invented_verdict.eligible_for_activation = false;
        assert!(matches!(
            validate_comparison_record(&suite, &incumbent, &challenger, &invented_verdict),
            Err(ValidationError::ComparisonInvariant(_))
        ));
    }

    #[test]
    fn suites_reject_ambiguous_cases_and_invalid_limits() {
        assert!(matches!(
            ValidationSuite::new(
                "suite",
                "transform",
                vec![
                    ValidationCase::returns("duplicate", 1, 2),
                    ValidationCase::returns("duplicate", 2, 3),
                ],
                ComponentExecutionLimits::default(),
            ),
            Err(ValidationError::DuplicateCaseId(_))
        ));
        assert!(matches!(
            ValidationSuite::new(
                "suite",
                "transform",
                vec![
                    ValidationCase::returns("first", 1, 2),
                    ValidationCase::returns("second", 1, 2),
                ],
                ComponentExecutionLimits::default(),
            ),
            Err(ValidationError::DuplicateCaseInput(1))
        ));
        assert!(matches!(
            ValidationSuite::new(
                "suite",
                "transform",
                vec![ValidationCase::returns("case", 1, 2)],
                ComponentExecutionLimits {
                    fuel: 0,
                    ..ComponentExecutionLimits::default()
                },
            ),
            Err(ValidationError::InvalidSuite(_))
        ));
    }
}
