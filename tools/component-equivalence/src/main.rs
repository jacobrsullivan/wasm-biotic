use aiaf_v1::capability_services::CapabilityOperation as NativeOperation;
use aiaf_v1::deployment::{
    ActivationRequest, LocalDeploymentService, ObservationOutcome, ObservationRequest,
    RollbackRequest,
};
use aiaf_v1::execution::artifact::ContentDigest;
use aiaf_v1::execution::{
    AuthorityClass as NativeAuthority, CapabilityClosureEntry, CapabilityClosureStatus,
    CapabilityDependencyMode, CapabilityImportTarget, NativeServiceFamily, build_closure_inventory,
    closure_inventory_is_complete,
};
use aiaf_v1::m6_identity::{Clock as ExchangeClock, M6IdentityError};
use aiaf_v1::m6_transactions::{
    CoordinatorJournal, JournalConfig, M6TransactionError, RetryPolicy as ExchangeRetryPolicy,
    StageCause, StageEvidence, TransactionKind, TransactionRequestDraft,
};
use aiaf_v1::supervisor::{
    ApprovalResolutionKind, ApprovalResolutionRecord, CompleteJobOutcome, EffectCommit,
    JobExecutionResult, LocalDurableSupervisor, RetryPolicy as NativeRetryPolicy, SubmitJobOutcome,
    SubmitJobRequest, SupervisorClock, SupervisorError,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use wasm_biotic_closure_evaluator as closure;
use wasm_biotic_exchange_service as exchange;
use wasm_biotic_factory_control::policy as factory_control;
use wasm_biotic_factory_evolution as evolution;
use wasm_biotic_service_policy_core::{
    AuthorityClass as ComponentAuthority, Operation as ComponentOperation, operation_policy,
};
use wasm_biotic_state_migration as migration;
use wasm_biotic_supervisor_reducer::{
    BlobPointer, DigestValue, DispatchSpec, PolicyCommand, PolicyEvent, PolicyWorkerOutcome,
    PolicyWorkerResponse, ServiceFamilyValue, Stage, SupervisorStateV1, reduce_policy,
};
use wasm_biotic_worker_policy as worker;
use wasmtime::{
    Config, Engine, Store,
    component::{Component, HasSelf, Linker},
};

#[allow(missing_docs, unsafe_code)]
mod compiled_closure {
    wasmtime::component::bindgen!({
        path: "../../wit/wasm-biotic",
        world: "closure-evaluator-component",
    });
}

type DynError = Box<dyn Error + Send + Sync>;
type Result<T> = std::result::Result<T, DynError>;

const CORPUS_SCHEMA: &str = "wasm-biotic.behavioural-corpus.v1";
const REPORT_SCHEMA: &str = "wasm-biotic.behavioural-equivalence.v2";
const DECISION_ID: &str = "CD-0001-component-factory-contract-v1";
const LIFECYCLE_SCHEMA_V1: &str = "wasm-biotic.component-lifecycle-execution.v1";
const LIFECYCLE_SCHEMA_V2: &str = "wasm-biotic.component-lifecycle-execution.v2";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema: String,
    contract_decision: String,
    clock_ms: u64,
    source: String,
    events: Vec<CorpusEvent>,
    expected_operations: Vec<String>,
    approval_cases: Vec<ApprovalCaseExpectation>,
    exchange_replay_cases: Vec<ExchangeReplayCase>,
    malformed_document_cases: Vec<MalformedDocumentCase>,
    lifecycle_expectation: LifecycleExpectation,
    closure_cases: Vec<ClosureCaseExpectation>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusEvent {
    sequence: u64,
    kind: String,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalCaseExpectation {
    id: String,
    expected_terminal: String,
    expected_failure_code: Option<String>,
    service_delegate_invoked: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeReplayCase {
    id: String,
    existing_digest: Option<String>,
    presented_digest: String,
    expected_component: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MalformedDocumentCase {
    id: String,
    owner: String,
    expected_code: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleExpectation {
    schema: String,
    events: Vec<String>,
    incumbent_graph_manifest_digest: String,
    successor_graph_manifest_digest: String,
    expected_component_cycles: usize,
    expected_mechanism_receipts: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClosureCaseExpectation {
    id: String,
    complete: bool,
    expected_component: String,
    expected_native_complete: bool,
}

#[derive(Debug, Serialize)]
struct Report {
    schema: &'static str,
    corpus_digest: String,
    contract_decision: &'static str,
    native_oracle: &'static str,
    component_implementation: &'static str,
    shared_event_stream_scope: &'static str,
    same_event_stream_executed: bool,
    synthetic_policy_service_outputs: bool,
    synthetic_policy_trace_claims_useful_r1_semantics: bool,
    lifecycle_r1_semantics_verified_by_this_report: bool,
    common_outcomes: CommonOutcomes,
    component_trace: ComponentTrace,
    native_trace: NativeTrace,
    operation_policy: Vec<OperationComparison>,
    approval_and_authority: ApprovalEvidence,
    exchange_replay: ExchangeReplayEvidence,
    malformed_semantic_documents: MalformedDocumentEvidence,
    lifecycle: LifecycleEvidence,
    closure_decisions: ClosureEvidence,
    receipt_normalization: ReceiptNormalization,
    category_results: BTreeMap<&'static str, CategoryResult>,
    section_3_gate_accounting: Section3GateAccounting,
    report_complete: bool,
    blockers: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct CommonOutcomes {
    admission_identical: bool,
    terminal_class_identical: bool,
    admitted: bool,
    terminal_class: &'static str,
}

#[derive(Debug, Serialize)]
struct ComponentTrace {
    state_digest: String,
    decision_digests: Vec<String>,
    worker_selection: Vec<String>,
    expected_capability_request_count: usize,
    capability_request_order_verified: bool,
    service_output_mode: &'static str,
    capability_requests: Vec<CapabilityCall>,
    receipt_outcomes: Vec<PolicyReceipt>,
    terminal_output_digest: String,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct CapabilityCall {
    role: String,
    family: String,
    operation: String,
    authority: String,
}

#[derive(Debug, Serialize)]
struct NativeTrace {
    state_digest: String,
    command_model: &'static str,
    worker_selection: Vec<String>,
    capability_requests: Vec<String>,
    receipt_outcomes: Vec<PolicyReceipt>,
    terminal_output_digest: String,
}

#[derive(Clone, Debug, Serialize)]
struct PolicyReceipt {
    ordinal: u64,
    status: &'static str,
    request_binding: String,
    executor_binding: String,
    outcome_binding: String,
    declared_clock_fields_removed: bool,
}

#[derive(Debug, Serialize)]
struct ReceiptNormalization {
    scope: &'static str,
    removed_fields: [&'static str; 3],
    policy_component_receipt_count: usize,
    full_graph_component_receipt_count: usize,
    initialization_receipt_count: usize,
    successor_activation_receipt_count: usize,
    rollback_receipt_count: usize,
    cycle_receipt_count: usize,
    native_oracle_receipt_count: usize,
    validated_graph_cycle_count: usize,
    receipt_ids_unique: bool,
    graph_and_executor_bindings_valid: bool,
    digest_fields_valid: bool,
    full_graph_completion_status_valid: bool,
    normalized_receipt_set_digest: String,
    normalized_component_receipts: Vec<NormalizedMechanismReceipt>,
    common_terminal_status_identical: bool,
    full_graph_receipts_consumed: bool,
    result: &'static str,
    decision: &'static str,
}

#[derive(Debug, Serialize)]
struct LifecycleEvidence {
    source_report_path: String,
    source_report_digest: String,
    source_schema: String,
    incumbent_graph_manifest_digest: String,
    successor_graph_manifest_digest: String,
    events: Vec<String>,
    component_cycle_count: usize,
    component_all_cycles_completed: bool,
    component_decided_initial_state_binding: bool,
    component_decided_successor_activation: bool,
    component_decided_rollback: bool,
    restart_preserved_rollback_pair: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    graph_qualified_activation_ownership_handoff_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_mapping_stable_across_restart_activation_and_rollback: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    principal_inventory_digests: Option<BTreeMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authority_trace_summaries: Option<Vec<RetainedAuthorityTraceSummary>>,
    native_oracle: &'static str,
    native_initialized: bool,
    native_successor_activated: bool,
    native_regression_observed: bool,
    native_rollback_restored_incumbent: bool,
    native_restart_preserved_rollback: bool,
    common_transition_classes_identical: bool,
    result: &'static str,
    decision: &'static str,
}

#[derive(Debug, Serialize)]
struct RetainedAuthorityTraceSummary {
    aliases: Vec<String>,
    call_count: usize,
    consumers: Vec<String>,
    graph_manifest_digests: Vec<String>,
    phase: String,
    profile_mapping_verified: bool,
    trace_digest: String,
}

#[derive(Debug)]
struct R2LifecycleFacts {
    principal_inventory_digests: BTreeMap<String, String>,
    authority_trace_summaries: Vec<RetainedAuthorityTraceSummary>,
}

#[derive(Debug, Serialize)]
struct ClosureEvidence {
    component_policy: &'static str,
    compiled_component_digest: String,
    compiled_component_parsed: bool,
    compiled_component_executed: bool,
    execution_test_identity: &'static str,
    native_oracle: &'static str,
    cases: Vec<ClosureCaseResult>,
    same_abstract_cases_executed: bool,
    common_decision_classes_identical: bool,
    result: &'static str,
    decision: &'static str,
}

#[derive(Debug, Serialize)]
struct ClosureCaseResult {
    id: String,
    component_decision: String,
    component_blocker_count: usize,
    native_inventory_complete: bool,
    common_decision_identical: bool,
    result: &'static str,
}

#[derive(Debug)]
struct FullGraphReceiptValidation {
    total_count: usize,
    initialization_count: usize,
    successor_activation_count: usize,
    rollback_count: usize,
    cycle_count: usize,
    graph_cycle_count: usize,
    receipt_ids_unique: bool,
    graph_and_executor_bindings_valid: bool,
    digest_fields_valid: bool,
    normalized_receipt_set_digest: String,
    normalized_receipts: Vec<NormalizedMechanismReceipt>,
}

#[derive(Clone, Debug, Serialize)]
struct NormalizedMechanismReceipt {
    scope: String,
    graph_manifest_digest: String,
    outcome_class: String,
    receipt_id: String,
    request_digest: String,
    executor_digest: String,
    outcome_digest: String,
    audit_sequence: u64,
    declared_clock_fields_removed: bool,
}

#[derive(Debug)]
struct NativeLifecycleObservation {
    initialized: bool,
    successor_activated: bool,
    regression_observed: bool,
    rollback_restored_incumbent: bool,
    restart_preserved_rollback: bool,
}

#[derive(Debug, Default)]
struct ClosureComponentState {
    blobs: BTreeMap<String, (String, Vec<u8>)>,
}

impl compiled_closure::wasm_biotic::factory::foundation::Host for ClosureComponentState {}

impl compiled_closure::wasm_biotic::factory::blob_store::Host for ClosureComponentState {
    fn put(
        &mut self,
        media_type: String,
        content: Vec<u8>,
    ) -> std::result::Result<
        compiled_closure::wasm_biotic::factory::foundation::BlobRef,
        compiled_closure::wasm_biotic::factory::foundation::Failure,
    > {
        Ok(self.insert_blob(media_type, content))
    }

    fn get(
        &mut self,
        reference: compiled_closure::wasm_biotic::factory::foundation::BlobRef,
    ) -> std::result::Result<Vec<u8>, compiled_closure::wasm_biotic::factory::foundation::Failure>
    {
        let key = reference.content_digest.hex;
        let Some((media_type, bytes)) = self.blobs.get(&key) else {
            return Err(closure_component_failure(
                "blob-not-found",
                "requested blob digest is absent",
            ));
        };
        if reference.size_bytes != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            || reference.media_type != *media_type
            || sha256_hex(bytes) != key
        {
            return Err(closure_component_failure(
                "blob-binding-mismatch",
                "requested blob reference does not match stored bytes",
            ));
        }
        Ok(bytes.clone())
    }

    fn has(
        &mut self,
        digest: compiled_closure::wasm_biotic::factory::foundation::Digest,
    ) -> std::result::Result<bool, compiled_closure::wasm_biotic::factory::foundation::Failure>
    {
        Ok(self.blobs.contains_key(&digest.hex))
    }
}

impl ClosureComponentState {
    fn insert_blob(
        &mut self,
        media_type: String,
        content: Vec<u8>,
    ) -> compiled_closure::wasm_biotic::factory::foundation::BlobRef {
        use compiled_closure::wasm_biotic::factory::foundation::{BlobRef, Digest, HashAlgorithm};
        let hex = sha256_hex(&content);
        let reference = BlobRef {
            content_digest: Digest {
                algorithm: HashAlgorithm::Sha256,
                hex: hex.clone(),
            },
            size_bytes: u64::try_from(content.len()).unwrap_or(u64::MAX),
            media_type: media_type.clone(),
        };
        self.blobs.insert(hex, (media_type, content));
        reference
    }
}

fn closure_component_failure(
    code: &str,
    message: &str,
) -> compiled_closure::wasm_biotic::factory::foundation::Failure {
    compiled_closure::wasm_biotic::factory::foundation::Failure {
        code: code.to_string(),
        message: message.to_string(),
        retryable: false,
        evidence: None,
    }
}

#[derive(Debug, Serialize)]
struct ApprovalEvidence {
    source_report_digest: String,
    compiled_component_digest: String,
    compiled_component_parsed: bool,
    component_cases: Vec<ApprovalCaseResult>,
    native_exact_replay_idempotent: bool,
    native_changed_binding_rejected: bool,
    replay_contract_identical: bool,
    authenticity_disposition: &'static str,
    decision: &'static str,
}

#[derive(Debug, Serialize)]
struct ApprovalCaseResult {
    id: String,
    terminal: String,
    failure_code: Option<String>,
    service_delegate_invoked: bool,
    result: &'static str,
}

#[derive(Debug, Serialize)]
struct ExchangeReplayEvidence {
    native_oracle: &'static str,
    component_policy: &'static str,
    cases: Vec<ExchangeReplayResult>,
    native_exact_replay_idempotent: bool,
    native_changed_binding_rejected: bool,
    same_replay_contract_executed: bool,
}

#[derive(Debug, Serialize)]
struct ExchangeReplayResult {
    id: String,
    component_decision: String,
    result: &'static str,
}

#[derive(Debug, Serialize)]
struct MalformedDocumentEvidence {
    cases: Vec<MalformedDocumentResult>,
    owner_count: usize,
    all_failed_closed: bool,
}

#[derive(Debug, Serialize)]
struct MalformedDocumentResult {
    id: String,
    owner: String,
    expected_code: String,
    actual_code: String,
    result: &'static str,
}

#[derive(Debug, Serialize)]
struct OperationComparison {
    operation: String,
    family_identical: bool,
    native_family: String,
    component_family: String,
    authority_identical: bool,
    native_authority: String,
    component_authority: String,
    component_approval_required: bool,
    disposition: &'static str,
    decision: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct CategoryResult {
    status: &'static str,
    detail: &'static str,
    decision: Option<&'static str>,
}

#[derive(Debug, Serialize)]
struct Section3GateAccounting {
    required_gate_count: usize,
    executed_gate_count: usize,
    identical_gate_count: usize,
    intentional_versioned_difference_count: usize,
    missing_or_untested_gate_count: usize,
    every_gate_satisfied_for_bounded_v1: bool,
    versioned_difference_decision: &'static str,
    rationale: &'static str,
}

#[derive(Debug)]
struct FixedClock(u64);

impl SupervisorClock for FixedClock {
    fn now_ms(&self) -> u64 {
        self.0
    }
}

impl ExchangeClock for FixedClock {
    fn now_ms(&self) -> std::result::Result<u64, M6IdentityError> {
        Ok(self.0)
    }
}

struct TempRoot(PathBuf);

impl TempRoot {
    fn create() -> Result<Self> {
        let path = std::env::temp_dir().join(format!(
            "wasm-biotic-equivalence-{}-{}",
            std::process::id(),
            Sha256::digest(format!("{:?}", std::thread::current().id()).as_bytes())[0]
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(Self(path))
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!("component equivalence failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut corpus_path = None;
    let mut output_path = None;
    let mut adversarial_report_path = None;
    let mut lifecycle_report_path = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--corpus" => corpus_path = args.next().map(PathBuf::from),
            "--out" => output_path = args.next().map(PathBuf::from),
            "--adversarial-report" => adversarial_report_path = args.next().map(PathBuf::from),
            "--lifecycle-report" => lifecycle_report_path = args.next().map(PathBuf::from),
            "--help" | "-h" => {
                println!(
                    "usage: component-equivalence --corpus PATH --out PATH --lifecycle-report PATH [--adversarial-report PATH]"
                );
                return Ok(());
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    let corpus_path = corpus_path.ok_or("--corpus is required")?;
    let output_path = output_path.ok_or("--out is required")?;
    let lifecycle_report_path = lifecycle_report_path.ok_or("--lifecycle-report is required")?;
    let adversarial_report_path =
        adversarial_report_path.unwrap_or_else(default_adversarial_report_path);
    let corpus_bytes = fs::read(&corpus_path)?;
    let corpus: Corpus = serde_json::from_slice(&corpus_bytes)?;
    validate_corpus(&corpus)?;

    let component = run_component_trace(&corpus)?;
    let native = run_native_trace(&corpus)?;
    let operation_policy = compare_operations(&corpus)?;
    let approval_and_authority = run_approval_evidence(&corpus, &adversarial_report_path)?;
    let exchange_replay = run_exchange_replay_evidence(&corpus)?;
    let malformed_semantic_documents = run_malformed_document_evidence(&corpus)?;
    let (lifecycle, full_graph_receipts) = run_lifecycle_evidence(&corpus, &lifecycle_report_path)?;
    let closure_decisions = run_closure_evidence(&corpus, &lifecycle_report_path)?;
    let receipt_normalization =
        normalize_policy_receipts(&component, &native, &full_graph_receipts);
    let all_families_identical = operation_policy.iter().all(|row| row.family_identical);
    if !all_families_identical {
        return Err("service-family ownership diverged without authorization".into());
    }

    let mut category_results = BTreeMap::new();
    category_results.insert(
        "admission-and-terminal",
        CategoryResult {
            status: "identical",
            detail: "both transitional adapters admit the same frozen abstract corpus input and terminate completed; this category does not assert useful R1 software semantics",
            decision: None,
        },
    );
    category_results.insert(
        "state-command-evidence-digests",
        CategoryResult {
            status: "intentional-versioned-difference",
            detail: "the component policy trace expands one generic native effect into six graph-bound worker stages and twelve ordered capability calls; its service outputs are deterministic synthetic blobs",
            decision: Some(DECISION_ID),
        },
    );
    category_results.insert(
        "worker-selection-and-capability-requests",
        CategoryResult {
            status: "intentional-versioned-difference",
            detail: "native v1 has no equivalent six-role, twelve-call typed component policy trace",
            decision: Some(DECISION_ID),
        },
    );
    category_results.insert(
        "approval-and-authority",
        CategoryResult {
            status: "executed-with-versioned-contract-difference",
            detail: "all 27 authority rows, native replay/conflict behavior and five compiled-router signed approval cases executed or content-bound",
            decision: Some(DECISION_ID),
        },
    );
    category_results.insert(
        "exchange-replay",
        CategoryResult {
            status: "executed",
            detail: "component first-use/exact/conflict policy and native durable exact-replay/conflict oracle agree",
            decision: None,
        },
    );
    category_results.insert(
        "malformed-semantic-documents",
        CategoryResult {
            status: "executed",
            detail: "eight malformed or extended documents were rejected by seven owning component policies",
            decision: None,
        },
    );
    category_results.insert(
        "promotion-rollback-closure",
        CategoryResult {
            status: "executed-with-versioned-contract-difference",
            detail: "component lifecycle artifact and native reference executed initialization, successor activation, regressed observation, rollback and restart; component and native closure policies agreed on complete and incomplete cases",
            decision: Some(DECISION_ID),
        },
    );
    category_results.insert(
        "normalized-receipts",
        CategoryResult {
            status: "executed-with-versioned-cardinality",
            detail: "all 21 exact lifecycle mechanism receipts and all 12 synthetic policy-call receipts were consumed; clock fields were normalized and graph/executor/digest bindings validated; component cardinality intentionally differs from the generic native effect",
            decision: Some(DECISION_ID),
        },
    );

    let report = Report {
        schema: REPORT_SCHEMA,
        corpus_digest: sha256_hex(&corpus_bytes),
        contract_decision: DECISION_ID,
        native_oracle: "aiaf-v1 transitional library",
        component_implementation: "supervisor-reducer + worker-policy with a deterministic synthetic service delegate; service-policy-core contributes only the operation-policy map",
        shared_event_stream_scope: "seven frozen abstract submit/worker-completion events; the twelve component-only capability calls have no native-oracle counterparts",
        same_event_stream_executed: true,
        synthetic_policy_service_outputs: true,
        synthetic_policy_trace_claims_useful_r1_semantics: false,
        lifecycle_r1_semantics_verified_by_this_report: false,
        common_outcomes: CommonOutcomes {
            admission_identical: true,
            terminal_class_identical: true,
            admitted: true,
            terminal_class: "completed",
        },
        component_trace: component,
        native_trace: native,
        operation_policy,
        approval_and_authority,
        exchange_replay,
        malformed_semantic_documents,
        lifecycle,
        closure_decisions,
        receipt_normalization,
        category_results,
        section_3_gate_accounting: Section3GateAccounting {
            required_gate_count: 6,
            executed_gate_count: 6,
            identical_gate_count: 1,
            intentional_versioned_difference_count: 5,
            missing_or_untested_gate_count: 0,
            every_gate_satisfied_for_bounded_v1: true,
            versioned_difference_decision: DECISION_ID,
            rationale: "all six CONFORMANCE.md Section 3 comparisons executed; five fixture-declared component-model differences are explicitly accepted by CD-0001 and none are hidden in the host or left untested; the twelve-call policy trace uses labelled synthetic service outputs and makes no useful-R1-semantics claim",
        },
        report_complete: true,
        blockers: Vec::new(),
    };
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    bytes.push(b'\n');
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, &bytes)?;
    println!("report={}", output_path.display());
    println!("report_digest={}", sha256_hex(&bytes));
    println!("report_complete=true");
    Ok(())
}

fn validate_corpus(corpus: &Corpus) -> Result<()> {
    if corpus.schema != CORPUS_SCHEMA || corpus.contract_decision != DECISION_ID {
        return Err("corpus schema or contract-decision binding is wrong".into());
    }
    if corpus.events.len() != 7
        || corpus
            .events
            .iter()
            .enumerate()
            .any(|(index, event)| event.sequence != u64::try_from(index + 1).unwrap_or(u64::MAX))
    {
        return Err("bounded corpus must contain contiguous event sequences 1..=7".into());
    }
    if corpus.events[0].kind != "submit" || corpus.events[0].role.is_some() {
        return Err("first event must be an unqualified submit".into());
    }
    let expected_roles = [
        "planner",
        "builder",
        "validator",
        "reviewer",
        "packager",
        "continuity-worker",
    ];
    for (event, expected) in corpus.events[1..].iter().zip(expected_roles) {
        if event.kind != "worker-completed" || event.role.as_deref() != Some(expected) {
            return Err(format!("expected worker-completed event for {expected}").into());
        }
    }
    let expected_approval_cases = [
        "approval-valid-first-use",
        "approval-exact-replay",
        "approval-altered-request-reuse",
        "approval-forged-signer",
        "approval-forged-signature",
    ];
    if corpus
        .approval_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>()
        != expected_approval_cases
    {
        return Err("frozen signed-approval case vocabulary changed".into());
    }
    let expected_exchange_cases = [
        "exchange-first-use",
        "exchange-exact-replay",
        "exchange-conflicting-replay",
    ];
    if corpus
        .exchange_replay_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>()
        != expected_exchange_cases
    {
        return Err("frozen exchange replay case vocabulary changed".into());
    }
    for case in &corpus.exchange_replay_cases {
        validate_hex_digest(&case.presented_digest)?;
        if let Some(existing) = &case.existing_digest {
            validate_hex_digest(existing)?;
        }
    }
    let expected_malformed_cases = [
        "factory-submit-unknown-field",
        "supervisor-state-unknown-field",
        "worker-task-unknown-field",
        "exchange-transfer-unknown-field",
        "exchange-envelope-malformed-json",
        "evolution-change-unknown-field",
        "migration-state-unknown-field",
        "closure-dossier-unknown-field",
    ];
    if corpus
        .malformed_document_cases
        .iter()
        .map(|case| case.id.as_str())
        .collect::<Vec<_>>()
        != expected_malformed_cases
    {
        return Err("frozen malformed-document case vocabulary changed".into());
    }
    let expected_lifecycle_events = [
        "initialize-incumbent",
        "execute-incumbent-cycle",
        "activate-successor",
        "execute-successor-cycle",
        "observe-regression",
        "rollback-incumbent",
        "restart",
        "execute-post-rollback-cycle",
    ];
    if !matches!(
        corpus.lifecycle_expectation.schema.as_str(),
        LIFECYCLE_SCHEMA_V1 | LIFECYCLE_SCHEMA_V2
    ) || corpus.lifecycle_expectation.events
        != expected_lifecycle_events
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
        || corpus.lifecycle_expectation.expected_component_cycles != 3
        || corpus.lifecycle_expectation.expected_mechanism_receipts != 21
    {
        return Err("frozen lifecycle expectation changed".into());
    }
    validate_prefixed_digest(&corpus.lifecycle_expectation.incumbent_graph_manifest_digest)?;
    validate_prefixed_digest(&corpus.lifecycle_expectation.successor_graph_manifest_digest)?;
    let expected_closure_cases = [
        ("closure-complete-evidence", true, "closed", true),
        ("closure-missing-evidence", false, "not-yet", false),
    ];
    if corpus.closure_cases.len() != expected_closure_cases.len()
        || corpus
            .closure_cases
            .iter()
            .zip(expected_closure_cases)
            .any(|(actual, expected)| {
                actual.id != expected.0
                    || actual.complete != expected.1
                    || actual.expected_component != expected.2
                    || actual.expected_native_complete != expected.3
            })
    {
        return Err("frozen closure case vocabulary changed".into());
    }
    Ok(())
}

fn expected_policy_capability_trace() -> Vec<CapabilityCall> {
    [
        ("planner", "build", "workspace-open", "observe"),
        ("planner", "build", "workspace-snapshot", "observe"),
        ("planner", "build", "workspace-patch", "local-mutate"),
        (
            "planner",
            "scheduling",
            "schedule-job",
            "automation-control",
        ),
        ("builder", "build", "candidate-build", "local-mutate"),
        (
            "validator",
            "validation",
            "factory-provider-proposal",
            "local-mutate",
        ),
        (
            "validator",
            "validation",
            "validation-prove",
            "automation-control",
        ),
        ("reviewer", "review", "review-candidate", "observe"),
        ("packager", "packaging", "package-publish", "local-mutate"),
        ("packager", "packaging", "package-verify", "observe"),
        (
            "continuity-worker",
            "continuity",
            "evidence-publish",
            "local-mutate",
        ),
        (
            "continuity-worker",
            "continuity",
            "evidence-resolve",
            "observe",
        ),
    ]
    .into_iter()
    .map(|(role, family, operation, authority)| CapabilityCall {
        role: role.to_string(),
        family: family.to_string(),
        operation: operation.to_string(),
        authority: authority.to_string(),
    })
    .collect()
}

fn run_component_trace(corpus: &Corpus) -> Result<ComponentTrace> {
    let graph = digest_value(b"component-equivalence-graph-v1");
    let workers = Stage::ALL
        .into_iter()
        .map(|stage| {
            let digest = digest_value(format!("worker:{stage:?}").as_bytes());
            (stage, digest)
        })
        .collect();
    let services = ServiceFamilyValue::ALL
        .into_iter()
        .map(|family| {
            let digest = digest_value(format!("service:{family:?}").as_bytes());
            (family, digest)
        })
        .collect();
    let initial = SupervisorStateV1::empty(graph.clone(), workers, services)?;
    let mut state = initial.to_json()?;
    // This differential trace intentionally exercises reducer/worker policy
    // shape only. The corpus source is not an R1 change request and the
    // delegated service outputs below are not useful software-work results.
    let source = blob(corpus.source.as_bytes(), "application/octet-stream");
    let mut commands = reduce_policy(
        graph.clone(),
        &state,
        corpus.events[0].sequence,
        PolicyEvent::JobSubmitted(source),
    )?;
    state = commands.next_state_json.clone();
    let mut decisions = vec![commands.decision_digest.hex];
    let mut worker_selection = Vec::new();
    let mut capability_requests = Vec::new();
    let mut receipt_outcomes = Vec::new();
    let mut terminal_output = None;

    for event in &corpus.events[1..] {
        let dispatch = one_dispatch(&commands.commands)?.clone();
        let expected_role = role_for_stage(&dispatch.stage);
        if event.role.as_deref() != Some(expected_role.as_str()) {
            return Err("event role and component dispatch disagree".into());
        }
        worker_selection.push(expected_role.as_str().to_string());
        let request = worker_request(&dispatch, expected_role);
        let response = worker::execute_worker(expected_role, request, |family, request| {
            capability_requests.push(CapabilityCall {
                role: expected_role.as_str().to_string(),
                family: family.as_str().to_string(),
                operation: request.operation.as_str().to_string(),
                authority: kebab_debug(request.authority),
            });
            // Preserve deterministic request/output bindings without
            // pretending to execute the capability service's R1 semantics.
            let output = blob_worker(
                format!(
                    "{}|{}|{}",
                    expected_role.as_str(),
                    request.operation.as_str(),
                    request.input.content_digest.hex
                )
                .as_bytes(),
                "application/octet-stream",
            );
            let ordinal = u64::try_from(receipt_outcomes.len() + 1).unwrap_or(u64::MAX);
            let request_binding = request.idempotency_key.clone();
            let executor_binding = request.service_component.clone();
            let outcome_binding = output.content_digest.clone();
            let receipt_id = format!(
                "policy-receipt-{}",
                sha256_hex(
                    format!(
                        "{}|{}|{}|{ordinal}",
                        request_binding.hex, executor_binding.hex, outcome_binding.hex
                    )
                    .as_bytes()
                )
            );
            receipt_outcomes.push(PolicyReceipt {
                ordinal,
                status: "committed",
                request_binding: request_binding.hex.clone(),
                executor_binding: executor_binding.hex.clone(),
                outcome_binding: outcome_binding.hex.clone(),
                declared_clock_fields_removed: true,
            });
            worker::CapabilityResponseValue {
                request_id: request.request_id,
                service_component: request.service_component,
                outcome: worker::ServiceOutcomeValue::Succeeded(output),
                effect_receipts: vec![worker::EffectReceiptValue {
                    receipt_id,
                    request_digest: request_binding,
                    executor_digest: executor_binding,
                    started_at_ms: corpus.clock_ms.saturating_add(ordinal),
                    finished_at_ms: corpus.clock_ms.saturating_add(ordinal),
                    outcome_digest: outcome_binding,
                    audit_sequence: ordinal,
                }],
                evidence: Vec::new(),
            }
        });
        let (outcome, checkpoint) = match response.outcome {
            worker::WorkerOutcomeValue::Completed(output) => {
                let output = BlobPointer {
                    content_digest: DigestValue {
                        algorithm: output.content_digest.algorithm,
                        hex: output.content_digest.hex,
                    },
                    size_bytes: output.size_bytes,
                    media_type: output.media_type,
                };
                terminal_output = Some(output.content_digest.hex.clone());
                (PolicyWorkerOutcome::Completed(output), response.checkpoint)
            }
            other => return Err(format!("component worker did not complete: {other:?}").into()),
        };
        let response = PolicyWorkerResponse {
            execution_id: response.execution_id,
            worker_component: DigestValue {
                algorithm: response.worker_component.algorithm,
                hex: response.worker_component.hex,
            },
            outcome,
            checkpoint: checkpoint.map(|value| BlobPointer {
                content_digest: DigestValue {
                    algorithm: value.content_digest.algorithm,
                    hex: value.content_digest.hex,
                },
                size_bytes: value.size_bytes,
                media_type: value.media_type,
            }),
            proof_digests: Vec::new(),
        };
        commands = reduce_policy(
            graph.clone(),
            &state,
            event.sequence,
            PolicyEvent::WorkerFinished(response),
        )?;
        state = commands.next_state_json.clone();
        decisions.push(commands.decision_digest.hex.clone());
    }
    if !matches!(
        commands.commands.as_slice(),
        [PolicyCommand::EmitResponse(_)]
    ) {
        return Err("component trace did not end with emit-response".into());
    }
    let expected_capability_requests = expected_policy_capability_trace();
    if capability_requests != expected_capability_requests
        || receipt_outcomes.len() != expected_capability_requests.len()
    {
        return Err(
            "component policy trace did not execute the exact expanded twelve-call sequence".into(),
        );
    }
    Ok(ComponentTrace {
        state_digest: sha256_hex(&state),
        decision_digests: decisions,
        worker_selection,
        expected_capability_request_count: expected_capability_requests.len(),
        capability_request_order_verified: true,
        service_output_mode: "deterministic-synthetic-blob; no useful R1 semantics executed",
        capability_requests,
        receipt_outcomes,
        terminal_output_digest: terminal_output.ok_or("component trace has no terminal output")?,
    })
}

fn run_native_trace(corpus: &Corpus) -> Result<NativeTrace> {
    let root = TempRoot::create()?;
    let mut supervisor = LocalDurableSupervisor::open(
        &root.0,
        "equivalence-oracle",
        Arc::new(FixedClock(corpus.clock_ms)),
    )?;
    let request = SubmitJobRequest {
        job_id: format!("job-sha256-{}", sha256_hex(corpus.source.as_bytes())),
        job_kind: "component-equivalence-corpus-v1".to_string(),
        payload_json: serde_json::to_string(&serde_json::json!({"source": corpus.source}))?,
        idempotency_key: format!("equivalence:{}", sha256_hex(corpus.source.as_bytes())),
        not_before_ms: corpus.clock_ms,
        deadline_at_ms: corpus.clock_ms + 60_000,
        retry_policy: NativeRetryPolicy::default(),
        approval_request_id: None,
    };
    if !matches!(
        supervisor.submit_job(request)?,
        SubmitJobOutcome::Created(_)
    ) {
        return Err("native oracle did not create the corpus job".into());
    }
    // Both adapters consume the same seven abstract events. Native v1 has no
    // representation for the first five component stage completions; CD-0001
    // records that intentional model difference. Its one generic effect is
    // completed on the final abstract completion event.
    for event in &corpus.events[1..corpus.events.len() - 1] {
        if event.kind != "worker-completed" {
            return Err("unexpected native adapter event".into());
        }
    }
    let dispatch = supervisor
        .claim_due_job()?
        .ok_or("native oracle did not dispatch the corpus job")?;
    let result = serde_json::json!({
        "status": "completed",
        "source_digest": sha256_hex(corpus.source.as_bytes()),
    });
    let commit = EffectCommit::from_json("effect:component-equivalence-v1", &result)?;
    let terminal_output_digest = commit.result_digest.as_str().to_string();
    if !matches!(
        supervisor.complete_dispatch(
            &dispatch,
            JobExecutionResult::EffectCommitted(commit.clone())
        )?,
        CompleteJobOutcome::Succeeded(_)
    ) {
        return Err("native oracle did not terminate successfully".into());
    }
    let receipt = supervisor
        .state()
        .effect_receipts
        .get(&dispatch.effect_receipt_id)
        .ok_or("native oracle omitted its durable effect receipt")?;
    if receipt.commit.as_ref() != Some(&commit) {
        return Err("native oracle receipt does not bind the committed effect".into());
    }
    let receipt_outcomes = vec![PolicyReceipt {
        ordinal: 1,
        status: "committed",
        request_binding: receipt.idempotency_key.clone(),
        executor_binding: commit.effect_id.clone(),
        outcome_binding: commit.result_digest.as_str().to_string(),
        declared_clock_fields_removed: true,
    }];
    let state = serde_json::to_vec(supervisor.state())?;
    Ok(NativeTrace {
        state_digest: sha256_hex(&state),
        command_model: "one-generic-idempotent-effect",
        worker_selection: Vec::new(),
        capability_requests: Vec::new(),
        receipt_outcomes,
        terminal_output_digest,
    })
}

fn default_adversarial_report_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../artifacts/fixtures/component-complete-history/2026-08-02-adversarial-isolation.v1.json")
}

fn run_approval_evidence(corpus: &Corpus, report_path: &PathBuf) -> Result<ApprovalEvidence> {
    let report_bytes = fs::read(report_path)?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    if report.get("schema").and_then(Value::as_str)
        != Some("wasm-biotic.adversarial-isolation-report.v1")
    {
        return Err("approval source report has the wrong schema".into());
    }
    let cases = report
        .get("cases")
        .and_then(Value::as_array)
        .ok_or("approval source report has no cases")?;
    let component_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(
        "../../artifacts/fixtures/component-complete-history/capability-router-component.wasm",
    );
    let component_bytes = fs::read(&component_path)?;
    let component_digest = format!("sha256:{}", sha256_hex(&component_bytes));
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    Component::new(&engine, &component_bytes)
        .map_err(|error| format!("compiled approval router is not a component: {error}"))?;

    let mut component_cases = Vec::new();
    for expected in &corpus.approval_cases {
        let case = cases
            .iter()
            .find(|case| case.get("id").and_then(Value::as_str) == Some(expected.id.as_str()))
            .ok_or_else(|| format!("approval report omitted {}", expected.id))?;
        let terminal = case
            .get("expected_terminal")
            .and_then(Value::as_str)
            .ok_or_else(|| format!("approval case {} has no terminal", expected.id))?;
        let failure_code = case
            .get("expected_failure_code")
            .and_then(Value::as_str)
            .map(str::to_string);
        let delegate = case
            .get("service_delegate_invoked")
            .and_then(Value::as_bool)
            .ok_or_else(|| format!("approval case {} has no delegate observation", expected.id))?;
        if case.get("result").and_then(Value::as_str) != Some("pass")
            || case.get("component_digest").and_then(Value::as_str)
                != Some(component_digest.as_str())
            || case.get("phase").and_then(Value::as_str)
                != Some("component-policy-execution-in-dedicated-wasmtime-adapter")
            || case.get("evidence_test").and_then(Value::as_str)
                != Some(
                    "wasm_adapter::compiled_router_authenticates_records_and_replay_binds_signed_approvals",
                )
            || terminal != expected.expected_terminal
            || failure_code != expected.expected_failure_code
            || delegate != expected.service_delegate_invoked
        {
            return Err(format!("approval evidence mismatch for {}", expected.id).into());
        }
        component_cases.push(ApprovalCaseResult {
            id: expected.id.clone(),
            terminal: terminal.to_string(),
            failure_code,
            service_delegate_invoked: delegate,
            result: "pass",
        });
    }

    let (native_exact_replay_idempotent, native_changed_binding_rejected) =
        run_native_approval_replay(corpus.clock_ms)?;
    Ok(ApprovalEvidence {
        source_report_digest: format!("sha256:{}", sha256_hex(&report_bytes)),
        compiled_component_digest: component_digest,
        compiled_component_parsed: true,
        component_cases,
        native_exact_replay_idempotent,
        native_changed_binding_rejected,
        replay_contract_identical: native_exact_replay_idempotent
            && native_changed_binding_rejected,
        authenticity_disposition: "component contract requires Ed25519 signer authentication; transitional native oracle has no signature model",
        decision: DECISION_ID,
    })
}

fn run_native_approval_replay(clock_ms: u64) -> Result<(bool, bool)> {
    let root = TempRoot::create()?;
    let mut supervisor = LocalDurableSupervisor::open(
        &root.0,
        "approval-equivalence-oracle",
        Arc::new(FixedClock(clock_ms)),
    )?;
    let approval_id = "approval-equivalence-1";
    let request = SubmitJobRequest {
        job_id: "job-approval-equivalence-1".to_string(),
        job_kind: "approval-equivalence".to_string(),
        payload_json: "{}".to_string(),
        idempotency_key: "approval-equivalence-job-key".to_string(),
        not_before_ms: clock_ms,
        deadline_at_ms: clock_ms.saturating_add(60_000),
        retry_policy: NativeRetryPolicy::default(),
        approval_request_id: Some(approval_id.to_string()),
    };
    if !matches!(
        supervisor.submit_job(request)?,
        SubmitJobOutcome::Created(_)
    ) {
        return Err("native approval oracle did not create its waiting job".into());
    }
    let resolution = ApprovalResolutionRecord {
        approval_request_id: approval_id.to_string(),
        resolution: ApprovalResolutionKind::Granted,
        evidence_ref: "sha256:approval-evidence-a".to_string(),
        resolved_at_ms: 0,
    };
    let first = supervisor.resolve_approval(resolution.clone())?;
    let replay = supervisor.resolve_approval(resolution)?;
    let exact_replay_idempotent = first == replay && first == ["job-approval-equivalence-1"];
    let changed = supervisor.resolve_approval(ApprovalResolutionRecord {
        approval_request_id: approval_id.to_string(),
        resolution: ApprovalResolutionKind::Granted,
        evidence_ref: "sha256:approval-evidence-b".to_string(),
        resolved_at_ms: clock_ms,
    });
    let changed_binding_rejected = matches!(
        changed,
        Err(SupervisorError::ApprovalResolutionConflict { .. })
    );
    Ok((exact_replay_idempotent, changed_binding_rejected))
}

fn run_exchange_replay_evidence(corpus: &Corpus) -> Result<ExchangeReplayEvidence> {
    let mut cases = Vec::new();
    for expected in &corpus.exchange_replay_cases {
        let decision = exchange::classify_envelope_replay(
            expected.existing_digest.as_deref(),
            &expected.presented_digest,
        )?;
        let actual = match decision {
            exchange::EnvelopeReplayDecision::FirstUse => "first-use",
            exchange::EnvelopeReplayDecision::ExactReplay => "exact-replay",
            exchange::EnvelopeReplayDecision::Conflict => "conflict",
        };
        if actual != expected.expected_component {
            return Err(format!("exchange replay mismatch for {}", expected.id).into());
        }
        cases.push(ExchangeReplayResult {
            id: expected.id.clone(),
            component_decision: actual.to_string(),
            result: "pass",
        });
    }
    let (native_exact_replay_idempotent, native_changed_binding_rejected) =
        run_native_exchange_replay(corpus.clock_ms)?;
    if !native_exact_replay_idempotent || !native_changed_binding_rejected {
        return Err("native exchange replay oracle did not preserve exact identity binding".into());
    }
    Ok(ExchangeReplayEvidence {
        native_oracle: "aiaf-v1 M6 durable coordinator transaction identity",
        component_policy: "exchange-service classify-envelope-replay",
        cases,
        native_exact_replay_idempotent,
        native_changed_binding_rejected,
        same_replay_contract_executed: true,
    })
}

fn run_native_exchange_replay(clock_ms: u64) -> Result<(bool, bool)> {
    let root = TempRoot::create()?;
    let journal = CoordinatorJournal::open_or_initialize(
        &root.0,
        JournalConfig::bounded(8, 8)?,
        Arc::new(FixedClock(clock_ms)),
    )?;
    let request = native_exchange_request(clock_ms)?;
    let evidence = native_exchange_initial_evidence()?;
    let first = journal.begin(request.clone(), evidence.clone())?;
    let replay = journal.begin(request.clone(), evidence)?;
    let exact_replay_idempotent =
        first.stage_digest == replay.stage_digest && first.recorded_at_ms == replay.recorded_at_ms;
    let mut changed = request;
    changed.exchange_digest = ContentDigest::from_bytes(b"changed-exchange-envelope");
    let changed_binding_rejected = matches!(
        journal.begin(changed, native_exchange_initial_evidence()?),
        Err(M6TransactionError::CrossRequestConflict { .. })
    );
    Ok((exact_replay_idempotent, changed_binding_rejected))
}

fn native_exchange_request(clock_ms: u64) -> Result<TransactionRequestDraft> {
    Ok(TransactionRequestDraft {
        kind: TransactionKind::ReceiverIntake,
        logical_operation_id: "exchange-equivalence-1".to_string(),
        idempotency_key: "exchange-equivalence-key-1".to_string(),
        route_id: "local-equivalence-route".to_string(),
        route_generation: 1,
        route_definition_digest: ContentDigest::from_bytes(b"route-definition"),
        message_digest: ContentDigest::from_bytes(b"message"),
        exchange_digest: ContentDigest::from_bytes(b"exchange-envelope"),
        package_digest: ContentDigest::from_bytes(b"package"),
        before_snapshot_digest: ContentDigest::from_bytes(b"before"),
        expected_after_snapshot_digest: ContentDigest::from_bytes(b"after"),
        policy_digest: ContentDigest::from_bytes(b"policy"),
        authority_refs: vec![ContentDigest::from_bytes(b"authority")],
        evidence_refs: vec![ContentDigest::from_bytes(b"request-evidence")],
        retry_policy: ExchangeRetryPolicy::bounded(2, 1, 1_000)?,
        deadline_ms: clock_ms.saturating_add(60_000),
    })
}

fn native_exchange_initial_evidence() -> Result<StageEvidence> {
    Ok(StageEvidence::new(
        StageCause::Normal,
        0,
        Some(ContentDigest::from_bytes(b"authority")),
        None,
        None,
        None,
        vec![ContentDigest::from_bytes(b"initial-stage-evidence")],
    )?)
}

fn run_malformed_document_evidence(corpus: &Corpus) -> Result<MalformedDocumentEvidence> {
    let mut cases = Vec::new();
    let mut owners = BTreeSet::new();
    for expected in &corpus.malformed_document_cases {
        let actual_code = execute_malformed_document_case(&expected.id)?;
        if actual_code != expected.expected_code {
            return Err(format!(
                "malformed document {} returned {}, expected {}",
                expected.id, actual_code, expected.expected_code
            )
            .into());
        }
        owners.insert(expected.owner.clone());
        cases.push(MalformedDocumentResult {
            id: expected.id.clone(),
            owner: expected.owner.clone(),
            expected_code: expected.expected_code.clone(),
            actual_code,
            result: "pass",
        });
    }
    Ok(MalformedDocumentEvidence {
        cases,
        owner_count: owners.len(),
        all_failed_closed: true,
    })
}

fn execute_malformed_document_case(id: &str) -> Result<String> {
    match id {
        "factory-submit-unknown-field" => {
            let state = semantic_state_bytes()?;
            let submit = factory_control::SubmitEnvelopeV1 {
                schema: factory_control::SUBMIT_SCHEMA.to_string(),
                graph_digest: factory_control::DigestValue::sha256(b"semantic-graph"),
                initial_state: factory_control::StateDocumentRef {
                    schema: factory_control::SUPERVISOR_STATE_SCHEMA.to_string(),
                    blob: factory_control::BlobValue::for_bytes("application/json", &state),
                },
                source: factory_control::BlobValue::for_bytes(
                    "application/octet-stream",
                    b"source",
                ),
            };
            let bytes = add_unknown_field(serde_json::to_vec(&submit)?, "native_policy")?;
            Ok(factory_control::SubmitEnvelopeV1::decode(&bytes)
                .expect_err("extended submit must fail")
                .code)
        }
        "supervisor-state-unknown-field" => {
            let graph = digest_value(b"semantic-graph");
            let bytes = add_unknown_field(semantic_state_bytes()?, "native_policy")?;
            let source = blob(b"source", "application/octet-stream");
            Ok(
                reduce_policy(graph, &bytes, 1, PolicyEvent::JobSubmitted(source))
                    .expect_err("extended supervisor state must fail")
                    .code,
            )
        }
        "worker-task-unknown-field" => {
            let graph = digest_value(b"semantic-graph");
            let state = semantic_state_bytes()?;
            let reduction = reduce_policy(
                graph,
                &state,
                1,
                PolicyEvent::JobSubmitted(blob(b"source", "application/octet-stream")),
            )?;
            let request = worker_request(one_dispatch(&reduction.commands)?, worker::Role::Planner);
            let bytes = worker::encode_task_request(request)
                .map_err(|error| format!("cannot encode worker request: {}", error.message))?;
            let bytes = add_unknown_field(bytes, "native_policy")?;
            Ok(worker::decode_task_request(&bytes)
                .expect_err("extended worker task must fail")
                .code)
        }
        "exchange-transfer-unknown-field" => {
            let transfer = serde_json::json!({
                "schema": exchange::TRANSFER_SCHEMA,
                "transfer_id": "transfer-equivalence-1",
                "sender": "factory-a",
                "receiver": "factory-b",
                "artifact": {
                    "digest": "a".repeat(64),
                    "size_bytes": 4,
                    "media_type": "application/wasm",
                },
                "expires_at_ms": 2_000,
                "signing_key_handle": "exchange-key",
                "destination_url": null,
                "idempotency_key": "b".repeat(64),
            });
            let bytes = add_unknown_field(serde_json::to_vec(&transfer)?, "native_policy")?;
            Ok(exchange::decode_transfer_policy(&bytes, 1_000)
                .expect_err("extended exchange transfer must fail")
                .code)
        }
        "exchange-envelope-malformed-json" => Ok(exchange::decode_envelope_policy(b"{", 1_000)
            .expect_err("malformed envelope must fail")
            .code),
        "evolution-change-unknown-field" => {
            let value = serde_json::json!({
                "schema": evolution::CHANGE_SCHEMA,
                "base_graph_digest": "a".repeat(64),
                "replacements": [{
                    "node_id": "validator-worker",
                    "component_digest": "b".repeat(64),
                    "expected_world": "wasm-biotic:factory/worker-component@0.1.0"
                }],
                "rationale": "frozen malformed corpus",
                "native_policy": true
            });
            Ok(evolution::propose_policy(&serde_json::to_vec(&value)?)
                .expect_err("extended evolution request must fail")
                .code)
        }
        "migration-state-unknown-field" => {
            let bytes = add_unknown_field(semantic_state_bytes()?, "native_policy")?;
            Ok(migration::migrate_policy(migration::CURRENT_SCHEMA, &bytes)
                .expect_err("extended migration state must fail")
                .code)
        }
        "closure-dossier-unknown-field" => {
            let evidence = closure::REQUIRED_EVIDENCE
                .iter()
                .map(|class| ((*class).to_string(), "c".repeat(64)))
                .collect::<BTreeMap<_, _>>();
            let value = serde_json::json!({
                "schema": closure::DOSSIER_SCHEMA,
                "graph_manifest_digest": "a".repeat(64),
                "native_tcb_digest": "b".repeat(64),
                "evidence": evidence,
                "unresolved_blockers": [],
                "native_policy": true
            });
            Ok(closure::evaluate_policy(&serde_json::to_vec(&value)?)
                .expect_err("extended closure dossier must fail")
                .code)
        }
        other => Err(format!("unknown malformed-document case {other}").into()),
    }
}

fn semantic_state_bytes() -> Result<Vec<u8>> {
    let graph = digest_value(b"semantic-graph");
    let workers = Stage::ALL
        .into_iter()
        .map(|stage| {
            let digest = digest_value(format!("semantic-worker:{stage:?}").as_bytes());
            (stage, digest)
        })
        .collect();
    let services = ServiceFamilyValue::ALL
        .into_iter()
        .map(|family| {
            let digest = digest_value(format!("semantic-service:{family:?}").as_bytes());
            (family, digest)
        })
        .collect();
    Ok(SupervisorStateV1::empty(graph, workers, services)?.to_json()?)
}

fn add_unknown_field(bytes: Vec<u8>, field: &str) -> Result<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(&bytes)?;
    value
        .as_object_mut()
        .ok_or("semantic document fixture is not a JSON object")?
        .insert(field.to_string(), Value::Bool(true));
    Ok(serde_json::to_vec(&value)?)
}

fn run_lifecycle_evidence(
    corpus: &Corpus,
    lifecycle_path: &Path,
) -> Result<(LifecycleEvidence, FullGraphReceiptValidation)> {
    let bytes = fs::read(lifecycle_path)?;
    let document: Value = serde_json::from_slice(&bytes)?;
    let expectation = &corpus.lifecycle_expectation;
    let source_schema = required_str(&document, "/schema")?;
    let is_r2 = match source_schema {
        LIFECYCLE_SCHEMA_V1 if expectation.schema == LIFECYCLE_SCHEMA_V1 => false,
        LIFECYCLE_SCHEMA_V2 => true,
        LIFECYCLE_SCHEMA_V1 => {
            return Err("v1 lifecycle report does not match the corpus contract".into());
        }
        _ => return Err("component lifecycle report schema changed".into()),
    };
    for flag in [
        "/all_factory_semantics_executed_as_components",
        "/component_decided_initial_state_binding",
        "/component_decided_successor_activation",
        "/component_decided_rollback",
        "/restart_preserved_rollback_pair",
    ] {
        if !required_bool(&document, flag)? {
            return Err(format!("component lifecycle report flag {flag} is false").into());
        }
    }
    if required_str(&document, "/native_substrate_responsibility")?
        != "verified admission, instantiation, metering, opaque persistence, communication and declared-capability enforcement only"
    {
        return Err("component lifecycle report broadened native responsibility".into());
    }
    let (incumbent, successor) = if is_r2 {
        let incumbent = required_str(&document, "/incumbent_graph_manifest_digest")?.to_string();
        let successor = required_str(&document, "/successor_graph_manifest_digest")?.to_string();
        validate_prefixed_digest(&incumbent)?;
        validate_prefixed_digest(&successor)?;
        if incumbent == successor {
            return Err("R2 lifecycle graph pair is not distinct".into());
        }
        (incumbent, successor)
    } else {
        let incumbent = expectation.incumbent_graph_manifest_digest.clone();
        let successor = expectation.successor_graph_manifest_digest.clone();
        if required_str(&document, "/incumbent_graph_manifest_digest")? != incumbent
            || required_str(&document, "/successor_graph_manifest_digest")? != successor
        {
            return Err("component lifecycle graph pair differs from the frozen corpus".into());
        }
        (incumbent, successor)
    };
    let r2_facts = if is_r2 {
        Some(validate_r2_lifecycle_facts(
            &document,
            lifecycle_path,
            &incumbent,
            &successor,
        )?)
    } else {
        None
    };
    for pointer in [
        "/initialization_result_digest",
        "/upgrade_result_digest",
        "/rollback_observation_result_digest",
    ] {
        validate_prefixed_digest(required_str(&document, pointer)?)?;
    }

    let incumbent_state = required_value(&document, "/incumbent_state")?;
    let successor_state = required_value(&document, "/successor_state")?;
    validate_blob_pointer(incumbent_state)?;
    validate_blob_pointer(successor_state)?;

    validate_lifecycle_transition(
        &document,
        "/initialization_result/committed",
        &incumbent,
        incumbent_state,
        "active",
    )?;
    if required_value(&document, "/initialization_result/migrated_state")? != incumbent_state
        || !required_value(&document, "/initialization_result/previous_state")?.is_null()
        || digest_object(required_value(
            &document,
            "/initialization_result/target_graph",
        )?)? != incumbent
    {
        return Err("component initialization state binding is inconsistent".into());
    }
    validate_lifecycle_transition(
        &document,
        "/upgrade_result/committed",
        &successor,
        successor_state,
        "active",
    )?;
    if required_value(&document, "/upgrade_result/migrated_state")? != successor_state
        || required_value(&document, "/upgrade_result/previous_state")? != incumbent_state
        || digest_object(required_value(&document, "/upgrade_result/previous_graph")?)? != incumbent
        || digest_object(required_value(&document, "/upgrade_result/target_graph")?)? != successor
    {
        return Err("component successor activation state binding is inconsistent".into());
    }
    if required_str(&document, "/rollback_observation_result/action")? != "rolled-back"
        || digest_object(required_value(
            &document,
            "/rollback_observation_result/observed_graph",
        )?)? != successor
    {
        return Err("component lifecycle did not observe and roll back the successor".into());
    }
    validate_lifecycle_transition(
        &document,
        "/rollback_observation_result/status",
        &incumbent,
        incumbent_state,
        "rolled-back",
    )?;

    let mut receipt_ids = BTreeSet::new();
    let mut normalized_receipts = Vec::new();
    for (pointer, scope, expected_graph, outcome_class) in [
        (
            "/initialization_result/committed/receipt",
            "initialization",
            incumbent.as_str(),
            "active",
        ),
        (
            "/upgrade_result/committed/receipt",
            "successor-activation",
            successor.as_str(),
            "active",
        ),
        (
            "/rollback_observation_result/status/receipt",
            "rollback",
            incumbent.as_str(),
            "rolled-back",
        ),
    ] {
        normalized_receipts.push(validate_mechanism_receipt(
            required_value(&document, pointer)?,
            None,
            Some(expected_graph),
            &mut receipt_ids,
            scope,
            expected_graph,
            outcome_class,
        )?);
    }

    let roles = [
        "planner",
        "builder",
        "validator",
        "reviewer",
        "packager",
        "continuity-worker",
    ];
    let cycle_specs = [
        ("incumbent_cycle", incumbent.as_str()),
        ("successor_cycle", successor.as_str()),
        ("post_rollback_cycle", incumbent.as_str()),
    ];
    for (cycle_name, expected_graph) in cycle_specs {
        validate_component_cycle(
            &document,
            cycle_name,
            expected_graph,
            &roles,
            &mut receipt_ids,
            &mut normalized_receipts,
        )?;
    }
    let initialization_count = 1;
    let successor_activation_count = 1;
    let rollback_count = 1;
    let cycle_count = roles.len() * cycle_specs.len();
    let total_count =
        initialization_count + successor_activation_count + rollback_count + cycle_count;
    if total_count != expectation.expected_mechanism_receipts
        || cycle_specs.len() != expectation.expected_component_cycles
        || receipt_ids.len() != total_count
    {
        return Err("component lifecycle receipt cardinality or identity changed".into());
    }
    let normalized_receipt_set_digest = format!(
        "sha256:{}",
        sha256_hex(&serde_json::to_vec(&normalized_receipts)?)
    );
    let component_cycle_count = cycle_specs.len();

    let native = run_native_lifecycle_reference()?;
    if !native.initialized
        || !native.successor_activated
        || !native.regression_observed
        || !native.rollback_restored_incumbent
        || !native.restart_preserved_rollback
    {
        return Err("transitional native lifecycle oracle failed the frozen events".into());
    }
    let evidence = LifecycleEvidence {
        // Record the package-relative identity, not the staging checkout used
        // to generate the report. The digest below is the authority; retaining
        // an absolute build path would make otherwise identical evidence
        // machine-specific and misleading after bundle relocation.
        source_report_path: "package:evidence/component-lifecycle.json".to_string(),
        source_report_digest: format!("sha256:{}", sha256_hex(&bytes)),
        source_schema: source_schema.to_string(),
        incumbent_graph_manifest_digest: incumbent.clone(),
        successor_graph_manifest_digest: successor.clone(),
        events: expectation.events.clone(),
        component_cycle_count,
        component_all_cycles_completed: true,
        component_decided_initial_state_binding: true,
        component_decided_successor_activation: true,
        component_decided_rollback: true,
        restart_preserved_rollback_pair: true,
        graph_qualified_activation_ownership_handoff_verified: r2_facts.as_ref().map(|_| true),
        principal_mapping_stable_across_restart_activation_and_rollback: r2_facts
            .as_ref()
            .map(|_| true),
        principal_inventory_digests: r2_facts
            .as_ref()
            .map(|facts| facts.principal_inventory_digests.clone()),
        authority_trace_summaries: r2_facts.map(|facts| facts.authority_trace_summaries),
        native_oracle: "aiaf-v1 LocalDeploymentService transitional reference",
        native_initialized: native.initialized,
        native_successor_activated: native.successor_activated,
        native_regression_observed: native.regression_observed,
        native_rollback_restored_incumbent: native.rollback_restored_incumbent,
        native_restart_preserved_rollback: native.restart_preserved_rollback,
        common_transition_classes_identical: true,
        result: "executed-with-versioned-contract-difference",
        decision: DECISION_ID,
    };
    let receipts = FullGraphReceiptValidation {
        total_count,
        initialization_count,
        successor_activation_count,
        rollback_count,
        cycle_count,
        graph_cycle_count: component_cycle_count,
        receipt_ids_unique: true,
        graph_and_executor_bindings_valid: true,
        digest_fields_valid: true,
        normalized_receipt_set_digest,
        normalized_receipts,
    };
    Ok((evidence, receipts))
}

fn validate_r2_lifecycle_facts(
    document: &Value,
    lifecycle_path: &Path,
    incumbent: &str,
    successor: &str,
) -> Result<R2LifecycleFacts> {
    for flag in [
        "/graph_qualified_activation_ownership_handoff_verified",
        "/principal_mapping_stable_across_restart_activation_and_rollback",
    ] {
        if !required_bool(document, flag)? {
            return Err(format!("R2 lifecycle report flag {flag} is false").into());
        }
    }

    let inventory_value = required_value(document, "/principal_inventory_digests")?
        .as_object()
        .ok_or("R2 principal inventory digests are not an object")?;
    if inventory_value
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != BTreeSet::from(["incumbent", "successor"])
    {
        return Err("R2 lifecycle does not bind exactly two principal inventories".into());
    }
    let mut principal_inventory_digests = BTreeMap::new();
    for kind in ["incumbent", "successor"] {
        let digest = inventory_value
            .get(kind)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("R2 lifecycle {kind} principal inventory is not a string"))?;
        validate_prefixed_digest(digest)?;
        principal_inventory_digests.insert(kind.to_string(), digest.to_string());
    }
    if principal_inventory_digests["incumbent"] == principal_inventory_digests["successor"] {
        return Err("R2 lifecycle principal inventories are not graph-qualified".into());
    }

    let incumbent_root = lifecycle_path
        .parent()
        .and_then(Path::parent)
        .ok_or("R2 lifecycle report is not inside a package evidence directory")?;
    let cohort_root = incumbent_root
        .parent()
        .ok_or("R2 lifecycle package has no cohort directory")?;
    let expected_incumbent_name = incumbent.replace(':', "-");
    if incumbent_root.file_name().and_then(|name| name.to_str())
        != Some(expected_incumbent_name.as_str())
    {
        return Err("R2 lifecycle path is not owned by its incumbent graph package".into());
    }
    let successor_root = cohort_root.join(successor.replace(':', "-"));
    validate_r2_package_identity(
        incumbent_root,
        incumbent,
        &principal_inventory_digests["incumbent"],
        None,
    )?;
    validate_r2_package_identity(
        &successor_root,
        successor,
        &principal_inventory_digests["successor"],
        Some(incumbent),
    )?;

    let summaries = required_value(document, "/authority_trace_summaries")?
        .as_array()
        .ok_or("R2 authority trace summaries are not an array")?;
    let expected_phases = [
        ("incumbent-cycle", vec![incumbent]),
        ("activation-and-successor-cycle", vec![incumbent, successor]),
        ("rollback", vec![successor]),
        ("restart-post-rollback-cycle", vec![incumbent]),
    ];
    if summaries.len() != expected_phases.len() {
        return Err("R2 lifecycle does not retain exactly four authority trace phases".into());
    }
    let mut authority_trace_summaries = Vec::with_capacity(summaries.len());
    for (index, (summary, (expected_phase, expected_graphs))) in
        summaries.iter().zip(expected_phases).enumerate()
    {
        let phase = required_str(summary, "/phase")?;
        if phase != expected_phase {
            return Err(format!("R2 authority trace phase {index} is not {expected_phase}").into());
        }
        if !required_bool(summary, "/profile_mapping_verified")? {
            return Err(
                format!("R2 authority trace phase {phase} did not verify its profile").into(),
            );
        }
        let call_count = usize::try_from(required_u64(summary, "/call_count")?)?;
        if call_count == 0 {
            return Err(format!("R2 authority trace phase {phase} is empty").into());
        }
        let aliases = required_sorted_unique_strings(summary, "/aliases")?;
        let consumers = required_sorted_unique_strings(summary, "/consumers")?;
        if aliases.is_empty() || consumers.is_empty() {
            return Err(
                format!("R2 authority trace phase {phase} has no authority mapping").into(),
            );
        }
        let graph_manifest_digests =
            required_sorted_unique_strings(summary, "/graph_manifest_digests")?;
        let mut expected_graphs = expected_graphs
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        expected_graphs.sort();
        if graph_manifest_digests != expected_graphs {
            return Err(
                format!("R2 authority trace phase {phase} names the wrong graph scope").into(),
            );
        }
        let trace_digest = required_str(summary, "/trace_digest")?.to_string();
        validate_prefixed_digest(&trace_digest)?;
        authority_trace_summaries.push(RetainedAuthorityTraceSummary {
            aliases,
            call_count,
            consumers,
            graph_manifest_digests,
            phase: phase.to_string(),
            profile_mapping_verified: true,
            trace_digest,
        });
    }

    Ok(R2LifecycleFacts {
        principal_inventory_digests,
        authority_trace_summaries,
    })
}

fn validate_r2_package_identity(
    package_root: &Path,
    graph_digest: &str,
    principal_inventory_digest: &str,
    previous_graph: Option<&str>,
) -> Result<()> {
    let manifest_bytes = fs::read(package_root.join("manifest.json"))?;
    if format!("sha256:{}", sha256_hex(&manifest_bytes)) != graph_digest {
        return Err("R2 lifecycle package manifest bytes do not match its graph digest".into());
    }
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let actual_previous = manifest.get("previous_graph").and_then(Value::as_str);
    if actual_previous != previous_graph {
        return Err("R2 lifecycle successor lineage is not the exact incumbent".into());
    }

    let inventory_bytes = fs::read(package_root.join("evidence/principal-inventory.json"))?;
    if format!("sha256:{}", sha256_hex(&inventory_bytes)) != principal_inventory_digest {
        return Err("R2 lifecycle principal inventory digest does not match retained bytes".into());
    }
    let inventory: Value = serde_json::from_slice(&inventory_bytes)?;
    if required_str(&inventory, "/schema")? != "wasm-biotic.principal-inventory-evidence.v1"
        || required_str(&inventory, "/graph_manifest_digest")? != graph_digest
    {
        return Err("R2 lifecycle principal inventory is not bound to its graph".into());
    }
    Ok(())
}

fn required_sorted_unique_strings(value: &Value, pointer: &str) -> Result<Vec<String>> {
    let items = required_value(value, pointer)?
        .as_array()
        .ok_or_else(|| format!("required lifecycle field {pointer} is not an array"))?;
    let strings = items
        .iter()
        .map(|item| {
            item.as_str().map(str::to_string).ok_or_else(|| {
                format!("required lifecycle field {pointer} contains non-string data")
            })
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if strings.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(format!("required lifecycle field {pointer} is not sorted and unique").into());
    }
    Ok(strings)
}

fn validate_lifecycle_transition(
    document: &Value,
    pointer: &str,
    expected_graph: &str,
    expected_state: &Value,
    expected_status: &str,
) -> Result<()> {
    let transition = required_value(document, pointer)?;
    if required_str(transition, "/state")? != expected_status
        || digest_object(required_value(transition, "/active_graph")?)? != expected_graph
        || required_value(transition, "/active_state")? != expected_state
    {
        return Err(format!("lifecycle transition {pointer} has an invalid state binding").into());
    }
    Ok(())
}

fn validate_component_cycle(
    document: &Value,
    cycle_name: &str,
    expected_graph: &str,
    expected_roles: &[&str],
    receipt_ids: &mut BTreeSet<String>,
    normalized_receipts: &mut Vec<NormalizedMechanismReceipt>,
) -> Result<()> {
    let cycle = required_value(document, &format!("/{cycle_name}"))?;
    if required_str(cycle, "/graph_manifest_digest")? != expected_graph {
        return Err(format!("{cycle_name} ran against the wrong graph").into());
    }
    let job_id = required_str(cycle, "/job_id")?;
    let source_digest = required_str(cycle, "/source_digest")?;
    validate_prefixed_digest(source_digest)?;
    if job_id != format!("job-{}", source_digest.replace(':', "-"))
        || required_str(cycle, "/terminal_result/job_id")? != job_id
        || required_str(cycle, "/terminal_result/schema")? != "wasm-biotic.factory-job-result.v1"
        || required_str(cycle, "/terminal_result/status")? != "completed"
        || required_u64(cycle, "/terminal_result/event_sequence")? != 7
    {
        return Err(format!("{cycle_name} terminal result is not the frozen completion").into());
    }
    validate_prefixed_digest(required_str(cycle, "/terminal_result_digest")?)?;
    validate_blob_pointer(required_value(cycle, "/terminal_result/output")?)?;
    validate_blob_pointer(required_value(
        cycle,
        "/terminal_result/supervisor_state/blob",
    )?)?;
    if required_str(cycle, "/terminal_result/supervisor_state/schema")?
        != "wasm-biotic.supervisor-state.v1"
    {
        return Err(format!("{cycle_name} terminal supervisor state schema changed").into());
    }
    let completions = required_value(cycle, "/execution_completions")?
        .as_object()
        .ok_or_else(|| format!("{cycle_name} execution completions are not an object"))?;
    let provenance = required_value(cycle, "/provenance")?
        .as_object()
        .ok_or_else(|| format!("{cycle_name} provenance is not an object"))?;
    let expected = expected_roles.iter().copied().collect::<BTreeSet<_>>();
    if completions
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected
        || provenance
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != expected
    {
        return Err(format!("{cycle_name} does not contain the exact six roles").into());
    }
    for role in expected_roles {
        let completion = completions
            .get(*role)
            .ok_or_else(|| format!("{cycle_name} omitted completion for {role}"))?;
        let provenance = provenance
            .get(*role)
            .ok_or_else(|| format!("{cycle_name} omitted provenance for {role}"))?;
        if required_str(provenance, "/graph_manifest_digest")? != expected_graph
            || required_str(completion, "/outcome/kind")? != "succeeded"
            || !required_str(completion, "/run_id")?.starts_with(&format!("{job_id}:{role}:"))
        {
            return Err(format!("{cycle_name} {role} binding is invalid").into());
        }
        validate_prefixed_digest(required_str(provenance, "/authority_component_digest")?)?;
        validate_prefixed_digest(required_str(provenance, "/executable_component_digest")?)?;
        let sources = required_value(provenance, "/source_component_digests")?
            .as_array()
            .ok_or_else(|| format!("{cycle_name} {role} source provenance is not an array"))?;
        if sources.is_empty() {
            return Err(format!("{cycle_name} {role} has no source provenance").into());
        }
        for source in sources {
            validate_prefixed_digest(
                source
                    .as_str()
                    .ok_or_else(|| format!("{cycle_name} {role} has non-string provenance"))?,
            )?;
        }
        validate_blob_pointer(required_value(completion, "/outcome/output")?)?;
        normalized_receipts.push(validate_mechanism_receipt(
            required_value(completion, "/receipt")?,
            Some(required_str(provenance, "/authority_component_digest")?),
            None,
            receipt_ids,
            &format!("{cycle_name}:{role}"),
            expected_graph,
            "succeeded",
        )?);
    }
    Ok(())
}

fn validate_mechanism_receipt(
    receipt: &Value,
    expected_executor: Option<&str>,
    expected_outcome: Option<&str>,
    receipt_ids: &mut BTreeSet<String>,
    scope: &str,
    graph_manifest_digest: &str,
    outcome_class: &str,
) -> Result<NormalizedMechanismReceipt> {
    let receipt_id = required_str(receipt, "/receipt_id")?;
    let suffix = receipt_id
        .strip_prefix("receipt-")
        .ok_or("mechanism receipt ID has no receipt- prefix")?;
    validate_hex_digest(suffix)?;
    if !receipt_ids.insert(receipt_id.to_string()) {
        return Err("mechanism receipt ID was reused".into());
    }
    let request = digest_object(required_value(receipt, "/request_digest")?)?;
    let executor = digest_object(required_value(receipt, "/executor_digest")?)?;
    let outcome = digest_object(required_value(receipt, "/outcome_digest")?)?;
    validate_prefixed_digest(&request)?;
    validate_prefixed_digest(&executor)?;
    validate_prefixed_digest(&outcome)?;
    if expected_executor.is_some_and(|expected| expected != executor)
        || expected_outcome.is_some_and(|expected| expected != outcome)
    {
        return Err("mechanism receipt is not bound to its executor or outcome".into());
    }
    let started = required_u64(receipt, "/started_at_ms")?;
    let finished = required_u64(receipt, "/finished_at_ms")?;
    if started > finished {
        return Err("mechanism receipt finished before it started".into());
    }
    let audit_sequence = required_u64(receipt, "/audit_sequence")?;
    Ok(NormalizedMechanismReceipt {
        scope: scope.to_string(),
        graph_manifest_digest: graph_manifest_digest.to_string(),
        outcome_class: outcome_class.to_string(),
        receipt_id: receipt_id.to_string(),
        request_digest: request,
        executor_digest: executor,
        outcome_digest: outcome,
        audit_sequence,
        declared_clock_fields_removed: true,
    })
}

fn run_native_lifecycle_reference() -> Result<NativeLifecycleObservation> {
    let root = TempRoot::create()?;
    let candidate_root = root.0.join("lifecycle-candidates");
    let deployment_root = root.0.join("lifecycle-deployment");
    fs::create_dir_all(&candidate_root)?;
    let incumbent_bytes = b"native-reference-incumbent-v1";
    let successor_bytes = b"native-reference-successor-v1";
    let candidate_path = candidate_root.join("successor.bin");
    fs::write(&candidate_path, successor_bytes)?;
    let service = LocalDeploymentService::open(&deployment_root, &candidate_root)?;
    let incumbent = ContentDigest::from_bytes(incumbent_bytes);
    let successor = ContentDigest::from_bytes(successor_bytes);
    let initialized = service
        .initialize_active("initialize-incumbent", incumbent_bytes)?
        .installed_artifact
        .digest
        == incumbent;
    let activation = service.activate(&ActivationRequest {
        operation_id: "activate-successor".to_string(),
        candidate_path: PathBuf::from("successor.bin"),
        expected_candidate_digest: successor.clone(),
        expected_active_digest: incumbent.clone(),
        approval_ref: "approval:frozen-lifecycle".to_string(),
        comparison_ref: "comparison:frozen-lifecycle".to_string(),
        observation_window_ref: "observation-window:frozen-lifecycle".to_string(),
    })?;
    let successor_activated = activation.previous_artifact.digest == incumbent
        && activation.activated_artifact.digest == successor
        && service.read_active_bytes()? == successor_bytes;
    let observation = service.record_observation(
        &ObservationRequest {
            observation_id: "observe-regression".to_string(),
            activation_id: activation.operation_id.clone(),
            expected_active_digest: successor.clone(),
            outcome: ObservationOutcome::Regressed,
            summary: "frozen same-event regression".to_string(),
        },
        b"frozen-regression-evidence",
    )?;
    let regression_observed = observation.outcome == ObservationOutcome::Regressed
        && observation.observed_artifact.digest == successor;
    let rollback = service.rollback(&RollbackRequest {
        operation_id: "rollback-incumbent".to_string(),
        activation_id: activation.operation_id,
        reason_ref: "observation:observe-regression".to_string(),
    })?;
    let rollback_restored_incumbent = rollback.from_artifact.digest == successor
        && rollback.restored_artifact.digest == incumbent
        && service.read_active_bytes()? == incumbent_bytes;
    let reopened = LocalDeploymentService::open(&deployment_root, &candidate_root)?;
    let reopened_state = reopened.state()?;
    let restart_preserved_rollback = reopened.read_active_bytes()? == incumbent_bytes
        && reopened_state.rollbacks.len() == 1
        && reopened_state
            .activations
            .iter()
            .any(|record| record.rolled_back_by.as_deref() == Some("rollback-incumbent"));
    Ok(NativeLifecycleObservation {
        initialized,
        successor_activated,
        regression_observed,
        rollback_restored_incumbent,
        restart_preserved_rollback,
    })
}

fn run_closure_evidence(corpus: &Corpus, lifecycle_path: &Path) -> Result<ClosureEvidence> {
    let (compiled_component_digest, compiled_component_bytes) =
        resolve_compiled_closure_component(lifecycle_path)?;
    let mut results = Vec::new();
    for expected in &corpus.closure_cases {
        let evidence = closure::REQUIRED_EVIDENCE
            .iter()
            .take(if expected.complete {
                closure::REQUIRED_EVIDENCE.len()
            } else {
                closure::REQUIRED_EVIDENCE.len() - 1
            })
            .map(|name| ((*name).to_string(), "c".repeat(64)))
            .collect::<BTreeMap<_, _>>();
        let unresolved = if expected.complete {
            Vec::<String>::new()
        } else {
            vec!["frozen-lifecycle-gap".to_string()]
        };
        let dossier = serde_json::to_vec(&serde_json::json!({
            "schema": closure::DOSSIER_SCHEMA,
            "graph_manifest_digest": "a".repeat(64),
            "native_tcb_digest": "b".repeat(64),
            "evidence": evidence,
            "unresolved_blockers": unresolved,
        }))?;
        let policy_decision_bytes = closure::evaluate_policy(&dossier).map_err(|error| {
            format!(
                "closure component rejected frozen case {}: {}: {}",
                expected.id, error.code, error.message
            )
        })?;
        let decision_bytes = run_compiled_closure_policy(&compiled_component_bytes, dossier)?;
        if decision_bytes != policy_decision_bytes {
            return Err(format!(
                "compiled closure component diverged from its policy for {}",
                expected.id
            )
            .into());
        }
        let decision: closure::ClosureDecision = serde_json::from_slice(&decision_bytes)?;
        let component_decision = match decision.status {
            closure::DecisionStatus::Closed => "closed",
            closure::DecisionStatus::NotYet => "not-yet",
        };
        let native_complete =
            closure_inventory_is_complete(&native_closure_inventory(expected.complete));
        let common_decision_identical = (component_decision == "closed") == native_complete;
        if component_decision != expected.expected_component
            || native_complete != expected.expected_native_complete
            || !common_decision_identical
            || decision.external_qualification_claimed
        {
            return Err(format!("closure decision mismatch for {}", expected.id).into());
        }
        results.push(ClosureCaseResult {
            id: expected.id.clone(),
            component_decision: component_decision.to_string(),
            component_blocker_count: decision.blockers.len(),
            native_inventory_complete: native_complete,
            common_decision_identical,
            result: "pass",
        });
    }
    Ok(ClosureEvidence {
        component_policy: "closure-evaluator evaluate-policy",
        compiled_component_digest,
        compiled_component_parsed: true,
        compiled_component_executed: true,
        execution_test_identity: "component-equivalence::compiled-closure-complete-and-missing-evidence",
        native_oracle: "aiaf-v1 closure_inventory_is_complete transitional reference",
        cases: results,
        same_abstract_cases_executed: true,
        common_decision_classes_identical: true,
        result: "executed-with-versioned-contract-difference",
        decision: DECISION_ID,
    })
}

fn resolve_compiled_closure_component(lifecycle_path: &Path) -> Result<(String, Vec<u8>)> {
    let package_root = lifecycle_path
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("lifecycle report is not inside a package evidence directory")?;
    let manifest_bytes = fs::read(package_root.join("manifest.json"))?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let nodes = manifest
        .get("nodes")
        .and_then(Value::as_array)
        .ok_or("component package manifest has no node array")?;
    let closure_node = nodes
        .iter()
        .find(|node| node.get("id").and_then(Value::as_str) == Some("closure-evaluator"))
        .ok_or("component package manifest omitted closure-evaluator")?;
    let digest = closure_node
        .get("component_digest")
        .and_then(Value::as_str)
        .ok_or("closure-evaluator node omitted its component digest")?;
    validate_prefixed_digest(digest)?;
    if closure_node.get("world").and_then(Value::as_str)
        != Some("wasm-biotic:factory/closure-evaluator-component@0.1.0")
    {
        return Err("closure-evaluator node world changed".into());
    }
    let artifact_path = package_root
        .join("components")
        .join(format!("{}.wasm", digest.replace(':', "-")));
    let bytes = fs::read(&artifact_path)?;
    let actual = format!("sha256:{}", sha256_hex(&bytes));
    if actual != digest {
        return Err(format!(
            "closure-evaluator artifact digest mismatch at {}",
            artifact_path.display()
        )
        .into());
    }
    Ok((digest.to_string(), bytes))
}

fn run_compiled_closure_policy(component_bytes: &[u8], dossier: Vec<u8>) -> Result<Vec<u8>> {
    let mut config = Config::new();
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let component = Component::new(&engine, component_bytes)?;
    let mut linker = Linker::<ClosureComponentState>::new(&engine);
    compiled_closure::ClosureEvaluatorComponent::add_to_linker::<_, HasSelf<_>>(
        &mut linker,
        |state| state,
    )?;
    let mut state = ClosureComponentState::default();
    let input = state.insert_blob("application/json".to_string(), dossier);
    let mut store = Store::new(&engine, state);
    let instance =
        compiled_closure::ClosureEvaluatorComponent::instantiate(&mut store, &component, &linker)?;
    let output = instance
        .wasm_biotic_factory_component_task()
        .call_run(&mut store, &input)?
        .map_err(|failure| {
            format!(
                "compiled closure component rejected dossier: {}: {}",
                failure.code, failure.message
            )
        })?;
    let (media_type, bytes) = store
        .data()
        .blobs
        .get(&output.content_digest.hex)
        .ok_or("compiled closure component returned an absent output blob")?;
    if output.media_type != *media_type
        || output.size_bytes != u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        || output.content_digest.hex != sha256_hex(bytes)
    {
        return Err("compiled closure component returned a misbound output blob".into());
    }
    Ok(bytes.clone())
}

fn native_closure_inventory(complete: bool) -> aiaf_v1::execution::ClosureInventory {
    let targets = [
        CapabilityImportTarget::TranscriptRetrieval,
        CapabilityImportTarget::CampaignControl,
        CapabilityImportTarget::ApprovalGateway,
        CapabilityImportTarget::ReviewPromotion,
        CapabilityImportTarget::ScheduleTick,
        CapabilityImportTarget::ModelHosting,
        CapabilityImportTarget::WorktreeHostAdapter,
        CapabilityImportTarget::EnvironmentBridge,
        CapabilityImportTarget::SemanticValidation,
        CapabilityImportTarget::ArtifactPackaging,
        CapabilityImportTarget::NativeSupervisorChallenger,
    ];
    let entries = targets
        .into_iter()
        .enumerate()
        .map(|(index, target)| CapabilityClosureEntry {
            target,
            current_mode: CapabilityDependencyMode::Native,
            closure_status: CapabilityClosureStatus::NativeClosed,
            capability_world_ref: Some(format!("world:native-reference:{index}")),
            audit_ref: Some(format!("audit:native-reference:{index}")),
            rationale: "frozen complete native reference entry".to_string(),
        })
        .collect();
    build_closure_inventory(
        "native-reference-closure",
        entries,
        if complete {
            Vec::new()
        } else {
            vec!["gap:frozen-lifecycle".to_string()]
        },
        "transitional native closure oracle",
    )
}

fn normalize_policy_receipts(
    component: &ComponentTrace,
    native: &NativeTrace,
    full_graph: &FullGraphReceiptValidation,
) -> ReceiptNormalization {
    ReceiptNormalization {
        scope: "full composed lifecycle mechanism log plus frozen policy/native oracle trace",
        removed_fields: ["started_at_ms", "finished_at_ms", "committed_at_ms"],
        policy_component_receipt_count: component.receipt_outcomes.len(),
        full_graph_component_receipt_count: full_graph.total_count,
        initialization_receipt_count: full_graph.initialization_count,
        successor_activation_receipt_count: full_graph.successor_activation_count,
        rollback_receipt_count: full_graph.rollback_count,
        cycle_receipt_count: full_graph.cycle_count,
        native_oracle_receipt_count: native.receipt_outcomes.len(),
        validated_graph_cycle_count: full_graph.graph_cycle_count,
        receipt_ids_unique: full_graph.receipt_ids_unique,
        graph_and_executor_bindings_valid: full_graph.graph_and_executor_bindings_valid,
        digest_fields_valid: full_graph.digest_fields_valid,
        full_graph_completion_status_valid: true,
        normalized_receipt_set_digest: full_graph.normalized_receipt_set_digest.clone(),
        normalized_component_receipts: full_graph.normalized_receipts.clone(),
        common_terminal_status_identical: component
            .receipt_outcomes
            .iter()
            .all(|receipt| receipt.status == "committed")
            && native
                .receipt_outcomes
                .iter()
                .all(|receipt| receipt.status == "committed"),
        full_graph_receipts_consumed: true,
        result: "executed-with-versioned-cardinality",
        decision: DECISION_ID,
    }
}

fn required_value<'a>(document: &'a Value, pointer: &str) -> Result<&'a Value> {
    document
        .pointer(pointer)
        .ok_or_else(|| format!("required lifecycle field {pointer} is absent").into())
}

fn required_str<'a>(document: &'a Value, pointer: &str) -> Result<&'a str> {
    required_value(document, pointer)?
        .as_str()
        .ok_or_else(|| format!("required lifecycle field {pointer} is not a string").into())
}

fn required_bool(document: &Value, pointer: &str) -> Result<bool> {
    required_value(document, pointer)?
        .as_bool()
        .ok_or_else(|| format!("required lifecycle field {pointer} is not a boolean").into())
}

fn required_u64(document: &Value, pointer: &str) -> Result<u64> {
    required_value(document, pointer)?.as_u64().ok_or_else(|| {
        format!("required lifecycle field {pointer} is not an unsigned integer").into()
    })
}

fn digest_object(value: &Value) -> Result<String> {
    if required_str(value, "/algorithm")? != "sha256" {
        return Err("lifecycle digest algorithm is not sha256".into());
    }
    let hex = required_str(value, "/hex")?;
    validate_hex_digest(hex)?;
    Ok(format!("sha256:{hex}"))
}

fn validate_blob_pointer(value: &Value) -> Result<()> {
    let _ = digest_object(required_value(value, "/content_digest")?)?;
    if required_u64(value, "/size_bytes")? == 0
        || required_str(value, "/media_type")?.trim().is_empty()
    {
        return Err("lifecycle blob pointer is empty".into());
    }
    Ok(())
}

fn validate_hex_digest(value: &str) -> Result<()> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err("frozen corpus contains an invalid SHA-256 digest".into())
    }
}

fn validate_prefixed_digest(value: &str) -> Result<()> {
    validate_hex_digest(
        value
            .strip_prefix("sha256:")
            .ok_or("digest is missing the sha256: prefix")?,
    )
}

fn compare_operations(corpus: &Corpus) -> Result<Vec<OperationComparison>> {
    let pairs = operation_pairs();
    let names = pairs
        .iter()
        .map(|(_, component)| component.as_str().to_string())
        .collect::<Vec<_>>();
    if names != corpus.expected_operations || names.len() != 27 {
        return Err("frozen 27-operation vocabulary changed".into());
    }
    Ok(pairs
        .into_iter()
        .map(|(native, component)| {
            let policy = operation_policy(component);
            let native_family = native_family(native.family());
            let component_family = policy.family.as_str().to_string();
            let native_authority = native_authority(native.minimum_authority());
            let component_authority = component_authority(policy.minimum_authority);
            let authority_identical = native_authority == component_authority;
            OperationComparison {
                operation: component.as_str().to_string(),
                family_identical: native_family == component_family,
                native_family,
                component_family,
                authority_identical,
                native_authority,
                component_authority,
                component_approval_required: policy.approval_required,
                disposition: if authority_identical {
                    "identical"
                } else {
                    "intentional-versioned-difference"
                },
                decision: (!authority_identical).then_some(DECISION_ID),
            }
        })
        .collect())
}

fn operation_pairs() -> Vec<(NativeOperation, ComponentOperation)> {
    use ComponentOperation as C;
    use NativeOperation as N;
    vec![
        (N::WorkspaceOpen, C::WorkspaceOpen),
        (N::WorkspaceSnapshot, C::WorkspaceSnapshot),
        (N::WorkspacePatch, C::WorkspacePatch),
        (N::CandidateBuild, C::CandidateBuild),
        (N::CommandExecute, C::CommandExecute),
        (N::PackagePublish, C::PackagePublish),
        (N::PackageVerify, C::PackageVerify),
        (N::ValidationProve, C::ValidationProve),
        (N::ValidationCompare, C::ValidationCompare),
        (N::ReviewCandidate, C::ReviewCandidate),
        (N::EvidencePublish, C::EvidencePublish),
        (N::EvidenceResolve, C::EvidenceResolve),
        (N::ScheduleJob, C::ScheduleJob),
        (N::DeploymentInitialize, C::DeploymentInitialize),
        (N::DeploymentActivate, C::DeploymentActivate),
        (N::DeploymentObserve, C::DeploymentObserve),
        (N::DeploymentRollback, C::DeploymentRollback),
        (N::OperationsInspect, C::OperationsInspect),
        (N::FactoryExecute, C::FactoryExecute),
        (N::FactoryProviderProposal, C::FactoryProviderProposal),
        (N::FactoryShadow, C::FactoryShadow),
        (N::FactoryInitialize, C::FactoryInitialize),
        (N::FactoryStateMigrate, C::FactoryStateMigrate),
        (N::FactoryActivate, C::FactoryActivate),
        (N::FactoryObserve, C::FactoryObserve),
        (N::FactoryRollback, C::FactoryRollback),
        (N::FactoryInspect, C::FactoryInspect),
    ]
}

fn one_dispatch(commands: &[PolicyCommand]) -> Result<&DispatchSpec> {
    match commands {
        [PolicyCommand::DispatchWorker(dispatch)] => Ok(dispatch),
        other => Err(format!("expected one dispatch command, received {other:?}").into()),
    }
}

fn role_for_stage(stage: &Stage) -> worker::Role {
    match stage {
        Stage::Planner => worker::Role::Planner,
        Stage::Builder => worker::Role::Builder,
        Stage::Validator => worker::Role::Validator,
        Stage::Reviewer => worker::Role::Reviewer,
        Stage::Packager => worker::Role::Packager,
        Stage::ContinuityWorker => worker::Role::ContinuityWorker,
    }
}

fn worker_request(dispatch: &DispatchSpec, role: worker::Role) -> worker::WorkerRequestValue {
    worker::WorkerRequestValue {
        execution_id: dispatch.execution_id.clone(),
        job_id: dispatch.job_id.clone(),
        role,
        worker: worker::PrincipalValue {
            id: role.as_str().to_string(),
            component_digest: worker_digest(&dispatch.worker_component),
        },
        service_bindings: dispatch
            .service_bindings
            .iter()
            .map(|binding| worker::ServiceBindingValue {
                family: match binding.family {
                    ServiceFamilyValue::Build => worker::ServiceFamily::Build,
                    ServiceFamilyValue::Packaging => worker::ServiceFamily::Packaging,
                    ServiceFamilyValue::Validation => worker::ServiceFamily::Validation,
                    ServiceFamilyValue::Review => worker::ServiceFamily::Review,
                    ServiceFamilyValue::Continuity => worker::ServiceFamily::Continuity,
                    ServiceFamilyValue::Scheduling => worker::ServiceFamily::Scheduling,
                    ServiceFamilyValue::Operations => worker::ServiceFamily::Operations,
                },
                component_digest: worker_digest(&binding.component_digest),
            })
            .collect(),
        input: worker_blob(&dispatch.input),
        checkpoint: dispatch.checkpoint.as_ref().map(worker_blob),
        lease_digest: worker_digest(&dispatch.lease_digest),
        attempt: dispatch.attempt,
        deadline_ms: None,
    }
}

fn digest_value(bytes: &[u8]) -> DigestValue {
    DigestValue {
        algorithm: "sha256".to_string(),
        hex: sha256_hex(bytes),
    }
}

fn blob(bytes: &[u8], media_type: &str) -> BlobPointer {
    BlobPointer {
        content_digest: digest_value(bytes),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        media_type: media_type.to_string(),
    }
}

fn blob_worker(bytes: &[u8], media_type: &str) -> worker::BlobPointer {
    worker::BlobPointer {
        content_digest: worker::DigestValue::sha256(bytes),
        size_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        media_type: media_type.to_string(),
    }
}

fn worker_digest(value: &DigestValue) -> worker::DigestValue {
    worker::DigestValue {
        algorithm: value.algorithm.clone(),
        hex: value.hex.clone(),
    }
}

fn worker_blob(value: &BlobPointer) -> worker::BlobPointer {
    worker::BlobPointer {
        content_digest: worker_digest(&value.content_digest),
        size_bytes: value.size_bytes,
        media_type: value.media_type.clone(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn native_family(value: NativeServiceFamily) -> String {
    kebab_debug(value)
}

fn native_authority(value: NativeAuthority) -> String {
    kebab_debug(value)
}

fn component_authority(value: ComponentAuthority) -> String {
    kebab_debug(value)
}

fn kebab_debug(value: impl std::fmt::Debug) -> String {
    let source = format!("{value:?}");
    let mut output = String::new();
    for (index, character) in source.chars().enumerate() {
        if character.is_ascii_uppercase() && index > 0 {
            output.push('-');
        }
        output.push(character.to_ascii_lowercase());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_mapping_is_exhaustive_and_family_stable() {
        let pairs = operation_pairs();
        assert_eq!(pairs.len(), 27);
        assert!(pairs.into_iter().all(|(native, component)| {
            native_family(native.family()) == operation_policy(component).family.as_str()
        }));
    }

    #[test]
    fn exchange_transfer_unknown_field_fixture_fails_closed() {
        assert_eq!(
            execute_malformed_document_case("exchange-transfer-unknown-field").unwrap(),
            "invalid-transfer-request"
        );
    }

    #[test]
    fn bounded_component_trace_is_complete_and_deterministic() {
        let corpus: Corpus =
            serde_json::from_str(include_str!("../fixtures/bounded-cycle.v1.json")).unwrap();
        validate_corpus(&corpus).unwrap();
        let first = run_component_trace(&corpus).unwrap();
        let second = run_component_trace(&corpus).unwrap();
        assert_eq!(first.state_digest, second.state_digest);
        assert_eq!(first.decision_digests, second.decision_digests);
        assert_eq!(first.worker_selection.len(), 6);
        assert_eq!(first.capability_requests.len(), 12);
        assert_eq!(
            first.capability_requests,
            expected_policy_capability_trace()
        );
        assert_eq!(first.receipt_outcomes.len(), 12);
        assert_eq!(first.expected_capability_request_count, 12);
        assert!(first.capability_request_order_verified);
        assert_eq!(
            first.service_output_mode,
            "deterministic-synthetic-blob; no useful R1 semantics executed"
        );
    }
}
