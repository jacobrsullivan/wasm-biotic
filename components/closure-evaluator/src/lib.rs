#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Component-owned closure policy over an immutable evidence dossier.

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};

/// Accepted dossier schema.
pub const DOSSIER_SCHEMA: &str = "wasm-biotic.component-complete-dossier.v1";
/// Returned decision schema.
pub const DECISION_SCHEMA: &str = "wasm-biotic.component-complete-decision.v1";
/// Canonical document media type.
pub const JSON_MEDIA_TYPE: &str = "application/json";

/// Exact evidence classes required for architectural closure.
pub const REQUIRED_EVIDENCE: [&str; 6] = [
    "graph-validation",
    "native-boundary",
    "complete-cycle",
    "restart-recovery",
    "adversarial-isolation",
    "successor-cycle",
];

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dossier {
    schema: String,
    graph_manifest_digest: String,
    native_tcb_digest: String,
    evidence: alloc::collections::BTreeMap<String, String>,
    #[serde(default)]
    unresolved_blockers: Vec<String>,
}

/// Component-complete architectural decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecisionStatus {
    /// All local architectural evidence is present.
    Closed,
    /// One or more evidence gates remain absent or explicitly blocked.
    NotYet,
}

/// Canonical decision returned by [`evaluate_policy`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClosureDecision {
    /// Decision wire schema.
    pub schema: String,
    /// Explicit bounded architectural scope.
    pub scope: String,
    /// Closure result.
    pub status: DecisionStatus,
    /// Exact graph evaluated.
    pub graph_manifest_digest: String,
    /// Exact native TCB evaluated.
    pub native_tcb_digest: String,
    /// Missing evidence classes and declared blockers, sorted.
    pub blockers: Vec<String>,
    /// Prevents this local result from being misreported as external proof.
    pub external_qualification_claimed: bool,
}

/// Fail-closed policy error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureError {
    /// Stable error code.
    pub code: String,
    /// Human-readable context.
    pub message: String,
}

impl ClosureError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Evaluates exact dossier JSON without any host decision logic.
pub fn evaluate_policy(bytes: &[u8]) -> Result<Vec<u8>, ClosureError> {
    let dossier: Dossier = serde_json::from_slice(bytes).map_err(|error| {
        ClosureError::new(
            "invalid-dossier",
            format!("dossier is not canonical schema JSON: {error}"),
        )
    })?;
    if dossier.schema != DOSSIER_SCHEMA {
        return Err(ClosureError::new(
            "unsupported-dossier-schema",
            format!("expected {DOSSIER_SCHEMA}, received {}", dossier.schema),
        ));
    }
    validate_digest("graph_manifest_digest", &dossier.graph_manifest_digest)?;
    validate_digest("native_tcb_digest", &dossier.native_tcb_digest)?;

    let mut blockers = Vec::new();
    for evidence_class in REQUIRED_EVIDENCE {
        match dossier.evidence.get(evidence_class) {
            Some(digest) => validate_digest(evidence_class, digest)?,
            None => blockers.push(format!("missing-evidence:{evidence_class}")),
        }
    }
    for blocker in dossier.unresolved_blockers {
        if blocker.trim().is_empty() {
            return Err(ClosureError::new(
                "invalid-blocker",
                "blocker names must not be blank",
            ));
        }
        blockers.push(format!("declared:{blocker}"));
    }
    blockers.sort();
    blockers.dedup();

    let decision = ClosureDecision {
        schema: DECISION_SCHEMA.to_string(),
        scope: "bounded-local-component-complete-architecture".to_string(),
        status: if blockers.is_empty() {
            DecisionStatus::Closed
        } else {
            DecisionStatus::NotYet
        },
        graph_manifest_digest: dossier.graph_manifest_digest,
        native_tcb_digest: dossier.native_tcb_digest,
        blockers,
        external_qualification_claimed: false,
    };
    serde_json::to_vec(&decision).map_err(|error| {
        ClosureError::new(
            "decision-serialization-failed",
            format!("cannot encode decision: {error}"),
        )
    })
}

fn validate_digest(field: &str, digest: &str) -> Result<(), ClosureError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ClosureError::new(
            "invalid-digest",
            format!("{field} must be 64 lower-case SHA-256 hex characters"),
        ));
    }
    Ok(())
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[global_allocator]
static ALLOCATOR: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

#[cfg(all(target_arch = "wasm32", not(test)))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn cabi_realloc(
    old_pointer: *mut u8,
    old_length: usize,
    alignment: usize,
    new_length: usize,
) -> *mut u8 {
    use alloc::alloc::{Layout, alloc, dealloc, handle_alloc_error, realloc};
    let alignment = alignment.max(1);
    if old_pointer.is_null() {
        if new_length == 0 {
            return core::ptr::null_mut();
        }
        let layout = Layout::from_size_align(new_length, alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        let pointer = unsafe { alloc(layout) };
        if pointer.is_null() {
            handle_alloc_error(layout);
        }
        pointer
    } else {
        let old_layout = Layout::from_size_align(old_length.max(1), alignment)
            .unwrap_or_else(|_| core::arch::wasm32::unreachable());
        if new_length == 0 {
            unsafe { dealloc(old_pointer, old_layout) };
            core::ptr::null_mut()
        } else {
            let pointer = unsafe { realloc(old_pointer, old_layout, new_length) };
            if pointer.is_null() {
                let layout = Layout::from_size_align(new_length, alignment)
                    .unwrap_or_else(|_| core::arch::wasm32::unreachable());
                handle_alloc_error(layout);
            }
            pointer
        }
    }
}

#[cfg(all(target_arch = "wasm32", not(test)))]
#[unsafe(no_mangle)]
unsafe extern "C" fn memcmp(left: *const u8, right: *const u8, length: usize) -> i32 {
    for offset in 0..length {
        let left_byte = unsafe { *left.add(offset) };
        let right_byte = unsafe { *right.add(offset) };
        if left_byte != right_byte {
            return i32::from(left_byte) - i32::from(right_byte);
        }
    }
    0
}

#[cfg(target_arch = "wasm32")]
mod component {
    use super::*;

    wit_bindgen::generate!({
        path: "../../wit/wasm-biotic",
        world: "closure-evaluator-component",
    });

    use exports::wasm_biotic::factory::closure_evaluator::Guest as ClosureGuest;
    use exports::wasm_biotic::factory::component_task::Guest as TaskGuest;
    use wasm_biotic::factory::foundation::{BlobRef, Failure};

    struct ClosureEvaluatorComponent;

    impl ClosureGuest for ClosureEvaluatorComponent {
        fn evaluate(dossier: BlobRef) -> Result<BlobRef, Failure> {
            evaluate(dossier)
        }
    }

    impl TaskGuest for ClosureEvaluatorComponent {
        fn run(input: BlobRef) -> Result<BlobRef, Failure> {
            evaluate(input)
        }
    }

    fn evaluate(dossier: BlobRef) -> Result<BlobRef, Failure> {
        let bytes = wasm_biotic::factory::blob_store::get(&dossier)?;
        let decision = evaluate_policy(&bytes).map_err(policy_failure)?;
        Ok(wasm_biotic::factory::blob_store::put(
            JSON_MEDIA_TYPE,
            &decision,
        )?)
    }

    fn policy_failure(error: ClosureError) -> Failure {
        Failure {
            code: error.code,
            message: error.message,
            retryable: false,
            evidence: None,
        }
    }

    export!(ClosureEvaluatorComponent);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(character: char) -> String {
        core::iter::repeat_n(character, 64).collect()
    }

    fn dossier(evidence: &[&str], blockers: &[&str]) -> Vec<u8> {
        let evidence = evidence
            .iter()
            .map(|name| ((*name).to_string(), digest('c')))
            .collect::<alloc::collections::BTreeMap<_, _>>();
        serde_json::to_vec(&serde_json::json!({
            "schema": DOSSIER_SCHEMA,
            "graph_manifest_digest": digest('a'),
            "native_tcb_digest": digest('b'),
            "evidence": evidence,
            "unresolved_blockers": blockers,
        }))
        .unwrap()
    }

    #[test]
    fn complete_evidence_closes_only_the_bounded_architecture_scope() {
        let bytes = evaluate_policy(&dossier(&REQUIRED_EVIDENCE, &[])).unwrap();
        let decision: ClosureDecision = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decision.status, DecisionStatus::Closed);
        assert!(!decision.external_qualification_claimed);
    }

    #[test]
    fn missing_or_declared_blockers_produce_not_yet() {
        let bytes = evaluate_policy(&dossier(
            &REQUIRED_EVIDENCE[..5],
            &["independent-substrate"],
        ))
        .unwrap();
        let decision: ClosureDecision = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decision.status, DecisionStatus::NotYet);
        assert_eq!(decision.blockers.len(), 2);
    }

    #[test]
    fn malformed_digests_and_unknown_schemas_fail_closed() {
        let mut value: serde_json::Value =
            serde_json::from_slice(&dossier(&REQUIRED_EVIDENCE, &[])).unwrap();
        value["graph_manifest_digest"] = serde_json::Value::String("not-a-digest".to_string());
        assert_eq!(
            evaluate_policy(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            "invalid-digest"
        );
        value["graph_manifest_digest"] = serde_json::Value::String(digest('a'));
        value["schema"] = serde_json::Value::String("unknown".to_string());
        assert_eq!(
            evaluate_policy(&serde_json::to_vec(&value).unwrap())
                .unwrap_err()
                .code,
            "unsupported-dossier-schema"
        );
    }
}
