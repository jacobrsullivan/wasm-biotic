#![cfg_attr(all(target_arch = "wasm32", not(test)), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]

//! Component-owned exchange envelope and replay policy.

extern crate alloc;

use alloc::{
    format,
    string::{String, ToString},
    vec::Vec,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

pub const TRANSFER_SCHEMA: &str = "wasm-biotic.transfer-request.v1";
pub const ENVELOPE_SCHEMA: &str = "wasm-biotic.exchange-envelope.v1";
pub const REVOCATION_SCHEMA: &str = "wasm-biotic.exchange-revocation.v1";
pub const TRANSPORT_OUTBOX_SCHEMA: &str = "wasm-biotic.exchange-transport-outbox.v1";
pub const JSON_MEDIA_TYPE: &str = "application/json";
pub const TRANSPORT_AUTHORIZATION_HEADER: &str = "authorization";
pub const TRANSPORT_AUTHORIZATION_PREFIX: &[u8] = b"Bearer ";
/// Component-owned dispatch timeout, bounded by the signed R3 transport grant.
pub const TRANSPORT_TIMEOUT_MS: u64 = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlobPointer {
    pub digest: String,
    pub size_bytes: u64,
    pub media_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferRequest {
    pub schema: String,
    pub transfer_id: String,
    pub sender: String,
    pub receiver: String,
    pub artifact: BlobPointer,
    pub expires_at_ms: u64,
    pub signing_key_handle: String,
    pub destination_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_credential_handle: Option<String>,
    pub idempotency_key: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TransportDisposition {
    Prepared,
    Pending,
    Delivered,
    DefiniteFailure,
    RejectedResponse,
    OutcomeUnknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportOutbox {
    pub schema: String,
    pub transfer_id: String,
    pub transfer_request_digest: String,
    pub envelope: BlobPointer,
    pub destination_url: String,
    pub credential_handle: Option<String>,
    pub http_request_id: String,
    pub http_operation_id: Option<String>,
    pub disposition: TransportDisposition,
    pub response_status: Option<u16>,
    pub response_body: Option<BlobPointer>,
    pub response_receipt_digest: Option<String>,
    pub failure_code: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
struct UnsignedEnvelope {
    schema: String,
    transfer_id: String,
    sender: String,
    receiver: String,
    artifact: BlobPointer,
    created_at_ms: u64,
    expires_at_ms: u64,
    idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SignatureAlgorithm {
    Ed25519,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeEnvelope {
    schema: String,
    transfer_id: String,
    sender: String,
    receiver: String,
    artifact: BlobPointer,
    created_at_ms: u64,
    expires_at_ms: u64,
    idempotency_key: String,
    signed_digest: String,
    key_id: String,
    signature_algorithm: SignatureAlgorithm,
    signature_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationRequest {
    pub schema: String,
    pub transfer_id: String,
    pub reason: String,
    pub idempotency_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExchangeError {
    pub code: String,
    pub message: String,
}

impl ExchangeError {
    fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

impl core::fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl core::error::Error for ExchangeError {}

/// Component-owned classification of a received envelope identity.
///
/// The native transaction store supplies only an optional previously stored
/// content digest. This policy decides whether the presented envelope is new,
/// a byte-exact idempotent replay, or a conflicting reuse of the transfer id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvelopeReplayDecision {
    FirstUse,
    ExactReplay,
    Conflict,
}

/// Decodes and validates the transfer document consumed by the component.
pub fn decode_transfer_policy(bytes: &[u8], now_ms: u64) -> Result<TransferRequest, ExchangeError> {
    let request = decode_transfer_document(bytes)?;
    validate_transfer(&request, now_ms)?;
    Ok(request)
}

fn decode_transfer_document(bytes: &[u8]) -> Result<TransferRequest, ExchangeError> {
    serde_json::from_slice(bytes).map_err(|error| {
        ExchangeError::new(
            "invalid-transfer-request",
            format!("cannot parse transfer request: {error}"),
        )
    })
}

/// Decodes the signed envelope's semantic fields before cryptographic and
/// storage checks are delegated to their separately granted primitives.
pub fn decode_envelope_policy(
    bytes: &[u8],
    now_ms: u64,
) -> Result<ExchangeEnvelope, ExchangeError> {
    let envelope: ExchangeEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        ExchangeError::new(
            "invalid-envelope",
            format!("cannot parse envelope: {error}"),
        )
    })?;
    if envelope.schema != ENVELOPE_SCHEMA {
        return Err(ExchangeError::new(
            "unsupported-envelope-schema",
            format!("expected {ENVELOPE_SCHEMA}"),
        ));
    }
    validate_digest("signed_digest", &envelope.signed_digest)?;
    validate_digest("idempotency_key", &envelope.idempotency_key)?;
    validate_digest("artifact.digest", &envelope.artifact.digest)?;
    if envelope.expires_at_ms <= now_ms {
        return Err(ExchangeError::new(
            "envelope-expired",
            "exchange envelope has expired",
        ));
    }
    Ok(envelope)
}

/// Decodes and validates an exchange revocation document.
pub fn decode_revocation_policy(bytes: &[u8]) -> Result<RevocationRequest, ExchangeError> {
    let request: RevocationRequest = serde_json::from_slice(bytes).map_err(|error| {
        ExchangeError::new(
            "invalid-revocation",
            format!("cannot parse revocation: {error}"),
        )
    })?;
    if request.schema != REVOCATION_SCHEMA
        || request.transfer_id.trim().is_empty()
        || request.reason.trim().is_empty()
    {
        return Err(ExchangeError::new(
            "invalid-revocation",
            "revocation schema, transfer id and reason are required",
        ));
    }
    validate_digest("idempotency_key", &request.idempotency_key)?;
    Ok(request)
}

/// Classifies durable replay without granting the host any exchange meaning.
pub fn classify_envelope_replay(
    existing_envelope_digest: Option<&str>,
    presented_envelope_digest: &str,
) -> Result<EnvelopeReplayDecision, ExchangeError> {
    validate_digest("presented_envelope_digest", presented_envelope_digest)?;
    let Some(existing) = existing_envelope_digest else {
        return Ok(EnvelopeReplayDecision::FirstUse);
    };
    validate_digest("existing_envelope_digest", existing)?;
    Ok(if existing == presented_envelope_digest {
        EnvelopeReplayDecision::ExactReplay
    } else {
        EnvelopeReplayDecision::Conflict
    })
}

/// Validates a transfer request before any effect is attempted.
pub fn validate_transfer(request: &TransferRequest, now_ms: u64) -> Result<(), ExchangeError> {
    validate_transfer_intent(request)?;
    if request.expires_at_ms <= now_ms {
        return Err(ExchangeError::new(
            "transfer-expired",
            "transfer expiry must be in the future",
        ));
    }
    Ok(())
}

fn validate_transfer_intent(request: &TransferRequest) -> Result<(), ExchangeError> {
    if request.schema != TRANSFER_SCHEMA {
        return Err(ExchangeError::new(
            "unsupported-transfer-schema",
            format!("expected {TRANSFER_SCHEMA}"),
        ));
    }
    for (field, value) in [
        ("transfer_id", request.transfer_id.as_str()),
        ("sender", request.sender.as_str()),
        ("receiver", request.receiver.as_str()),
        ("signing_key_handle", request.signing_key_handle.as_str()),
        ("artifact.media_type", request.artifact.media_type.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(ExchangeError::new(
                "invalid-transfer-field",
                format!("{field} must not be blank"),
            ));
        }
    }
    validate_digest("artifact.digest", &request.artifact.digest)?;
    validate_digest("idempotency_key", &request.idempotency_key)?;
    if let Some(url) = &request.destination_url
        && !(url.starts_with("https://")
            || url.starts_with("http://127.0.0.1:")
            || url.starts_with("http://localhost:"))
    {
        return Err(ExchangeError::new(
            "forbidden-destination",
            "v1 exchange permits HTTPS or explicit loopback HTTP only",
        ));
    }
    if request
        .transport_credential_handle
        .as_ref()
        .is_some_and(|handle| handle.trim().is_empty())
    {
        return Err(ExchangeError::new(
            "invalid-transport-credential-handle",
            "transport credential handle must not be blank",
        ));
    }
    if request.destination_url.is_none() && request.transport_credential_handle.is_some() {
        return Err(ExchangeError::new(
            "credential-without-destination",
            "transport credential handle requires an explicit destination",
        ));
    }
    Ok(())
}

/// Constructs the durable component-owned intent that must exist before an
/// irreversible transport call is started. The record contains only the
/// opaque credential handle, never credential bytes.
pub fn prepare_transport_outbox(
    request: &TransferRequest,
    envelope: BlobPointer,
) -> Result<Option<TransportOutbox>, ExchangeError> {
    let Some(destination_url) = request.destination_url.clone() else {
        return Ok(None);
    };
    let transfer_request_digest = sha256_hex(&canonical_bytes(request)?);
    Ok(Some(TransportOutbox {
        schema: TRANSPORT_OUTBOX_SCHEMA.to_string(),
        transfer_id: request.transfer_id.clone(),
        transfer_request_digest,
        envelope,
        destination_url,
        credential_handle: request.transport_credential_handle.clone(),
        http_request_id: format!("exchange-send/{}", request.transfer_id),
        http_operation_id: None,
        disposition: TransportDisposition::Prepared,
        response_status: None,
        response_body: None,
        response_receipt_digest: None,
        failure_code: None,
    }))
}

/// Verifies that a replay is byte-identical to the durable outgoing intent.
pub fn validate_transport_outbox_replay(
    stored: &TransportOutbox,
    expected: &TransportOutbox,
) -> Result<(), ExchangeError> {
    if stored.schema != TRANSPORT_OUTBOX_SCHEMA
        || expected.schema != TRANSPORT_OUTBOX_SCHEMA
        || stored.transfer_id != expected.transfer_id
        || stored.transfer_request_digest != expected.transfer_request_digest
        || stored.envelope != expected.envelope
        || stored.destination_url != expected.destination_url
        || stored.credential_handle != expected.credential_handle
        || stored.http_request_id != expected.http_request_id
    {
        return Err(ExchangeError::new(
            "transport-outbox-conflict",
            "transfer id was reused with different transport intent bytes",
        ));
    }
    Ok(())
}

/// Applies only component-owned HTTP status meaning. Native transport returns
/// every status and body unchanged and never calls this function.
pub fn classify_transport_status(status: u16) -> TransportDisposition {
    if (200..300).contains(&status) {
        TransportDisposition::Delivered
    } else {
        TransportDisposition::RejectedResponse
    }
}

/// Constructs the non-secret request headers as component policy. When a
/// credential handle is present, native code may only append the hidden bytes
/// to this exact prefix under the separately signed constraint.
pub fn transport_request_headers(request: &TransferRequest) -> Vec<(String, Vec<u8>)> {
    let mut headers = alloc::vec![(
        "content-type".to_string(),
        JSON_MEDIA_TYPE.as_bytes().to_vec(),
    )];
    if request.transport_credential_handle.is_some() {
        headers.push((
            TRANSPORT_AUTHORIZATION_HEADER.to_string(),
            TRANSPORT_AUTHORIZATION_PREFIX.to_vec(),
        ));
    }
    headers
}

/// Builds the exact unsigned material whose digest is signed.
#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn unsigned(request: &TransferRequest, created_at_ms: u64) -> UnsignedEnvelope {
    UnsignedEnvelope {
        schema: ENVELOPE_SCHEMA.to_string(),
        transfer_id: request.transfer_id.clone(),
        sender: request.sender.clone(),
        receiver: request.receiver.clone(),
        artifact: request.artifact.clone(),
        created_at_ms,
        expires_at_ms: request.expires_at_ms,
        idempotency_key: request.idempotency_key.clone(),
    }
}

#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
fn unsigned_from_envelope(envelope: &ExchangeEnvelope) -> UnsignedEnvelope {
    UnsignedEnvelope {
        schema: envelope.schema.clone(),
        transfer_id: envelope.transfer_id.clone(),
        sender: envelope.sender.clone(),
        receiver: envelope.receiver.clone(),
        artifact: envelope.artifact.clone(),
        created_at_ms: envelope.created_at_ms,
        expires_at_ms: envelope.expires_at_ms,
        idempotency_key: envelope.idempotency_key.clone(),
    }
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ExchangeError> {
    serde_json::to_vec(value).map_err(|error| {
        ExchangeError::new(
            "serialization-failed",
            format!("cannot encode exchange document: {error}"),
        )
    })
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn sha256_hex(bytes: &[u8]) -> String {
    encode_hex(&Sha256::digest(bytes))
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn decode_hex(value: &str) -> Result<Vec<u8>, ExchangeError> {
    if !value.len().is_multiple_of(2) {
        return Err(ExchangeError::new(
            "invalid-signature",
            "signature hex length must be even",
        ));
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let raw = value.as_bytes();
    for index in (0..raw.len()).step_by(2) {
        let high = decode_nibble(raw[index])?;
        let low = decode_nibble(raw[index + 1])?;
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

#[cfg_attr(not(any(target_arch = "wasm32", test)), allow(dead_code))]
fn decode_nibble(byte: u8) -> Result<u8, ExchangeError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(ExchangeError::new(
            "invalid-signature",
            "signature must use lower-case hex",
        )),
    }
}

fn validate_digest(field: &str, digest: &str) -> Result<(), ExchangeError> {
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExchangeError::new(
            "invalid-digest",
            format!("{field} must be lower-case SHA-256 hex"),
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

    const MAX_TRANSPORT_POLLS_PER_CALL: usize = 256;

    wit_bindgen::generate!({ path: "../../wit/wasm-biotic", world: "exchange-service-component" });

    use exports::wasm_biotic::factory::exchange_service::Guest;
    use wasm_biotic::factory::foundation::{BlobRef, Digest, Failure, HashAlgorithm};
    use wasm_biotic::factory::http_transport::{Header, Method, Request as HttpRequest};
    use wasm_biotic::factory::key_service::{
        Signature, SignatureAlgorithm as WitSignatureAlgorithm,
    };
    use wasm_biotic::factory::transaction_store::{Assertion, CommitRequest, Mutation};

    struct ExchangeServiceComponent;

    impl Guest for ExchangeServiceComponent {
        fn create_envelope(transfer_request: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&transfer_request)?;
            let request = decode_transfer_document(&bytes).map_err(policy_failure)?;
            let now = wasm_biotic::factory::clock::now_ms();
            validate_transfer(&request, now).map_err(policy_failure)?;
            let transfer_key = format!("transfer/{}", request.transfer_id);
            if let Some(existing) =
                wasm_biotic::factory::transaction_store::read("exchange-v1", &transfer_key)?
            {
                ensure_transfer_request_identity(&request, false)?;
                return Ok(existing.value);
            }
            if let Some(envelope_ref) = resume_transport_outbox(&request)? {
                commit_pointer(
                    &format!("exchange-create/{}", request.transfer_id),
                    &transfer_key,
                    None,
                    envelope_ref.clone(),
                    &request.idempotency_key,
                )?;
                return Ok(envelope_ref);
            }
            let artifact = blob_ref(&request.artifact);
            if !wasm_biotic::factory::blob_store::has(&artifact.content_digest)? {
                return Err(failure(
                    "missing-artifact",
                    "transfer artifact is not present in the content store",
                ));
            }
            ensure_transfer_request_identity(&request, true)?;
            let unsigned = unsigned(&request, now);
            let signed_digest_hex =
                sha256_hex(&canonical_bytes(&unsigned).map_err(policy_failure)?);
            let signed_digest = digest(&signed_digest_hex);
            let signature = wasm_biotic::factory::key_service::sign_digest(
                &request.signing_key_handle,
                &signed_digest,
            )?;
            if signature.algorithm != WitSignatureAlgorithm::Ed25519 {
                return Err(failure(
                    "unsupported-signature-algorithm",
                    "exchange v1 requires deterministic Ed25519",
                ));
            }
            let envelope = ExchangeEnvelope {
                schema: unsigned.schema,
                transfer_id: unsigned.transfer_id,
                sender: unsigned.sender,
                receiver: unsigned.receiver,
                artifact: unsigned.artifact,
                created_at_ms: unsigned.created_at_ms,
                expires_at_ms: unsigned.expires_at_ms,
                idempotency_key: unsigned.idempotency_key,
                signed_digest: signed_digest_hex,
                key_id: signature.key_id,
                signature_algorithm: SignatureAlgorithm::Ed25519,
                signature_hex: encode_hex(&signature.bytes),
            };
            let envelope_bytes = canonical_bytes(&envelope).map_err(policy_failure)?;
            let envelope_ref =
                wasm_biotic::factory::blob_store::put(JSON_MEDIA_TYPE, &envelope_bytes)?;

            if request.destination_url.is_some() {
                deliver_transport_outbox(&request, &envelope_ref)?;
            }

            commit_pointer(
                &format!("exchange-create/{}", request.transfer_id),
                &transfer_key,
                None,
                envelope_ref.clone(),
                &request.idempotency_key,
            )?;
            Ok(envelope_ref)
        }

        fn receive_envelope(envelope_ref: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&envelope_ref)?;
            let envelope = decode_envelope_policy(&bytes, wasm_biotic::factory::clock::now_ms())
                .map_err(policy_failure)?;
            if wasm_biotic::factory::transaction_store::read(
                "exchange-v1",
                &format!("revocation/{}", envelope.transfer_id),
            )?
            .is_some()
            {
                return Err(failure(
                    "transfer-revoked",
                    "exchange authority was revoked",
                ));
            }
            let actual_signed_digest = sha256_hex(
                &canonical_bytes(&unsigned_from_envelope(&envelope)).map_err(policy_failure)?,
            );
            if actual_signed_digest != envelope.signed_digest {
                return Err(failure(
                    "envelope-digest-mismatch",
                    "signed envelope material was modified",
                ));
            }
            let signature = Signature {
                key_id: envelope.key_id.clone(),
                algorithm: WitSignatureAlgorithm::Ed25519,
                bytes: decode_hex(&envelope.signature_hex).map_err(policy_failure)?,
            };
            if !wasm_biotic::factory::key_service::verify_digest(
                &envelope.key_id,
                &digest(&envelope.signed_digest),
                &signature,
            )? {
                return Err(failure(
                    "invalid-envelope-signature",
                    "exchange signature did not verify",
                ));
            }
            let artifact = blob_ref(&envelope.artifact);
            if !wasm_biotic::factory::blob_store::has(&artifact.content_digest)? {
                return Err(failure(
                    "missing-artifact",
                    "received artifact is not present in the content store",
                ));
            }
            let key = format!("received/{}", envelope.transfer_id);
            if let Some(existing) =
                wasm_biotic::factory::transaction_store::read("exchange-v1", &key)?
            {
                match classify_envelope_replay(
                    Some(&existing.value.content_digest.hex),
                    &envelope_ref.content_digest.hex,
                )
                .map_err(policy_failure)?
                {
                    EnvelopeReplayDecision::ExactReplay => return Ok(artifact),
                    EnvelopeReplayDecision::Conflict => {
                        return Err(failure(
                            "exchange-replay-conflict",
                            "transfer id was replayed with different envelope bytes",
                        ));
                    }
                    EnvelopeReplayDecision::FirstUse => {
                        return Err(failure(
                            "exchange-replay-state-violation",
                            "durable exchange record was present but replay policy reported first use",
                        ));
                    }
                }
            }
            commit_pointer(
                &format!("exchange-receive/{}", envelope.transfer_id),
                &key,
                None,
                envelope_ref,
                &envelope.idempotency_key,
            )?;
            Ok(artifact)
        }

        fn revoke_authority(revocation_request: BlobRef) -> Result<BlobRef, Failure> {
            let bytes = wasm_biotic::factory::blob_store::get(&revocation_request)?;
            let request = decode_revocation_policy(&bytes).map_err(policy_failure)?;
            let canonical = canonical_bytes(&request).map_err(policy_failure)?;
            let record = wasm_biotic::factory::blob_store::put(JSON_MEDIA_TYPE, &canonical)?;
            let key = format!("revocation/{}", request.transfer_id);
            if let Some(existing) =
                wasm_biotic::factory::transaction_store::read("exchange-v1", &key)?
            {
                if existing.value.content_digest.hex == record.content_digest.hex {
                    return Ok(record);
                }
                return Err(failure(
                    "revocation-conflict",
                    "transfer already has different revocation bytes",
                ));
            }
            commit_pointer(
                &format!("exchange-revoke/{}", request.transfer_id),
                &key,
                None,
                record.clone(),
                &request.idempotency_key,
            )?;
            Ok(record)
        }

        fn inspect_transfer(transfer_id: String) -> Result<BlobRef, Failure> {
            if transfer_id.trim().is_empty() {
                return Err(failure(
                    "invalid-transfer-id",
                    "transfer id must not be blank",
                ));
            }
            for prefix in ["revocation", "received", "transfer"] {
                if let Some(value) = wasm_biotic::factory::transaction_store::read(
                    "exchange-v1",
                    &format!("{prefix}/{transfer_id}"),
                )? {
                    return Ok(value.value);
                }
            }
            Err(failure(
                "unknown-transfer",
                "no exchange record exists for transfer id",
            ))
        }
    }

    fn deliver_transport_outbox(
        request: &TransferRequest,
        envelope_ref: &BlobRef,
    ) -> Result<(), Failure> {
        let expected = prepare_transport_outbox(request, blob_pointer(envelope_ref))
            .map_err(policy_failure)?
            .ok_or_else(|| {
                failure(
                    "missing-transport-destination",
                    "transport outbox requires an explicit destination",
                )
            })?;
        let key = format!("outbox/{}", request.transfer_id);
        let existing = wasm_biotic::factory::transaction_store::read("exchange-v1", &key)?;
        let (mut outbox, mut version) = if let Some(existing) = existing {
            let bytes = wasm_biotic::factory::blob_store::get(&existing.value)?;
            let stored: TransportOutbox = serde_json::from_slice(&bytes).map_err(|_| {
                failure(
                    "invalid-transport-outbox",
                    "durable transport outbox is not a closed v1 record",
                )
            })?;
            validate_transport_outbox_replay(&stored, &expected).map_err(policy_failure)?;
            (stored, existing.version)
        } else {
            let (_, version) = persist_transport_outbox(&key, None, &expected)?;
            (expected, version)
        };

        match outbox.disposition {
            TransportDisposition::Delivered => return Ok(()),
            TransportDisposition::RejectedResponse => {
                return Err(failure(
                    "exchange-send-rejected",
                    format!(
                        "destination returned HTTP {}",
                        outbox.response_status.unwrap_or(0)
                    ),
                ));
            }
            TransportDisposition::DefiniteFailure => {
                return Err(failure(
                    outbox
                        .failure_code
                        .clone()
                        .unwrap_or_else(|| "transport-failed".to_string()),
                    "bounded transport attempt failed before a response was available",
                ));
            }
            TransportDisposition::OutcomeUnknown => {
                return Err(failure(
                    "transport-outcome-unknown",
                    "the durable transport journal cannot prove the remote outcome",
                ));
            }
            TransportDisposition::Prepared | TransportDisposition::Pending => {}
        }

        let http = HttpRequest {
            request_id: outbox.http_request_id.clone(),
            method: Method::Post,
            url: outbox.destination_url.clone(),
            headers: transport_request_headers(request)
                .into_iter()
                .map(|(name, value)| Header { name, value })
                .collect(),
            body: Some(envelope_ref.clone()),
            timeout_ms: TRANSPORT_TIMEOUT_MS,
            idempotency_key: digest(&request.idempotency_key),
            credential_handle: outbox.credential_handle.clone(),
        };
        let operation_id = if let Some(operation_id) = outbox.http_operation_id.clone() {
            operation_id
        } else {
            let operation_id = wasm_biotic::factory::http_transport::start(&http)?;
            outbox.http_operation_id = Some(operation_id.clone());
            outbox.disposition = TransportDisposition::Pending;
            (_, version) = persist_transport_outbox(&key, Some(version), &outbox)?;
            operation_id
        };

        for _ in 0..MAX_TRANSPORT_POLLS_PER_CALL {
            let response = match wasm_biotic::factory::http_transport::poll(&operation_id) {
                Ok(Some(response)) => response,
                Ok(None) => continue,
                Err(error) => {
                    outbox.failure_code = Some(error.code.clone());
                    outbox.disposition = if error.code == "transport-outcome-unknown" {
                        TransportDisposition::OutcomeUnknown
                    } else {
                        TransportDisposition::DefiniteFailure
                    };
                    let _ = persist_transport_outbox(&key, Some(version), &outbox)?;
                    return Err(error);
                }
            };
            outbox.response_status = Some(response.status);
            outbox.response_body = response.body.as_ref().map(blob_pointer);
            outbox.response_receipt_digest = Some(effect_receipt_digest(&response.receipt));
            outbox.disposition = classify_transport_status(response.status);
            let _ = persist_transport_outbox(&key, Some(version), &outbox)?;
            return if outbox.disposition == TransportDisposition::Delivered {
                Ok(())
            } else {
                Err(failure(
                    "exchange-send-rejected",
                    format!("destination returned HTTP {}", response.status),
                ))
            };
        }

        let (evidence, _) = persist_transport_outbox(&key, Some(version), &outbox)?;
        Err(Failure {
            code: "exchange-send-pending".to_string(),
            message: "component polling budget ended before transport completion".to_string(),
            retryable: true,
            evidence: Some(evidence),
        })
    }

    fn resume_transport_outbox(request: &TransferRequest) -> Result<Option<BlobRef>, Failure> {
        let key = format!("outbox/{}", request.transfer_id);
        let Some(existing) = wasm_biotic::factory::transaction_store::read("exchange-v1", &key)?
        else {
            return Ok(None);
        };
        ensure_transfer_request_identity(request, false)?;
        let bytes = wasm_biotic::factory::blob_store::get(&existing.value)?;
        let stored: TransportOutbox = serde_json::from_slice(&bytes).map_err(|_| {
            failure(
                "invalid-transport-outbox",
                "durable transport outbox is not a closed v1 record",
            )
        })?;
        let expected = prepare_transport_outbox(request, stored.envelope.clone())
            .map_err(policy_failure)?
            .ok_or_else(|| {
                failure(
                    "missing-transport-destination",
                    "transport outbox requires an explicit destination",
                )
            })?;
        validate_transport_outbox_replay(&stored, &expected).map_err(policy_failure)?;
        let envelope_ref = blob_ref(&stored.envelope);
        let _ = wasm_biotic::factory::blob_store::get(&envelope_ref)?;
        deliver_transport_outbox(request, &envelope_ref)?;
        Ok(Some(envelope_ref))
    }

    fn ensure_transfer_request_identity(
        request: &TransferRequest,
        allow_create: bool,
    ) -> Result<(), Failure> {
        let bytes = canonical_bytes(request).map_err(policy_failure)?;
        let reference = wasm_biotic::factory::blob_store::put(JSON_MEDIA_TYPE, &bytes)?;
        let key = format!("request/{}", request.transfer_id);
        if let Some(existing) = wasm_biotic::factory::transaction_store::read("exchange-v1", &key)?
        {
            return validate_transfer_request_identity(&existing.value, &reference);
        }
        if !allow_create {
            return Err(failure(
                "unverifiable-transfer-replay",
                "a completed transfer has no durable canonical request identity",
            ));
        }
        let marker_idempotency = sha256_hex(
            format!(
                "wasm-biotic.exchange-request-marker.v1|{}|{}",
                request.transfer_id, request.idempotency_key
            )
            .as_bytes(),
        );
        match commit_pointer(
            &format!("exchange-request/{}", request.transfer_id),
            &key,
            None,
            reference.clone(),
            &marker_idempotency,
        ) {
            Ok(()) => Ok(()),
            Err(commit_error) => {
                let Some(existing) =
                    wasm_biotic::factory::transaction_store::read("exchange-v1", &key)?
                else {
                    return Err(commit_error);
                };
                validate_transfer_request_identity(&existing.value, &reference)
            }
        }
    }

    fn validate_transfer_request_identity(
        stored: &BlobRef,
        presented: &BlobRef,
    ) -> Result<(), Failure> {
        if stored.content_digest.algorithm == presented.content_digest.algorithm
            && stored.content_digest.hex == presented.content_digest.hex
            && stored.size_bytes == presented.size_bytes
            && stored.media_type == presented.media_type
        {
            Ok(())
        } else {
            Err(failure(
                "transfer-request-conflict",
                "transfer id was reused with different canonical request bytes",
            ))
        }
    }

    fn persist_transport_outbox(
        key: &str,
        expected_version: Option<u64>,
        outbox: &TransportOutbox,
    ) -> Result<(BlobRef, u64), Failure> {
        let bytes = canonical_bytes(outbox).map_err(policy_failure)?;
        let reference = wasm_biotic::factory::blob_store::put(JSON_MEDIA_TYPE, &bytes)?;
        let material = (
            "wasm-biotic.exchange-outbox-commit.v1",
            key,
            expected_version,
            reference.content_digest.hex.as_str(),
        );
        let idempotency = sha256_hex(&canonical_bytes(&material).map_err(policy_failure)?);
        let receipt = wasm_biotic::factory::transaction_store::commit(&CommitRequest {
            transaction_id: format!("exchange-outbox/{}/{}", outbox.transfer_id, idempotency),
            assertions: alloc::vec![Assertion {
                namespace: "exchange-v1".to_string(),
                key: key.to_string(),
                expected_version,
            }],
            mutations: alloc::vec![Mutation::Put((
                "exchange-v1".to_string(),
                key.to_string(),
                reference.clone(),
            ))],
            idempotency_key: digest(&idempotency),
        })?;
        if receipt.transaction_id.is_empty() {
            return Err(failure(
                "invalid-outbox-commit-receipt",
                "transaction store returned an empty receipt identity",
            ));
        }
        Ok((reference, receipt.commit_version))
    }

    fn blob_pointer(reference: &BlobRef) -> BlobPointer {
        BlobPointer {
            digest: reference.content_digest.hex.clone(),
            size_bytes: reference.size_bytes,
            media_type: reference.media_type.clone(),
        }
    }

    fn effect_receipt_digest(receipt: &wasm_biotic::factory::foundation::EffectReceipt) -> String {
        let material = format!(
            "wasm-biotic.effect-receipt-digest.v1|{}|{}|{}|{}|{}|{}|{}",
            receipt.receipt_id,
            receipt.request_digest.hex,
            receipt.executor_digest.hex,
            receipt.started_at_ms,
            receipt.finished_at_ms,
            receipt.outcome_digest.hex,
            receipt.audit_sequence,
        );
        sha256_hex(material.as_bytes())
    }

    fn commit_pointer(
        transaction_id: &str,
        key: &str,
        expected_version: Option<u64>,
        value: BlobRef,
        idempotency: &str,
    ) -> Result<(), Failure> {
        let request = CommitRequest {
            transaction_id: transaction_id.to_string(),
            assertions: alloc::vec![Assertion {
                namespace: "exchange-v1".to_string(),
                key: key.to_string(),
                expected_version
            }],
            mutations: alloc::vec![Mutation::Put((
                "exchange-v1".to_string(),
                key.to_string(),
                value
            ))],
            idempotency_key: digest(idempotency),
        };
        let _ = wasm_biotic::factory::transaction_store::commit(&request)?;
        Ok(())
    }

    fn blob_ref(pointer: &BlobPointer) -> BlobRef {
        BlobRef {
            content_digest: digest(&pointer.digest),
            size_bytes: pointer.size_bytes,
            media_type: pointer.media_type.clone(),
        }
    }
    fn digest(hex: &str) -> Digest {
        Digest {
            algorithm: HashAlgorithm::Sha256,
            hex: hex.to_string(),
        }
    }
    fn policy_failure(error: ExchangeError) -> Failure {
        failure(error.code, error.message)
    }
    fn failure(code: impl Into<String>, message: impl Into<String>) -> Failure {
        Failure {
            code: code.into(),
            message: message.into(),
            retryable: false,
            evidence: None,
        }
    }

    export!(ExchangeServiceComponent);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(c: char) -> String {
        core::iter::repeat_n(c, 64).collect()
    }
    fn request() -> TransferRequest {
        TransferRequest {
            schema: TRANSFER_SCHEMA.to_string(),
            transfer_id: "transfer-1".to_string(),
            sender: "factory-a".to_string(),
            receiver: "factory-b".to_string(),
            artifact: BlobPointer {
                digest: digest('a'),
                size_bytes: 4,
                media_type: "application/wasm".to_string(),
            },
            expires_at_ms: 2_000,
            signing_key_handle: "exchange-key".to_string(),
            destination_url: None,
            transport_credential_handle: None,
            idempotency_key: digest('b'),
        }
    }

    #[test]
    fn transfer_policy_accepts_local_content_addressed_request() {
        assert!(validate_transfer(&request(), 1_000).is_ok());
    }

    #[test]
    fn expired_bad_digest_and_unsafe_destination_fail_closed() {
        assert_eq!(
            validate_transfer(&request(), 2_000).unwrap_err().code,
            "transfer-expired"
        );
        let mut invalid = request();
        invalid.artifact.digest = "bad".to_string();
        assert_eq!(
            validate_transfer(&invalid, 1_000).unwrap_err().code,
            "invalid-digest"
        );
        let mut unsafe_url = request();
        unsafe_url.destination_url = Some("http://example.com/upload".to_string());
        assert_eq!(
            validate_transfer(&unsafe_url, 1_000).unwrap_err().code,
            "forbidden-destination"
        );
    }

    #[test]
    fn signed_material_is_canonical_and_tamper_evident() {
        let request = request();
        let first = canonical_bytes(&unsigned(&request, 1_000)).unwrap();
        let second = canonical_bytes(&unsigned(&request, 1_000)).unwrap();
        assert_eq!(first, second);
        let digest_before = sha256_hex(&first);
        let mut changed = request;
        changed.receiver = "factory-c".to_string();
        assert_ne!(
            digest_before,
            sha256_hex(&canonical_bytes(&unsigned(&changed, 1_000)).unwrap())
        );
    }

    #[test]
    fn transport_outbox_is_durable_intent_and_exact_replay_only() {
        let mut transfer = request();
        transfer.destination_url = Some("https://exchange.example/v1/envelopes".to_string());
        transfer.transport_credential_handle = Some("exchange-api".to_string());
        let envelope = BlobPointer {
            digest: digest('c'),
            size_bytes: 128,
            media_type: JSON_MEDIA_TYPE.to_string(),
        };

        let expected = prepare_transport_outbox(&transfer, envelope.clone())
            .unwrap()
            .unwrap();
        assert_eq!(expected.disposition, TransportDisposition::Prepared);
        assert_eq!(expected.envelope, envelope);
        assert_eq!(expected.credential_handle.as_deref(), Some("exchange-api"));
        assert!(expected.http_operation_id.is_none());
        validate_transport_outbox_replay(&expected, &expected).unwrap();

        let mut conflicting = expected.clone();
        conflicting.destination_url = "https://other.example/v1/envelopes".to_string();
        assert_eq!(
            validate_transport_outbox_replay(&expected, &conflicting)
                .unwrap_err()
                .code,
            "transport-outbox-conflict"
        );
    }

    #[test]
    fn transport_policy_and_http_status_meaning_remain_component_owned() {
        assert_eq!(
            classify_transport_status(204),
            TransportDisposition::Delivered
        );
        assert_eq!(
            classify_transport_status(302),
            TransportDisposition::RejectedResponse
        );
        assert_eq!(
            classify_transport_status(503),
            TransportDisposition::RejectedResponse
        );

        let mut transfer = request();
        transfer.transport_credential_handle = Some("exchange-api".to_string());
        assert_eq!(
            validate_transfer(&transfer, 1_000).unwrap_err().code,
            "credential-without-destination"
        );
        transfer.destination_url = Some("https://exchange.example/v1/envelopes".to_string());
        assert!(validate_transfer(&transfer, 1_000).is_ok());
        assert_eq!(
            transport_request_headers(&transfer),
            alloc::vec![
                (
                    "content-type".to_string(),
                    JSON_MEDIA_TYPE.as_bytes().to_vec()
                ),
                (
                    TRANSPORT_AUTHORIZATION_HEADER.to_string(),
                    TRANSPORT_AUTHORIZATION_PREFIX.to_vec()
                ),
            ]
        );
    }

    #[test]
    fn signature_hex_round_trips_and_rejects_uppercase() {
        let bytes = alloc::vec![0, 1, 127, 255];
        assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
        assert_eq!(decode_hex("AA").unwrap_err().code, "invalid-signature");
    }

    #[test]
    fn exact_replay_is_idempotent_and_conflicting_transfer_reuse_fails_closed() {
        let first = digest('a');
        let changed = digest('b');
        assert_eq!(
            classify_envelope_replay(None, &first).unwrap(),
            EnvelopeReplayDecision::FirstUse
        );
        assert_eq!(
            classify_envelope_replay(Some(&first), &first).unwrap(),
            EnvelopeReplayDecision::ExactReplay
        );
        assert_eq!(
            classify_envelope_replay(Some(&first), &changed).unwrap(),
            EnvelopeReplayDecision::Conflict
        );
        assert_eq!(
            classify_envelope_replay(Some(&first), "not-a-digest")
                .unwrap_err()
                .code,
            "invalid-digest"
        );
    }

    #[test]
    fn malformed_and_extended_exchange_documents_fail_closed() {
        assert_eq!(
            decode_transfer_policy(b"{", 1_000).unwrap_err().code,
            "invalid-transfer-request"
        );
        let mut extended = serde_json::to_value(request()).unwrap();
        extended["native_policy"] = serde_json::Value::Bool(true);
        assert_eq!(
            decode_transfer_policy(&serde_json::to_vec(&extended).unwrap(), 1_000)
                .unwrap_err()
                .code,
            "invalid-transfer-request"
        );

        assert_eq!(
            decode_envelope_policy(b"{", 1_000).unwrap_err().code,
            "invalid-envelope"
        );
        let revocation = serde_json::json!({
            "schema": REVOCATION_SCHEMA,
            "transfer_id": "transfer-1",
            "reason": "operator revocation",
            "idempotency_key": digest('c'),
            "native_policy": true,
        });
        assert_eq!(
            decode_revocation_policy(&serde_json::to_vec(&revocation).unwrap())
                .unwrap_err()
                .code,
            "invalid-revocation"
        );
    }
}
