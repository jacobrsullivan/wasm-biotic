//! Independent bounded HTTP transport for profile v3.
//!
//! This module deliberately owns its admission-time data model, operation
//! journal, DNS checks and HTTP implementation. It does not call the
//! production kernel. The journal stores only signed identities, opaque
//! request bytes and raw response facts; credential material lives in a
//! separate in-memory vault and is never journaled.

use crate::model::{
    Digest, HttpOperatorCapacity, HttpOriginConstraint, HttpTransportConstraints, canonical_json,
};
use ipnet::IpNet;
use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs as _};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

const PROFILE_V3: &str = "wasm-biotic.factory-substrate-profile.v3";
const MIN_CREDENTIAL_BYTES: usize = 16;
const MAX_CREDENTIAL_BYTES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(crate) struct TransportOwner {
    pub graph_manifest_digest: Digest,
    pub authority_component_digest: Digest,
    pub principal_seed: Digest,
    pub consumer: String,
    pub alias: String,
    pub constraints: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TransportHeader {
    pub name: String,
    pub value: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TransportRequest {
    pub request_id: String,
    pub method: String,
    pub url: String,
    pub headers: Vec<TransportHeader>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u64,
    pub idempotency_key: Digest,
    pub credential_handle: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportResponse {
    pub status: u16,
    pub headers: Vec<TransportHeader>,
    pub body: Option<Vec<u8>>,
    pub receipt: TransportReceipt,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportReceipt {
    pub receipt_id: String,
    pub request_digest: Digest,
    pub executor_digest: Digest,
    pub started_at_ms: u64,
    pub finished_at_ms: u64,
    pub outcome_digest: Digest,
    pub audit_sequence: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TransportFailure {
    pub code: &'static str,
    pub message: &'static str,
}

impl TransportFailure {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self { code, message }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OperationPhase {
    Prepared,
    Dispatching,
    Completed,
    DefiniteFailure,
    CancelledBeforeDispatch,
    Indeterminate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransportPoll {
    Pending,
    Completed(TransportResponse),
    DefiniteFailure(TransportFailure),
    CancelledBeforeDispatch,
    Indeterminate(TransportFailure),
}

#[derive(Clone)]
pub(crate) struct TransportRuntime {
    inner: Arc<TransportInner>,
}

struct TransportInner {
    configuration: Option<TransportConfiguration>,
    journal: Mutex<Journal>,
    credentials: Mutex<BTreeMap<String, Arc<[u8]>>>,
    #[cfg(test)]
    pause_before_dispatch: AtomicBool,
}

#[derive(Clone)]
struct TransportConfiguration {
    constraints: BTreeMap<Digest, HttpTransportConstraints>,
    operator: HttpOperatorCapacity,
}

#[derive(Default)]
struct Journal {
    operations: BTreeMap<String, OperationRecord>,
    replay: BTreeMap<ReplayIdentity, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayIdentity {
    owner: TransportOwner,
    idempotency_key: Digest,
}

struct OperationRecord {
    owner: TransportOwner,
    request_digest: Digest,
    phase: OperationPhase,
    result: Option<TransportPoll>,
}

#[derive(Serialize)]
struct OperationIdentity<'a> {
    schema: &'static str,
    owner: &'a TransportOwner,
    idempotency_key: Digest,
}

/// Deliberately does not implement `Debug`: this short-lived dispatch value
/// may carry an operator credential. It is never inserted into the journal.
#[derive(Clone)]
struct ValidatedRequest {
    owner: TransportOwner,
    request: TransportRequest,
    request_digest: Digest,
    constraints: HttpTransportConstraints,
    operator: HttpOperatorCapacity,
    origin: HttpOriginConstraint,
    credential: Option<Arc<[u8]>>,
}

impl TransportRuntime {
    /// Constructs a transport with no operator capacity. Even an admitted R3
    /// profile therefore cannot cause external traffic through this runtime.
    pub(crate) fn new(
        _profile_schema: &str,
        _constraints: BTreeMap<Digest, HttpTransportConstraints>,
    ) -> Self {
        Self {
            inner: Arc::new(TransportInner {
                configuration: None,
                journal: Mutex::new(Journal::default()),
                credentials: Mutex::new(BTreeMap::new()),
                #[cfg(test)]
                pause_before_dispatch: AtomicBool::new(false),
            }),
        }
    }

    /// Enables R3 transport only when the operator supplies a closed,
    /// independently validated capacity. Older profiles remain disabled.
    pub(crate) fn new_with_operator(
        profile_schema: &str,
        constraints: BTreeMap<Digest, HttpTransportConstraints>,
        operator: HttpOperatorCapacity,
    ) -> Result<Self, TransportFailure> {
        if profile_schema != PROFILE_V3 {
            return Err(TransportFailure::new(
                "operator-capacity-invalid",
                "HTTP operator capacity requires substrate profile v3",
            ));
        }
        validate_operator_capacity(&operator)?;
        Ok(Self {
            inner: Arc::new(TransportInner {
                configuration: Some(TransportConfiguration {
                    constraints,
                    operator,
                }),
                journal: Mutex::new(Journal::default()),
                credentials: Mutex::new(BTreeMap::new()),
                #[cfg(test)]
                pause_before_dispatch: AtomicBool::new(false),
            }),
        })
    }

    pub(crate) fn install_credential(
        &self,
        handle: &str,
        secret: Vec<u8>,
    ) -> Result<(), TransportFailure> {
        if handle.is_empty()
            || handle.len() > 256
            || !handle.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(TransportFailure::new(
                "invalid-credential",
                "credential handle is not exact nonempty ASCII",
            ));
        }
        if !(MIN_CREDENTIAL_BYTES..=MAX_CREDENTIAL_BYTES).contains(&secret.len())
            || !secret.iter().all(|byte| (0x21..=0x7e).contains(byte))
        {
            return Err(TransportFailure::new(
                "invalid-credential",
                "credential bytes are not bounded header-safe bytes",
            ));
        }
        let known = self
            .inner
            .configuration
            .as_ref()
            .is_some_and(|configuration| {
                configuration
                    .operator
                    .credential_handles
                    .contains(&handle.to_string())
                    && configuration.constraints.values().any(|constraints| {
                        constraints
                            .credential_bindings
                            .iter()
                            .any(|binding| binding.handle == handle)
                    })
            });
        if !known {
            return Err(TransportFailure::new(
                "credential-not-authorized",
                "credential handle is not declared by signed constraints",
            ));
        }
        self.inner
            .credentials
            .lock()
            .expect("credential vault lock poisoned")
            .insert(handle.to_string(), Arc::from(secret));
        Ok(())
    }

    pub(crate) fn start(
        &self,
        owner: TransportOwner,
        request: TransportRequest,
    ) -> Result<String, TransportFailure> {
        let validated = self.validate(owner, request)?;
        let replay_identity = ReplayIdentity {
            owner: validated.owner.clone(),
            idempotency_key: validated.request.idempotency_key,
        };
        let operation_id = format!(
            "http-{}",
            Digest::of(
                &canonical_json(&OperationIdentity {
                    schema: "wasm-biotic.http-operation-identity.v1",
                    owner: &validated.owner,
                    idempotency_key: validated.request.idempotency_key,
                })
                .map_err(|_| {
                    TransportFailure::new("invalid-request", "request identity is not canonical")
                })?
            )
            .hex()
        );

        {
            let mut journal = self
                .inner
                .journal
                .lock()
                .expect("HTTP journal lock poisoned");
            if let Some(existing_id) = journal.replay.get(&replay_identity) {
                let existing = journal
                    .operations
                    .get(existing_id)
                    .expect("HTTP replay index is closed");
                if existing.request_digest != validated.request_digest {
                    return Err(TransportFailure::new(
                        "idempotency-conflict",
                        "HTTP idempotency identity was reused with different request bytes",
                    ));
                }
                return Ok(existing_id.clone());
            }
            let in_flight = journal
                .operations
                .values()
                .filter(|record| {
                    record.owner.constraints == validated.owner.constraints
                        && matches!(
                            record.phase,
                            OperationPhase::Prepared | OperationPhase::Dispatching
                        )
                })
                .count();
            if in_flight
                >= validated
                    .constraints
                    .max_concurrency
                    .min(validated.operator.max_concurrency) as usize
            {
                return Err(TransportFailure::new(
                    "concurrency-exhausted",
                    "HTTP constraint concurrency bound is exhausted",
                ));
            }
            if journal.operations.contains_key(&operation_id) {
                return Err(TransportFailure::new(
                    "digest-collision",
                    "HTTP operation identity collided with another journal entry",
                ));
            }
            journal.replay.insert(replay_identity, operation_id.clone());
            journal.operations.insert(
                operation_id.clone(),
                OperationRecord {
                    owner: validated.owner.clone(),
                    request_digest: validated.request_digest,
                    phase: OperationPhase::Prepared,
                    result: None,
                },
            );
        }

        let inner = self.inner.clone();
        let worker_operation_id = operation_id.clone();
        thread::spawn(move || dispatch_one(inner, worker_operation_id, validated));
        Ok(operation_id)
    }

    pub(crate) fn poll(
        &self,
        owner: &TransportOwner,
        operation_id: &str,
    ) -> Result<TransportPoll, TransportFailure> {
        let journal = self
            .inner
            .journal
            .lock()
            .expect("HTTP journal lock poisoned");
        let record = journal
            .operations
            .get(operation_id)
            .ok_or_else(|| TransportFailure::new("not-found", "HTTP operation does not exist"))?;
        if &record.owner != owner {
            return Err(TransportFailure::new(
                "not-owned",
                "HTTP operation belongs to another graph principal and alias",
            ));
        }
        Ok(record.result.clone().unwrap_or(TransportPoll::Pending))
    }

    pub(crate) fn cancel(
        &self,
        owner: &TransportOwner,
        operation_id: &str,
    ) -> Result<bool, TransportFailure> {
        let mut journal = self
            .inner
            .journal
            .lock()
            .expect("HTTP journal lock poisoned");
        let record = journal
            .operations
            .get_mut(operation_id)
            .ok_or_else(|| TransportFailure::new("not-found", "HTTP operation does not exist"))?;
        if &record.owner != owner {
            return Err(TransportFailure::new(
                "not-owned",
                "HTTP operation belongs to another graph principal and alias",
            ));
        }
        if record.phase == OperationPhase::Prepared {
            record.phase = OperationPhase::CancelledBeforeDispatch;
            record.result = Some(TransportPoll::CancelledBeforeDispatch);
            return Ok(true);
        }
        Ok(false)
    }

    /// Reconstruct the only safe post-crash interpretation of an operation
    /// whose durable journal reached `Dispatching` without a terminal record.
    pub(crate) fn recover_dispatching_as_indeterminate(&self) {
        let mut journal = self
            .inner
            .journal
            .lock()
            .expect("HTTP journal lock poisoned");
        for record in journal.operations.values_mut() {
            if record.phase == OperationPhase::Dispatching {
                record.phase = OperationPhase::Indeterminate;
                record.result = Some(TransportPoll::Indeterminate(TransportFailure::new(
                    "transport-outcome-unknown",
                    "HTTP dispatch may have occurred and will not be resent automatically",
                )));
            }
        }
    }

    fn validate(
        &self,
        owner: TransportOwner,
        request: TransportRequest,
    ) -> Result<ValidatedRequest, TransportFailure> {
        let configuration = self.inner.configuration.as_ref().ok_or_else(|| {
            TransportFailure::new(
                "transport-unavailable",
                "bounded external HTTP is disabled for this profile",
            )
        })?;
        let constraints = configuration
            .constraints
            .get(&owner.constraints)
            .ok_or_else(|| {
                TransportFailure::new(
                    "constraint-mismatch",
                    "active alias does not bind admitted HTTP constraints",
                )
            })?
            .clone();
        let operator = configuration.operator.clone();
        if request.request_id.trim().is_empty() || request.request_id != request.request_id.trim() {
            return Err(TransportFailure::new(
                "invalid-request",
                "HTTP request id is blank or noncanonical",
            ));
        }
        if request.url.len() as u64 > constraints.max_url_bytes.min(operator.max_url_bytes)
            || !request.url.is_ascii()
        {
            return Err(TransportFailure::new(
                "limit-exceeded",
                "HTTP URL exceeds its byte bound or is not ASCII",
            ));
        }
        if !constraints.methods.contains(&request.method)
            || !operator.allowed_methods.contains(&request.method)
        {
            return Err(TransportFailure::new(
                "method-not-authorized",
                "HTTP method is outside signed constraints",
            ));
        }
        if request.timeout_ms == 0
            || request.timeout_ms > constraints.max_timeout_ms.min(operator.max_timeout_ms)
        {
            return Err(TransportFailure::new(
                "limit-exceeded",
                "HTTP timeout is outside signed bounds",
            ));
        }
        if request.body.as_ref().is_some_and(|body| {
            body.len() as u64
                > constraints
                    .max_request_body_bytes
                    .min(operator.max_request_body_bytes)
        }) {
            return Err(TransportFailure::new(
                "limit-exceeded",
                "HTTP request body exceeds signed bounds",
            ));
        }
        validate_request_headers(&request.headers, &constraints, &operator)?;

        let parsed = Url::parse(&request.url).map_err(|_| {
            TransportFailure::new("invalid-url", "HTTP URL is not an absolute canonical URL")
        })?;
        if parsed.as_str() != request.url
            || parsed.scheme() != "https"
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
            || request.url.contains('\\')
            || !is_safe_request_path(parsed.path())
        {
            return Err(TransportFailure::new(
                "invalid-url",
                "HTTP URL is not exact canonical HTTPS",
            ));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| TransportFailure::new("invalid-url", "HTTP URL has no host"))?;
        let port = parsed
            .port_or_known_default()
            .expect("HTTPS has a known port");
        let origin = constraints
            .origins
            .iter()
            .find(|origin| {
                origin.scheme == parsed.scheme()
                    && origin.host == host
                    && origin.port == port
                    && origin
                        .path_prefixes
                        .iter()
                        .any(|prefix| path_matches(parsed.path(), prefix))
            })
            .cloned()
            .ok_or_else(|| {
                TransportFailure::new(
                    "origin-not-authorized",
                    "HTTP destination is outside signed origins and paths",
                )
            })?;
        if !operator.allowed_origins.contains(&origin_key(
            &origin.scheme,
            &origin.host,
            origin.port,
        )) {
            return Err(TransportFailure::new(
                "origin-not-authorized",
                "HTTP destination is outside operator capacity",
            ));
        }

        let credential = if let Some(handle) = request.credential_handle.as_deref() {
            let binding = constraints
                .credential_bindings
                .iter()
                .find(|binding| binding.handle == handle && binding.origin_id == origin.id)
                .ok_or_else(|| {
                    TransportFailure::new(
                        "credential-not-authorized",
                        "credential handle is not authorized for this origin",
                    )
                })?;
            if !operator
                .credential_handles
                .iter()
                .any(|value| value == handle)
            {
                return Err(TransportFailure::new(
                    "credential-not-authorized",
                    "credential handle is outside operator capacity",
                ));
            }
            let matching = request
                .headers
                .iter()
                .filter(|header| header.name == binding.header_name)
                .collect::<Vec<_>>();
            if matching.len() != 1 || matching[0].value != binding.value_prefix.as_bytes() {
                return Err(TransportFailure::new(
                    "credential-prefix-mismatch",
                    "component did not supply the exact signed credential prefix",
                ));
            }
            Some(
                self.inner
                    .credentials
                    .lock()
                    .expect("credential vault lock poisoned")
                    .get(handle)
                    .cloned()
                    .ok_or_else(|| {
                        TransportFailure::new(
                            "credential-unavailable",
                            "authorized credential handle is not available",
                        )
                    })?,
            )
        } else {
            if constraints.credential_bindings.iter().any(|binding| {
                request
                    .headers
                    .iter()
                    .any(|header| header.name == binding.header_name)
            }) {
                return Err(TransportFailure::new(
                    "credential-handle-required",
                    "credential-owned HTTP header requires its opaque handle",
                ));
            }
            None
        };

        let request_digest = Digest::of(&canonical_json(&request).map_err(|_| {
            TransportFailure::new("invalid-request", "HTTP request is not canonical")
        })?);
        Ok(ValidatedRequest {
            owner,
            request,
            request_digest,
            constraints,
            operator,
            origin,
            credential,
        })
    }

    #[cfg(test)]
    fn pause_dispatch(&self, paused: bool) {
        self.inner
            .pause_before_dispatch
            .store(paused, Ordering::SeqCst);
    }
}

fn is_safe_request_path(path: &str) -> bool {
    path.is_ascii()
        && path.starts_with('/')
        && path.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !path.contains(['\\', '%'])
        && !path.contains("//")
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

fn path_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || path.strip_prefix(prefix).is_some_and(|suffix| {
            prefix.ends_with('/') || suffix.starts_with('/') || suffix.is_empty()
        })
}

fn validate_operator_capacity(operator: &HttpOperatorCapacity) -> Result<(), TransportFailure> {
    if !operator.enabled
        || operator.max_url_bytes == 0
        || operator.max_request_body_bytes == 0
        || operator.max_response_body_bytes == 0
        || operator.max_request_header_count == 0
        || operator.max_request_header_bytes == 0
        || operator.max_response_header_count == 0
        || operator.max_response_header_bytes == 0
        || operator.max_timeout_ms == 0
        || operator.max_concurrency == 0
    {
        return Err(TransportFailure::new(
            "operator-capacity-invalid",
            "enabled HTTP operator capacity contains a zero or disabled bound",
        ));
    }
    if operator.allowed_origins.is_empty()
        || operator.allowed_methods.is_empty()
        || operator.allowed_cidrs.is_empty()
        || !is_sorted_unique(&operator.allowed_origins)
        || !is_sorted_unique(&operator.allowed_methods)
        || !is_sorted_unique(&operator.allowed_request_headers)
        || !is_sorted_unique(&operator.allowed_response_headers)
        || !is_sorted_unique(&operator.allowed_cidrs)
        || !is_sorted_unique(&operator.credential_handles)
    {
        return Err(TransportFailure::new(
            "operator-capacity-invalid",
            "HTTP operator capacity sets must be nonempty where required, sorted and unique",
        ));
    }
    if operator
        .allowed_origins
        .iter()
        .any(|origin| !is_canonical_operator_origin(origin))
        || operator.allowed_methods.iter().any(|method| {
            !matches!(
                method.as_str(),
                "delete" | "get" | "head" | "patch" | "post" | "put"
            )
        })
        || operator
            .allowed_request_headers
            .iter()
            .chain(&operator.allowed_response_headers)
            .any(|name| {
                name.is_empty()
                    || name != &name.to_ascii_lowercase()
                    || HeaderName::from_bytes(name.as_bytes()).is_err()
            })
        || operator.allowed_cidrs.iter().any(|cidr| {
            cidr.parse::<IpNet>()
                .map_or(true, |parsed| parsed.to_string() != *cidr)
        })
        || operator.credential_handles.iter().any(|handle| {
            handle.is_empty()
                || handle.len() > 256
                || !handle
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
    {
        return Err(TransportFailure::new(
            "operator-capacity-invalid",
            "HTTP operator capacity contains noncanonical authority",
        ));
    }
    Ok(())
}

fn is_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn origin_key(scheme: &str, host: &str, port: u16) -> String {
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("{scheme}://{host}:{port}")
}

fn is_canonical_operator_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@', '\\'])
        || !authority.is_ascii()
    {
        return false;
    }
    let (host, port_text) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, port)) = bracketed.split_once("]:") else {
            return false;
        };
        let Ok(ip) = host.parse::<Ipv6Addr>() else {
            return false;
        };
        if ip.to_string() != host {
            return false;
        }
        (host, port)
    } else {
        let Some((host, port)) = authority.rsplit_once(':') else {
            return false;
        };
        if host.is_empty() || host.contains(':') || host != host.to_ascii_lowercase() {
            return false;
        }
        let Ok(parsed) = Url::parse(&format!("https://{host}:8443/")) else {
            return false;
        };
        if parsed.host_str() != Some(host) {
            return false;
        }
        (host, port)
    };
    let Ok(port) = port_text.parse::<u16>() else {
        return false;
    };
    port != 0 && port_text == port.to_string() && value == origin_key("https", host, port)
}

fn validate_request_headers(
    headers: &[TransportHeader],
    constraints: &HttpTransportConstraints,
    operator: &HttpOperatorCapacity,
) -> Result<(), TransportFailure> {
    if headers.len()
        > constraints
            .request_headers
            .max_count
            .min(operator.max_request_header_count) as usize
    {
        return Err(TransportFailure::new(
            "limit-exceeded",
            "HTTP request header count exceeds signed bounds",
        ));
    }
    let mut total = 0_u64;
    let mut seen = BTreeSet::new();
    for header in headers {
        total = total
            .checked_add(header.name.len() as u64)
            .and_then(|value| value.checked_add(header.value.len() as u64))
            .ok_or_else(|| {
                TransportFailure::new("limit-exceeded", "HTTP request header bytes overflow")
            })?;
        if !seen.insert(header.name.as_str())
            || !constraints
                .request_headers
                .allowed_names
                .contains(&header.name)
            || !operator.allowed_request_headers.contains(&header.name)
            || HeaderName::from_bytes(header.name.as_bytes()).is_err()
            || HeaderValue::from_bytes(&header.value).is_err()
        {
            return Err(TransportFailure::new(
                "header-not-authorized",
                "HTTP request header is duplicate, invalid or outside signed constraints",
            ));
        }
    }
    if total
        > constraints
            .request_headers
            .max_total_bytes
            .min(operator.max_request_header_bytes)
    {
        return Err(TransportFailure::new(
            "limit-exceeded",
            "HTTP request header bytes exceed signed bounds",
        ));
    }
    Ok(())
}

fn dispatch_one(inner: Arc<TransportInner>, operation_id: String, request: ValidatedRequest) {
    #[cfg(test)]
    while inner.pause_before_dispatch.load(Ordering::SeqCst) {
        thread::yield_now();
    }
    {
        let mut journal = inner.journal.lock().expect("HTTP journal lock poisoned");
        let Some(record) = journal.operations.get_mut(&operation_id) else {
            return;
        };
        if record.phase != OperationPhase::Prepared {
            return;
        }
        // This transition is the durable point of no automatic return. Any
        // ambiguity after it resolves to Indeterminate, never a second send.
        record.phase = OperationPhase::Dispatching;
    }

    let started_at_ms = unix_ms();
    let addresses = match resolve_once(
        &request.origin,
        &request.operator,
        Duration::from_millis(request.request.timeout_ms),
    ) {
        Ok(addresses) => addresses,
        Err(failure) => {
            finish(
                &inner,
                &operation_id,
                OperationPhase::DefiniteFailure,
                TransportPoll::DefiniteFailure(failure),
            );
            return;
        }
    };
    let credential = request.credential.clone();
    let client = match build_client(&request.origin, &addresses, request.request.timeout_ms) {
        Ok(client) => client,
        Err(failure) => {
            finish(
                &inner,
                &operation_id,
                OperationPhase::DefiniteFailure,
                TransportPoll::DefiniteFailure(failure),
            );
            return;
        }
    };
    let outgoing = match build_outgoing_request(&client, &request, credential.as_deref()) {
        Ok(outgoing) => outgoing,
        Err(failure) => {
            finish(
                &inner,
                &operation_id,
                OperationPhase::DefiniteFailure,
                TransportPoll::DefiniteFailure(failure),
            );
            return;
        }
    };

    // From this call forward reqwest cannot prove whether zero request bytes
    // reached the peer. Every error therefore closes as Indeterminate.
    let response = match outgoing.send() {
        Ok(response) => response,
        Err(_) => {
            finish_unknown(&inner, &operation_id);
            return;
        }
    };
    let raw = match bounded_response(
        response,
        &request.constraints,
        &request.operator,
        credential.as_deref(),
    ) {
        Ok(raw) => raw,
        Err(_) => {
            finish_unknown(&inner, &operation_id);
            return;
        }
    };
    let finished_at_ms = unix_ms().max(started_at_ms);
    let outcome_material = (
        raw.status,
        &raw.headers,
        raw.body.as_deref().map(Digest::of),
    );
    let outcome_digest = Digest::of(&canonical_json(&outcome_material).unwrap_or_default());
    let response = TransportResponse {
        status: raw.status,
        headers: raw.headers,
        body: raw.body,
        receipt: TransportReceipt {
            receipt_id: format!("http-receipt-{}", request.request.idempotency_key.hex()),
            request_digest: request.request_digest,
            executor_digest: Digest::of(b"wasm-biotic:independent-http-transport.v1"),
            started_at_ms,
            finished_at_ms,
            outcome_digest,
            audit_sequence: 0,
        },
    };
    finish(
        &inner,
        &operation_id,
        OperationPhase::Completed,
        TransportPoll::Completed(response),
    );
}

fn finish(
    inner: &TransportInner,
    operation_id: &str,
    phase: OperationPhase,
    result: TransportPoll,
) {
    let mut journal = inner.journal.lock().expect("HTTP journal lock poisoned");
    if let Some(record) = journal.operations.get_mut(operation_id)
        && record.phase == OperationPhase::Dispatching
    {
        record.phase = phase;
        record.result = Some(result);
    }
}

fn finish_unknown(inner: &TransportInner, operation_id: &str) {
    finish(
        inner,
        operation_id,
        OperationPhase::Indeterminate,
        TransportPoll::Indeterminate(TransportFailure::new(
            "transport-outcome-unknown",
            "HTTP dispatch may have occurred and will not be resent automatically",
        )),
    );
}

fn resolve_once(
    origin: &HttpOriginConstraint,
    operator: &HttpOperatorCapacity,
    timeout: Duration,
) -> Result<Vec<SocketAddr>, TransportFailure> {
    let addresses = if let Ok(ip) = origin.host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, origin.port)]
    } else {
        let host = origin.host.clone();
        let port = origin.port;
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("wasm-biotic-independent-http-dns".to_string())
            .spawn(move || {
                let result = (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|addresses| addresses.collect::<Vec<_>>());
                let _ = sender.send(result);
            })
            .map_err(|_| {
                TransportFailure::new("dns-failed", "HTTP DNS resolver could not be started")
            })?;
        receiver
            .recv_timeout(timeout)
            .map_err(|_| {
                TransportFailure::new("dns-failed", "HTTP DNS resolution exceeded its timeout")
            })?
            .map_err(|_| TransportFailure::new("dns-failed", "HTTP origin DNS resolution failed"))?
    };
    validate_resolved_addresses(origin, operator, addresses)
}

fn validate_resolved_addresses(
    origin: &HttpOriginConstraint,
    operator: &HttpOperatorCapacity,
    mut addresses: Vec<SocketAddr>,
) -> Result<Vec<SocketAddr>, TransportFailure> {
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| address.port() != origin.port)
    {
        return Err(TransportFailure::new(
            "dns-denied",
            "HTTP origin resolved to no exact-port address",
        ));
    }
    let cidrs = origin
        .dns
        .cidrs
        .iter()
        .map(|value| value.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| TransportFailure::new("constraint-invalid", "signed DNS CIDR is invalid"))?;
    let operator_cidrs = operator
        .allowed_cidrs
        .iter()
        .map(|value| value.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            TransportFailure::new("operator-capacity-invalid", "operator DNS CIDR is invalid")
        })?;
    let all_allowed = addresses
        .iter()
        .all(|address| match origin.dns.policy.as_str() {
            "public-only" => {
                is_public_ip(address.ip())
                    && operator_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(&address.ip()))
            }
            "exact-cidrs" => {
                cidrs.iter().any(|cidr| cidr.contains(&address.ip()))
                    && operator_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(&address.ip()))
            }
            _ => false,
        });
    if !all_allowed {
        return Err(TransportFailure::new(
            "dns-denied",
            "entire DNS answer set is not inside signed and operator address authority",
        ));
    }
    Ok(addresses)
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    ![
        ("0.0.0.0/8", 8),
        ("10.0.0.0/8", 8),
        ("100.64.0.0/10", 10),
        ("127.0.0.0/8", 8),
        ("169.254.0.0/16", 16),
        ("172.16.0.0/12", 12),
        ("192.0.0.0/24", 24),
        ("192.0.2.0/24", 24),
        ("192.88.99.0/24", 24),
        ("192.168.0.0/16", 16),
        ("198.18.0.0/15", 15),
        ("198.51.100.0/24", 24),
        ("203.0.113.0/24", 24),
        ("224.0.0.0/4", 4),
        ("240.0.0.0/4", 4),
    ]
    .iter()
    .any(|(network, prefix)| {
        let base = network
            .split('/')
            .next()
            .and_then(|text| text.parse::<Ipv4Addr>().ok())
            .map(u32::from)
            .unwrap_or_default();
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or_default();
        value & mask == base & mask
    })
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let octets = ip.octets();
    let value = u128::from(ip);
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || octets[0] & 0xfe == 0xfc
        || (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
        || (octets[0] == 0xfe && octets[1] & 0xc0 == 0xc0)
        || ipv6_prefix(value, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96)
        || ipv6_prefix(value, 0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48)
        || ipv6_prefix(value, 0x0100_0000_0000_0000_0000_0000_0000_0000, 64)
        || ipv6_prefix(value, 0x2001_0000_0000_0000_0000_0000_0000_0000, 23)
        || ipv6_prefix(value, 0x2001_0db8_0000_0000_0000_0000_0000_0000, 32)
        || ipv6_prefix(value, 0x2002_0000_0000_0000_0000_0000_0000_0000, 16)
        || ipv6_prefix(value, 0x3fff_0000_0000_0000_0000_0000_0000_0000, 20)
        || ipv6_prefix(value, 0x5f00_0000_0000_0000_0000_0000_0000_0000, 16))
}

fn ipv6_prefix(value: u128, network: u128, prefix: u32) -> bool {
    let mask = u128::MAX << (128 - prefix);
    value & mask == network & mask
}

fn build_client(
    origin: &HttpOriginConstraint,
    addresses: &[SocketAddr],
    timeout_ms: u64,
) -> Result<Client, TransportFailure> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = Arc::new(RootCertStore::from_iter(
        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
    ));
    let webpki = WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|_| {
            TransportFailure::new("tls-config-failed", "TLS verifier could not be configured")
        })?;
    let verifier = Arc::new(PinnedVerifier {
        delegate: webpki,
        pins: origin.tls.peer_spki_sha256.iter().copied().collect(),
    });
    let tls = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| TransportFailure::new("tls-config-failed", "TLS 1.3 could not be configured"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Client::builder()
        .use_preconfigured_tls(tls)
        .https_only(true)
        .http1_only()
        .default_headers(HeaderMap::new())
        .referer(false)
        .retry(reqwest::retry::never())
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_millis(timeout_ms))
        .connect_timeout(Duration::from_millis(timeout_ms))
        .resolve_to_addrs(&origin.host, &addresses[..1])
        .build()
        .map_err(|_| {
            TransportFailure::new(
                "transport-config-failed",
                "bounded HTTP client could not be configured",
            )
        })
}

fn build_outgoing_request(
    client: &Client,
    validated: &ValidatedRequest,
    credential: Option<&[u8]>,
) -> Result<reqwest::blocking::RequestBuilder, TransportFailure> {
    let method =
        reqwest::Method::from_bytes(validated.request.method.as_bytes()).map_err(|_| {
            TransportFailure::new("invalid-method", "HTTP method could not be represented")
        })?;
    let mut headers = HeaderMap::new();
    let credential_binding = validated
        .request
        .credential_handle
        .as_deref()
        .and_then(|handle| {
            validated
                .constraints
                .credential_bindings
                .iter()
                .find(|binding| {
                    binding.handle == handle && binding.origin_id == validated.origin.id
                })
        });
    let mut total_bytes = 0_u64;
    for header in &validated.request.headers {
        let mut value = header.value.clone();
        if credential_binding.is_some_and(|binding| binding.header_name == header.name) {
            value.extend_from_slice(credential.ok_or_else(|| {
                TransportFailure::new("credential-unavailable", "credential bytes are unavailable")
            })?);
        }
        total_bytes = total_bytes
            .checked_add(header.name.len() as u64)
            .and_then(|size| size.checked_add(value.len() as u64))
            .ok_or_else(|| {
                TransportFailure::new(
                    "limit-exceeded",
                    "credential-expanded HTTP headers overflow their byte bound",
                )
            })?;
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| TransportFailure::new("invalid-header", "HTTP header name is invalid"))?;
        let value = HeaderValue::from_bytes(&value)
            .map_err(|_| TransportFailure::new("invalid-header", "HTTP header value is invalid"))?;
        headers.insert(name, value);
    }
    if total_bytes
        > validated
            .constraints
            .request_headers
            .max_total_bytes
            .min(validated.operator.max_request_header_bytes)
    {
        return Err(TransportFailure::new(
            "limit-exceeded",
            "credential-expanded HTTP headers exceed their signed byte bound",
        ));
    }
    let mut outgoing = client
        .request(method, &validated.request.url)
        .headers(headers);
    if let Some(body) = &validated.request.body {
        outgoing = outgoing.body(body.clone());
    }
    Ok(outgoing)
}

struct RawResponse {
    status: u16,
    headers: Vec<TransportHeader>,
    body: Option<Vec<u8>>,
}

fn bounded_response(
    response: Response,
    constraints: &HttpTransportConstraints,
    operator: &HttpOperatorCapacity,
    credential: Option<&[u8]>,
) -> Result<RawResponse, TransportFailure> {
    let status = response.status().as_u16();
    let mut total = 0_u64;
    let count = response.headers().iter().count();
    if count
        > constraints
            .response_headers
            .max_count
            .min(operator.max_response_header_count) as usize
    {
        return Err(TransportFailure::new(
            "response-limit-exceeded",
            "HTTP response header count exceeds signed bounds",
        ));
    }
    let mut exposed = Vec::new();
    for (name, value) in response.headers() {
        total = total
            .checked_add(name.as_str().len() as u64)
            .and_then(|size| size.checked_add(value.as_bytes().len() as u64))
            .ok_or_else(|| {
                TransportFailure::new(
                    "response-limit-exceeded",
                    "HTTP response header bytes overflow",
                )
            })?;
        if credential.is_some_and(|secret| {
            contains_bytes(name.as_str().as_bytes(), secret)
                || contains_bytes(value.as_bytes(), secret)
        }) {
            return Err(TransportFailure::new(
                "credential-reflection",
                "HTTP peer reflected credential bytes",
            ));
        }
        if constraints
            .response_headers
            .exposed_names
            .iter()
            .any(|allowed| allowed == name.as_str())
            && operator
                .allowed_response_headers
                .iter()
                .any(|allowed| allowed == name.as_str())
        {
            exposed.push(TransportHeader {
                name: name.as_str().to_string(),
                value: value.as_bytes().to_vec(),
            });
        }
    }
    if total
        > constraints
            .response_headers
            .max_total_bytes
            .min(operator.max_response_header_bytes)
    {
        return Err(TransportFailure::new(
            "response-limit-exceeded",
            "HTTP response header bytes exceed signed bounds",
        ));
    }
    let max = constraints
        .max_response_body_bytes
        .min(operator.max_response_body_bytes);
    let mut body = Vec::new();
    response
        .take(max.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(|_| {
            TransportFailure::new(
                "response-read-failed",
                "HTTP response body could not be read within bounds",
            )
        })?;
    if body.len() as u64 > max {
        return Err(TransportFailure::new(
            "response-limit-exceeded",
            "HTTP response body exceeds signed bounds",
        ));
    }
    if credential.is_some_and(|secret| contains_bytes(&body, secret)) {
        return Err(TransportFailure::new(
            "credential-reflection",
            "HTTP peer reflected credential bytes",
        ));
    }
    Ok(RawResponse {
        status,
        headers: exposed,
        // The WIT body is optional: zero response bytes are `none`; every
        // nonempty opaque byte sequence is returned through a blob reference.
        body: optional_response_body(body),
    })
}

fn optional_response_body(body: Vec<u8>) -> Option<Vec<u8>> {
    (!body.is_empty()).then_some(body)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[derive(Debug)]
struct PinnedVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    pins: BTreeSet<Digest>,
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let spki = certificate_spki_der(end_entity.as_ref())
            .ok_or_else(|| rustls::Error::General("peer certificate SPKI is malformed".into()))?;
        if !self.pins.contains(&Digest::of(spki)) {
            return Err(rustls::Error::General(
                "peer certificate SPKI is outside signed pins".into(),
            ));
        }
        self.delegate
            .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate
            .verify_tls12_signature(message, certificate, signed)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signed: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate
            .verify_tls13_signature(message, certificate, signed)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

fn certificate_spki_der(certificate: &[u8]) -> Option<&[u8]> {
    let outer = der_tlv(certificate, 0)?;
    if outer.tag != 0x30 || outer.end != certificate.len() {
        return None;
    }
    let tbs = der_tlv(certificate, outer.content_start)?;
    if tbs.tag != 0x30 {
        return None;
    }
    let mut cursor = tbs.content_start;
    let first = der_tlv(certificate, cursor)?;
    if first.tag == 0xa0 {
        cursor = first.end;
    }
    // serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    for index in 0..6 {
        let field = der_tlv(certificate, cursor)?;
        if field.end > tbs.end {
            return None;
        }
        if index == 5 {
            return (field.tag == 0x30).then_some(&certificate[field.start..field.end]);
        }
        cursor = field.end;
    }
    None
}

struct DerTlv {
    tag: u8,
    start: usize,
    content_start: usize,
    end: usize,
}

fn der_tlv(bytes: &[u8], start: usize) -> Option<DerTlv> {
    let tag = *bytes.get(start)?;
    let first_length = *bytes.get(start.checked_add(1)?)?;
    let (length, content_start) = if first_length & 0x80 == 0 {
        (usize::from(first_length), start.checked_add(2)?)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return None;
        }
        let length_start = start.checked_add(2)?;
        if *bytes.get(length_start)? == 0 {
            return None;
        }
        let mut length = 0_usize;
        for byte in bytes.get(length_start..length_start.checked_add(count)?)? {
            length = length.checked_mul(256)?.checked_add(usize::from(*byte))?;
        }
        if length < 128 {
            return None;
        }
        (length, length_start.checked_add(count)?)
    };
    Some(DerTlv {
        tag,
        start,
        content_start,
        end: content_start
            .checked_add(length)
            .filter(|end| *end <= bytes.len())?,
    })
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

impl fmt::Debug for TransportRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TransportRuntime")
            .field("enabled", &self.inner.configuration.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        HttpCredentialBinding, HttpDnsConstraint, HttpOperatorCapacity, HttpTlsConstraint,
        RequestHeaderConstraints, ResponseHeaderConstraints,
    };

    fn origin(policy: &str, cidrs: &[&str]) -> HttpOriginConstraint {
        HttpOriginConstraint {
            id: "exchange".to_string(),
            scheme: "https".to_string(),
            host: "example.com".to_string(),
            port: 443,
            path_prefixes: vec!["/v1/".to_string()],
            dns: HttpDnsConstraint {
                policy: policy.to_string(),
                cidrs: cidrs.iter().map(|value| (*value).to_string()).collect(),
            },
            tls: HttpTlsConstraint {
                minimum_version: "tls-1.3".to_string(),
                server_name: "example.com".to_string(),
                peer_spki_sha256: vec![Digest::of(b"pin")],
            },
        }
    }

    fn constraints() -> HttpTransportConstraints {
        let mut bounded_origin = origin("exact-cidrs", &["198.51.100.0/24"]);
        bounded_origin.host = "192.0.2.1".to_string();
        bounded_origin.tls.server_name = "192.0.2.1".to_string();
        HttpTransportConstraints {
            schema: "wasm-biotic.http-transport-constraints.v1".to_string(),
            origins: vec![bounded_origin],
            methods: vec!["post".to_string()],
            request_headers: RequestHeaderConstraints {
                allowed_names: vec!["authorization".to_string(), "content-type".to_string()],
                max_count: 2,
                max_total_bytes: 256,
            },
            response_headers: ResponseHeaderConstraints {
                exposed_names: vec!["content-type".to_string()],
                max_count: 32,
                max_total_bytes: 4096,
            },
            max_url_bytes: 1024,
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            max_timeout_ms: 1000,
            max_concurrency: 1,
            redirects: "deny".to_string(),
            credential_bindings: vec![HttpCredentialBinding {
                handle: "exchange-api".to_string(),
                origin_id: "exchange".to_string(),
                header_name: "authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                placement: "append-to-header-value".to_string(),
            }],
        }
    }

    fn capacity() -> HttpOperatorCapacity {
        HttpOperatorCapacity {
            enabled: true,
            allowed_origins: vec!["https://192.0.2.1:443".to_string()],
            allowed_methods: vec!["post".to_string()],
            allowed_request_headers: vec!["authorization".to_string(), "content-type".to_string()],
            allowed_response_headers: vec!["content-type".to_string()],
            allowed_cidrs: vec!["198.51.100.0/24".to_string()],
            credential_handles: vec!["exchange-api".to_string()],
            max_url_bytes: 1024,
            max_request_body_bytes: 1024,
            max_response_body_bytes: 1024,
            max_request_header_count: 2,
            max_request_header_bytes: 256,
            max_response_header_count: 32,
            max_response_header_bytes: 4096,
            max_timeout_ms: 1000,
            max_concurrency: 1,
        }
    }

    fn owner(digest: Digest) -> TransportOwner {
        TransportOwner {
            graph_manifest_digest: Digest::of(b"graph"),
            authority_component_digest: Digest::of(b"authority"),
            principal_seed: Digest::of(b"principal"),
            consumer: "exchange-service".to_string(),
            alias: "signed-http-alias".to_string(),
            constraints: digest,
        }
    }

    fn request() -> TransportRequest {
        TransportRequest {
            request_id: "request-1".to_string(),
            method: "post".to_string(),
            url: "https://192.0.2.1/v1/messages".to_string(),
            headers: vec![
                TransportHeader {
                    name: "authorization".to_string(),
                    value: b"Bearer ".to_vec(),
                },
                TransportHeader {
                    name: "content-type".to_string(),
                    value: b"application/json".to_vec(),
                },
            ],
            body: Some(b"{}".to_vec()),
            timeout_ms: 100,
            idempotency_key: Digest::of(b"request-1"),
            credential_handle: Some("exchange-api".to_string()),
        }
    }

    fn runtime_with_capacity(operator: HttpOperatorCapacity) -> (TransportRuntime, Digest) {
        let constraints = constraints();
        let digest = Digest::of(&canonical_json(&constraints).unwrap());
        (
            TransportRuntime::new_with_operator(
                PROFILE_V3,
                BTreeMap::from([(digest, constraints)]),
                operator,
            )
            .unwrap(),
            digest,
        )
    }

    #[test]
    fn operator_capacity_is_explicit_closed_and_intersected_with_signed_authority() {
        let constraints = constraints();
        let digest = Digest::of(&canonical_json(&constraints).unwrap());
        let disabled =
            TransportRuntime::new(PROFILE_V3, BTreeMap::from([(digest, constraints.clone())]));
        assert_eq!(
            disabled.start(owner(digest), request()).unwrap_err().code,
            "transport-unavailable"
        );

        let mut malformed = capacity();
        malformed.enabled = false;
        assert_eq!(
            TransportRuntime::new_with_operator(
                PROFILE_V3,
                BTreeMap::from([(digest, constraints.clone())]),
                malformed,
            )
            .unwrap_err()
            .code,
            "operator-capacity-invalid"
        );

        let mut narrow_method = capacity();
        narrow_method.allowed_methods = vec!["get".to_string()];
        let (runtime, digest) = runtime_with_capacity(narrow_method);
        assert_eq!(
            runtime.start(owner(digest), request()).unwrap_err().code,
            "method-not-authorized"
        );

        let mut narrow_headers = capacity();
        narrow_headers.allowed_request_headers = vec!["authorization".to_string()];
        let (runtime, digest) = runtime_with_capacity(narrow_headers);
        assert_eq!(
            runtime.start(owner(digest), request()).unwrap_err().code,
            "header-not-authorized"
        );

        let mut narrow_bytes = capacity();
        narrow_bytes.max_request_body_bytes = 1;
        let (runtime, digest) = runtime_with_capacity(narrow_bytes);
        assert_eq!(
            runtime.start(owner(digest), request()).unwrap_err().code,
            "limit-exceeded"
        );

        let mut no_credentials = capacity();
        no_credentials.credential_handles.clear();
        let (runtime, digest) = runtime_with_capacity(no_credentials);
        assert_eq!(
            runtime
                .install_credential("exchange-api", b"0123456789abcdef".to_vec())
                .unwrap_err()
                .code,
            "credential-not-authorized"
        );
        assert_eq!(
            runtime.start(owner(digest), request()).unwrap_err().code,
            "credential-not-authorized"
        );

        let mut overbroad = capacity();
        overbroad.allowed_methods = vec!["get".to_string(), "post".to_string()];
        overbroad.allowed_origins = vec![
            "https://192.0.2.1:443".to_string(),
            "https://203.0.113.7:443".to_string(),
        ];
        overbroad.allowed_request_headers = vec![
            "authorization".to_string(),
            "content-type".to_string(),
            "x-operator-extra".to_string(),
        ];
        let (runtime, digest) = runtime_with_capacity(overbroad);
        let mut signed_denies_method = request();
        signed_denies_method.method = "get".to_string();
        assert_eq!(
            runtime
                .start(owner(digest), signed_denies_method)
                .unwrap_err()
                .code,
            "method-not-authorized"
        );
        let mut signed_denies_origin = request();
        signed_denies_origin.url = "https://203.0.113.7/v1/messages".to_string();
        assert_eq!(
            runtime
                .start(owner(digest), signed_denies_origin)
                .unwrap_err()
                .code,
            "origin-not-authorized"
        );
        let mut signed_denies_header = request();
        signed_denies_header.headers[1] = TransportHeader {
            name: "x-operator-extra".to_string(),
            value: b"permitted-locally-only".to_vec(),
        };
        assert_eq!(
            runtime
                .start(owner(digest), signed_denies_header)
                .unwrap_err()
                .code,
            "header-not-authorized"
        );
    }

    #[test]
    fn path_credential_and_response_representation_edge_cases_fail_closed() {
        assert!(path_matches("/api", "/api"));
        assert!(path_matches("/api/v1", "/api"));
        assert!(!path_matches("/apix", "/api"));
        assert!(optional_response_body(Vec::new()).is_none());
        assert_eq!(optional_response_body(vec![0]), Some(vec![0]));

        let (runtime, digest) = runtime_with_capacity(capacity());
        let mut request = request();
        request.credential_handle = None;
        assert_eq!(
            runtime.start(owner(digest), request).unwrap_err().code,
            "credential-handle-required"
        );
    }

    #[test]
    fn public_only_rejects_special_ipv6_ranges() {
        for address in [
            "::",
            "::1",
            "::ffff:127.0.0.1",
            "ff02::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "64:ff9b::1",
            "64:ff9b:1::1",
            "100::1",
            "2001::1",
            "2001:db8::1",
            "2002::1",
            "3fff::1",
            "5f00::1",
        ] {
            assert!(!is_public_ipv6(address.parse().unwrap()), "{address}");
        }
        assert!(is_public_ipv6("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn mixed_dns_answer_sets_fail_closed_and_exact_sets_are_sorted() {
        let public = origin("public-only", &[]);
        let mixed = validate_resolved_addresses(
            &public,
            &HttpOperatorCapacity {
                allowed_origins: vec!["https://example.com:443".to_string()],
                allowed_cidrs: vec!["0.0.0.0/0".to_string()],
                ..capacity()
            },
            vec![
                "93.184.216.34:443".parse().unwrap(),
                "127.0.0.1:443".parse().unwrap(),
            ],
        )
        .unwrap_err();
        assert_eq!(mixed.code, "dns-denied");

        let exact = origin("exact-cidrs", &["192.0.2.0/24"]);
        let addresses = validate_resolved_addresses(
            &exact,
            &HttpOperatorCapacity {
                allowed_origins: vec!["https://example.com:443".to_string()],
                allowed_cidrs: vec!["192.0.2.0/24".to_string()],
                ..capacity()
            },
            vec![
                "192.0.2.2:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.1:443".parse().unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(
            addresses,
            vec![
                "192.0.2.1:443".parse().unwrap(),
                "192.0.2.2:443".parse().unwrap()
            ]
        );

        let narrowed = validate_resolved_addresses(
            &exact,
            &HttpOperatorCapacity {
                allowed_origins: vec!["https://example.com:443".to_string()],
                allowed_cidrs: vec!["203.0.113.0/24".to_string()],
                ..capacity()
            },
            vec!["192.0.2.1:443".parse().unwrap()],
        )
        .unwrap_err();
        assert_eq!(narrowed.code, "dns-denied");
    }

    #[test]
    fn static_bounds_credentials_and_exact_replay_are_enforced_before_dispatch() {
        let constraints = constraints();
        let digest = Digest::of(&canonical_json(&constraints).unwrap());
        let runtime = TransportRuntime::new_with_operator(
            PROFILE_V3,
            BTreeMap::from([(digest, constraints)]),
            capacity(),
        )
        .unwrap();
        assert_eq!(
            runtime
                .install_credential("exchange-api", b"short".to_vec())
                .unwrap_err()
                .code,
            "invalid-credential"
        );
        runtime
            .install_credential("exchange-api", b"0123456789abcdef".to_vec())
            .unwrap();

        let owner = owner(digest);
        let mut invalid = request();
        invalid.url = "https://192.0.2.1:444/v1/messages".to_string();
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "origin-not-authorized"
        );
        let mut invalid = request();
        invalid.headers[0].value = b"bearer ".to_vec();
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "credential-prefix-mismatch"
        );
        let mut invalid = request();
        invalid.method = "get".to_string();
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "method-not-authorized"
        );
        let mut invalid = request();
        invalid.timeout_ms = 0;
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "limit-exceeded"
        );
        let mut invalid = request();
        invalid.body = Some(vec![0; 1_025]);
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "limit-exceeded"
        );
        let mut invalid = request();
        invalid.headers[1].name = "x-not-allowed".to_string();
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "header-not-authorized"
        );
        let mut invalid = request();
        invalid.url = "https://192.0.2.1/v1/%2e%2e/private".to_string();
        assert_eq!(
            runtime.start(owner.clone(), invalid).unwrap_err().code,
            "invalid-url"
        );
        let mut wrong_constraint = owner.clone();
        wrong_constraint.constraints = Digest::of(b"wrong-constraint");
        assert_eq!(
            runtime.start(wrong_constraint, request()).unwrap_err().code,
            "constraint-mismatch"
        );
        let disabled =
            TransportRuntime::new("wasm-biotic.factory-substrate-profile.v2", BTreeMap::new());
        assert_eq!(
            disabled.start(owner.clone(), request()).unwrap_err().code,
            "transport-unavailable"
        );

        // Use an exact-CIDR configuration pointed at documentation space so
        // the worker terminates before any socket dispatch. Replay identity
        // remains durable and exact in every terminal phase.
        let mut request = request();
        request.url = "https://192.0.2.1/v1/messages".to_string();
        let operation = runtime.start(owner.clone(), request.clone()).unwrap();
        assert_eq!(
            runtime.start(owner.clone(), request.clone()).unwrap(),
            operation
        );
        let terminal = (0..10_000).find_map(|_| match runtime.poll(&owner, &operation).unwrap() {
            TransportPoll::Pending => {
                thread::yield_now();
                None
            }
            result => Some(result),
        });
        assert!(matches!(
            terminal,
            Some(TransportPoll::DefiniteFailure(TransportFailure {
                code: "dns-denied",
                ..
            }))
        ));
        request.body = Some(b"different".to_vec());
        assert_eq!(
            runtime.start(owner, request).unwrap_err().code,
            "idempotency-conflict"
        );
    }

    #[test]
    fn concurrency_and_credential_expansion_are_bounded_before_send() {
        let constraints = constraints();
        let digest = Digest::of(&canonical_json(&constraints).unwrap());
        let runtime = TransportRuntime::new_with_operator(
            PROFILE_V3,
            BTreeMap::from([(digest, constraints.clone())]),
            capacity(),
        )
        .unwrap();
        runtime
            .install_credential("exchange-api", b"0123456789abcdef".to_vec())
            .unwrap();
        runtime.pause_dispatch(true);
        let owner = owner(digest);
        let first = runtime.start(owner.clone(), request()).unwrap();
        let mut second = request();
        second.request_id = "request-2".to_string();
        second.idempotency_key = Digest::of(b"request-2");
        assert_eq!(
            runtime.start(owner.clone(), second).unwrap_err().code,
            "concurrency-exhausted"
        );
        assert!(runtime.cancel(&owner, &first).unwrap());
        runtime.pause_dispatch(false);

        let mut tight = constraints;
        tight.request_headers.max_total_bytes = request()
            .headers
            .iter()
            .map(|header| header.name.len() + header.value.len())
            .sum::<usize>() as u64;
        let validated = ValidatedRequest {
            owner,
            request: request(),
            request_digest: Digest::of(b"request"),
            constraints: tight,
            operator: capacity(),
            origin: origin("public-only", &[]),
            credential: Some(Arc::from(b"0123456789abcdef".to_vec())),
        };
        assert_eq!(
            build_outgoing_request(
                &Client::builder().build().unwrap(),
                &validated,
                validated.credential.as_deref(),
            )
            .unwrap_err()
            .code,
            "limit-exceeded"
        );
    }

    #[test]
    fn cancellation_and_recovery_are_terminal_and_never_delete_identity() {
        let constraints = constraints();
        let digest = Digest::of(&canonical_json(&constraints).unwrap());
        let runtime = TransportRuntime::new_with_operator(
            PROFILE_V3,
            BTreeMap::from([(digest, constraints)]),
            capacity(),
        )
        .unwrap();
        runtime
            .install_credential("exchange-api", b"0123456789abcdef".to_vec())
            .unwrap();
        runtime.pause_dispatch(true);
        let owner = owner(digest);
        let request = request();
        let operation = runtime.start(owner.clone(), request.clone()).unwrap();
        assert!(runtime.cancel(&owner, &operation).unwrap());
        assert_eq!(
            runtime.poll(&owner, &operation).unwrap(),
            TransportPoll::CancelledBeforeDispatch
        );
        assert_eq!(runtime.start(owner, request).unwrap(), operation);
        runtime.pause_dispatch(false);
    }

    #[test]
    fn operation_ownership_and_dispatch_recovery_fail_closed() {
        let constraints = constraints();
        let digest = Digest::of(&canonical_json(&constraints).unwrap());
        let runtime = TransportRuntime::new_with_operator(
            PROFILE_V3,
            BTreeMap::from([(digest, constraints)]),
            capacity(),
        )
        .unwrap();
        runtime
            .install_credential("exchange-api", b"0123456789abcdef".to_vec())
            .unwrap();
        runtime.pause_dispatch(true);
        let owner = owner(digest);
        let operation = runtime.start(owner.clone(), request()).unwrap();
        let mut attacker = owner.clone();
        attacker.principal_seed = Digest::of(b"attacker");
        assert_eq!(
            runtime.poll(&attacker, &operation).unwrap_err().code,
            "not-owned"
        );
        assert_eq!(
            runtime.cancel(&attacker, &operation).unwrap_err().code,
            "not-owned"
        );

        {
            let mut journal = runtime.inner.journal.lock().unwrap();
            journal.operations.get_mut(&operation).unwrap().phase = OperationPhase::Dispatching;
        }
        runtime.recover_dispatching_as_indeterminate();
        assert!(matches!(
            runtime.poll(&owner, &operation).unwrap(),
            TransportPoll::Indeterminate(_)
        ));
        assert!(!runtime.cancel(&owner, &operation).unwrap());

        let mut completed_request = request();
        completed_request.request_id = "completed".to_string();
        completed_request.idempotency_key = Digest::of(b"completed");
        let completed_id = runtime
            .start(owner.clone(), completed_request.clone())
            .unwrap();
        {
            let mut journal = runtime.inner.journal.lock().unwrap();
            journal.operations.get_mut(&completed_id).unwrap().phase = OperationPhase::Dispatching;
        }
        let completed = TransportResponse {
            status: 307,
            headers: vec![TransportHeader {
                name: "content-type".to_string(),
                value: b"application/octet-stream".to_vec(),
            }],
            body: Some(b"raw".to_vec()),
            receipt: TransportReceipt {
                receipt_id: "receipt".to_string(),
                request_digest: Digest::of(&canonical_json(&completed_request).unwrap()),
                executor_digest: Digest::of(b"executor"),
                started_at_ms: 1,
                finished_at_ms: 2,
                outcome_digest: Digest::of(b"outcome"),
                audit_sequence: 0,
            },
        };
        finish(
            &runtime.inner,
            &completed_id,
            OperationPhase::Completed,
            TransportPoll::Completed(completed.clone()),
        );
        assert_eq!(
            runtime.poll(&owner, &completed_id).unwrap(),
            TransportPoll::Completed(completed)
        );
        runtime.pause_dispatch(false);
    }

    #[test]
    fn reflection_search_is_exact_and_der_reader_fails_closed() {
        assert!(contains_bytes(b"prefix-secret-suffix", b"secret"));
        assert!(!contains_bytes(b"prefix-secret-suffix", b"Secret"));
        assert!(certificate_spki_der(b"not-der").is_none());
        let certificate = [
            0x30, 0x17, 0x30, 0x10, 0x02, 0x01, 0x01, 0x30, 0x00, 0x30, 0x00, 0x30, 0x00, 0x30,
            0x00, 0x30, 0x03, 0x02, 0x01, 0x07, 0x30, 0x00, 0x03, 0x01, 0x00,
        ];
        assert_eq!(
            certificate_spki_der(&certificate),
            Some(&certificate[15..20][..])
        );
    }
}
