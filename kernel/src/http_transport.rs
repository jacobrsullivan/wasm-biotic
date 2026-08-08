//! Generic, policy-neutral enforcement for the bounded HTTP byte transport.

use crate::bindings::root::wasm_biotic::factory::http_transport;
use crate::{KernelError, Sha256Digest, canonical_json_bytes};
use http::header::{HeaderName, HeaderValue};
use ipnet::IpNet;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme, StreamOwned,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};
use url::Url;

pub(crate) const HTTP_CONSTRAINT_SCHEMA_V1: &str = "wasm-biotic.http-transport-constraints.v1";

const MAX_CREDENTIAL_BYTES: u64 = 16 * 1024;
const MAX_OPERATOR_TLS_ROOTS: usize = 64;
const MAX_OPERATOR_TLS_ROOT_BYTES: u64 = 64 * 1024;
const MAX_NATIVE_HEADER_COUNT: u32 = 256;
const MAX_NATIVE_HEADER_BYTES: u64 = 256 * 1024;
const MAX_HTTP_STATUS_LINE_BYTES: u64 = 1024;
const MAX_CHUNK_LINE_BYTES: usize = 128;
const MAX_NATIVE_DNS_RESOLUTIONS: usize = 32;
const MAX_NATIVE_HTTP_CONCURRENCY: u32 = 256;
const CREDENTIALS_DIRECTORY: &str = "credentials";
const TLS_ROOTS_DIRECTORY: &str = "tls-roots";
const FORBIDDEN_REQUEST_HEADERS: [&str; 10] = [
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
];

static ACTIVE_DNS_RESOLUTIONS: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpOperatorCapacity {
    pub(crate) enabled: bool,
    pub(crate) allowed_origins: Vec<String>,
    pub(crate) allowed_methods: Vec<String>,
    pub(crate) allowed_request_headers: Vec<String>,
    pub(crate) allowed_response_headers: Vec<String>,
    pub(crate) allowed_cidrs: Vec<String>,
    pub(crate) credential_handles: Vec<String>,
    pub(crate) max_url_bytes: u64,
    pub(crate) max_request_body_bytes: u64,
    pub(crate) max_response_body_bytes: u64,
    pub(crate) max_request_header_count: u32,
    pub(crate) max_request_header_bytes: u64,
    pub(crate) max_response_header_count: u32,
    pub(crate) max_response_header_bytes: u64,
    pub(crate) max_timeout_ms: u64,
    pub(crate) max_concurrency: u32,
}

impl HttpOperatorCapacity {
    pub(crate) fn validate(&self) -> Result<(), KernelError> {
        if !self.enabled
            || self.max_url_bytes == 0
            || self.max_request_body_bytes == 0
            || self.max_response_body_bytes == 0
            || self.max_request_header_count == 0
            || self.max_request_header_bytes == 0
            || self.max_response_header_count == 0
            || self.max_response_header_bytes == 0
            || self.max_timeout_ms == 0
            || self.max_concurrency == 0
        {
            return Err(invalid_config(
                "enabled HTTP operator capacity contains a zero or disabled bound",
            ));
        }
        if self.max_request_header_count > MAX_NATIVE_HEADER_COUNT
            || self.max_response_header_count > MAX_NATIVE_HEADER_COUNT
            || self.max_request_header_bytes > MAX_NATIVE_HEADER_BYTES
            || self.max_response_header_bytes > MAX_NATIVE_HEADER_BYTES
        {
            return Err(invalid_config(
                "HTTP operator header capacity exceeds the native parser bound",
            ));
        }
        if self.max_concurrency > MAX_NATIVE_HTTP_CONCURRENCY {
            return Err(invalid_config(
                "HTTP operator concurrency exceeds the native dispatch bound",
            ));
        }
        require_sorted_unique(&self.allowed_origins, "operator HTTP origins")?;
        require_sorted_unique(&self.allowed_methods, "operator HTTP methods")?;
        require_sorted_unique(
            &self.allowed_request_headers,
            "operator HTTP request headers",
        )?;
        require_sorted_unique(
            &self.allowed_response_headers,
            "operator HTTP response headers",
        )?;
        require_sorted_unique(&self.allowed_cidrs, "operator HTTP CIDRs")?;
        require_sorted_unique(&self.credential_handles, "operator HTTP credential handles")?;
        if self.allowed_origins.is_empty()
            || self.allowed_methods.is_empty()
            || self.allowed_cidrs.is_empty()
        {
            return Err(invalid_config(
                "enabled HTTP operator capacity must allow an exact origin, method, and CIDR",
            ));
        }
        for origin in &self.allowed_origins {
            parse_operator_origin(origin)?;
        }
        for method in &self.allowed_methods {
            validate_method(method)?;
        }
        for header in self
            .allowed_request_headers
            .iter()
            .chain(self.allowed_response_headers.iter())
        {
            validate_header_name(header)?;
        }
        if self.allowed_request_headers.iter().any(|name| {
            FORBIDDEN_REQUEST_HEADERS
                .binary_search(&name.as_str())
                .is_ok()
        }) {
            return Err(invalid_config(
                "operator HTTP request-header capacity contains a substrate-owned or hop-by-hop header",
            ));
        }
        for cidr in &self.allowed_cidrs {
            parse_canonical_cidr(cidr)?;
        }
        for handle in &self.credential_handles {
            validate_material_name(handle, "credential handle")?;
        }
        Ok(())
    }

    pub(crate) fn origin_allowed(&self, origin: &HttpOriginV1) -> bool {
        self.allowed_origins
            .binary_search(&origin_key(&origin.scheme, &origin.host, origin.port))
            .is_ok()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpTransportConstraintsV1 {
    pub(crate) schema: String,
    pub(crate) origins: Vec<HttpOriginV1>,
    pub(crate) methods: Vec<String>,
    pub(crate) request_headers: HttpRequestHeaderConstraintsV1,
    pub(crate) response_headers: HttpResponseHeaderConstraintsV1,
    pub(crate) max_url_bytes: u64,
    pub(crate) max_request_body_bytes: u64,
    pub(crate) max_response_body_bytes: u64,
    pub(crate) max_timeout_ms: u64,
    pub(crate) max_concurrency: u32,
    pub(crate) redirects: HttpRedirectPolicyV1,
    pub(crate) credential_bindings: Vec<HttpCredentialBindingV1>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpOriginV1 {
    pub(crate) id: String,
    pub(crate) scheme: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) path_prefixes: Vec<String>,
    pub(crate) dns: HttpDnsConstraintsV1,
    pub(crate) tls: HttpTlsConstraintsV1,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpDnsConstraintsV1 {
    pub(crate) policy: HttpDnsPolicyV1,
    pub(crate) cidrs: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HttpDnsPolicyV1 {
    PublicOnly,
    ExactCidrs,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpTlsConstraintsV1 {
    pub(crate) minimum_version: HttpTlsVersionV1,
    pub(crate) server_name: String,
    pub(crate) peer_spki_sha256: Vec<Sha256Digest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HttpTlsVersionV1 {
    #[serde(rename = "tls-1.3")]
    Tls13,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpRequestHeaderConstraintsV1 {
    pub(crate) allowed_names: Vec<String>,
    pub(crate) max_count: u32,
    pub(crate) max_total_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpResponseHeaderConstraintsV1 {
    pub(crate) exposed_names: Vec<String>,
    pub(crate) max_count: u32,
    pub(crate) max_total_bytes: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HttpRedirectPolicyV1 {
    Deny,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HttpCredentialBindingV1 {
    pub(crate) handle: String,
    pub(crate) origin_id: String,
    pub(crate) header_name: String,
    pub(crate) value_prefix: String,
    pub(crate) placement: HttpCredentialPlacementV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HttpCredentialPlacementV1 {
    AppendToHeaderValue,
}

#[derive(Clone)]
pub(crate) struct ValidatedRequest {
    pub(crate) url: Url,
    pub(crate) origin: HttpOriginV1,
    pub(crate) method: String,
    pub(crate) headers: Vec<(String, Vec<u8>)>,
    pub(crate) credential: Option<ValidatedCredential>,
    pub(crate) selected_address: SocketAddr,
    deadline: Instant,
}

#[derive(Clone)]
pub(crate) struct ValidatedCredential {
    pub(crate) handle: String,
    pub(crate) secret: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TransportFactsV1 {
    pub(crate) schema: String,
    pub(crate) canonical_url: String,
    pub(crate) origin_id: String,
    pub(crate) method: String,
    pub(crate) resolved_ip: String,
    pub(crate) tls_version: String,
    pub(crate) peer_certificate_sha256: Sha256Digest,
    pub(crate) peer_spki_sha256: Sha256Digest,
    pub(crate) status: u16,
    pub(crate) response_header_digest: Sha256Digest,
    pub(crate) response_header_bytes: u64,
    pub(crate) response_body_digest: Sha256Digest,
    pub(crate) response_body_bytes: u64,
    pub(crate) credential_handle_digest: Option<Sha256Digest>,
}

pub(crate) struct TransportSuccess {
    pub(crate) status: u16,
    pub(crate) headers: Vec<http_transport::Header>,
    pub(crate) body: Vec<u8>,
    pub(crate) facts: TransportFactsV1,
}

#[derive(Clone, Debug)]
pub(crate) struct TransportFailure {
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) dispatch_may_have_occurred: bool,
}

impl TransportFailure {
    fn new(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            dispatch_may_have_occurred: false,
        }
    }

    fn after_dispatch(code: &'static str, message: &'static str) -> Self {
        Self {
            code,
            message,
            dispatch_may_have_occurred: true,
        }
    }
}

pub(crate) fn parse_constraints(bytes: &[u8]) -> Result<HttpTransportConstraintsV1, KernelError> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| invalid_config(format!("HTTP constraint is not valid JSON: {error}")))?;
    let canonical = canonical_json_bytes(&value)?;
    if canonical != bytes {
        return Err(invalid_config("HTTP constraint is not canonical JSON"));
    }
    let constraints: HttpTransportConstraintsV1 =
        serde_json::from_value(value).map_err(|error| {
            invalid_config(format!(
                "HTTP constraint does not match its closed schema: {error}"
            ))
        })?;
    if canonical_json_bytes(&constraints)? != bytes {
        return Err(invalid_config(
            "HTTP constraint is not its canonical closed-schema representation",
        ));
    }
    validate_constraints(&constraints)?;
    Ok(constraints)
}

pub(crate) fn validate_constraints(
    constraints: &HttpTransportConstraintsV1,
) -> Result<(), KernelError> {
    if constraints.schema != HTTP_CONSTRAINT_SCHEMA_V1
        || constraints.origins.is_empty()
        || constraints.methods.is_empty()
        || constraints.max_url_bytes == 0
        || constraints.max_request_body_bytes == 0
        || constraints.max_response_body_bytes == 0
        || constraints.max_timeout_ms == 0
        || constraints.max_concurrency == 0
        || constraints.request_headers.max_count == 0
        || constraints.request_headers.max_total_bytes == 0
        || constraints.response_headers.max_count == 0
        || constraints.response_headers.max_total_bytes == 0
    {
        return Err(invalid_config(
            "HTTP constraint schema, collections, or numeric bounds are invalid",
        ));
    }
    if constraints
        .origins
        .windows(2)
        .any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(invalid_config("HTTP origins are not strictly sorted by id"));
    }
    require_sorted_unique(&constraints.methods, "HTTP methods")?;
    require_sorted_unique(
        &constraints.request_headers.allowed_names,
        "HTTP request header names",
    )?;
    require_sorted_unique(
        &constraints.response_headers.exposed_names,
        "HTTP response header names",
    )?;
    for method in &constraints.methods {
        validate_method(method)?;
    }
    for header in constraints
        .request_headers
        .allowed_names
        .iter()
        .chain(constraints.response_headers.exposed_names.iter())
    {
        validate_header_name(header)?;
    }
    if constraints
        .request_headers
        .allowed_names
        .iter()
        .any(|name| {
            FORBIDDEN_REQUEST_HEADERS
                .binary_search(&name.as_str())
                .is_ok()
        })
    {
        return Err(invalid_config(
            "HTTP request-header grant contains a substrate-owned or hop-by-hop header",
        ));
    }
    let mut origin_ids = BTreeSet::new();
    for origin in &constraints.origins {
        validate_material_name(&origin.id, "HTTP origin id")?;
        if !origin_ids.insert(origin.id.as_str())
            || origin.scheme != "https"
            || origin.port == 0
            || origin.host != origin.host.to_ascii_lowercase()
            || origin.host.ends_with('.')
            || origin.tls.server_name != origin.host
            || origin.tls.peer_spki_sha256.is_empty()
        {
            return Err(invalid_config(
                "HTTP origin is not an exact HTTPS/TLS1.3 origin with a signed SPKI pin",
            ));
        }
        validate_origin_host(&origin.host, origin.port)?;
        require_sorted_unique(&origin.path_prefixes, "HTTP path prefixes")?;
        if origin.path_prefixes.is_empty()
            || origin
                .path_prefixes
                .iter()
                .any(|prefix| !canonical_path_prefix(prefix))
        {
            return Err(invalid_config(
                "HTTP origin path prefixes must be nonempty absolute paths",
            ));
        }
        require_sorted_unique(&origin.dns.cidrs, "HTTP DNS CIDRs")?;
        match origin.dns.policy {
            HttpDnsPolicyV1::PublicOnly if !origin.dns.cidrs.is_empty() => {
                return Err(invalid_config(
                    "public-only HTTP DNS policy cannot contain CIDRs",
                ));
            }
            HttpDnsPolicyV1::ExactCidrs if origin.dns.cidrs.is_empty() => {
                return Err(invalid_config(
                    "exact-cidrs HTTP DNS policy requires at least one CIDR",
                ));
            }
            _ => {}
        }
        for cidr in &origin.dns.cidrs {
            if parse_canonical_cidr(cidr)?.prefix_len() == 0 {
                return Err(invalid_config("HTTP exact CIDR cannot be a zero prefix"));
            }
        }
        let mut pins = origin.tls.peer_spki_sha256.clone();
        pins.sort_unstable();
        pins.dedup();
        if pins != origin.tls.peer_spki_sha256 {
            return Err(invalid_config(
                "HTTP TLS SPKI pins are not strictly sorted and unique",
            ));
        }
    }
    if constraints
        .credential_bindings
        .windows(2)
        .any(|pair| credential_sort_key(&pair[0]) >= credential_sort_key(&pair[1]))
    {
        return Err(invalid_config(
            "HTTP credential bindings are not in strict canonical order",
        ));
    }
    let mut handles = BTreeSet::new();
    for binding in &constraints.credential_bindings {
        validate_material_name(&binding.handle, "credential handle")?;
        validate_header_name(&binding.header_name)?;
        if !handles.insert(binding.handle.as_str())
            || !origin_ids.contains(binding.origin_id.as_str())
            || constraints
                .request_headers
                .allowed_names
                .binary_search(&binding.header_name)
                .is_err()
            || binding.value_prefix.is_empty()
            || !binding
                .value_prefix
                .bytes()
                .all(|byte| (0x20..=0x7e).contains(&byte))
        {
            return Err(invalid_config(
                "HTTP credential binding is duplicate, unresolved, disallowed, or unsafe",
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_operator_intersection(
    _constraints: &HttpTransportConstraintsV1,
    operator: &HttpOperatorCapacity,
) -> Result<(), TransportFailure> {
    if !operator.enabled {
        return Err(TransportFailure::new(
            "not-granted",
            "HTTP transport is disabled by immutable operator capacity",
        ));
    }
    Ok(())
}

/// Rejects an unbounded or syntactically invalid request before its bytes are
/// admitted to the durable operation journal. Destination resolution and
/// credential access deliberately remain in the asynchronous dispatch path.
pub(crate) fn validate_persistable_request(
    request: &http_transport::Request,
    body_size: u64,
    constraints: &HttpTransportConstraintsV1,
    operator: &HttpOperatorCapacity,
) -> Result<(), TransportFailure> {
    validate_operator_intersection(constraints, operator)?;
    if u64::try_from(request.url.len()).unwrap_or(u64::MAX)
        > constraints.max_url_bytes.min(operator.max_url_bytes)
    {
        return Err(limit("HTTP URL exceeds its byte bound"));
    }
    if request.timeout_ms == 0
        || request.timeout_ms > constraints.max_timeout_ms.min(operator.max_timeout_ms)
    {
        return Err(limit("HTTP timeout exceeds its bound"));
    }
    if body_size
        > constraints
            .max_request_body_bytes
            .min(operator.max_request_body_bytes)
    {
        return Err(limit("HTTP request body exceeds its byte bound"));
    }
    let method = method_name(request.method).to_string();
    if constraints.methods.binary_search(&method).is_err()
        || operator.allowed_methods.binary_search(&method).is_err()
    {
        return Err(TransportFailure::new(
            "not-granted",
            "HTTP method is outside the signed authority",
        ));
    }
    if u32::try_from(request.headers.len()).unwrap_or(u32::MAX)
        > constraints
            .request_headers
            .max_count
            .min(operator.max_request_header_count)
    {
        return Err(limit("HTTP request header count exceeds its bound"));
    }
    let mut total = 0_u64;
    for header in &request.headers {
        validate_header_name_runtime(&header.name)?;
        HeaderValue::from_bytes(&header.value)
            .map_err(|_| invalid("HTTP request header value is invalid"))?;
        total = total
            .checked_add(u64::try_from(header.name.len() + header.value.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| limit("HTTP request header bytes overflow"))?;
    }
    if total
        > constraints
            .request_headers
            .max_total_bytes
            .min(operator.max_request_header_bytes)
    {
        return Err(limit("HTTP request header bytes exceed their bound"));
    }
    if let Some(handle) = &request.credential_handle {
        validate_material_name_runtime(handle)?;
    }
    Ok(())
}

pub(crate) fn validate_request(
    request: &http_transport::Request,
    body_size: u64,
    constraints: &HttpTransportConstraintsV1,
    operator: &HttpOperatorCapacity,
    material_root: Option<&Path>,
) -> Result<ValidatedRequest, TransportFailure> {
    validate_persistable_request(request, body_size, constraints, operator)?;
    let deadline = Instant::now()
        .checked_add(Duration::from_millis(request.timeout_ms))
        .ok_or_else(|| limit("HTTP timeout cannot be represented"))?;
    if u64::try_from(request.url.len()).unwrap_or(u64::MAX)
        > constraints.max_url_bytes.min(operator.max_url_bytes)
    {
        return Err(limit("HTTP URL exceeds its byte bound"));
    }
    if request.timeout_ms == 0
        || request.timeout_ms > constraints.max_timeout_ms.min(operator.max_timeout_ms)
    {
        return Err(limit("HTTP timeout exceeds its bound"));
    }
    if body_size
        > constraints
            .max_request_body_bytes
            .min(operator.max_request_body_bytes)
    {
        return Err(limit("HTTP request body exceeds its byte bound"));
    }
    let method = method_name(request.method).to_string();
    if constraints.methods.binary_search(&method).is_err()
        || operator.allowed_methods.binary_search(&method).is_err()
    {
        return Err(TransportFailure::new(
            "not-granted",
            "HTTP method is outside the signed authority",
        ));
    }
    let url = Url::parse(&request.url)
        .map_err(|_| TransportFailure::new("invalid-request", "HTTP URL is invalid"))?;
    if !request.url.is_ascii()
        || request.url.chars().any(char::is_control)
        || request.url.contains('\\')
        || url.as_str() != request.url
        || url.path().contains('%')
        || url.path().contains("//")
        || url
            .path()
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(TransportFailure::new(
            "not-granted",
            "HTTP URL is outside the exact HTTPS authority",
        ));
    }
    let host = canonical_url_host(&url)
        .ok_or_else(|| TransportFailure::new("invalid-request", "HTTP URL has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| TransportFailure::new("invalid-request", "HTTP URL has no port"))?;
    let origin = constraints
        .origins
        .iter()
        .find(|origin| {
            origin.scheme == url.scheme()
                && origin.host == host
                && origin.port == port
                && origin
                    .path_prefixes
                    .iter()
                    .any(|prefix| path_matches(url.path(), prefix))
        })
        .cloned()
        .ok_or_else(|| {
            TransportFailure::new(
                "not-granted",
                "HTTP destination is outside the signed origins",
            )
        })?;
    if !operator.origin_allowed(&origin) {
        return Err(TransportFailure::new(
            "not-granted",
            "HTTP destination is outside operator capacity",
        ));
    }
    let mut headers = Vec::new();
    let mut header_bytes = 0_u64;
    let mut counts = BTreeMap::<String, usize>::new();
    for header in &request.headers {
        validate_header_name_runtime(&header.name)?;
        if FORBIDDEN_REQUEST_HEADERS
            .binary_search(&header.name.as_str())
            .is_ok()
            || constraints
                .request_headers
                .allowed_names
                .binary_search(&header.name)
                .is_err()
            || operator
                .allowed_request_headers
                .binary_search(&header.name)
                .is_err()
        {
            return Err(TransportFailure::new(
                "not-granted",
                "HTTP request header is outside the signed authority",
            ));
        }
        header_bytes = header_bytes
            .checked_add(u64::try_from(header.name.len() + header.value.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| limit("HTTP request header bytes overflow"))?;
        *counts.entry(header.name.clone()).or_default() += 1;
        HeaderName::from_bytes(header.name.as_bytes())
            .map_err(|_| invalid("HTTP request header name is invalid"))?;
        HeaderValue::from_bytes(&header.value)
            .map_err(|_| invalid("HTTP request header value is invalid"))?;
        headers.push((header.name.clone(), header.value.clone()));
    }
    if u32::try_from(request.headers.len()).unwrap_or(u32::MAX)
        > constraints
            .request_headers
            .max_count
            .min(operator.max_request_header_count)
        || header_bytes
            > constraints
                .request_headers
                .max_total_bytes
                .min(operator.max_request_header_bytes)
    {
        return Err(limit("HTTP request headers exceed their bound"));
    }
    let selected_address = resolve_destination(&origin, operator, remaining(deadline)?)?;
    let credential = match request.credential_handle.as_deref() {
        Some(handle) => {
            let binding = constraints
                .credential_bindings
                .iter()
                .find(|binding| binding.handle == handle && binding.origin_id == origin.id)
                .ok_or_else(|| {
                    TransportFailure::new(
                        "not-granted",
                        "HTTP credential handle is outside the signed origin binding",
                    )
                })?;
            if operator
                .credential_handles
                .binary_search(&binding.handle)
                .is_err()
                || counts.get(&binding.header_name).copied() != Some(1)
            {
                return Err(TransportFailure::new(
                    "not-granted",
                    "HTTP credential placement is not exactly authorized",
                ));
            }
            let existing = headers
                .iter_mut()
                .find(|(name, _)| name == &binding.header_name)
                .ok_or_else(|| invalid("HTTP credential prefix header is missing"))?;
            if existing.1.as_slice() != binding.value_prefix.as_bytes() {
                return Err(TransportFailure::new(
                    "not-granted",
                    "HTTP credential prefix differs from the signed placement",
                ));
            }
            let root = material_root.ok_or_else(|| {
                TransportFailure::new(
                    "credential-unavailable",
                    "HTTP credential material is not provisioned",
                )
            })?;
            let secret = read_credential(root, handle)?;
            let mut injected = binding.value_prefix.as_bytes().to_vec();
            injected.extend_from_slice(&secret);
            let injected_total = header_bytes
                .checked_add(u64::try_from(secret.len()).unwrap_or(u64::MAX))
                .ok_or_else(|| limit("HTTP credential-injected header bytes overflow"))?;
            if injected_total
                > constraints
                    .request_headers
                    .max_total_bytes
                    .min(operator.max_request_header_bytes)
            {
                return Err(limit(
                    "HTTP credential-injected request headers exceed their bound",
                ));
            }
            HeaderValue::from_bytes(&injected)
                .map_err(|_| invalid("HTTP credential material is not a valid header value"))?;
            existing.1 = injected;
            Some(ValidatedCredential {
                handle: handle.to_string(),
                secret,
            })
        }
        None => {
            if constraints
                .credential_bindings
                .iter()
                .any(|binding| counts.contains_key(&binding.header_name))
            {
                return Err(TransportFailure::new(
                    "not-granted",
                    "credential-owned HTTP header requires its opaque handle",
                ));
            }
            None
        }
    };
    Ok(ValidatedRequest {
        url,
        origin,
        method,
        headers,
        credential,
        selected_address,
        deadline,
    })
}

pub(crate) fn execute_validated(
    _request: &http_transport::Request,
    body: Option<Vec<u8>>,
    constraints: &HttpTransportConstraintsV1,
    operator: &HttpOperatorCapacity,
    material_root: Option<&Path>,
    validated: ValidatedRequest,
) -> Result<TransportSuccess, TransportFailure> {
    let tls = build_tls_config(&validated, material_root)?;
    let timeout = remaining(validated.deadline)?;
    let mut socket = TcpStream::connect_timeout(&validated.selected_address, timeout)
        .map_err(|_| after_dispatch("HTTP destination could not be connected"))?;
    configure_socket_timeout(&socket, validated.deadline)?;
    let server_name = ServerName::try_from(validated.origin.tls.server_name.clone())
        .map_err(|_| after_dispatch("HTTP TLS server name is invalid"))?;
    let mut connection = ClientConnection::new(tls, server_name)
        .map_err(|_| after_dispatch("HTTP TLS client could not be constructed"))?;
    while connection.is_handshaking() {
        configure_socket_timeout(&socket, validated.deadline)?;
        connection
            .complete_io(&mut socket)
            .map_err(|_| after_dispatch("HTTP TLS handshake did not complete"))?;
    }
    if connection.protocol_version() != Some(rustls::ProtocolVersion::TLSv1_3) {
        return Err(after_dispatch("HTTP peer did not negotiate TLS1.3"));
    }
    let certificate = connection
        .peer_certificates()
        .and_then(|certificates| certificates.first())
        .map(|certificate| certificate.as_ref().to_vec())
        .ok_or_else(|| after_dispatch("HTTPS response contains no peer certificate"))?;
    let outgoing = encode_http1_request(&validated, body.as_deref())?;
    let mut stream = StreamOwned::new(connection, socket);
    configure_socket_timeout(&stream.sock, validated.deadline)?;
    stream
        .write_all(&outgoing)
        .and_then(|()| stream.flush())
        .map_err(|_| after_dispatch("HTTP request bytes could not be dispatched"))?;
    configure_socket_timeout(&stream.sock, validated.deadline)?;
    collect_response(&mut stream, &validated, constraints, operator, &certificate)
}

fn build_tls_config(
    request: &ValidatedRequest,
    material_root: Option<&Path>,
) -> Result<Arc<rustls::ClientConfig>, TransportFailure> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(root) = material_root {
        for certificate in load_operator_tls_roots(root)? {
            roots
                .add(certificate)
                .map_err(|_| invalid("operator TLS root certificate is invalid"))?;
        }
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let delegate = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|_| invalid("TLS verifier could not be constructed"))?;
    let verifier = Arc::new(PinnedServerVerifier {
        delegate,
        allowed_spki: request
            .origin
            .tls
            .peer_spki_sha256
            .iter()
            .copied()
            .collect(),
    });
    let tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| invalid("TLS1.3 configuration is unavailable"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(Arc::new(tls))
}

fn encode_http1_request(
    request: &ValidatedRequest,
    body: Option<&[u8]>,
) -> Result<Vec<u8>, TransportFailure> {
    let method = wire_method(&request.method)?;
    let mut target = request.url.path().to_string();
    if let Some(query) = request.url.query() {
        target.push('?');
        target.push_str(query);
    }
    if target.is_empty() {
        target.push('/');
    }
    let mut encoded = Vec::new();
    encoded.extend_from_slice(method.as_bytes());
    encoded.push(b' ');
    encoded.extend_from_slice(target.as_bytes());
    encoded.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    encoded.extend_from_slice(bracket_host(&request.origin.host).as_bytes());
    encoded.push(b':');
    encoded.extend_from_slice(request.origin.port.to_string().as_bytes());
    encoded.extend_from_slice(b"\r\nConnection: close\r\n");
    for (name, value) in &request.headers {
        encoded.extend_from_slice(name.as_bytes());
        encoded.extend_from_slice(b": ");
        encoded.extend_from_slice(value);
        encoded.extend_from_slice(b"\r\n");
    }
    if let Some(body) = body {
        encoded.extend_from_slice(b"Content-Length: ");
        encoded.extend_from_slice(body.len().to_string().as_bytes());
        encoded.extend_from_slice(b"\r\n");
    }
    encoded.extend_from_slice(b"\r\n");
    if let Some(body) = body {
        encoded.extend_from_slice(body);
    }
    Ok(encoded)
}

fn collect_response<R: Read>(
    stream: &mut R,
    request: &ValidatedRequest,
    constraints: &HttpTransportConstraintsV1,
    operator: &HttpOperatorCapacity,
    certificate: &[u8],
) -> Result<TransportSuccess, TransportFailure> {
    let peer_certificate_sha256 = Sha256Digest::from_bytes(certificate);
    let peer_spki_sha256 = certificate_spki_sha256(certificate)
        .map_err(|_| after_dispatch("HTTPS peer certificate SPKI is invalid"))?;
    if request
        .origin
        .tls
        .peer_spki_sha256
        .binary_search(&peer_spki_sha256)
        .is_err()
    {
        return Err(TransportFailure::after_dispatch(
            "tls-peer-rejected",
            "HTTPS peer key differs from the signed pin set",
        ));
    }
    let max_count = constraints
        .response_headers
        .max_count
        .min(operator.max_response_header_count);
    let max_header_bytes = constraints
        .response_headers
        .max_total_bytes
        .min(operator.max_response_header_bytes);
    let raw_header_cap = max_header_bytes
        .checked_add(u64::from(max_count).saturating_mul(4))
        .and_then(|value| value.checked_add(MAX_HTTP_STATUS_LINE_BYTES))
        .ok_or_else(|| after_dispatch_limit("HTTP response header budget overflow"))?;
    let header_block = read_header_block(stream, raw_header_cap)?;
    let parsed = parse_response_head(&header_block, max_count, max_header_bytes)?;
    let mut total_bytes = 0_u64;
    let mut exposed = Vec::new();
    let mut all_header_bytes = Vec::new();
    for (name, value) in &parsed.headers {
        total_bytes = total_bytes
            .checked_add(u64::try_from(name.len() + value.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| after_dispatch_limit("HTTP response header bytes overflow"))?;
        all_header_bytes.extend_from_slice(name.as_bytes());
        all_header_bytes.push(0);
        all_header_bytes.extend_from_slice(value);
        all_header_bytes.push(0xff);
        if let Some(credential) = &request.credential
            && contains_subslice(value, &credential.secret)
        {
            return Err(TransportFailure::after_dispatch(
                "credential-reflection",
                "HTTP response was rejected by credential non-exportability enforcement",
            ));
        }
        if constraints
            .response_headers
            .exposed_names
            .binary_search(name)
            .is_ok()
            && operator
                .allowed_response_headers
                .binary_search(name)
                .is_ok()
        {
            exposed.push(http_transport::Header {
                name: name.clone(),
                value: value.clone(),
            });
        }
    }
    let max_body = constraints
        .max_response_body_bytes
        .min(operator.max_response_body_bytes);
    let body = read_response_body(
        stream,
        &request.method,
        parsed.status,
        &parsed.headers,
        max_body,
    )?;
    if let Some(credential) = &request.credential
        && contains_subslice(&body, &credential.secret)
    {
        return Err(TransportFailure::after_dispatch(
            "credential-reflection",
            "HTTP response was rejected by credential non-exportability enforcement",
        ));
    }
    let status = parsed.status;
    let facts = TransportFactsV1 {
        schema: "wasm-biotic.http-transport-facts.v1".to_string(),
        canonical_url: request.url.to_string(),
        origin_id: request.origin.id.clone(),
        method: request.method.clone(),
        resolved_ip: request.selected_address.ip().to_string(),
        tls_version: "tls-1.3".to_string(),
        peer_certificate_sha256,
        peer_spki_sha256,
        status,
        response_header_digest: Sha256Digest::from_bytes(&all_header_bytes),
        response_header_bytes: total_bytes,
        response_body_digest: Sha256Digest::from_bytes(&body),
        response_body_bytes: u64::try_from(body.len()).unwrap_or(u64::MAX),
        credential_handle_digest: request
            .credential
            .as_ref()
            .map(|credential| Sha256Digest::from_bytes(credential.handle.as_bytes())),
    };
    Ok(TransportSuccess {
        status,
        headers: exposed,
        body,
        facts,
    })
}

struct ParsedResponseHead {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
}

fn read_header_block<R: Read>(
    stream: &mut R,
    raw_header_cap: u64,
) -> Result<Vec<u8>, TransportFailure> {
    let mut block = Vec::new();
    let mut byte = [0_u8; 1];
    while !block.ends_with(b"\r\n\r\n") {
        if u64::try_from(block.len()).unwrap_or(u64::MAX) >= raw_header_cap {
            return Err(after_dispatch_limit(
                "HTTP response head exceeds its wire bound",
            ));
        }
        let read = stream
            .read(&mut byte)
            .map_err(|_| after_dispatch("HTTP response head could not be read"))?;
        if read == 0 {
            return Err(after_dispatch("HTTP response ended before its head"));
        }
        block.push(byte[0]);
    }
    Ok(block)
}

fn parse_response_head(
    block: &[u8],
    max_count: u32,
    max_header_bytes: u64,
) -> Result<ParsedResponseHead, TransportFailure> {
    let first_end = find_crlf(block, 0)
        .ok_or_else(|| after_dispatch("HTTP response status line is malformed"))?;
    if u64::try_from(first_end).unwrap_or(u64::MAX) > MAX_HTTP_STATUS_LINE_BYTES {
        return Err(after_dispatch_limit(
            "HTTP response status line is too long",
        ));
    }
    let status_line = std::str::from_utf8(&block[..first_end])
        .map_err(|_| after_dispatch("HTTP response status line is not ASCII"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts.next().unwrap_or_default();
    let status_text = status_parts.next().unwrap_or_default();
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || status_text.len() != 3
        || !status_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(after_dispatch("HTTP response status line is invalid"));
    }
    let status = status_text
        .parse::<u16>()
        .map_err(|_| after_dispatch("HTTP response status is invalid"))?;
    if !(100..=599).contains(&status) || (100..200).contains(&status) {
        return Err(after_dispatch("HTTP informational response is unsupported"));
    }
    let terminal = block
        .len()
        .checked_sub(2)
        .ok_or_else(|| after_dispatch("HTTP response head is truncated"))?;
    let mut cursor = first_end + 2;
    let mut headers = Vec::new();
    let mut total_bytes = 0_u64;
    while cursor < terminal {
        let end = find_crlf(block, cursor)
            .ok_or_else(|| after_dispatch("HTTP response header line is malformed"))?;
        if end == cursor {
            if end != terminal {
                return Err(after_dispatch("HTTP response head has trailing bytes"));
            }
            break;
        }
        if u32::try_from(headers.len()).unwrap_or(u32::MAX) >= max_count {
            return Err(after_dispatch_limit(
                "HTTP response header count exceeds its bound",
            ));
        }
        let line = &block[cursor..end];
        if line
            .first()
            .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
        {
            return Err(after_dispatch("HTTP folded response header is forbidden"));
        }
        let colon = line
            .iter()
            .position(|byte| *byte == b':')
            .ok_or_else(|| after_dispatch("HTTP response header has no delimiter"))?;
        let parsed_name = HeaderName::from_bytes(&line[..colon])
            .map_err(|_| after_dispatch("HTTP response header name is invalid"))?;
        let name = parsed_name.as_str().to_ascii_lowercase();
        let value = trim_optional_whitespace(&line[colon + 1..]);
        HeaderValue::from_bytes(value)
            .map_err(|_| after_dispatch("HTTP response header value is invalid"))?;
        total_bytes = total_bytes
            .checked_add(u64::try_from(name.len() + value.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| after_dispatch_limit("HTTP response header bytes overflow"))?;
        if total_bytes > max_header_bytes {
            return Err(after_dispatch_limit(
                "HTTP response header bytes exceed their bound",
            ));
        }
        headers.push((name, value.to_vec()));
        cursor = end + 2;
    }
    if cursor != terminal {
        return Err(after_dispatch("HTTP response head terminator is invalid"));
    }
    Ok(ParsedResponseHead { status, headers })
}

fn read_response_body<R: Read>(
    stream: &mut R,
    method: &str,
    status: u16,
    headers: &[(String, Vec<u8>)],
    max_body: u64,
) -> Result<Vec<u8>, TransportFailure> {
    if method == "head" || status == 204 || status == 304 {
        return Ok(Vec::new());
    }
    let content_lengths = header_values(headers, "content-length");
    let transfer_encodings = header_values(headers, "transfer-encoding");
    if !content_lengths.is_empty() && !transfer_encodings.is_empty() {
        return Err(after_dispatch("HTTP response has conflicting body framing"));
    }
    if !transfer_encodings.is_empty() {
        if transfer_encodings.len() != 1 || !transfer_encodings[0].eq_ignore_ascii_case(b"chunked")
        {
            return Err(after_dispatch(
                "HTTP response transfer encoding is unsupported",
            ));
        }
        return read_chunked_body(stream, max_body);
    }
    if !content_lengths.is_empty() {
        if content_lengths.len() != 1
            || content_lengths[0].is_empty()
            || !content_lengths[0].iter().all(u8::is_ascii_digit)
        {
            return Err(after_dispatch("HTTP response content length is invalid"));
        }
        let length = std::str::from_utf8(content_lengths[0])
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or_else(|| after_dispatch("HTTP response content length is invalid"))?;
        if length > max_body {
            return Err(after_dispatch_limit(
                "HTTP response body exceeds its byte bound",
            ));
        }
        let length = usize::try_from(length)
            .map_err(|_| after_dispatch_limit("HTTP response body cannot be represented"))?;
        let mut body = vec![0_u8; length];
        stream
            .read_exact(&mut body)
            .map_err(|_| after_dispatch("HTTP response body ended early"))?;
        return Ok(body);
    }
    let mut body = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let read = stream
            .read(&mut buffer)
            .map_err(|_| after_dispatch("HTTP response body could not be read"))?;
        if read == 0 {
            break;
        }
        let next = u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
        if next > max_body {
            return Err(after_dispatch_limit(
                "HTTP response body exceeds its byte bound",
            ));
        }
        body.extend_from_slice(&buffer[..read]);
    }
    Ok(body)
}

fn read_chunked_body<R: Read>(stream: &mut R, max_body: u64) -> Result<Vec<u8>, TransportFailure> {
    let mut body = Vec::new();
    loop {
        let line = read_crlf_line(stream, MAX_CHUNK_LINE_BYTES)?;
        if line.is_empty() || line.contains(&b';') || !line.iter().all(u8::is_ascii_hexdigit) {
            return Err(after_dispatch("HTTP chunk size is invalid"));
        }
        let size = std::str::from_utf8(&line)
            .ok()
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .ok_or_else(|| after_dispatch("HTTP chunk size is invalid"))?;
        if size == 0 {
            if !read_crlf_line(stream, MAX_CHUNK_LINE_BYTES)?.is_empty() {
                return Err(after_dispatch("HTTP response trailers are forbidden"));
            }
            return Ok(body);
        }
        let next = u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .checked_add(size)
            .ok_or_else(|| after_dispatch_limit("HTTP response body size overflow"))?;
        if next > max_body {
            return Err(after_dispatch_limit(
                "HTTP response body exceeds its byte bound",
            ));
        }
        let size = usize::try_from(size)
            .map_err(|_| after_dispatch_limit("HTTP response chunk cannot be represented"))?;
        let start = body.len();
        body.resize(start + size, 0);
        stream
            .read_exact(&mut body[start..])
            .map_err(|_| after_dispatch("HTTP response chunk ended early"))?;
        let mut terminator = [0_u8; 2];
        stream
            .read_exact(&mut terminator)
            .map_err(|_| after_dispatch("HTTP response chunk terminator is missing"))?;
        if terminator != *b"\r\n" {
            return Err(after_dispatch("HTTP response chunk terminator is invalid"));
        }
    }
}

fn read_crlf_line<R: Read>(stream: &mut R, max_bytes: usize) -> Result<Vec<u8>, TransportFailure> {
    let mut line = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if line.len() >= max_bytes {
            return Err(after_dispatch_limit("HTTP framing line exceeds its bound"));
        }
        stream
            .read_exact(&mut byte)
            .map_err(|_| after_dispatch("HTTP framing line ended early"))?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
    }
}

fn header_values<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Vec<&'a [u8]> {
    headers
        .iter()
        .filter(|(candidate, _)| candidate == name)
        .map(|(_, value)| value.as_slice())
        .collect()
}

fn find_crlf(bytes: &[u8], start: usize) -> Option<usize> {
    bytes
        .get(start..)?
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|position| start + position)
}

fn trim_optional_whitespace(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

fn configure_socket_timeout(socket: &TcpStream, deadline: Instant) -> Result<(), TransportFailure> {
    let timeout = remaining(deadline)?;
    socket
        .set_read_timeout(Some(timeout))
        .and_then(|()| socket.set_write_timeout(Some(timeout)))
        .map_err(|_| after_dispatch("HTTP socket timeout could not be configured"))
}

fn remaining(deadline: Instant) -> Result<Duration, TransportFailure> {
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        Err(TransportFailure::new(
            "timeout",
            "HTTP operation exhausted its time budget",
        ))
    } else {
        Ok(timeout)
    }
}

#[derive(Debug)]
struct PinnedServerVerifier {
    delegate: Arc<WebPkiServerVerifier>,
    allowed_spki: BTreeSet<Sha256Digest>,
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.delegate.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let digest = certificate_spki_sha256(end_entity.as_ref()).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        if !self.allowed_spki.contains(&digest) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate
            .verify_tls12_signature(message, certificate, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.delegate
            .verify_tls13_signature(message, certificate, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.delegate.supported_verify_schemes()
    }
}

fn resolve_destination(
    origin: &HttpOriginV1,
    operator: &HttpOperatorCapacity,
    timeout: Duration,
) -> Result<SocketAddr, TransportFailure> {
    let mut addresses = if let Ok(address) = origin.host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, origin.port)]
    } else {
        let permit = acquire_dns_resolution_permit()?;
        let host = origin.host.clone();
        let port = origin.port;
        let (sender, receiver) = mpsc::sync_channel(1);
        std::thread::Builder::new()
            .name("wasm-biotic-http-dns".to_string())
            .spawn(move || {
                let _permit = permit;
                let result = (host.as_str(), port)
                    .to_socket_addrs()
                    .map(|addresses| addresses.collect::<Vec<_>>());
                let _ = sender.send(result);
            })
            .map_err(|_| network("HTTP DNS resolver could not be started"))?;
        receiver
            .recv_timeout(timeout)
            .map_err(|_| network("HTTP destination resolution exceeded its time budget"))?
            .map_err(|_| network("HTTP destination could not be resolved"))?
    };
    addresses.sort_unstable();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(network("HTTP destination resolved to no addresses"));
    }
    let exact_cidrs = origin
        .dns
        .cidrs
        .iter()
        .map(|cidr| cidr.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("HTTP origin CIDR is invalid"))?;
    let operator_cidrs = operator
        .allowed_cidrs
        .iter()
        .map(|cidr| cidr.parse::<IpNet>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("operator HTTP CIDR is invalid"))?;
    for address in &addresses {
        let allowed = match origin.dns.policy {
            HttpDnsPolicyV1::PublicOnly => {
                globally_routable(address.ip())
                    && operator_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(&address.ip()))
            }
            HttpDnsPolicyV1::ExactCidrs => {
                exact_cidrs.iter().any(|cidr| cidr.contains(&address.ip()))
                    && operator_cidrs
                        .iter()
                        .any(|cidr| cidr.contains(&address.ip()))
            }
        };
        if !allowed {
            return Err(TransportFailure::new(
                "destination-rejected",
                "HTTP DNS answer is outside the signed address authority",
            ));
        }
    }
    addresses
        .into_iter()
        .next()
        .ok_or_else(|| network("HTTP destination resolved to no selectable address"))
}

struct DnsResolutionPermit;

impl Drop for DnsResolutionPermit {
    fn drop(&mut self) {
        ACTIVE_DNS_RESOLUTIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_dns_resolution_permit() -> Result<DnsResolutionPermit, TransportFailure> {
    let mut active = ACTIVE_DNS_RESOLUTIONS.load(Ordering::Acquire);
    loop {
        if active >= MAX_NATIVE_DNS_RESOLUTIONS {
            return Err(network("HTTP DNS resolver capacity is exhausted"));
        }
        match ACTIVE_DNS_RESOLUTIONS.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(DnsResolutionPermit),
            Err(current) => active = current,
        }
    }
}

fn load_operator_tls_roots(root: &Path) -> Result<Vec<CertificateDer<'static>>, TransportFailure> {
    let directory = root.join(TLS_ROOTS_DIRECTORY);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    require_private_directory(&directory)?;
    let mut paths = fs::read_dir(&directory)
        .map_err(|_| invalid("operator TLS root directory cannot be read"))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid("operator TLS root directory cannot be enumerated"))?;
    paths.sort();
    if paths.len() > MAX_OPERATOR_TLS_ROOTS {
        return Err(limit("operator TLS root count exceeds the native bound"));
    }
    let mut roots = Vec::new();
    for path in paths {
        if path.extension().and_then(|value| value.to_str()) != Some("der") {
            return Err(invalid(
                "operator TLS root directory contains a non-DER entry",
            ));
        }
        require_private_file(&path)?;
        if fs::metadata(&path)
            .map_err(|_| invalid("operator TLS root certificate cannot be inspected"))?
            .len()
            > MAX_OPERATOR_TLS_ROOT_BYTES
        {
            return Err(limit(
                "operator TLS root certificate exceeds the native bound",
            ));
        }
        let bytes =
            fs::read(&path).map_err(|_| invalid("operator TLS root certificate cannot be read"))?;
        roots.push(CertificateDer::from(bytes));
    }
    Ok(roots)
}

fn read_credential(root: &Path, handle: &str) -> Result<Vec<u8>, TransportFailure> {
    validate_material_name_runtime(handle)?;
    let root = fs::canonicalize(root).map_err(|_| {
        TransportFailure::new(
            "credential-unavailable",
            "HTTP material root is unavailable",
        )
    })?;
    require_private_directory(&root)?;
    let credentials = root.join(CREDENTIALS_DIRECTORY);
    require_private_directory(&credentials)?;
    let path = fs::canonicalize(credentials.join(handle)).map_err(|_| {
        TransportFailure::new(
            "credential-unavailable",
            "HTTP credential handle is not provisioned",
        )
    })?;
    if !path.starts_with(&credentials) {
        return Err(TransportFailure::new(
            "credential-unavailable",
            "HTTP credential handle escapes its vault",
        ));
    }
    require_private_file(&path)?;
    let metadata =
        fs::metadata(&path).map_err(|_| invalid("HTTP credential metadata cannot be read"))?;
    if metadata.len() < 16 || metadata.len() > MAX_CREDENTIAL_BYTES {
        return Err(TransportFailure::new(
            "credential-unavailable",
            "HTTP credential size is outside the native bound",
        ));
    }
    let bytes = fs::read(path).map_err(|_| {
        TransportFailure::new("credential-unavailable", "HTTP credential cannot be read")
    })?;
    if bytes.iter().any(|byte| {
        *byte == b'\r' || *byte == b'\n' || (*byte < 0x20 && *byte != b'\t') || *byte == 0x7f
    }) {
        return Err(TransportFailure::new(
            "credential-unavailable",
            "HTTP credential is not a safe header value",
        ));
    }
    Ok(bytes)
}

pub(crate) fn validate_material_root(root: &Path) -> Result<PathBuf, KernelError> {
    let root = fs::canonicalize(root)
        .map_err(|error| invalid_config(format!("HTTP material root cannot be opened: {error}")))?;
    if !root.is_dir() {
        return Err(invalid_config("HTTP material root is not a directory"));
    }
    #[cfg(unix)]
    if fs::metadata(&root)
        .map_err(|error| invalid_config(error.to_string()))?
        .permissions()
        .mode()
        & 0o077
        != 0
    {
        return Err(invalid_config(
            "HTTP material root is accessible outside its owner",
        ));
    }
    Ok(root)
}

fn require_private_directory(path: &Path) -> Result<(), TransportFailure> {
    let metadata = fs::metadata(path)
        .map_err(|_| invalid("operator HTTP material directory is unavailable"))?;
    if !metadata.is_dir() {
        return Err(invalid("operator HTTP material path is not a directory"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid(
            "operator HTTP material directory is not owner-only",
        ));
    }
    Ok(())
}

fn require_private_file(path: &Path) -> Result<(), TransportFailure> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| invalid("operator HTTP material file is unavailable"))?;
    if !metadata.file_type().is_file() {
        return Err(invalid("operator HTTP material is not a regular file"));
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(invalid("operator HTTP material file is not owner-only"));
    }
    Ok(())
}

pub(crate) fn certificate_spki_sha256(certificate: &[u8]) -> Result<Sha256Digest, ()> {
    let (_, certificate_value) = der_tlv(certificate, 0, 0x30)?;
    let (tbs_end, tbs_value) = der_tlv(certificate_value, 0, 0x30)?;
    if tbs_end > certificate_value.len() {
        return Err(());
    }
    let mut offset = 0;
    if tbs_value.first() == Some(&0xa0) {
        offset = der_any(tbs_value, offset)?.0;
    }
    for _ in 0..5 {
        offset = der_any(tbs_value, offset)?.0;
    }
    let (end, _) = der_tlv(tbs_value, offset, 0x30)?;
    Ok(Sha256Digest::from_bytes(&tbs_value[offset..end]))
}

fn der_any(bytes: &[u8], offset: usize) -> Result<(usize, &[u8]), ()> {
    let tag = *bytes.get(offset).ok_or(())?;
    der_tlv(bytes, offset, tag)
}

fn der_tlv(bytes: &[u8], offset: usize, expected_tag: u8) -> Result<(usize, &[u8]), ()> {
    if bytes.get(offset).copied() != Some(expected_tag) {
        return Err(());
    }
    let first_length = *bytes.get(offset + 1).ok_or(())?;
    let (length, header) = if first_length & 0x80 == 0 {
        (usize::from(first_length), 2_usize)
    } else {
        let count = usize::from(first_length & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return Err(());
        }
        let mut length = 0_usize;
        for byte in bytes.get(offset + 2..offset + 2 + count).ok_or(())? {
            length = length
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or(())?;
        }
        (length, 2 + count)
    };
    let value_start = offset.checked_add(header).ok_or(())?;
    let end = value_start.checked_add(length).ok_or(())?;
    let value = bytes.get(value_start..end).ok_or(())?;
    Ok((end, value))
}

fn method_name(method: http_transport::Method) -> &'static str {
    match method {
        http_transport::Method::Get => "get",
        http_transport::Method::Head => "head",
        http_transport::Method::Post => "post",
        http_transport::Method::Put => "put",
        http_transport::Method::Patch => "patch",
        http_transport::Method::Delete => "delete",
    }
}

fn wire_method(method: &str) -> Result<&'static str, TransportFailure> {
    match method {
        "delete" => Ok("DELETE"),
        "get" => Ok("GET"),
        "head" => Ok("HEAD"),
        "patch" => Ok("PATCH"),
        "post" => Ok("POST"),
        "put" => Ok("PUT"),
        _ => Err(invalid("HTTP method could not be encoded")),
    }
}

fn validate_method(method: &str) -> Result<(), KernelError> {
    if matches!(method, "delete" | "get" | "head" | "patch" | "post" | "put") {
        Ok(())
    } else {
        Err(invalid_config("HTTP method is outside the WIT enum"))
    }
}

fn validate_header_name(name: &str) -> Result<(), KernelError> {
    if name.is_empty()
        || name != name.to_ascii_lowercase()
        || HeaderName::from_bytes(name.as_bytes()).is_err()
    {
        Err(invalid_config(
            "HTTP header name is not canonical lower-case syntax",
        ))
    } else {
        Ok(())
    }
}

fn validate_header_name_runtime(name: &str) -> Result<(), TransportFailure> {
    validate_header_name(name)
        .map_err(|_| invalid("HTTP header name is not canonical lower-case syntax"))
}

fn validate_origin_host(host: &str, port: u16) -> Result<(), KernelError> {
    let candidate = format!("https://{}:{port}/", bracket_host(host));
    let url = Url::parse(&candidate).map_err(|_| invalid_config("HTTP origin host is invalid"))?;
    if canonical_url_host(&url) != Some(host) || url.port_or_known_default() != Some(port) {
        return Err(invalid_config("HTTP origin host is not canonical"));
    }
    Ok(())
}

fn parse_operator_origin(value: &str) -> Result<(), KernelError> {
    let url = Url::parse(value).map_err(|_| invalid_config("operator HTTP origin is invalid"))?;
    let host = canonical_url_host(&url)
        .ok_or_else(|| invalid_config("operator HTTP origin has no host"))?;
    let port = url
        .port_or_known_default()
        .ok_or_else(|| invalid_config("operator HTTP origin has no effective port"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || value != origin_key("https", host, port)
    {
        return Err(invalid_config(
            "operator HTTP origin is not canonical https://host:port",
        ));
    }
    Ok(())
}

fn canonical_url_host(url: &Url) -> Option<&str> {
    let host = url.host_str()?;
    Some(
        host.strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .unwrap_or(host),
    )
}

fn origin_key(scheme: &str, host: &str, port: u16) -> String {
    format!("{scheme}://{}:{port}", bracket_host(host))
}

fn bracket_host(host: &str) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    }
}

fn parse_canonical_cidr(value: &str) -> Result<IpNet, KernelError> {
    let network = value
        .parse::<IpNet>()
        .map_err(|_| invalid_config("HTTP CIDR is invalid"))?;
    if network.to_string() != value {
        return Err(invalid_config("HTTP CIDR is not canonical"));
    }
    Ok(network)
}

fn globally_routable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => globally_routable_v4(address),
        IpAddr::V6(address) => globally_routable_v6(address),
    }
}

fn globally_routable_v4(address: Ipv4Addr) -> bool {
    let value = u32::from(address);
    ![
        (0x0000_0000, 8),
        (0x0a00_0000, 8),
        (0x6440_0000, 10),
        (0x7f00_0000, 8),
        (0xa9fe_0000, 16),
        (0xac10_0000, 12),
        (0xc000_0000, 24),
        (0xc000_0200, 24),
        (0xc058_6300, 24),
        (0xc0a8_0000, 16),
        (0xc612_0000, 15),
        (0xc633_6400, 24),
        (0xcb00_7100, 24),
        (0xe000_0000, 4),
        (0xf000_0000, 4),
    ]
    .iter()
    .any(|(network, prefix)| {
        let mask = if *prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        value & mask == *network & mask
    })
}

fn globally_routable_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return globally_routable_v4(mapped);
    }
    let octets = address.octets();
    let value = u128::from(address);
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
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

fn validate_material_name(value: &str, subject: &str) -> Result<(), KernelError> {
    if value.is_empty()
        || value.len() > 128
        || value == "."
        || value == ".."
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        Err(invalid_config(format!(
            "{subject} is not a safe opaque name"
        )))
    } else {
        Ok(())
    }
}

fn validate_material_name_runtime(value: &str) -> Result<(), TransportFailure> {
    validate_material_name(value, "credential handle")
        .map_err(|_| invalid("HTTP credential handle is invalid"))
}

fn credential_sort_key(binding: &HttpCredentialBindingV1) -> (&str, &str, &str) {
    (
        binding.handle.as_str(),
        binding.origin_id.as_str(),
        binding.header_name.as_str(),
    )
}

fn require_sorted_unique(values: &[String], subject: &str) -> Result<(), KernelError> {
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        Err(invalid_config(format!(
            "{subject} are not strictly sorted and unique"
        )))
    } else {
        Ok(())
    }
}

fn path_matches(path: &str, prefix: &str) -> bool {
    path == prefix
        || path.strip_prefix(prefix).is_some_and(|suffix| {
            prefix.ends_with('/') || suffix.starts_with('/') || suffix.is_empty()
        })
}

fn canonical_path_prefix(prefix: &str) -> bool {
    prefix.starts_with('/')
        && prefix.is_ascii()
        && prefix.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        && !prefix.contains('%')
        && !prefix.contains('?')
        && !prefix.contains('#')
        && !prefix.contains('\\')
        && !prefix.contains("//")
        && !prefix
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && !prefix.chars().any(char::is_control)
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn invalid_config(message: impl Into<String>) -> KernelError {
    KernelError::InvalidConfiguration(message.into())
}

fn invalid(message: &'static str) -> TransportFailure {
    TransportFailure::new("invalid-request", message)
}

fn limit(message: &'static str) -> TransportFailure {
    TransportFailure::new("limit-exceeded", message)
}

fn network(message: &'static str) -> TransportFailure {
    TransportFailure::new("transport-failure", message)
}

fn after_dispatch(message: &'static str) -> TransportFailure {
    TransportFailure::after_dispatch("transport-outcome-unknown", message)
}

fn after_dispatch_limit(message: &'static str) -> TransportFailure {
    TransportFailure::after_dispatch("transport-outcome-unknown", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_address_filter_rejects_local_and_special_ranges() {
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.168.0.1",
            "198.18.0.1",
            "224.0.0.1",
            "::",
            "::1",
            "fc00::1",
            "fe80::1",
            "fec0::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!globally_routable(address.parse().unwrap()), "{address}");
        }
        assert!(globally_routable("1.1.1.1".parse().unwrap()));
        assert!(globally_routable("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn der_spki_extractor_rejects_non_certificates() {
        assert!(certificate_spki_sha256(b"not a certificate").is_err());
    }

    #[test]
    fn path_prefixes_do_not_match_neighboring_segments() {
        assert!(path_matches("/api", "/api"));
        assert!(path_matches("/api/v1", "/api"));
        assert!(!path_matches("/apix", "/api"));
    }

    #[test]
    fn operator_origin_requires_an_explicit_port_including_https_default() {
        assert!(parse_operator_origin("https://example.com:443").is_ok());
        assert!(parse_operator_origin("https://example.com").is_err());
        assert!(parse_operator_origin("https://example.com:8443").is_ok());
        assert!(parse_operator_origin("https://[2001:4860:4860::8888]:443").is_ok());
        assert!(validate_origin_host("2001:4860:4860::8888", 443).is_ok());
    }

    #[test]
    fn response_parser_enforces_closed_head_and_body_framing() {
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nX-Result: yes\r\n\r\n";
        let parsed = parse_response_head(head, 2, 128).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(
            parsed.headers[0],
            ("content-length".to_string(), b"3".to_vec())
        );
        assert_eq!(parsed.headers[1], ("x-result".to_string(), b"yes".to_vec()));
        let mut body = &b"abc"[..];
        assert_eq!(
            read_response_body(&mut body, "get", 200, &parsed.headers, 3).unwrap(),
            b"abc"
        );
        assert!(parse_response_head(head, 1, 128).is_err());
        assert!(parse_response_head(b"HTTP/1.1 100 Continue\r\n\r\n", 1, 64).is_err());
        assert!(parse_response_head(b"HTTP/1.1 200 OK\r\n folded\r\n\r\n", 1, 64).is_err());
    }

    #[test]
    fn chunked_decoder_is_bounded_and_rejects_trailers() {
        let mut encoded = &b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n"[..];
        assert_eq!(read_chunked_body(&mut encoded, 5).unwrap(), b"abcde");
        let mut too_large = &b"6\r\nabcdef\r\n0\r\n\r\n"[..];
        assert!(read_chunked_body(&mut too_large, 5).is_err());
        let mut trailers = &b"0\r\nX-Trailer: forbidden\r\n\r\n"[..];
        assert!(read_chunked_body(&mut trailers, 5).is_err());
    }
}
