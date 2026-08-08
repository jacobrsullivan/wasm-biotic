use super::*;

use crate::http_transport::{
    HttpCredentialBindingV1, HttpCredentialPlacementV1, HttpDnsConstraintsV1, HttpDnsPolicyV1,
    HttpOperatorCapacity, HttpOriginV1, HttpRedirectPolicyV1, HttpRequestHeaderConstraintsV1,
    HttpResponseHeaderConstraintsV1, HttpTlsConstraintsV1, HttpTlsVersionV1,
    HttpTransportConstraintsV1,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

static NEXT_HTTP_TEMP: AtomicUsize = AtomicUsize::new(0);

struct HttpTestDirectory {
    root: PathBuf,
    state: PathBuf,
    materials: PathBuf,
}

impl HttpTestDirectory {
    fn new(name: &str, trust_root: &[u8]) -> Self {
        let root = std::env::temp_dir().join(format!(
            "wasm-biotic-http-{name}-{}-{}",
            std::process::id(),
            NEXT_HTTP_TEMP.fetch_add(1, Ordering::SeqCst)
        ));
        let state = root.join("state");
        let materials = root.join("materials");
        let tls_roots = materials.join("tls-roots");
        fs::create_dir_all(&state).unwrap();
        fs::create_dir_all(&tls_roots).unwrap();
        #[cfg(unix)]
        {
            fs::set_permissions(&materials, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&tls_roots, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let trust_path = tls_roots.join("test.der");
        fs::write(&trust_path, trust_root).unwrap();
        #[cfg(unix)]
        fs::set_permissions(&trust_path, fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            root,
            state,
            materials,
        }
    }
}

impl Drop for HttpTestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct LocalTlsServer {
    port: u16,
    certificate: Vec<u8>,
    captured: Arc<Mutex<Vec<u8>>>,
    dispatches: Arc<AtomicUsize>,
    worker: Option<thread::JoinHandle<()>>,
}

impl LocalTlsServer {
    fn one(response_body: Vec<u8>) -> Self {
        let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
        let certificate = certified.cert.der().to_vec();
        let private_key = certified.signing_key.serialize_der();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate.clone())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(private_key)),
            )
            .unwrap();
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let captured = Arc::new(Mutex::new(Vec::new()));
        let dispatches = Arc::new(AtomicUsize::new(0));
        let captured_worker = captured.clone();
        let dispatches_worker = dispatches.clone();
        let worker = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            dispatches_worker.fetch_add(1, Ordering::SeqCst);
            serve_one_tls(socket, Arc::new(config), &response_body, &captured_worker);
        });
        Self {
            port,
            certificate,
            captured,
            dispatches,
            worker: Some(worker),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.worker.take().unwrap().join().unwrap();
        self.captured.lock().unwrap().clone()
    }
}

fn serve_one_tls(
    socket: TcpStream,
    config: Arc<rustls::ServerConfig>,
    response_body: &[u8],
    captured: &Mutex<Vec<u8>>,
) {
    let connection = rustls::ServerConnection::new(config).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, socket);
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let read = stream.read(&mut buffer).unwrap();
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    *captured.lock().unwrap() = request;
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    )
    .unwrap();
    stream.write_all(response_body).unwrap();
    stream.flush().unwrap();
}

fn operator(port: u16, credential_handles: Vec<String>) -> HttpOperatorCapacity {
    HttpOperatorCapacity {
        enabled: true,
        allowed_origins: vec![format!("https://127.0.0.1:{port}")],
        allowed_methods: vec!["get".to_string()],
        allowed_request_headers: if credential_handles.is_empty() {
            Vec::new()
        } else {
            vec!["authorization".to_string()]
        },
        allowed_response_headers: vec!["content-type".to_string()],
        allowed_cidrs: vec!["127.0.0.0/8".to_string()],
        credential_handles,
        max_url_bytes: 2048,
        max_request_body_bytes: 1024,
        max_response_body_bytes: 1024,
        max_request_header_count: 8,
        max_request_header_bytes: 4096,
        max_response_header_count: 8,
        max_response_header_bytes: 4096,
        max_timeout_ms: 2_000,
        max_concurrency: 2,
    }
}

fn constraints(
    port: u16,
    certificate: &[u8],
    credential_bindings: Vec<HttpCredentialBindingV1>,
) -> HttpTransportConstraintsV1 {
    HttpTransportConstraintsV1 {
        schema: bounded_http::HTTP_CONSTRAINT_SCHEMA_V1.to_string(),
        origins: vec![HttpOriginV1 {
            id: "local-test".to_string(),
            scheme: "https".to_string(),
            host: "127.0.0.1".to_string(),
            port,
            path_prefixes: vec!["/api".to_string()],
            dns: HttpDnsConstraintsV1 {
                policy: HttpDnsPolicyV1::ExactCidrs,
                cidrs: vec!["127.0.0.0/8".to_string()],
            },
            tls: HttpTlsConstraintsV1 {
                minimum_version: HttpTlsVersionV1::Tls13,
                server_name: "127.0.0.1".to_string(),
                peer_spki_sha256: vec![bounded_http::certificate_spki_sha256(certificate).unwrap()],
            },
        }],
        methods: vec!["get".to_string()],
        request_headers: HttpRequestHeaderConstraintsV1 {
            allowed_names: if credential_bindings.is_empty() {
                Vec::new()
            } else {
                vec!["authorization".to_string()]
            },
            max_count: 8,
            max_total_bytes: 4096,
        },
        response_headers: HttpResponseHeaderConstraintsV1 {
            exposed_names: vec!["content-type".to_string()],
            max_count: 8,
            max_total_bytes: 4096,
        },
        max_url_bytes: 2048,
        max_request_body_bytes: 1024,
        max_response_body_bytes: 1024,
        max_timeout_ms: 2_000,
        max_concurrency: 2,
        redirects: HttpRedirectPolicyV1::Deny,
        credential_bindings,
    }
}

fn config(operator: HttpOperatorCapacity) -> LocalConfig {
    LocalConfig {
        http_transport: Some(operator),
        ..LocalConfig::default()
    }
}

fn authority(constraint_digest: Sha256Digest) -> HttpAuthority {
    HttpAuthority {
        graph_manifest_digest: Sha256Digest::from_bytes(b"graph-a"),
        principal_seed: Sha256Digest::from_bytes(b"principal-a"),
        alias: "wasm-biotic:factory/host-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@0.1.0".to_string(),
        constraint_digest,
    }
}

fn request(port: u16) -> http_transport::Request {
    http_transport::Request {
        request_id: "request-1".to_string(),
        method: http_transport::Method::Get,
        url: format!("https://127.0.0.1:{port}/api"),
        headers: Vec::new(),
        body: None,
        timeout_ms: 2_000,
        idempotency_key: digest_value(Sha256Digest::from_bytes(b"idempotency-1")),
        credential_handle: None,
    }
}

fn await_response(
    mechanisms: &LocalMechanisms,
    operation: &str,
    authority: &HttpAuthority,
) -> http_transport::Response {
    for _ in 0..200 {
        match mechanisms.poll_http_for_authority(operation, authority) {
            Ok(Some(response)) => return response,
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Err(error) => panic!("unexpected HTTP failure: {}", error.code),
        }
    }
    panic!("HTTP operation did not complete")
}

#[test]
fn production_tls_dispatch_is_durable_owned_and_replayed_without_resend() {
    let server = LocalTlsServer::one(b"bounded-response".to_vec());
    let server_port = server.port;
    let directory = HttpTestDirectory::new("dispatch", &server.certificate);
    let mut capacity = operator(server.port, Vec::new());
    // The signed document is an authority ceiling, not a demand that the
    // operator expose every permitted byte.  Exercise a materially narrower
    // local capacity and prove that the operational intersection still runs.
    capacity.allowed_response_headers.clear();
    capacity.max_url_bytes = 256;
    capacity.max_request_body_bytes = 64;
    capacity.max_response_body_bytes = 64;
    capacity.max_request_header_count = 2;
    capacity.max_request_header_bytes = 512;
    capacity.max_response_header_count = 4;
    capacity.max_response_header_bytes = 512;
    capacity.max_timeout_ms = 1_000;
    capacity.max_concurrency = 1;
    let mechanisms = LocalMechanisms::open_with_http_materials(
        &directory.state,
        config(capacity.clone()),
        &directory.materials,
    )
    .unwrap();
    assert!(
        LocalMechanisms::open_with_http_materials(
            &directory.state,
            config(capacity),
            &directory.materials,
        )
        .is_err(),
        "HTTP dispatch lease must be process-exclusive"
    );
    let constraint_bytes =
        crate::canonical_json_bytes(&constraints(server.port, &server.certificate, Vec::new()))
            .unwrap();
    let constraint = mechanisms
        .put_blob("application/json".to_string(), constraint_bytes)
        .unwrap();
    let authority = authority(validate_digest(&constraint.content_digest).unwrap());
    let mut request = request(server.port);
    request.timeout_ms = 1_000;
    let operation = mechanisms
        .start_http_for_authority(request.clone(), authority.clone())
        .unwrap();
    let response = await_response(&mechanisms, &operation, &authority);
    assert_eq!(response.status, 200);
    assert_eq!(
        mechanisms.get_blob(response.body.clone().unwrap()).unwrap(),
        b"bounded-response"
    );
    assert_eq!(
        validate_digest(&response.receipt.executor_digest).unwrap(),
        crate::compiled_native_tcb_inventory_digest()
    );
    let dispatches = server.dispatches.clone();
    let captured = server.finish();
    assert!(
        captured.starts_with(b"GET /api HTTP/1.1\r\n"),
        "captured request: {}",
        String::from_utf8_lossy(&captured)
    );
    assert!(
        !String::from_utf8_lossy(&captured)
            .to_ascii_lowercase()
            .contains("\r\naccept:"),
        "the native adapter must not add a semantic Accept header: {}",
        String::from_utf8_lossy(&captured)
    );
    assert!(response.headers.is_empty());
    assert_eq!(dispatches.load(Ordering::SeqCst), 1);

    let repeated = mechanisms
        .start_http_for_authority(request.clone(), authority.clone())
        .unwrap();
    assert_eq!(repeated, operation);
    assert_eq!(
        crate::canonical_json_bytes(&await_response(&mechanisms, &operation, &authority).receipt)
            .unwrap(),
        crate::canonical_json_bytes(&response.receipt).unwrap()
    );
    let wrong_graph = HttpAuthority {
        graph_manifest_digest: Sha256Digest::from_bytes(b"graph-b"),
        ..authority.clone()
    };
    assert_eq!(
        mechanisms
            .poll_http_for_authority(&operation, &wrong_graph)
            .unwrap_err()
            .code,
        "not-granted"
    );
    let receipt_before = mechanisms
        .http_transport_receipt(&operation)
        .unwrap()
        .unwrap();
    let receipt_value: serde_json::Value = serde_json::from_slice(&receipt_before).unwrap();
    assert_eq!(
        receipt_value["resolved_address"].as_str(),
        Some(format!("127.0.0.1:{server_port}").as_str())
    );
    assert_eq!(
        receipt_value["owner"]["constraint_digest"].as_str(),
        Some(authority.constraint_digest.to_string().as_str())
    );
    let mut changed_request = request.clone();
    changed_request.request_id = "request-conflict".to_string();
    assert_eq!(
        mechanisms
            .start_http_for_authority(changed_request, authority.clone())
            .unwrap_err()
            .code,
        "idempotency-conflict"
    );
    for wrong_owner in [
        HttpAuthority {
            graph_manifest_digest: Sha256Digest::from_bytes(b"graph-b"),
            ..authority.clone()
        },
        HttpAuthority {
            principal_seed: Sha256Digest::from_bytes(b"principal-b"),
            ..authority.clone()
        },
        HttpAuthority {
            alias: format!("{}-wrong", authority.alias),
            ..authority.clone()
        },
        HttpAuthority {
            constraint_digest: Sha256Digest::from_bytes(b"constraint-b"),
            ..authority.clone()
        },
    ] {
        assert_eq!(
            mechanisms
                .poll_http_for_authority(&operation, &wrong_owner)
                .unwrap_err()
                .code,
            "not-granted"
        );
        assert_eq!(
            mechanisms
                .cancel_http_for_authority(&operation, &wrong_owner)
                .unwrap_err()
                .code,
            "not-granted"
        );
    }
    drop(mechanisms);
    let reopened =
        LocalMechanisms::open_existing_with_http_materials(&directory.state, &directory.materials)
            .unwrap();
    let replayed = reopened
        .start_http_for_authority(request, authority.clone())
        .unwrap();
    assert_eq!(replayed, operation);
    assert_eq!(
        reopened
            .http_transport_receipt(&operation)
            .unwrap()
            .unwrap(),
        receipt_before
    );
    assert!(
        reopened
            .poll_http_for_authority(&operation, &authority)
            .unwrap()
            .is_some()
    );
}

#[test]
fn dispatch_boundary_restart_becomes_indeterminate_and_never_retries() {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let certificate = certified.cert.der().to_vec();
    let unused = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let directory = HttpTestDirectory::new("restart", &certificate);
    let faults = DurabilityFaultController::default();
    faults.arm(
        DurabilityFaultPoint::BeforeHttpSocketDispatch,
        "http-dispatch",
    );
    let mechanisms = LocalMechanisms::open_with_http_fault_injection(
        &directory.state,
        config(operator(port, Vec::new())),
        &directory.materials,
        Arc::new(SystemTimeSource),
        faults.clone(),
    )
    .unwrap();
    let constraint_bytes =
        crate::canonical_json_bytes(&constraints(port, &certificate, Vec::new())).unwrap();
    let constraint = mechanisms
        .put_blob("application/json".to_string(), constraint_bytes)
        .unwrap();
    let authority = authority(validate_digest(&constraint.content_digest).unwrap());
    let request = request(port);
    let operation = mechanisms
        .start_http_for_authority(request.clone(), authority.clone())
        .unwrap();
    for _ in 0..200 {
        if !faults.fired().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(faults.fired().len(), 1);
    drop(mechanisms);
    let reopened = loop {
        match LocalMechanisms::open_existing_with_http_materials(
            &directory.state,
            &directory.materials,
        ) {
            Ok(mechanisms) => break mechanisms,
            Err(_) => thread::sleep(Duration::from_millis(5)),
        }
    };
    assert_eq!(
        reopened
            .poll_http_for_authority(&operation, &authority)
            .unwrap_err()
            .code,
        "transport-outcome-unknown"
    );
    assert_eq!(
        reopened
            .start_http_for_authority(request, authority.clone())
            .unwrap(),
        operation
    );
    assert_eq!(
        reopened
            .poll_http_for_authority(&operation, &authority)
            .unwrap_err()
            .code,
        "transport-outcome-unknown"
    );
}

#[test]
fn prepared_operation_can_only_be_cancelled_before_dispatch() {
    let certified = rcgen::generate_simple_self_signed(vec!["127.0.0.1".to_string()]).unwrap();
    let certificate = certified.cert.der().to_vec();
    let unused = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = unused.local_addr().unwrap().port();
    drop(unused);
    let directory = HttpTestDirectory::new("cancel", &certificate);
    let faults = DurabilityFaultController::default();
    faults.arm(
        DurabilityFaultPoint::BeforeHttpDispatchRecord,
        "http-dispatch",
    );
    let mechanisms = LocalMechanisms::open_with_http_fault_injection(
        &directory.state,
        config(operator(port, Vec::new())),
        &directory.materials,
        Arc::new(SystemTimeSource),
        faults.clone(),
    )
    .unwrap();
    let constraint = mechanisms
        .put_blob(
            "application/json".to_string(),
            crate::canonical_json_bytes(&constraints(port, &certificate, Vec::new())).unwrap(),
        )
        .unwrap();
    let authority = authority(validate_digest(&constraint.content_digest).unwrap());
    let operation = mechanisms
        .start_http_for_authority(request(port), authority.clone())
        .unwrap();
    for _ in 0..200 {
        if !faults.fired().is_empty() {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(
        mechanisms
            .cancel_http_for_authority(&operation, &authority)
            .unwrap()
    );
    assert_eq!(
        mechanisms
            .poll_http_for_authority(&operation, &authority)
            .unwrap_err()
            .code,
        "cancelled-before-dispatch"
    );
    assert!(
        !mechanisms
            .cancel_http_for_authority(&operation, &authority)
            .unwrap()
    );
}

#[test]
fn credential_is_injected_only_after_authorization_and_reflection_never_persists() {
    let secret = b"operator-secret-0123456789".to_vec();
    let server = LocalTlsServer::one(secret.clone());
    let directory = HttpTestDirectory::new("credential", &server.certificate);
    let credentials = directory.materials.join("credentials");
    fs::create_dir_all(&credentials).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&credentials, fs::Permissions::from_mode(0o700)).unwrap();
    let credential_path = credentials.join("delivery-token");
    fs::write(&credential_path, &secret).unwrap();
    #[cfg(unix)]
    fs::set_permissions(&credential_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mechanisms = LocalMechanisms::open_with_http_materials(
        &directory.state,
        config(operator(server.port, vec!["delivery-token".to_string()])),
        &directory.materials,
    )
    .unwrap();
    let binding = HttpCredentialBindingV1 {
        handle: "delivery-token".to_string(),
        origin_id: "local-test".to_string(),
        header_name: "authorization".to_string(),
        value_prefix: "Bearer ".to_string(),
        placement: HttpCredentialPlacementV1::AppendToHeaderValue,
    };
    let constraint = mechanisms
        .put_blob(
            "application/json".to_string(),
            crate::canonical_json_bytes(&constraints(
                server.port,
                &server.certificate,
                vec![binding],
            ))
            .unwrap(),
        )
        .unwrap();
    let authority = authority(validate_digest(&constraint.content_digest).unwrap());
    let mut request = request(server.port);
    request.headers.push(http_transport::Header {
        name: "authorization".to_string(),
        value: b"Bearer ".to_vec(),
    });
    request.credential_handle = Some("delivery-token".to_string());
    let operation = mechanisms
        .start_http_for_authority(request, authority.clone())
        .unwrap();
    let failure = loop {
        match mechanisms.poll_http_for_authority(&operation, &authority) {
            Err(failure) => break failure,
            Ok(None) => thread::sleep(Duration::from_millis(5)),
            Ok(Some(_)) => panic!("reflected credential response was exposed"),
        }
    };
    assert_eq!(failure.code, "transport-outcome-unknown");
    let captured = server.finish();
    let expected = [b"authorization: Bearer ".as_slice(), secret.as_slice()].concat();
    assert!(
        captured
            .windows(expected.len())
            .any(|window| window == expected)
    );
    let durable = fs::read(directory.state.join(STATE_FILE)).unwrap();
    assert!(!durable.windows(secret.len()).any(|window| window == secret));
    let receipt = mechanisms
        .http_transport_receipt(&operation)
        .unwrap()
        .unwrap();
    assert!(!receipt.windows(secret.len()).any(|window| window == secret));
}
