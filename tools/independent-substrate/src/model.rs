use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeMap;
use std::fmt::{self, Display};
use std::str::FromStr;

pub type AnyError = Box<dyn std::error::Error + Send + Sync>;
pub type Result<T> = std::result::Result<T, AnyError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Digest(pub [u8; 32]);

impl Digest {
    pub fn of(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    pub fn hex(self) -> String {
        encode_hex(&self.0)
    }

    pub fn file_stem(self) -> String {
        format!("sha256-{}", self.hex())
    }
}

impl Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "sha256:{}", encode_hex(&self.0))
    }
}

impl FromStr for Digest {
    type Err = AnyError;

    fn from_str(value: &str) -> Result<Self> {
        let hex = value
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("digest has no sha256 prefix: {value}"))?;
        let bytes = decode_hex(hex, 32, "digest")?;
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes);
        Ok(Self(digest))
    }
}

impl Serialize for Digest {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub capability: String,
    pub scope: String,
    pub constraints: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    pub id: String,
    pub kind: String,
    pub component_digest: Digest,
    pub world: String,
    pub exports: Vec<String>,
    pub grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_schema: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema: String,
    pub wit_package: String,
    pub root_node: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_graph: Option<Digest>,
    pub state_schema: String,
    pub nodes: Vec<Node>,
    pub bindings: Vec<Binding>,
    pub invocations: Vec<Invocation>,
    pub metadata: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub consumer: String,
    #[serde(rename = "import")]
    pub import_name: String,
    pub provider: BindingProvider,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingProvider {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invocation {
    pub consumer: String,
    pub target: String,
    pub export: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metadata {
    pub schema: String,
    pub wit_package_digest: Digest,
    pub wit_world_digests: BTreeMap<String, Digest>,
    pub substrate_profile_digest: Digest,
    pub derivation_descriptor_digest: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivationSource {
    pub node_id: String,
    pub component_digest: Digest,
    pub world: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Executable {
    pub authority_node: String,
    pub authority_digest: Digest,
    pub executable_digest: Digest,
    pub source_digests: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scoped_source_digests: Vec<Digest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_seeds: Vec<Digest>,
    pub world: String,
    pub configuration_digest: Digest,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub grants: Vec<Grant>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub schema: String,
    pub wit_package_digest: Digest,
    pub sources: Vec<DerivationSource>,
    pub executables: Vec<Executable>,
    pub tool: serde_json::Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Constraints {
    pub schema: String,
    pub max_blob_bytes: u64,
    pub max_total_blob_bytes: u64,
    pub max_random_bytes: u32,
    pub max_wake_delay_ms: u64,
    pub max_http_timeout_ms: u64,
    pub max_component_fuel: u64,
    pub max_component_memory_bytes: u64,
    pub max_component_output_bytes: u64,
    pub max_component_wall_time_ms: u64,
    pub transaction_namespaces: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: String,
    pub wit_package: String,
    pub primitives: Vec<String>,
    pub static_grant_model: String,
    pub root_node: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub root_grants: Vec<Grant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub import_alias_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_id_scheme: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principals: Vec<Principal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_transport: Option<HttpTransportProfile>,
    pub ceilings: Constraints,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportProfile {
    pub mode: String,
    pub bindings: Vec<HttpTransportBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportBinding {
    pub consumer: String,
    pub alias: String,
    pub constraints: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTransportConstraints {
    pub schema: String,
    pub origins: Vec<HttpOriginConstraint>,
    pub methods: Vec<String>,
    pub request_headers: RequestHeaderConstraints,
    pub response_headers: ResponseHeaderConstraints,
    pub max_url_bytes: u64,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub max_timeout_ms: u64,
    pub max_concurrency: u32,
    pub redirects: String,
    pub credential_bindings: Vec<HttpCredentialBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOriginConstraint {
    pub id: String,
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_prefixes: Vec<String>,
    pub dns: HttpDnsConstraint,
    pub tls: HttpTlsConstraint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpDnsConstraint {
    pub policy: String,
    pub cidrs: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpTlsConstraint {
    pub minimum_version: String,
    pub server_name: String,
    pub peer_spki_sha256: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHeaderConstraints {
    pub allowed_names: Vec<String>,
    pub max_count: u32,
    pub max_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseHeaderConstraints {
    pub exposed_names: Vec<String>,
    pub max_count: u32,
    pub max_total_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpCredentialBinding {
    pub handle: String,
    pub origin_id: String,
    pub header_name: String,
    pub value_prefix: String,
    pub placement: String,
}

/// Immutable local capacity supplied by the operator. Signed component
/// authority and this capacity are enforced independently; the effective
/// HTTP authority is their intersection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOperatorCapacity {
    pub enabled: bool,
    pub allowed_origins: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_request_headers: Vec<String>,
    pub allowed_response_headers: Vec<String>,
    pub allowed_cidrs: Vec<String>,
    pub credential_handles: Vec<String>,
    pub max_url_bytes: u64,
    pub max_request_body_bytes: u64,
    pub max_response_body_bytes: u64,
    pub max_request_header_count: u32,
    pub max_request_header_bytes: u64,
    pub max_response_header_count: u32,
    pub max_response_header_bytes: u64,
    pub max_timeout_ms: u64,
    pub max_concurrency: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub consumer: String,
    pub authority_component_digest: Digest,
    pub principal_seed: Digest,
    pub scoped_component_digest: Digest,
    pub host_imports: Vec<HostImport>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostImport {
    pub alias: String,
    pub source_import: String,
    pub capability: String,
    pub scope: String,
    pub constraints: Digest,
}

#[derive(Serialize)]
pub struct PrincipalSeedMaterial<'a> {
    pub schema: &'static str,
    pub consumer: &'a str,
    pub authority_component_digest: Digest,
}

#[derive(Serialize)]
pub struct HostImportAliasMaterial<'a> {
    pub schema: &'static str,
    pub consumer: &'a str,
    pub authority_component_digest: Digest,
    pub capability: &'a str,
    pub source_import: &'a str,
}

pub fn principal_seed(consumer: &str, authority_component_digest: Digest) -> Result<Digest> {
    Ok(Digest::of(&canonical_json(&PrincipalSeedMaterial {
        schema: "wasm-biotic.principal-seed.v1",
        consumer,
        authority_component_digest,
    })?))
}

pub fn host_import_alias(
    consumer: &str,
    authority_component_digest: Digest,
    capability: &str,
    source_import: &str,
) -> Result<String> {
    let digest = Digest::of(&canonical_json(&HostImportAliasMaterial {
        schema: "wasm-biotic.host-import-alias-material.v1",
        consumer,
        authority_component_digest,
        capability,
        source_import,
    })?);
    Ok(format!("wasm-biotic:factory/host-{}@0.1.0", digest.hex()))
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIndex {
    pub certification_digest: Digest,
    pub certified_kernel_tcb_inventory_digest: Digest,
    pub package_schema: String,
    pub graph_manifest_digest: Digest,
    pub root_authority_digest: Digest,
    pub root_executable_digest: Digest,
    pub validation_report_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationStatement {
    pub schema: String,
    pub graph_manifest_digest: Digest,
    pub native_tcb_inventory_digest: Digest,
    pub wit_package_digest: Digest,
    pub metadata_digest: Digest,
    pub raw_artifacts: BTreeMap<String, Digest>,
    pub derived_artifacts: BTreeMap<String, Digest>,
    pub derivation_descriptor_digest: Digest,
    pub substrate_profile_digest: Digest,
    pub wit_world_digests: BTreeMap<String, Digest>,
    pub composition_configuration_digests: Vec<Digest>,
    pub constraint_digests: Vec<Digest>,
    pub validation_report_digest: Digest,
    pub validator_identity: String,
    pub validator_version: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificationSignature {
    pub algorithm: String,
    pub signature_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub schema: String,
    pub certifier_key_id: Digest,
    pub statement: CertificationStatement,
    pub signature: CertificationSignature,
}

#[derive(Serialize)]
pub struct SigningPayload<'a> {
    pub certifier_key_id: Digest,
    pub schema: &'static str,
    pub statement: &'a CertificationStatement,
}

pub fn parse_canonical<T>(bytes: &[u8], label: &str) -> Result<T>
where
    T: DeserializeOwned + Serialize,
{
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|error| format!("{label} is not JSON: {error}"))?;
    let canonical = canonical_json(&value)?;
    if canonical != bytes {
        return Err(format!("{label} is not canonical JSON").into());
    }
    let parsed: T = serde_json::from_value(value)?;
    if canonical_json(&parsed)? != bytes {
        return Err(format!("{label} is not a closed canonical representation").into());
    }
    Ok(parsed)
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value)?;
    let mut bytes = Vec::new();
    write_value(&value, &mut bytes)?;
    Ok(bytes)
}

fn write_value(value: &serde_json::Value, output: &mut Vec<u8>) -> Result<()> {
    match value {
        serde_json::Value::Null => output.extend_from_slice(b"null"),
        serde_json::Value::Bool(value) => {
            output.extend_from_slice(if *value { b"true" } else { b"false" });
        }
        serde_json::Value::Number(value) => {
            if value.is_f64() {
                return Err("floating-point values are outside canonical JSON".into());
            }
            output.extend_from_slice(value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => output.extend_from_slice(&serde_json::to_vec(value)?),
        serde_json::Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(value, output)?;
            }
            output.push(b']');
        }
        serde_json::Value::Object(values) => {
            output.push(b'{');
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_value(&serde_json::Value::String(key.clone()), output)?;
                output.push(b':');
                write_value(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

pub fn decode_hex(value: &str, length: usize, label: &str) -> Result<Vec<u8>> {
    if value.len() != length * 2
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} is not {length}-byte lowercase hexadecimal").into());
    }
    (0..length)
        .map(|index| {
            u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
                .map_err(|error| -> AnyError { Box::new(error) })
        })
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut output, "{byte:02x}").expect("string formatting cannot fail");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_json_sorts_nested_object_keys() {
        let value = serde_json::json!({"z": 1, "a": {"d": 2, "b": 3}});
        assert_eq!(
            canonical_json(&value).unwrap(),
            br#"{"a":{"b":3,"d":2},"z":1}"#
        );
    }

    #[test]
    fn digest_round_trip_is_closed() {
        let digest = Digest::of(b"independent substrate");
        assert_eq!(digest.to_string().parse::<Digest>().unwrap(), digest);
        assert!(digest.hex().bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn r2_principal_and_alias_derivation_are_canonical_and_domain_separated() {
        let authority = format!("sha256:{}", "11".repeat(32))
            .parse::<Digest>()
            .unwrap();
        assert_eq!(
            principal_seed("worker-router", authority).unwrap().hex(),
            "1736b0f8fb155133c0ffe4e14fd11462848851ffe582b929163cf716e58581de"
        );
        assert_eq!(
            host_import_alias(
                "worker-router",
                authority,
                "component-runner",
                "wasm-biotic:factory/component-runner@0.1.0",
            )
            .unwrap(),
            "wasm-biotic:factory/host-86d567641e83d46313951e785fcb35b8bcdb63cdd05443c7ea0f19cccff372d1@0.1.0"
        );
    }
}
