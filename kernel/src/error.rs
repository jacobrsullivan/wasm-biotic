use crate::Sha256Digest;
use std::error::Error;
use std::fmt::{Display, Formatter};

/// Failure returned while validating, linking, or invoking a graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelError {
    /// Persistent state or content storage failed.
    Persistence(String),
    /// Explicit local configuration was invalid.
    InvalidConfiguration(String),
    /// Manifest bytes did not decode as the declared JSON shape.
    ManifestDecode(String),
    /// The manifest-byte digest did not match the expected digest.
    ManifestDigestMismatch {
        /// Digest supplied by the caller.
        expected: Sha256Digest,
        /// Digest recomputed from exact bytes.
        actual: Sha256Digest,
    },
    /// The schema identifier is unsupported.
    UnsupportedSchema(String),
    /// The typed ABI identifier is unsupported.
    UnsupportedAbi(String),
    /// The graph has no component nodes.
    EmptyGraph,
    /// A node identifier or port name is empty.
    EmptyIdentifier(&'static str),
    /// Two nodes use the same identifier.
    DuplicateNode(String),
    /// A referenced node does not exist.
    UnknownNode(String),
    /// The entry point does not name a declared node export.
    InvalidEntryPoint,
    /// More than one binding targets the same consumer import.
    DuplicateImport {
        /// Importing node.
        node: String,
        /// Imported function name.
        import: String,
    },
    /// A typed edge violates dependency-first manifest ordering.
    DependencyOrder {
        /// Importing node.
        consumer: String,
        /// Target node.
        target: String,
    },
    /// A typed edge names an export other than the target's declared export.
    UnknownExport {
        /// Target node.
        node: String,
        /// Exported function name.
        export: String,
    },
    /// Bytes for a declared digest were absent.
    MissingComponent(Sha256Digest),
    /// Supplied bytes did not match their map key or manifest digest.
    ComponentDigestMismatch {
        /// Node whose bytes failed verification.
        node: String,
        /// Digest declared in the manifest.
        expected: Sha256Digest,
        /// Digest recomputed from exact bytes.
        actual: Sha256Digest,
    },
    /// Bytes were supplied for a digest absent from the manifest.
    UnlistedComponent(Sha256Digest),
    /// One or more validated native interfaces have no implementation here.
    HostInterfacesUnavailable,
    /// A resource bound was zero.
    InvalidLimit {
        /// Bound name.
        name: &'static str,
        /// Rejected value.
        value: u64,
    },
    /// A bound could not fit the platform representation.
    LimitOutOfRange {
        /// Bound name.
        name: &'static str,
        /// Rejected value.
        value: u64,
    },
    /// Wasmtime engine initialization failed.
    Engine(String),
    /// Component compilation or validation failed.
    Compile {
        /// Manifest node identifier.
        node: String,
        /// Engine diagnostic.
        reason: String,
    },
    /// Typed import linking failed.
    Link {
        /// Manifest node identifier.
        node: String,
        /// Engine diagnostic.
        reason: String,
    },
    /// Component instantiation failed.
    Instantiate {
        /// Manifest node identifier.
        node: String,
        /// Engine diagnostic.
        reason: String,
    },
    /// The declared typed export was absent or had the wrong type.
    Export {
        /// Manifest node identifier.
        node: String,
        /// Engine diagnostic.
        reason: String,
    },
    /// A component invocation trapped or failed.
    Invoke {
        /// Manifest node identifier.
        node: String,
        /// Engine diagnostic.
        reason: String,
        /// Whether deterministic fuel was exhausted.
        fuel_exhausted: bool,
        /// Fuel consumed before termination.
        fuel_consumed: u64,
    },
    /// A runtime mutex was poisoned.
    Synchronization(&'static str),
}

impl Display for KernelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Persistence(reason) => write!(formatter, "persistence failed: {reason}"),
            Self::InvalidConfiguration(reason) => {
                write!(formatter, "invalid local configuration: {reason}")
            }
            Self::ManifestDecode(reason) => write!(formatter, "manifest decode failed: {reason}"),
            Self::ManifestDigestMismatch { expected, actual } => write!(
                formatter,
                "manifest digest mismatch: expected {expected}, got {actual}"
            ),
            Self::UnsupportedSchema(schema) => {
                write!(formatter, "unsupported manifest schema '{schema}'")
            }
            Self::UnsupportedAbi(abi) => write!(formatter, "unsupported typed ABI '{abi}'"),
            Self::EmptyGraph => formatter.write_str("graph must contain at least one node"),
            Self::EmptyIdentifier(kind) => write!(formatter, "{kind} must not be empty"),
            Self::DuplicateNode(node) => write!(formatter, "duplicate node '{node}'"),
            Self::UnknownNode(node) => write!(formatter, "unknown node '{node}'"),
            Self::InvalidEntryPoint => formatter.write_str("entry point is not a declared export"),
            Self::DuplicateImport { node, import } => {
                write!(formatter, "node '{node}' has duplicate import binding '{import}'")
            }
            Self::DependencyOrder { consumer, target } => write!(
                formatter,
                "edge '{consumer}' -> '{target}' violates dependency-first ordering"
            ),
            Self::UnknownExport { node, export } => {
                write!(formatter, "node '{node}' does not declare export '{export}'")
            }
            Self::MissingComponent(digest) => {
                write!(formatter, "component bytes are missing for {digest}")
            }
            Self::ComponentDigestMismatch {
                node,
                expected,
                actual,
            } => write!(
                formatter,
                "node '{node}' digest mismatch: expected {expected}, got {actual}"
            ),
            Self::UnlistedComponent(digest) => {
                write!(formatter, "component bytes for unlisted digest {digest}")
            }
            Self::HostInterfacesUnavailable => formatter.write_str(
                "this executable slice validates native interface declarations but does not implement them",
            ),
            Self::InvalidLimit { name, value } => {
                write!(formatter, "resource limit '{name}' must be positive, got {value}")
            }
            Self::LimitOutOfRange { name, value } => {
                write!(formatter, "resource limit '{name}' is out of range: {value}")
            }
            Self::Engine(reason) => write!(formatter, "engine setup failed: {reason}"),
            Self::Compile { node, reason } => {
                write!(formatter, "node '{node}' failed component validation: {reason}")
            }
            Self::Link { node, reason } => {
                write!(formatter, "node '{node}' failed typed linking: {reason}")
            }
            Self::Instantiate { node, reason } => {
                write!(formatter, "node '{node}' failed instantiation: {reason}")
            }
            Self::Export { node, reason } => {
                write!(formatter, "node '{node}' has an invalid typed export: {reason}")
            }
            Self::Invoke {
                node,
                reason,
                fuel_exhausted,
                fuel_consumed,
            } => write!(
                formatter,
                "node '{node}' invocation failed (fuel_exhausted={fuel_exhausted}, fuel_consumed={fuel_consumed}): {reason}"
            ),
            Self::Synchronization(context) => {
                write!(formatter, "runtime synchronization failed at {context}")
            }
        }
    }
}

impl Error for KernelError {}
