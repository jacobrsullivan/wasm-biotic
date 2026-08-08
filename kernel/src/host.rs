use serde::{Deserialize, Serialize};

/// The complete set of interface names that may cross the native boundary.
pub const HOST_INTERFACE_ALLOWLIST: [&str; 8] = [
    "activation",
    "audit-log",
    "blob-store",
    "clock",
    "component-runner",
    "http-transport",
    "key-service",
    "transaction-store",
];

/// A closed native-boundary interface identifier.
///
/// Deserialization rejects every name not represented here. The production
/// root runtime implements these names only as the generic substrate mechanisms
/// and exact profiles recorded by the native-boundary inventory. The small
/// scalar graph harness rejects host-bound manifests instead of supplying a
/// second implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostInterface {
    /// Atomic graph activation mechanics.
    Activation,
    /// Opaque append-only bytes.
    AuditLog,
    /// Immutable content-addressed bytes.
    BlobStore,
    /// Time reads and requested wake delivery.
    Clock,
    /// Digest-selected component invocation.
    ComponentRunner,
    /// Grant-bounded byte transport.
    HttpTransport,
    /// Non-exportable key operations.
    KeyService,
    /// Atomic opaque-reference updates.
    TransactionStore,
}

impl HostInterface {
    /// Every value admitted at the native boundary.
    pub const ALL: [Self; 8] = [
        Self::Activation,
        Self::AuditLog,
        Self::BlobStore,
        Self::Clock,
        Self::ComponentRunner,
        Self::HttpTransport,
        Self::KeyService,
        Self::TransactionStore,
    ];

    /// Returns the exact WIT interface name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Activation => "activation",
            Self::AuditLog => "audit-log",
            Self::BlobStore => "blob-store",
            Self::Clock => "clock",
            Self::ComponentRunner => "component-runner",
            Self::HttpTransport => "http-transport",
            Self::KeyService => "key-service",
            Self::TransactionStore => "transaction-store",
        }
    }
}
