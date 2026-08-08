use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

const PREFIX: &str = "sha256:";
const BYTE_COUNT: usize = 32;
const HEX_COUNT: usize = BYTE_COUNT * 2;

/// A validated SHA-256 content digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest([u8; BYTE_COUNT]);

impl Sha256Digest {
    /// Hashes the exact supplied bytes.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Sha256::digest(bytes).into())
    }

    /// Returns the raw 32-byte digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; BYTE_COUNT] {
        &self.0
    }
}

impl Display for Sha256Digest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(PREFIX)?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl FromStr for Sha256Digest {
    type Err = DigestParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let hex = value
            .strip_prefix(PREFIX)
            .ok_or(DigestParseError::MissingPrefix)?;
        if hex.len() != HEX_COUNT {
            return Err(DigestParseError::WrongLength(hex.len()));
        }
        let mut bytes = [0_u8; BYTE_COUNT];
        for (position, destination) in bytes.iter_mut().enumerate() {
            let offset = position * 2;
            *destination = u8::from_str_radix(&hex[offset..offset + 2], 16)
                .map_err(|_| DigestParseError::InvalidHex(offset))?;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

/// Failure to parse a canonical SHA-256 digest string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DigestParseError {
    /// The `sha256:` prefix was absent.
    MissingPrefix,
    /// The hexadecimal suffix had the wrong number of bytes.
    WrongLength(usize),
    /// A non-hexadecimal pair began at the supplied offset.
    InvalidHex(usize),
}

impl Display for DigestParseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPrefix => formatter.write_str("digest must start with 'sha256:'"),
            Self::WrongLength(actual) => write!(
                formatter,
                "digest hexadecimal suffix must contain {HEX_COUNT} characters, got {actual}"
            ),
            Self::InvalidHex(offset) => {
                write!(
                    formatter,
                    "digest contains invalid hexadecimal at offset {offset}"
                )
            }
        }
    }
}

impl Error for DigestParseError {}
