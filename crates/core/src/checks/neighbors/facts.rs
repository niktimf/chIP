use std::fmt;
use std::net::Ipv4Addr;

/// A normalized, non-empty PTR record returned by reverse DNS.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PtrName(String);

impl PtrName {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("PTR name is empty")]
pub struct InvalidPtrName;

impl TryFrom<&str> for PtrName {
    type Error = InvalidPtrName;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let normalized = value.trim().trim_end_matches('.');
        if normalized.is_empty() {
            Err(InvalidPtrName)
        } else {
            Ok(Self(normalized.to_string()))
        }
    }
}

impl fmt::Display for PtrName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reverse-DNS lookup outcome. `NotFound` is intentionally distinct from an
/// unavailable resolver/process so reports never claim an absent PTR when the
/// lookup itself failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtrLookup {
    Resolved(PtrName),
    NotFound,
    Unavailable(String),
}

/// What a TLS handshake with a neighbor's `:443` produced.
///
/// `NoCertificate` and `Unavailable` are kept apart like the variants of
/// `PtrLookup`: only the second means the handshake itself could not be run.
#[derive(Debug, Clone)]
pub enum TlsHandshake {
    Presented(TlsHandshakeFacts),
    /// The handshake ran, but its output held no readable certificate.
    NoCertificate,
    /// The handshake could not be run or did not finish; the string is the
    /// cause.
    Unavailable(String),
}

#[derive(Debug, Clone)]
pub struct TlsHandshakeFacts {
    pub cert_cn: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_san: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum NeighborHttps {
    Closed,
    Open { handshake: TlsHandshake },
}

#[derive(Debug, Clone)]
pub struct NeighborProbe {
    pub ip: Ipv4Addr,
    pub ptr: PtrLookup,
    pub https: NeighborHttps,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ptr_name_is_trimmed_and_normalized_from_dns_form() {
        let sut = PtrName::try_from("  vpn1.example.net.  ").unwrap();

        assert_eq!(sut.as_str(), "vpn1.example.net");
    }

    #[test]
    fn a_root_only_ptr_name_is_rejected() {
        let error = PtrName::try_from(".").unwrap_err();

        assert_eq!(error, InvalidPtrName);
    }
}
