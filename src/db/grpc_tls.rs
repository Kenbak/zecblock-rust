//! Optional mutual TLS for connections to a Zakura indexer gRPC listener.
//!
//! Zakura serves plaintext indexer gRPC on loopback only; any other address
//! requires mutual TLS (`[rpc.indexer_tls]`). To reach a remote node, set
//! `ZEBRA_GRPC_URL=https://host:8230` and:
//!
//! - `ZEBRA_GRPC_TLS_CA_FILE`: PEM CA that signed the node's server certificate.
//!   Only this CA is trusted; system roots are not used.
//! - `ZEBRA_GRPC_TLS_CERT_FILE` / `ZEBRA_GRPC_TLS_KEY_FILE`: our PEM client
//!   certificate and key, signed by the CA the operator lists in `client_ca_file`.
//! - `ZEBRA_GRPC_TLS_DOMAIN` (optional): name to verify in the server
//!   certificate when it differs from the URL host (e.g. connecting by IP).
//!
//! Plain `http://` URLs keep the existing loopback behaviour. Mixing them is
//! refused: TLS settings with an `http://` URL, or `https://` without all three
//! files, are configuration errors rather than silent downgrades.

use std::path::{Path, PathBuf};
use tonic::transport::{Certificate, ClientTlsConfig, Endpoint, Identity};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GrpcTls {
    pub ca_file: Option<PathBuf>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub domain: Option<String>,
}

fn non_empty(value: Option<String>) -> Option<String> {
    value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
}

impl GrpcTls {
    pub fn from_env() -> Self {
        let var = |name: &str| non_empty(std::env::var(name).ok());
        Self {
            ca_file: var("ZEBRA_GRPC_TLS_CA_FILE").map(PathBuf::from),
            cert_file: var("ZEBRA_GRPC_TLS_CERT_FILE").map(PathBuf::from),
            key_file: var("ZEBRA_GRPC_TLS_KEY_FILE").map(PathBuf::from),
            domain: var("ZEBRA_GRPC_TLS_DOMAIN"),
        }
    }

    fn any_set(&self) -> bool {
        self.ca_file.is_some()
            || self.cert_file.is_some()
            || self.key_file.is_some()
            || self.domain.is_some()
    }

    /// Validate the combination for `url` without reading files.
    pub fn check(&self, url: &str) -> Result<bool, String> {
        let https = url.starts_with("https://");
        if !https {
            if self.any_set() {
                return Err("gRPC TLS settings require an https:// ZEBRA_GRPC_URL".into());
            }
            return Ok(false);
        }
        if self.ca_file.is_none() || self.cert_file.is_none() || self.key_file.is_none() {
            return Err(
                "https:// gRPC requires ZEBRA_GRPC_TLS_CA_FILE, ZEBRA_GRPC_TLS_CERT_FILE and ZEBRA_GRPC_TLS_KEY_FILE"
                    .into(),
            );
        }
        Ok(true)
    }

    fn read(path: &Path, what: &str) -> Result<Vec<u8>, String> {
        // The path is configuration, not a secret; contents are never logged.
        std::fs::read(path).map_err(|e| {
            format!(
                "cannot read gRPC TLS {what} {}: {}",
                path.display(),
                e.kind()
            )
        })
    }

    /// Endpoint for `url`, with mutual TLS when the URL is https://.
    pub fn endpoint(&self, url: &str) -> Result<Endpoint, String> {
        let use_tls = self.check(url)?;
        let endpoint =
            Endpoint::from_shared(url.to_owned()).map_err(|e| format!("Invalid gRPC URL: {e}"))?;
        if !use_tls {
            return Ok(endpoint);
        }
        let ca = Self::read(self.ca_file.as_deref().expect("checked"), "CA")?;
        let cert = Self::read(self.cert_file.as_deref().expect("checked"), "certificate")?;
        let key = Self::read(self.key_file.as_deref().expect("checked"), "key")?;
        let mut tls = ClientTlsConfig::new()
            .ca_certificate(Certificate::from_pem(ca))
            .identity(Identity::from_pem(cert, key));
        if let Some(domain) = &self.domain {
            tls = tls.domain_name(domain.clone());
        }
        endpoint
            .tls_config(tls)
            .map_err(|e| format!("invalid gRPC TLS configuration: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> GrpcTls {
        GrpcTls {
            ca_file: Some("/ca.pem".into()),
            cert_file: Some("/client.pem".into()),
            key_file: Some("/client.key".into()),
            domain: None,
        }
    }

    #[test]
    fn plaintext_loopback_is_unchanged() {
        assert_eq!(GrpcTls::default().check("http://127.0.0.1:8230"), Ok(false));
    }

    #[test]
    fn https_requires_all_three_files() {
        assert_eq!(full().check("https://node.example:8230"), Ok(true));
        let mut missing_key = full();
        missing_key.key_file = None;
        assert!(missing_key.check("https://node.example:8230").is_err());
        assert!(GrpcTls::default()
            .check("https://node.example:8230")
            .is_err());
    }

    #[test]
    fn tls_settings_never_silently_downgrade_to_plaintext() {
        assert!(full().check("http://node.example:8230").is_err());
        let domain_only = GrpcTls {
            domain: Some("node".into()),
            ..Default::default()
        };
        assert!(domain_only.check("http://127.0.0.1:8230").is_err());
    }

    #[test]
    fn unreadable_files_name_the_path_but_not_contents() {
        let err = full().endpoint("https://node.example:8230").unwrap_err();
        assert!(err.contains("/ca.pem"), "{err}");
    }
}
