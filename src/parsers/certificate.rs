use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use std::path::Path;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

#[derive(Debug)]
#[allow(dead_code)]
pub struct CertInfo {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub key_size_bits: u32,
    pub subject: String,
}

pub fn parse_pem_file(path: &Path) -> Result<CertInfo> {
    let content = std::fs::read(path)
        .with_context(|| format!("Failed to read certificate {}", path.display()))?;
    parse_pem_bytes(&content)
}

pub fn parse_pem_bytes(data: &[u8]) -> Result<CertInfo> {
    let (_, pem) = parse_x509_pem(data).map_err(|e| anyhow::anyhow!("PEM parse error: {}", e))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("X509 parse error: {}", e))?;

    let not_before = cert.validity().not_before.to_datetime();
    let not_after = cert.validity().not_after.to_datetime();

    let key_size_bits = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => rsa.key_size() as u32,
        Ok(PublicKey::EC(_)) => {
            // For EC keys, estimate from the algorithm parameters OID
            if let Some(params) = &cert.public_key().algorithm.parameters {
                if let Ok(oid) = params.as_oid() {
                    let oid_str = oid.to_string();
                    match oid_str.as_str() {
                        "1.2.840.10045.3.1.7" => 256, // P-256
                        "1.3.132.0.34" => 384,         // P-384
                        "1.3.132.0.35" => 521,         // P-521
                        _ => 256,
                    }
                } else {
                    256
                }
            } else {
                256
            }
        }
        _ => 0,
    };

    let subject = cert.subject().to_string();

    Ok(CertInfo {
        not_before: DateTime::from_timestamp(not_before.unix_timestamp(), 0)
            .unwrap_or_default(),
        not_after: DateTime::from_timestamp(not_after.unix_timestamp(), 0)
            .unwrap_or_default(),
        key_size_bits,
        subject,
    })
}

const PEM_KEY_HEADERS: &[&str] = &[
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN EC PRIVATE KEY-----",
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",
];

/// Validate that a file contains a PEM-encoded private key.
/// Returns Ok(()) if valid, Err with description if not.
pub fn validate_pem_key_file(path: &Path) -> Result<()> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read key file {}", path.display()))?;
    let trimmed = content.trim();
    if PEM_KEY_HEADERS.iter().any(|h| trimmed.starts_with(h)) {
        Ok(())
    } else {
        anyhow::bail!("File does not contain a recognized PEM private key header")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_invalid_pem() {
        let result = parse_pem_bytes(b"not a certificate");
        assert!(result.is_err());
    }
}
