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
                        "1.3.132.0.34" => 384,        // P-384
                        "1.3.132.0.35" => 521,        // P-521
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
        not_before: DateTime::from_timestamp(not_before.unix_timestamp(), 0).unwrap_or_default(),
        not_after: DateTime::from_timestamp(not_after.unix_timestamp(), 0).unwrap_or_default(),
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

/// Check if a certificate and private key file form a matching pair.
/// Returns Ok(true) if they match, Ok(false) if mismatch.
/// Returns Err if the files can't be parsed or aren't RSA (non-RSA is skipped by the caller).
pub fn check_cert_key_match(cert_path: &Path, key_path: &Path) -> Result<bool> {
    let cert_modulus = extract_cert_rsa_modulus(cert_path)?;
    let key_modulus = extract_key_rsa_modulus(key_path)?;
    Ok(cert_modulus == key_modulus)
}

fn extract_cert_rsa_modulus(cert_path: &Path) -> Result<Vec<u8>> {
    let content = std::fs::read(cert_path)
        .with_context(|| format!("Failed to read certificate {}", cert_path.display()))?;
    let (_, pem) =
        parse_x509_pem(&content).map_err(|e| anyhow::anyhow!("PEM parse error: {}", e))?;
    let (_, cert) = X509Certificate::from_der(&pem.contents)
        .map_err(|e| anyhow::anyhow!("X509 parse error: {}", e))?;
    match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => Ok(rsa.modulus.to_vec()),
        _ => anyhow::bail!("Not an RSA certificate"),
    }
}

fn extract_key_rsa_modulus(key_path: &Path) -> Result<Vec<u8>> {
    let data = std::fs::read(key_path)
        .with_context(|| format!("Failed to read key file {}", key_path.display()))?;
    let parsed = ::pem::parse(&data).map_err(|e| anyhow::anyhow!("PEM parse error: {}", e))?;
    match parsed.tag() {
        "RSA PRIVATE KEY" => extract_rsa_modulus_pkcs1(parsed.contents()),
        "PRIVATE KEY" => extract_rsa_modulus_pkcs8(parsed.contents()),
        other => anyhow::bail!("Unsupported key type: {}", other),
    }
}

/// Extract RSA modulus from a PKCS#8 DER-encoded private key.
fn extract_rsa_modulus_pkcs8(der: &[u8]) -> Result<Vec<u8>> {
    // PrivateKeyInfo ::= SEQUENCE { version INTEGER, algorithmId SEQUENCE, privateKey OCTET STRING }
    let inner = der_enter_sequence(der)?;
    let rest = der_skip_element(inner)?;
    let rest = der_skip_element(rest)?;
    let (octet_contents, _) = der_read_octet_string(rest)?;
    extract_rsa_modulus_pkcs1(octet_contents)
}

/// Extract RSA modulus from a PKCS#1 DER-encoded RSA private key.
fn extract_rsa_modulus_pkcs1(der: &[u8]) -> Result<Vec<u8>> {
    // RSAPrivateKey ::= SEQUENCE { version INTEGER, modulus INTEGER, ... }
    let inner = der_enter_sequence(der)?;
    let rest = der_skip_element(inner)?;
    let (modulus, _) = der_read_integer(rest)?;
    Ok(modulus.to_vec())
}

fn der_enter_sequence(data: &[u8]) -> Result<&[u8]> {
    anyhow::ensure!(!data.is_empty() && data[0] == 0x30, "Expected SEQUENCE tag");
    let (len, hdr) = der_read_length(&data[1..])?;
    anyhow::ensure!(data.len() >= 1 + hdr + len, "SEQUENCE data too short");
    Ok(&data[1 + hdr..1 + hdr + len])
}

fn der_skip_element(data: &[u8]) -> Result<&[u8]> {
    anyhow::ensure!(!data.is_empty(), "Unexpected end of DER data");
    let (len, hdr) = der_read_length(&data[1..])?;
    let total = 1 + hdr + len;
    anyhow::ensure!(data.len() >= total, "Element data too short");
    Ok(&data[total..])
}

fn der_read_integer(data: &[u8]) -> Result<(&[u8], &[u8])> {
    anyhow::ensure!(!data.is_empty() && data[0] == 0x02, "Expected INTEGER tag");
    let (len, hdr) = der_read_length(&data[1..])?;
    let start = 1 + hdr;
    let end = start + len;
    anyhow::ensure!(data.len() >= end, "INTEGER data too short");
    Ok((&data[start..end], &data[end..]))
}

fn der_read_octet_string(data: &[u8]) -> Result<(&[u8], &[u8])> {
    anyhow::ensure!(
        !data.is_empty() && data[0] == 0x04,
        "Expected OCTET STRING tag"
    );
    let (len, hdr) = der_read_length(&data[1..])?;
    let start = 1 + hdr;
    let end = start + len;
    anyhow::ensure!(data.len() >= end, "OCTET STRING data too short");
    Ok((&data[start..end], &data[end..]))
}

fn der_read_length(data: &[u8]) -> Result<(usize, usize)> {
    anyhow::ensure!(!data.is_empty(), "Empty length field");
    if data[0] < 0x80 {
        Ok((data[0] as usize, 1))
    } else {
        let num = (data[0] & 0x7f) as usize;
        anyhow::ensure!(data.len() >= 1 + num, "Length bytes missing");
        let mut len = 0usize;
        for i in 0..num {
            len = (len << 8) | data[1 + i] as usize;
        }
        Ok((len, 1 + num))
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
