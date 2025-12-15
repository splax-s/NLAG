//! Certificate generation and management
//!
//! Provides utilities for generating certificates, primarily for development
//! and testing. Production deployments should use proper PKI infrastructure.

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use std::time::Duration;

use crate::error::{NlagError, Result};

/// Information about a generated certificate
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// PEM-encoded certificate
    pub cert_pem: String,
    /// PEM-encoded private key
    pub key_pem: String,
    /// Certificate fingerprint (SHA-256)
    pub fingerprint: String,
}

/// Generate a self-signed certificate for development/testing
///
/// # Arguments
/// * `common_name` - The CN for the certificate (e.g., "nlag-edge.local")
/// * `san_dns` - Subject Alternative Names (DNS)
/// * `san_ips` - Subject Alternative Names (IP addresses)
/// * `validity_days` - How long the certificate should be valid
/// * `is_ca` - Whether this is a CA certificate
///
/// # Security Note
/// Self-signed certificates should ONLY be used for development.
/// Production deployments must use certificates from a trusted CA.
pub fn generate_self_signed_cert(
    common_name: &str,
    san_dns: &[String],
    san_ips: &[std::net::IpAddr],
    validity_days: u32,
    is_ca: bool,
) -> Result<CertificateInfo> {
    let mut params = CertificateParams::default();

    // Set distinguished name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    dn.push(DnType::OrganizationName, "NLAG");
    params.distinguished_name = dn;

    // Set validity
    params.not_before = time::OffsetDateTime::now_utc();
    params.not_after =
        time::OffsetDateTime::now_utc() + Duration::from_secs(validity_days as u64 * 24 * 60 * 60);

    // Set Subject Alternative Names
    let mut sans = Vec::new();
    for dns in san_dns {
        sans.push(SanType::DnsName(dns.clone().try_into().map_err(|e| {
            NlagError::CertificateError(format!("Invalid DNS name: {}", e))
        })?));
    }
    for ip in san_ips {
        sans.push(SanType::IpAddress(*ip));
    }
    // Always include localhost for development
    if san_dns.is_empty() && san_ips.is_empty() {
        sans.push(
            SanType::DnsName("localhost".to_string().try_into().map_err(|e| {
                NlagError::CertificateError(format!("Invalid DNS name: {}", e))
            })?),
        );
        sans.push(SanType::IpAddress(std::net::IpAddr::V4(
            std::net::Ipv4Addr::LOCALHOST,
        )));
        sans.push(SanType::IpAddress(std::net::IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST,
        )));
    }
    params.subject_alt_names = sans;

    // Set key usage
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];

    // CA settings
    if is_ca {
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::CrlSign);
    } else {
        params.is_ca = IsCa::NoCa;
    }

    // Generate key pair
    let key_pair = KeyPair::generate().map_err(|e| {
        NlagError::CertificateError(format!("Failed to generate key pair: {}", e))
    })?;

    // Generate certificate
    let cert = params.self_signed(&key_pair).map_err(|e| {
        NlagError::CertificateError(format!("Failed to generate certificate: {}", e))
    })?;

    // Calculate fingerprint (simplified - in production use proper DER parsing)
    let cert_der = cert.der();
    let fingerprint = format!("{:x}", md5_hash(cert_der));

    Ok(CertificateInfo {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
        fingerprint,
    })
}

/// Simple hash for fingerprint (NOT cryptographically secure - use SHA-256 in production)
fn md5_hash(data: &[u8]) -> u128 {
    // Simple hash for demo - replace with ring::digest::SHA256 in production
    let mut hash: u128 = 0;
    for (i, &byte) in data.iter().enumerate() {
        hash = hash.wrapping_add((byte as u128).wrapping_mul((i as u128).wrapping_add(1)));
    }
    hash
}

/// Load a certificate from PEM files
pub fn load_cert_from_pem(cert_pem: &str, key_pem: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    use rustls_pemfile::{certs, private_key};
    use std::io::BufReader;

    let cert_reader = &mut BufReader::new(cert_pem.as_bytes());
    let certs: Vec<_> = certs(cert_reader)
        .filter_map(|c| c.ok())
        .map(|c| c.to_vec())
        .collect();

    if certs.is_empty() {
        return Err(NlagError::CertificateError(
            "No certificates found in PEM".to_string(),
        ));
    }

    let key_reader = &mut BufReader::new(key_pem.as_bytes());
    let key = private_key(key_reader)
        .map_err(|e| NlagError::CertificateError(format!("Failed to parse key: {}", e)))?
        .ok_or_else(|| NlagError::CertificateError("No private key found in PEM".to_string()))?;

    Ok((certs[0].clone(), key.secret_der().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_self_signed() {
        let info = generate_self_signed_cert("test.local", &[], &[], 1, false).unwrap();

        assert!(info.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(info.key_pem.contains("BEGIN PRIVATE KEY"));
        assert!(!info.fingerprint.is_empty());
    }

    #[test]
    fn test_generate_ca() {
        let info = generate_self_signed_cert("NLAG CA", &[], &[], 365, true).unwrap();

        assert!(info.cert_pem.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn test_load_cert() {
        let info = generate_self_signed_cert("test.local", &[], &[], 1, false).unwrap();
        let result = load_cert_from_pem(&info.cert_pem, &info.key_pem);
        assert!(result.is_ok());
    }
}
