//! Ed25519 authorization: binds the executable's ID to the original USB seal.
//!
//! The signing key exists only in the provisioning authority. Distributed
//! applications contain the public verifying key, never the signing key.
use std::{fs, io::Write, path::Path};
use anyhow::{ensure, Context, Result};
use chrono::Utc;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{InstallationSeal, SealPolicy};

const LICENSE_VERSION: u16 = 1;
const LICENSE_MAGIC: &[u8; 8] = b"DSLIC001";
const SIGN_DOMAIN: &[u8] = b"disk-seal/installation-authorization/v1\0";
const MAX_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LicenseClaims {
    pub format_version: u16,
    pub application_id: String,
    pub installation_id: String,
    pub authorized_seal_sha256: String,
    pub issued_at_utc: String,
    pub assigned_to: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedLicense {
    pub claims: LicenseClaims,
    pub signature_hex: String,
}

pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut OsRng)
}

impl SignedLicense {
    /// Only the issuer calls this method, with a private key stored outside
    /// USB installations and outside distributed applications.
    pub fn issue(
        binary_seal: &[u8],
        assigned_to: &str,
        private_key: &SigningKey,
    ) -> Result<Self> {
        let seal = InstallationSeal::from_binary(binary_seal)?;
        ensure!(seal.policy == SealPolicy::portable_usb(),
            "la autorización exige la política USB estricta");
        ensure!(!assigned_to.trim().is_empty() && assigned_to.len() <= 256,
            "el titular debe identificarse");
        let claims = LicenseClaims {
            format_version: LICENSE_VERSION,
            application_id: seal.application_id,
            installation_id: seal.installation_id,
            authorized_seal_sha256: crate::hex(&Sha256::digest(binary_seal)),
            issued_at_utc: Utc::now().to_rfc3339(),
            assigned_to: assigned_to.trim().to_owned(),
        };
        let data = signing_bytes(&claims)?;
        let sig: Signature = private_key.sign(&data);
        Ok(Self {
            claims,
            signature_hex: crate::hex(&sig.to_bytes()),
        })
    }

    /// Cryptographically validate the entire seal's exact bytes and the
    /// separately embedded executable ID. No online connection is required.
    pub fn verify(
        &self,
        binary_seal: &[u8],
        embedded_installation_id: &str,
        expected_app_id: &str,
        trusted_public_key: &VerifyingKey,
    ) -> Result<InstallationSeal> {
        ensure!(self.claims.format_version == LICENSE_VERSION, "versión de licencia inválida");
        ensure!(
            self.claims.application_id == expected_app_id,
            "licencia emitida para otra aplicación"
        );
        ensure!(
            self.claims.installation_id == embedded_installation_id,
            "el ejecutable tiene una identidad distinta de la licencia"
        );
        ensure!(
            self.claims.authorized_seal_sha256 == crate::hex(&Sha256::digest(binary_seal)),
            "el sello fue alterado o no pertenece a esta licencia"
        );
        let signature = crate::decode_hex(&self.signature_hex)?;
        ensure!(signature.len() == 64, "firma de longitud inválida");
        let signature = Signature::from_slice(&signature)?;
        trusted_public_key
            .verify_strict(&signing_bytes(&self.claims)?, &signature)
            .context("firma de licencia no autorizada")?;
        let seal = InstallationSeal::from_binary(binary_seal)?;
        ensure!(
            seal.application_id == expected_app_id &&
            seal.installation_id == embedded_installation_id &&
            seal.policy == SealPolicy::portable_usb(),
            "el sello no coincide con el ejecutable o la política USB"
        );
        Ok(seal)
    }

    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        ciborium::into_writer(self, &mut body)?;
        ensure!(body.len() <= MAX_BYTES, "licencia demasiado grande");
        let mut file = Vec::with_capacity(12 + body.len());
        file.extend_from_slice(LICENSE_MAGIC);
        file.extend_from_slice(&(body.len() as u32).to_le_bytes());
        file.extend_from_slice(&body);
        Ok(file)
    }

    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 12 && bytes.len() <= MAX_BYTES + 12, "licencia truncada o excesiva");
        ensure!(&bytes[..8] == LICENSE_MAGIC, "cabecera de licencia inválida");
        let length = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(length == bytes.len() - 12, "longitud de licencia inconsistente");
        ciborium::from_reader(&bytes[12..])
            .context("licencia binaria corrupta")
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = fs::read(path).with_context(|| format!("licencia ausente: {}", path.display()))?;
        Self::from_binary(&bytes)
    }

    pub fn save_new(&self, path: &Path) -> Result<()> {
        let bytes = self.to_binary()?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(path)
            .with_context(|| format!("la licencia ya existe o no es accesible: {}", path.display()))?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        Ok(())
    }
}

fn signing_bytes(claims: &LicenseClaims) -> Result<Vec<u8>> {
    ensure!(!claims.application_id.is_empty() && !claims.installation_id.is_empty(),
        "identidad de licencia vacía");
    let mut content = Vec::with_capacity(512);
    content.extend_from_slice(SIGN_DOMAIN);
    let version = claims.format_version.to_string();
    for part in [
        version.as_str(),
        &claims.application_id,
        &claims.installation_id,
        &claims.authorized_seal_sha256,
        &claims.issued_at_utc,
        &claims.assigned_to,
    ] {
        let value = part.as_bytes();
        ensure!(value.len() <= 4096, "campo de licencia excesivamente largo");
        content.extend_from_slice(&(value.len() as u32).to_le_bytes());
        content.extend_from_slice(value);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SealPolicy, StorageIdentity};
    use std::path::Path;

    fn fake_identity() -> StorageIdentity {
        StorageIdentity {
            physical_serial: Some("USB-ORIGINAL".into()),
            volume_serial: Some("A1B2C3D4".into()),
            filesystem: Some("NTFS".into()),
            removable: true,
        }
    }

    fn fixture() -> (Vec<u8>, String, SigningKey) {
        let seal = InstallationSeal::create_with_identity(
            "demo", "1.0", Path::new("unused"),
            SealPolicy::portable_usb(), &fake_identity()
        ).unwrap();
        let id = seal.installation_id.clone();
        (seal.to_binary().unwrap(), id, generate_signing_key())
    }

    #[test]
    fn genuine_license_passes_and_foreign_key_fails() {
        let (seal, id, key) = fixture();
        let license = SignedLicense::issue(&seal, "Juan", &key).unwrap();
        assert!(license.verify(&seal, &id, "demo", &key.verifying_key()).is_ok());
        assert!(license.verify(&seal, &id, "demo", &generate_signing_key().verifying_key()).is_err());
    }

    #[test]
    fn copied_executable_id_and_tampered_seal_are_rejected() {
        let (seal, id, key) = fixture();
        let license = SignedLicense::issue(&seal, "Juan", &key).unwrap();
        let cloned_id = "DS-0123456789ABCDEF0123456789ABCDEF";
        assert_ne!(id, cloned_id);
        assert!(license.verify(&seal, cloned_id, "demo", &key.verifying_key()).is_err());
        let mut altered_seal = seal.clone();
        let end = altered_seal.len() - 1;
        altered_seal[end] ^= 0x01;
        assert!(license.verify(&altered_seal, &id, "demo", &key.verifying_key()).is_err());
    }

    #[test]
    fn modified_license_claims_fail_strict_signature_check() {
        let (seal, id, key) = fixture();
        let mut license = SignedLicense::issue(&seal, "Juan", &key).unwrap();
        license.claims.assigned_to = "Otro usuario".into();
        assert!(license.verify(&seal, &id, "demo", &key.verifying_key()).is_err());
        let mut license = SignedLicense::issue(&seal, "Juan", &key).unwrap();
        license.claims.issued_at_utc = "2080-01-01T00:00:00Z".into();
        assert!(license.verify(&seal, &id, "demo", &key.verifying_key()).is_err());
    }

    #[test]
    fn binary_license_detects_truncation_and_bad_headers() {
        let (seal, _, key) = fixture();
        let license = SignedLicense::issue(&seal, "Juan", &key).unwrap();
        let bytes = license.to_binary().unwrap();
        assert_eq!(SignedLicense::from_binary(&bytes).unwrap().claims.assigned_to, "Juan");
        assert!(SignedLicense::from_binary(&bytes[..bytes.len() - 1]).is_err());
        let mut corrupt = bytes;
        corrupt[0] = b'X';
        assert!(SignedLicense::from_binary(&corrupt).is_err());
    }
}
