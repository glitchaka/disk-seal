//! Storage identity binding for portable Windows applications.
//!
//! This crate does not grant a license, impersonate a user, or store signing
//! keys. A valid seal must still be accompanied by an authority-signed license
//! in applications requiring authorization.
use std::{fs, io::Write, path::{Path, PathBuf}};
use anyhow::{bail, ensure, Context, Result};
use chrono::{DateTime, FixedOffset, Local};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(windows)]
mod windows;

pub mod authorization;
pub mod executable;

pub use authorization::{generate_signing_key, SignedLicense};
pub use executable::{personalize_executable, read_executable_id};

const BINARY_MAGIC: &[u8; 8] = b"DSSEAL01";
const MAX_SEAL_BYTES: usize = 128 * 1024;

const SEAL_VERSION: u32 = 1;
const HASH_DOMAIN: &[u8] = b"disk-seal/windows/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SealPolicy {
    pub bind_to_volume: bool,
    pub bind_to_physical_device: bool,
    pub require_removable_media: bool,
    pub bind_to_executable: bool,
    pub bind_to_machine: bool,
}

impl Default for SealPolicy {
    fn default() -> Self {
        Self {
            bind_to_volume: true,
            bind_to_physical_device: true,
            require_removable_media: true,
            bind_to_executable: false,
            bind_to_machine: false,
        }
    }
}

impl SealPolicy {
    pub fn portable_usb() -> Self { Self::default() }

    fn validate(&self) -> Result<()> {
        ensure!(self.bind_to_volume || self.bind_to_physical_device,
            "la política requiere al menos una identidad de almacenamiento");
        ensure!(!self.bind_to_machine,
            "la política portátil no puede vincular la instalación al PC anfitrión");
        Ok(())
    }
}

/// Public, non-reversible representation. Never contains raw serial numbers.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationSeal {
    pub seal_format_version: u32,
    pub application_id: String,
    pub application_version: String,
    pub installation_id: String,
    pub created_at: DateTime<FixedOffset>,
    pub storage_fingerprint: String,
    pub nonce: String,
    pub policy: SealPolicy,
    pub identity_sources: Vec<String>,
    pub executable_hash: Option<String>,
}

#[derive(Clone, Debug)]
pub struct VerifiedInstallation {
    pub installation_id: String,
    pub created_at: DateTime<FixedOffset>,
    pub storage_fingerprint: String,
    pub identity_sources: Vec<String>,
}

#[derive(Clone, Debug)]
struct StorageIdentity {
    physical_serial: Option<String>,
    volume_serial: Option<String>,
    filesystem: Option<String>,
    removable: bool,
}

/// Safe diagnostic information without exposing raw drive or volume serials.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StorageInspection {
    pub removable: bool,
    pub has_volume_serial: bool,
    pub has_physical_serial: bool,
    pub filesystem: Option<String>,
    pub strict_usb_compatible: bool,
}

pub fn inspect_storage(executable: &Path) -> Result<StorageInspection> {
    let storage = capture_storage(executable)?;
    let policy = SealPolicy::portable_usb();
    Ok(StorageInspection {
        removable: storage.removable,
        has_volume_serial: storage.volume_serial.is_some(),
        has_physical_serial: storage.physical_serial.is_some(),
        filesystem: storage.filesystem.clone(),
        strict_usb_compatible: check_sources(&storage, &policy).is_ok(),
    })
}

/// Generate a fresh 128-bit identity for a new authorized installation.
/// The same ID must be embedded into its personalized executable.
pub fn new_installation_id() -> String {
    let mut unique = [0u8; 16];
    OsRng.fill_bytes(&mut unique);
    format!("DS-{}", hex(&unique).to_uppercase())
}

impl InstallationSeal {
    /// Build the seal for an already-personalized executable; its embedded
    /// ID remains the immutable installation identity.
    pub fn create_for_personalized_executable(
        app_id: &str,
        app_version: &str,
        executable: &Path,
        policy: SealPolicy,
    ) -> Result<Self> {
        let id = executable::read_executable_id(executable)?;
        let mut seal = Self::create(app_id, app_version, executable, policy)?;
        seal.installation_id = id;
        Ok(seal)
    }

    /// Called once by the installer after extraction, on the original drive.
    /// Create a seal for an existing executable on the USB drive.
    /// The caller must store and authenticate the seal using a separately
    /// signed activation license; this library does not grant authorization.
    pub fn create(
        app_id: &str,
        app_version: &str,
        executable: &Path,
        policy: SealPolicy,
    ) -> Result<Self> {
        let identity = capture_storage(executable)?;
        Self::create_with_identity(app_id, app_version, executable, policy, &identity)
    }

    fn create_with_identity(
        app_id: &str,
        app_version: &str,
        executable: &Path,
        policy: SealPolicy,
        identity: &StorageIdentity,
    ) -> Result<Self> {
        policy.validate()?;
        ensure!(
            !app_id.is_empty()
                && app_id.len() <= 64
                && app_id.bytes().all(|byte| byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.')),
            "application_id no válido"
        );
        ensure!(
            !app_version.is_empty() && app_version.len() <= 128,
            "application_version no válido"
        );
        check_sources(identity, &policy)?;

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let executable_hash = if policy.bind_to_executable {
            Some(hash_file(executable)?)
        } else {
            None
        };

        Ok(Self {
            seal_format_version: SEAL_VERSION,
            application_id: app_id.to_owned(),
            application_version: app_version.to_owned(),
            installation_id: new_installation_id(),
            created_at: Local::now().fixed_offset(),
            storage_fingerprint: hex(&fingerprint(identity, &policy, &nonce)),
            nonce: hex(&nonce),
            identity_sources: source_names(identity, &policy),
            policy,
            executable_hash,
        })
    }

    /// Verify the actual storage identity before enabling the consumer app.
    pub fn verify_current_environment(&self, executable: &Path) -> Result<VerifiedInstallation> {
        let identity = capture_storage(executable)?;
        self.verify_with_identity(executable, &identity)
    }

    /// Verify both storage and application identity (recommended for consumers).
    pub fn verify_for_application(
        &self,
        expected_application_id: &str,
        executable: &Path,
    ) -> Result<VerifiedInstallation> {
        ensure!(
            self.application_id == expected_application_id,
            "el sello no pertenece a la aplicación solicitada"
        );
        self.verify_current_environment(executable)
    }

    fn verify_with_identity(
        &self,
        executable: &Path,
        identity: &StorageIdentity,
    ) -> Result<VerifiedInstallation> {
        ensure!(self.seal_format_version == SEAL_VERSION, "formato de sello no compatible");
        self.policy.validate()?;
        ensure!(!self.installation_id.is_empty(), "Installation ID vacío");
        ensure!(!self.application_id.is_empty(), "application_id vacío");
        ensure!(!self.application_version.is_empty(), "application_version vacío");
        let nonce = decode_hex(&self.nonce)?;
        ensure!(nonce.len() == 32, "nonce inválido");
        check_sources(identity, &self.policy)?;
        let actual_sources = source_names(identity, &self.policy);
        ensure!(
            actual_sources == self.identity_sources,
            "las fuentes de identidad del dispositivo cambiaron"
        );
        let expected = fingerprint(identity, &self.policy, &nonce);
        let pinned = decode_hex(&self.storage_fingerprint)?;
        ensure!(
            pinned.len() == 32 && fixed_time_equal(&expected, &pinned),
            "el volumen o el dispositivo físico no coincide con la instalación original"
        );
        if self.policy.bind_to_executable {
            let pinned = self.executable_hash.as_deref()
                .context("falta el hash del ejecutable sellado")?;
            ensure!(
                hash_file(executable)? == pinned,
                "el ejecutable cambió desde el sellado"
            );
        }
        Ok(VerifiedInstallation {
            installation_id: self.installation_id.clone(),
            created_at: self.created_at,
            storage_fingerprint: self.storage_fingerprint.clone(),
            identity_sources: actual_sources,
        })
    }

    /// The canonical binary seal representation used by signed deployments.
    /// Ed25519 authorizes the exact bytes returned here (including the policy).
    pub fn to_binary(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        ciborium::into_writer(self, &mut bytes)?;
        ensure!(bytes.len() <= MAX_SEAL_BYTES, "sello demasiado grande");
        let mut out = Vec::with_capacity(12 + bytes.len());
        out.extend_from_slice(BINARY_MAGIC);
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&bytes);
        Ok(out)
    }

    pub fn from_binary(bytes: &[u8]) -> Result<Self> {
        ensure!(bytes.len() >= 12 && bytes.len() <= MAX_SEAL_BYTES + 12,
            "sello truncado o demasiado grande");
        ensure!(&bytes[..8] == BINARY_MAGIC, "cabecera de sello inválida");
        let length = u32::from_le_bytes(bytes[8..12].try_into()?) as usize;
        ensure!(length == bytes.len() - 12, "longitud de sello inconsistente");
        ciborium::from_reader(&bytes[12..]).context("sello CBOR corrupto")
    }

    /// Write the binary seal once. A missing/corrupt seal must never be
    /// automatically regenerated on consumer startup.
    pub fn save_binary_new(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let bytes = self.to_binary()?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true)
            .open(path).with_context(|| format!(
                "sello existente o ruta inaccesible: {}", path.display()
            ))?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        Ok(())
    }

    pub fn load_binary(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).with_context(|| format!(
            "sello ausente: {}", path.display()
        ))?;
        Self::from_binary(&bytes)
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        serde_json::from_slice(&fs::read(path)
            .with_context(|| format!("no se pudo leer sello {}", path.display()))?)
            .context("sello ilegible o inválido")
    }

    /// Create a new seal file without overwriting any existing installation.
    pub fn save_new(&self, path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        let mut file = fs::OpenOptions::new().write(true).create_new(true)
            .open(path).with_context(|| format!("sello ya existente o inaccesible: {}", path.display()))?;
        file.write_all(&serde_json::to_vec_pretty(self)?)?;
        file.sync_all()?;
        Ok(())
    }
}

fn source_names(identity: &StorageIdentity, policy: &SealPolicy) -> Vec<String> {
    let mut sources=Vec::new();
    if policy.bind_to_physical_device && identity.physical_serial.is_some() {
        sources.push("storage_device_serial".to_owned());
    }
    if policy.bind_to_volume && identity.volume_serial.is_some() {
        sources.push("volume_serial".to_owned());
    }
    if policy.bind_to_volume && identity.filesystem.is_some() {
        sources.push("filesystem".to_owned());
    }
    sources
}

fn check_sources(identity: &StorageIdentity, policy: &SealPolicy) -> Result<()> {
    if policy.require_removable_media {
        ensure!(identity.removable, "se requiere soporte extraíble");
    }
    if policy.bind_to_volume {
        ensure!(identity.volume_serial.is_some(), "el volumen no informa un serial");
    }
    if policy.bind_to_physical_device {
        ensure!(identity.physical_serial.is_some(),
            "el dispositivo físico no informa serial: no se puede sellar con seguridad");
    }
    Ok(())
}

fn fingerprint(id: &StorageIdentity, policy: &SealPolicy, nonce: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update(nonce);
    if policy.bind_to_volume {
        hash_field(&mut hasher, b"volume_serial", id.volume_serial.as_deref().unwrap_or_default());
        hash_field(&mut hasher, b"filesystem", id.filesystem.as_deref().unwrap_or_default());
    }
    if policy.bind_to_physical_device {
        hash_field(&mut hasher, b"physical_serial", id.physical_serial.as_deref().unwrap_or_default());
    }
    hasher.finalize().into()
}

fn hash_field(hash: &mut Sha256, label: &[u8], data: &str) {
    hash.update((label.len() as u32).to_le_bytes());
    hash.update(label);
    hash.update((data.len() as u32).to_le_bytes());
    hash.update(data.as_bytes());
}

fn hash_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut sha = Sha256::new();
    let mut block = [0u8; 65536];
    loop {
        let read = file.read(&mut block)?;
        if read == 0 { break; }
        sha.update(&block[..read]);
    }
    Ok(hex(&sha.finalize()))
}

fn hex(data: &[u8]) -> String {
    const ABC: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(data.len() * 2);
    for byte in data {
        result.push(ABC[(byte >> 4) as usize] as char);
        result.push(ABC[(byte & 0xf) as usize] as char);
    }
    result
}

fn decode_hex(data: &str) -> Result<Vec<u8>> {
    if !data.len().is_multiple_of(2) { bail!("hex inválido"); }
    let mut output = Vec::new();
    for pair in data.as_bytes().chunks(2) {
        let digit = |b: u8| -> Result<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => bail!("hex inválido"),
            }
        };
        output.push(digit(pair[0])? << 4 | digit(pair[1])?);
    }
    Ok(output)
}

fn fixed_time_equal(lhs: &[u8], rhs: &[u8]) -> bool {
    if lhs.len() != rhs.len() { return false; }
    let mut difference = 0u8;
    for (a, b) in lhs.iter().zip(rhs.iter()) { difference |= a ^ b; }
    difference == 0
}

/// Complete check for any consumer executable, not limited to SST:
/// 1. read its embedded identity; 2. validate issuer's Ed25519 signature;
/// 3. validate exact binary seal; 4. match physical USB/volume metadata.
/// A consumer must call this before enabling protected functionality.
pub fn verify_authorized_installation(
    executable: &Path,
    binary_seal_path: &Path,
    signed_license_path: &Path,
    expected_application_id: &str,
    trusted_public_key: &[u8; 32],
) -> Result<VerifiedInstallation> {
    let embedded_id = executable::read_executable_id(executable)?;
    let seal_bytes = fs::read(binary_seal_path)
        .with_context(|| format!("sello ausente: {}", binary_seal_path.display()))?;
    let license = authorization::SignedLicense::load(signed_license_path)?;
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(trusted_public_key)
        .context("la clave pública de la autoridad es inválida")?;
    let seal = license.verify(&seal_bytes, &embedded_id,
        expected_application_id, &verifying_key)?;
    seal.verify_for_application(expected_application_id, executable)
}

fn capture_storage(executable: &Path) -> Result<StorageIdentity> {
    #[cfg(windows)]
    { windows::capture(executable) }
    #[cfg(not(windows))]
    {
        let _ = executable;
        bail!("disk-seal requiere el subsistema de almacenamiento de Windows")
    }
}

/// Layout recommendation for the consumer. Does not create the file.
pub fn default_seal_path(root: &Path) -> PathBuf {
    root.join("data").join("installation.seal")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(serial: &str) -> StorageIdentity {
        StorageIdentity {
            physical_serial: Some("physical-1".to_owned()),
            volume_serial: Some(serial.to_owned()),
            filesystem: Some("NTFS".to_owned()),
            removable: true,
        }
    }
    #[test]
    fn different_volumes_generate_different_fingerprints() {
        let nonce = [17u8; 32];
        let policy = SealPolicy::portable_usb();
        assert_ne!(fingerprint(&identity("a"), &policy, &nonce),
                   fingerprint(&identity("b"), &policy, &nonce));
    }
    #[test]
    fn same_device_and_nonce_remain_stable() {
        let nonce = [5u8; 32];
        let policy = SealPolicy::portable_usb();
        assert_eq!(fingerprint(&identity("same"), &policy, &nonce),
                   fingerprint(&identity("same"), &policy, &nonce));
    }
    #[test]
    fn refuses_missing_physical_identifier() {
        let mut identity = identity("v");
        identity.physical_serial = None;
        assert!(check_sources(&identity, &SealPolicy::portable_usb()).is_err());
    }
    #[test]
    fn round_trips_hex_without_exposing_raw_serial() {
        let nonce = [42u8; 32];
        assert_eq!(decode_hex(&hex(&nonce)).unwrap(), nonce);
    }
    #[test]
    fn creates_and_verifies_on_original_usb_identity() {
        let original = identity("volume-1");
        let seal = InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &original
        ).unwrap();
        let verified = seal.verify_with_identity(Path::new("unused.exe"), &original).unwrap();
        assert_eq!(verified.installation_id, seal.installation_id);
        assert!(seal.installation_id.starts_with("DS-"));
    }

    #[test]
    fn copied_directory_or_seal_cannot_pass_on_another_usb() {
        let original = identity("volume-1");
        let mut copy = identity("volume-2");
        copy.physical_serial = Some("different-physical-drive".to_owned());
        let seal = InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &original
        ).unwrap();
        let transferred = serde_json::from_str::<InstallationSeal>(
            &serde_json::to_string(&seal).unwrap()
        ).unwrap();
        assert!(transferred.verify_with_identity(Path::new("unused.exe"), &copy).is_err());
        assert!(transferred.verify_with_identity(Path::new("unused.exe"), &original).is_ok());
    }

    #[test]
    fn changing_only_physical_serial_invalidates_the_seal() {
        let original = identity("volume-1");
        let seal = InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &original
        ).unwrap();
        let mut copied = original;
        copied.physical_serial = Some("other-drive".to_owned());
        assert!(seal.verify_with_identity(Path::new("unused.exe"), &copied).is_err());
    }

    #[test]
    fn fixed_disk_is_rejected_by_strict_usb_policy() {
        let mut disk = identity("volume-1");
        disk.removable = false;
        assert!(InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &disk,
        ).is_err());
    }

    #[test]
    fn altered_nonce_or_fingerprint_is_rejected() {
        let original = identity("volume-1");
        let seal = InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &original
        ).unwrap();
        let mut bad_nonce = seal.clone();
        bad_nonce.nonce = "ff".repeat(32);
        assert!(bad_nonce.verify_with_identity(Path::new("unused.exe"), &original).is_err());
        let mut bad_hash = seal;
        bad_hash.storage_fingerprint = "0".repeat(64);
        assert!(bad_hash.verify_with_identity(Path::new("unused.exe"), &original).is_err());
    }

    #[test]
    fn application_identity_must_be_checked_by_consumer() {
        let original = identity("volume-1");
        let seal = InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &original
        ).unwrap();
        assert_ne!(seal.application_id, "some-other-app");
        assert!(seal.verify_with_identity(Path::new("unused.exe"), &original).is_ok());
    }

    #[test]
    fn rejects_unknown_fields_in_serialized_seal() {
        let original = identity("volume-1");
        let seal = InstallationSeal::create_with_identity(
            "sst", "1.0", Path::new("unused.exe"),
            SealPolicy::portable_usb(), &original
        ).unwrap();
        let mut value = serde_json::to_value(seal).unwrap();
        value["unexpected_permission"] = serde_json::json!(true);
        assert!(serde_json::from_value::<InstallationSeal>(value).is_err());
    }

}
