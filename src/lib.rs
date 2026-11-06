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

const SEAL_VERSION: u32 = 1;
const HASH_DOMAIN: &[u8] = b"disk-seal/windows/v1\0";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
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

impl InstallationSeal {
    /// Called once by the installer after extraction, on the original drive.
    pub fn create(
        app_id: &str,
        app_version: &str,
        executable: &Path,
        policy: SealPolicy,
    ) -> Result<Self> {
        policy.validate()?;
        ensure!(!app_id.is_empty() && app_id.len() <= 64 &&
            app_id.bytes().all(|byte| byte.is_ascii_alphanumeric() ||
                matches!(byte, b'_' | b'-' | b'.')),
            "application_id no válido");
        let identity = capture_storage(executable)?;
        check_sources(&identity, &policy)?;

        let mut nonce = [0u8; 32];
        let mut installation = [0u8; 16];
        OsRng.fill_bytes(&mut nonce);
        OsRng.fill_bytes(&mut installation);
        let nonce_hex = hex(&nonce);
        let sources = source_names(&identity, &policy);
        let fingerprint = fingerprint(&identity, &policy, &nonce);
        let executable_hash = if policy.bind_to_executable {
            Some(hash_file(executable)?)
        } else {
            None
        };

        Ok(Self {
            seal_format_version: SEAL_VERSION,
            application_id: app_id.to_owned(),
            application_version: app_version.to_owned(),
            installation_id: format!("SST-{}", hex(&installation).to_uppercase()),
            created_at: Local::now().fixed_offset(),
            storage_fingerprint: hex(&fingerprint),
            nonce: nonce_hex,
            policy,
            identity_sources: sources,
            executable_hash,
        })
    }

    pub fn verify_current_environment(&self, executable: &Path) -> Result<VerifiedInstallation> {
        ensure!(self.seal_format_version == SEAL_VERSION, "formato de sello no compatible");
        self.policy.validate()?;
        ensure!(!self.installation_id.is_empty(), "Installation ID vacío");
        ensure!(!self.application_id.is_empty(), "application_id vacío");
        let nonce = decode_hex(&self.nonce)?;
        ensure!(nonce.len() == 32, "nonce inválido");
        let identity = capture_storage(executable)?;
        check_sources(&identity, &self.policy)?;
        let actual_sources = source_names(&identity, &self.policy);
        ensure!(actual_sources == self.identity_sources,
            "las fuentes de identidad del dispositivo cambiaron");
        let expected = fingerprint(&identity, &self.policy, &nonce);
        let pinned = decode_hex(&self.storage_fingerprint)?;
        ensure!(pinned.len() == 32 && fixed_time_equal(&expected, &pinned),
            "el volumen o el dispositivo físico no coincide con la instalación original");
        if self.policy.bind_to_executable {
            let pinned = self.executable_hash.as_deref()
                .context("falta el hash del ejecutable sellado")?;
            let actual = hash_file(executable)?;
            ensure!(actual == pinned, "el ejecutable cambió desde el sellado");
        }
        Ok(VerifiedInstallation {
            installation_id: self.installation_id.clone(),
            created_at: self.created_at,
            storage_fingerprint: self.storage_fingerprint.clone(),
            identity_sources: actual_sources,
        })
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
    if data.len() % 2 != 0 { bail!("hex inválido"); }
    let mut output = Vec::new();
    for pair in data.as_bytes().chunks_exact(2) {
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
}
