//! Executable-bound installation identities.
//!
//! The identity is stored in a fixed-size binary trailer. It is NOT a
//! signature; an Ed25519 authorization must bind the ID to the seal.
//! On Windows the installer must personalize BEFORE Authenticode signing.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};
use anyhow::{bail, ensure, Context, Result};
use sha2::{Digest, Sha256};

const MARKER: &[u8; 8] = b"DSIDV001";
const DOMAIN: &[u8] = b"disk-seal/executable-identity/v1\0";
const TRAILER_SIZE: u64 = 8 + 16 + 32;

fn id_bytes(installation_id: &str) -> Result<[u8; 16]> {
    let suffix = installation_id.strip_prefix("DS-")
        .context("Installation ID debe comenzar con DS-")?;
    ensure!(suffix.len() == 32 &&
        suffix.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_lowercase()),
        "Installation ID no es hexadecimal canónico");
    let decoded = crate::decode_hex(suffix)?;
    Ok(decoded.try_into().map_err(|_| anyhow::anyhow!("Installation ID de longitud incorrecta"))?)
}

fn checksum(id: &[u8; 16]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(DOMAIN);
    sha.update(MARKER);
    sha.update(id);
    sha.finalize().into()
}

/// Read the identifier from the executable itself, not a sidecar file.
pub fn read_executable_id(path: &Path) -> Result<String> {
    let mut exe = File::open(path)
        .with_context(|| format!("no se pudo abrir el ejecutable {}", path.display()))?;
    ensure!(exe.metadata()?.len() >= TRAILER_SIZE, "ejecutable sin identidad disk-seal");
    exe.seek(SeekFrom::End(-(TRAILER_SIZE as i64)))?;
    let mut trailer = [0u8; TRAILER_SIZE as usize];
    exe.read_exact(&mut trailer)?;
    ensure!(&trailer[..8] == MARKER, "ejecutable sin identidad disk-seal");
    let id: [u8; 16] = trailer[8..24].try_into()?;
    ensure!(
        crate::fixed_time_equal(&checksum(&id), &trailer[24..56]),
        "identidad incorporada al ejecutable corrupta"
    );
    Ok(format!("DS-{}", crate::hex(&id).to_uppercase()))
}

/// Copy an **unsigned** template to a new file and embed a unique ID.
/// The source template is never modified and the output is never overwritten.
/// Personalizing an Authenticode-signed PE invalidates its existing signature:
/// sign the newly personalized executable AFTER this call.
pub fn personalize_executable(
    unsigned_template: &Path,
    destination: &Path,
    installation_id: &str,
) -> Result<()> {
    let id = id_bytes(installation_id)?;
    ensure!(read_executable_id(unsigned_template).is_err(),
        "el ejecutable de origen ya está personalizado");
    let mut source = File::open(unsigned_template)?;
    ensure!(source.metadata()?.len() >= 64, "ejecutable de origen demasiado pequeño");
    let mut output = OpenOptions::new().write(true).create_new(true)
        .open(destination)
        .with_context(|| format!("destino ocupado o inaccesible: {}", destination.display()))?;
    let copied = (|| -> Result<()> {
        std::io::copy(&mut source, &mut output)?;
        output.write_all(MARKER)?;
        output.write_all(&id)?;
        output.write_all(&checksum(&id))?;
        output.sync_all()?;
        Ok(())
    })();
    if copied.is_err() {
        drop(output);
        let _ = fs::remove_file(destination);
    }
    copied
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn personalized_executables_have_distinct_internal_ids() {
        let mut bytes = [0u8; 8];
        OsRng.fill_bytes(&mut bytes);
        let root = std::env::temp_dir().join(format!("disk-seal-exe-{}", crate::hex(&bytes)));
        fs::create_dir_all(&root).unwrap();
        let template = root.join("template.bin");
        let copy_a = root.join("juan.exe");
        let copy_b = root.join("maria.exe");
        fs::write(&template, [42u8; 256]).unwrap();
        const A: &str = "DS-0123456789ABCDEF0123456789ABCDEF";
        const B: &str = "DS-FEDCBA9876543210FEDCBA9876543210";
        personalize_executable(&template, &copy_a, A).unwrap();
        personalize_executable(&template, &copy_b, B).unwrap();
        assert_eq!(read_executable_id(&copy_a).unwrap(), A);
        assert_eq!(read_executable_id(&copy_b).unwrap(), B);
        assert!(read_executable_id(&template).is_err());
        assert!(personalize_executable(&copy_a, &root.join("second.exe"), A).is_err());
        assert!(personalize_executable(&template, &copy_b, A).is_err());
        // A copied personalized executable keeps the original ID.
        let stolen = root.join("stolen.exe");
        fs::copy(&copy_a, &stolen).unwrap();
        assert_eq!(read_executable_id(&stolen).unwrap(), A);
        let mut content = fs::read(&stolen).unwrap();
        let last = content.len() - 1;
        content[last] ^= 0x01;
        fs::write(&stolen, content).unwrap();
        assert!(read_executable_id(&stolen).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
