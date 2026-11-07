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
use anyhow::{ensure, Context, Result};
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
    decoded.try_into().map_err(|_| anyhow::anyhow!("Installation ID de longitud incorrecta"))
}

fn checksum(id: &[u8; 16]) -> [u8; 32] {
    let mut sha = Sha256::new();
    sha.update(DOMAIN);
    sha.update(MARKER);
    sha.update(id);
    sha.finalize().into()
}

/// Return the file offset of an Authenticode certificate table, when present.
/// The PE security data directory uses a file OFFSET rather than an RVA.
/// Signing normally appends the certificate after the personalized trailer,
/// sometimes adding 0-7 zero padding bytes for 8-byte alignment.
fn certificate_table(exe: &mut File) -> Result<Option<(u64, u64)>> {
    let length = exe.metadata()?.len();
    if length < 64 {
        return Ok(None);
    }
    exe.seek(SeekFrom::Start(0))?;
    let mut dos = [0u8; 64];
    exe.read_exact(&mut dos)?;
    if &dos[..2] != b"MZ" {
        return Ok(None);
    }
    let pe_offset = u32::from_le_bytes(dos[0x3c..0x40].try_into()?) as u64;
    ensure!((64..1024 * 1024).contains(&pe_offset) && pe_offset + 26 <= length,
        "cabecera PE inválida");
    exe.seek(SeekFrom::Start(pe_offset))?;
    let mut coff = [0u8; 24];
    exe.read_exact(&mut coff)?;
    ensure!(&coff[..4] == b"PE\0\0", "firma PE inválida");
    let optional_size = u16::from_le_bytes(coff[20..22].try_into()?) as u64;
    let optional_start = pe_offset + 24;
    ensure!(optional_start + optional_size <= length, "cabecera PE truncada");
    exe.seek(SeekFrom::Start(optional_start))?;
    let mut magic = [0u8; 2];
    exe.read_exact(&mut magic)?;
    let directory_offset: u64 = match u16::from_le_bytes(magic) {
        0x10b => 96,  // PE32
        0x20b => 112, // PE32+
        _ => anyhow::bail!("formato de cabecera PE desconocido"),
    };
    // Security directory (index 4), 8 bytes per entry.
    let security_offset = directory_offset + 4 * 8;
    if optional_size < security_offset + 8 {
        return Ok(None);
    }
    exe.seek(SeekFrom::Start(optional_start + security_offset))?;
    let mut security = [0u8; 8];
    exe.read_exact(&mut security)?;
    let start = u32::from_le_bytes(security[..4].try_into()?) as u64;
    let size = u32::from_le_bytes(security[4..].try_into()?) as u64;
    if start == 0 && size == 0 {
        return Ok(None);
    }
    ensure!(start > 0 && size >= 8 && start + size <= length,
        "tabla de certificados PE corrupta");
    Ok(Some((start, size)))
}

/// Read the identifier from the executable itself, not a sidecar file.
/// Handles unsigned binaries and PE files signed with Authenticode AFTER
/// personalization (where the certificate table appears after our identity).
pub fn read_executable_id(path: &Path) -> Result<String> {
    let mut exe = File::open(path)
        .with_context(|| format!("no se pudo abrir el ejecutable {}", path.display()))?;
    let length = exe.metadata()?.len();
    ensure!(length >= TRAILER_SIZE, "ejecutable sin identidad disk-seal");
    let certificate = certificate_table(&mut exe)?;
    let trailer_end = certificate.map(|(start, _)| start).unwrap_or(length);
    let max_padding = if certificate.is_some() { 7 } else { 0 };

    for padding in 0..=max_padding {
        let Some(start) = trailer_end.checked_sub(TRAILER_SIZE + padding) else {
            continue;
        };
        exe.seek(SeekFrom::Start(start))?;
        let mut trailer = [0u8; TRAILER_SIZE as usize];
        exe.read_exact(&mut trailer)?;
        if &trailer[..8] != MARKER {
            continue;
        }
        if padding > 0 {
            let mut bytes = [0u8; 7];
            exe.read_exact(&mut bytes[..padding as usize])?;
            ensure!(bytes[..padding as usize].iter().all(|b| *b == 0),
                "relleno del certificado PE alterado");
        }
        let id: [u8; 16] = trailer[8..24].try_into()?;
        ensure!(
            crate::fixed_time_equal(&checksum(&id), &trailer[24..56]),
            "identidad incorporada al ejecutable corrupta"
        );
        return Ok(format!("DS-{}", crate::hex(&id).to_uppercase()));
    }
    anyhow::bail!("ejecutable sin identidad disk-seal")
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
    ensure!(certificate_table(&mut source)?.is_none(),
        "la plantilla ya tiene firma Authenticode; personalizarla invalidaría la firma");
    source.seek(SeekFrom::Start(0))?;
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

    #[test]
    fn signed_pe_reads_identity_before_authenticode_certificate_table() {
        let mut seed = [0u8; 8];
        OsRng.fill_bytes(&mut seed);
        let root = std::env::temp_dir().join(format!("disk-seal-signed-{}", crate::hex(&seed)));
        fs::create_dir_all(&root).unwrap();
        let template = root.join("unsigned.exe");
        let personalized = root.join("personalized.exe");
        const ID: &str = "DS-ABABABABABABABABABABABABABABABAB";

        // Minimal PE32+ headers (for metadata parsing tests, not executable).
        let mut binary = vec![0u8; 513];
        binary[..2].copy_from_slice(b"MZ");
        binary[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        binary[0x80..0x84].copy_from_slice(b"PE\0\0");
        binary[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
        binary[0x98..0x9a].copy_from_slice(&0x20Bu16.to_le_bytes());
        fs::write(&template, binary).unwrap();
        personalize_executable(&template, &personalized, ID).unwrap();
        assert_eq!(read_executable_id(&personalized).unwrap(), ID);

        // A mock Authenticode signer aligns to 8 bytes and appends a
        // WIN_CERTIFICATE. This exercises the real security directory layout.
        let mut signed = fs::read(&personalized).unwrap();
        let padding = (8 - signed.len() % 8) % 8;
        let cert_start = (signed.len() + padding) as u32;
        signed[0x128..0x12c].copy_from_slice(&cert_start.to_le_bytes());
        signed[0x12c..0x130].copy_from_slice(&16u32.to_le_bytes());
        signed.resize(signed.len() + padding, 0);
        signed.extend_from_slice(&[0u8; 16]);
        fs::write(&personalized, &signed).unwrap();

        assert_eq!(read_executable_id(&personalized).unwrap(), ID);
        assert!(personalize_executable(&personalized, &root.join("copy.exe"), ID).is_err());
        let identity_index = cert_start as usize - padding - TRAILER_SIZE as usize;
        signed[identity_index + 8] ^= 0x55;
        fs::write(&personalized, signed).unwrap();
        assert!(read_executable_id(&personalized).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
