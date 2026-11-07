//! Local Ed25519 issuing authority. The private key is encrypted for the
//! current WINDOWS USER by DPAPI, not stored on a portable USB or in Git.
//! The key is NEVER present in a recipient's installation package.
use std::{fs::{self, OpenOptions}, io::Write, path::Path};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;

use crate::{generate_signing_key, hex};

const KEY_MAGIC: &[u8; 8] = b"DSAUTH01";

/// Create a new, Windows-user-scoped issuing authority.
/// The private key cannot be exported merely by copying the .dskey file.
pub fn generate_authority_files(private_path: &Path, public_path: &Path) -> Result<String> {
    ensure!(private_path != public_path, "rutas pública y privada iguales");
    ensure!(!private_path.exists() && !public_path.exists(),
        "la autoridad ya existe; nunca sobrescriba claves");
    let key = generate_signing_key();
    let public = hex(key.verifying_key().as_bytes());
    let protected = protect_current_user(&key.to_bytes())?;
    let mut secret = Vec::with_capacity(KEY_MAGIC.len() + protected.len());
    secret.extend_from_slice(KEY_MAGIC);
    secret.extend_from_slice(&protected);
    let mut secret_file = OpenOptions::new().create_new(true).write(true)
        .open(private_path).context("no se pudo crear archivo privado; use carpeta protegida del administrador")?;
    let result = (|| -> Result<()> {
        secret_file.write_all(&secret)?;
        secret_file.sync_all()?;
        let mut pub_file = OpenOptions::new().create_new(true).write(true).open(public_path)?;
        pub_file.write_all(public.as_bytes())?;
        pub_file.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        drop(secret_file);
        let _ = fs::remove_file(private_path);
    }
    result?;
    Ok(public)
}

/// Read only in the original Windows user context, unless the owner
/// has explicitly arranged DPAPI recovery. No passphrase in argv or env.
pub fn load_authority_key(private_path: &Path) -> Result<SigningKey> {
    let ciphertext = fs::read(private_path)
        .with_context(|| format!("clave privada ausente: {}", private_path.display()))?;
    ensure!(ciphertext.len() > KEY_MAGIC.len() && ciphertext.len() < 65536,
        "formato/tamaño de clave privada inválido");
    ensure!(&ciphertext[..KEY_MAGIC.len()] == KEY_MAGIC,
        "archivo de clave privada incorrecto");
    let plain = unprotect_current_user(&ciphertext[KEY_MAGIC.len()..])?;
    ensure!(plain.len() == 32, "DPAPI devolvió una clave de longitud inválida");
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&plain);
    let key = SigningKey::from_bytes(&secret);
    secret.fill(0);
    Ok(key)
}

#[cfg(windows)]
fn dpapi(input: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    use std::{ptr::{null, null_mut}, slice};
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData,
            CRYPTPROTECT_UI_FORBIDDEN,
        },
    };
    let input_blob = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr() as *mut u8,
    };
    let mut output_blob = CRYPT_INTEGER_BLOB { cbData: 0, pbData: null_mut() };
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &input_blob, null(), null(), null(), null(),
                CRYPTPROTECT_UI_FORBIDDEN, &mut output_blob
            )
        } else {
            CryptUnprotectData(
                &input_blob, null_mut(), null(), null(), null(),
                CRYPTPROTECT_UI_FORBIDDEN, &mut output_blob
            )
        }
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context(
            "DPAPI: operación no autorizada para este usuario o equipo"
        );
    }
    ensure!(!output_blob.pbData.is_null() && output_blob.cbData > 0,
        "DPAPI devolvió datos vacíos");
    let result = unsafe {
        slice::from_raw_parts(output_blob.pbData, output_blob.cbData as usize).to_vec()
    };
    unsafe { LocalFree(output_blob.pbData.cast()); }
    Ok(result)
}

#[cfg(windows)]
fn protect_current_user(bytes: &[u8]) -> Result<Vec<u8>> { dpapi(bytes, true) }
#[cfg(windows)]
fn unprotect_current_user(bytes: &[u8]) -> Result<Vec<u8>> { dpapi(bytes, false) }

#[cfg(not(windows))]
fn protect_current_user(_: &[u8]) -> Result<Vec<u8>> {
    anyhow::bail!("la autoridad de licencias requiere Windows DPAPI")
}
#[cfg(not(windows))]
fn unprotect_current_user(_: &[u8]) -> Result<Vec<u8>> {
    anyhow::bail!("la autoridad de licencias requiere Windows DPAPI")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn user_scoped_dpapi_key_round_trip_without_plaintext_on_disk() {
        use rand_core::{OsRng, RngCore};
        let mut nonce=[0u8;8];
        OsRng.fill_bytes(&mut nonce);
        let dir=std::env::temp_dir().join(format!("diskseal-authority-{}",hex(&nonce)));
        fs::create_dir_all(&dir).unwrap();
        let private=dir.join("private.dskey");
        let public=dir.join("public.hex");
        let created=generate_authority_files(&private,&public).unwrap();
        let loaded=load_authority_key(&private).unwrap();
        assert_eq!(hex(loaded.verifying_key().as_bytes()), created);
        assert_eq!(fs::read_to_string(&public).unwrap(), created);
        let encrypted=fs::read(&private).unwrap();
        assert!(encrypted.starts_with(KEY_MAGIC));
        assert!(!encrypted.windows(32).any(|window|window == loaded.to_bytes()));
        assert!(generate_authority_files(&private,&public).is_err());
        fs::remove_dir_all(dir).unwrap();
    }
}
