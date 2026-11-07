//! Administrative provisioning of a brand-new, personalized USB installation.
//! Only the issuing authority calls this; the recipient executes the verifier.
use std::{fs, path::{Path, PathBuf}};
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use crate::{
    authority_store::load_authority_key,
    new_installation_id,
    personalize_executable,
    read_executable_id,
    verify_authorized_installation,
    InstallationSeal, SealPolicy, SignedLicense,
};

#[derive(Debug, Serialize)]
pub struct ProvisionedCopy {
    pub installation_id: String,
    pub assigned_to: String,
    pub executable: PathBuf,
    pub seal_file: PathBuf,
    pub license_file: PathBuf,
}

/// Personalize an unsigned application template and license the current USB.
/// The caller supplies the *private key path on the ADMIN PC*, never secret
/// material in arguments. The target executable must reside on the target USB.
///
/// This function does not copy or expose the authority key to the USB.
pub fn create_authorized_copy(
    app_id: &str,
    version: &str,
    unsigned_template: &Path,
    usb_executable: &Path,
    assigned_to: &str,
    private_authority_key: &Path,
) -> Result<ProvisionedCopy> {
    ensure!(!assigned_to.trim().is_empty(), "titular de copia vacío");
    ensure!(!unsigned_template.eq(usb_executable), "la plantilla no puede ser el destino");
    let destination_parent = usb_executable.parent().context("ejecutable sin directorio")?;
    ensure!(destination_parent.is_dir(), "crea primero la carpeta destino del USB");
    let data_dir = destination_parent.join("data");
    let seal_file = data_dir.join("installation.seal");
    let license_file = data_dir.join("installation.license");
    ensure!(!usb_executable.exists() && !seal_file.exists() && !license_file.exists(),
        "la copia de destino ya existe: no sobrescribir identidad/activación");

    // Do not allow the authority's private key to live on the recipient's
    // drive. DPAPI protects the key, but the USB must never carry the file.
    #[cfg(windows)]
    {
        let admin_key = private_authority_key.canonicalize()
            .context("la clave de autoridad no está en una ruta local válida")?;
        let destination = destination_parent.canonicalize()?;
        let admin_volume = admin_key.components().next()
            .context("ubicación de clave privada inválida")?
            .as_os_str().to_string_lossy().to_uppercase();
        let target_volume = destination.components().next()
            .context("volumen de instalación inválido")?
            .as_os_str().to_string_lossy().to_uppercase();
        ensure!(admin_volume != target_volume,
            "la clave privada debe permanecer fuera del pendrive de destino");
    }
    // Load and authenticate the authority in the user's trusted admin context.
    let signing_key = load_authority_key(private_authority_key)?;
    let trusted_key = signing_key.verifying_key().to_bytes();
    let installation_id = new_installation_id();
    fs::create_dir_all(&data_dir)?;

    // Keep a precise list of files created so errors cannot silently leave
    // partially authorized copies. Never remove arbitrary existing files.
    let mut created: Vec<PathBuf> = Vec::new();
    let result = (|| -> Result<ProvisionedCopy> {
        personalize_executable(unsigned_template, usb_executable, &installation_id)?;
        created.push(usb_executable.to_path_buf());
        ensure!(read_executable_id(usb_executable)? == installation_id,
            "el ID interno del ejecutable no coincide");

        let seal = InstallationSeal::create_for_personalized_executable(
            app_id, version, usb_executable, SealPolicy::portable_usb(),
        )?;
        ensure!(seal.installation_id == installation_id, "identidad del sello inconsistente");
        let seal_bytes = seal.to_binary()?;
        seal.save_binary_new(&seal_file)?;
        created.push(seal_file.clone());

        let license = SignedLicense::issue(&seal_bytes, assigned_to, &signing_key)?;
        license.save_new(&license_file)?;
        created.push(license_file.clone());

        // Perform the full verifier check as the recipient would, on the
        // ORIGINAL pendrive, before declaring provisioning successful.
        let verified = verify_authorized_installation(
            usb_executable, &seal_file, &license_file, app_id, &trusted_key
        )?;
        ensure!(verified.installation_id == installation_id, "verificación final incorrecta");

        Ok(ProvisionedCopy {
            installation_id,
            assigned_to: assigned_to.trim().to_owned(),
            executable: usb_executable.to_path_buf(),
            seal_file,
            license_file,
        })
    })();
    if result.is_err() {
        for path in created.iter().rev() { let _ = fs::remove_file(path); }
    }
    result
}
