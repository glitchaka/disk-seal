//! Thin CLI for installers and SST integration, not a license authority.
use std::{env, path::{Path, PathBuf}, process};
use anyhow::{bail, Context, Result};
use disk_seal::{inspect_storage, InstallationSeal, SealPolicy};

enum Operation {
    Inspect { executable: PathBuf },
    Create {
        app: String,
        version: String,
        executable: PathBuf,
        seal_file: PathBuf,
    },
    Verify {
        app: String,
        executable: PathBuf,
        seal_file: PathBuf,
    },
}

fn parse(args: &[String]) -> Result<Operation> {
    match args {
        [command] if command == "inspect" =>
            Ok(Operation::Inspect { executable: env::current_exe()? }),
        [command, executable] if command == "inspect" =>
            Ok(Operation::Inspect { executable: PathBuf::from(executable) }),
        [command, app, version, executable, seal_file] if command == "create" =>
            Ok(Operation::Create {
                app: app.clone(),
                version: version.clone(),
                executable: PathBuf::from(executable),
                seal_file: PathBuf::from(seal_file),
            }),
        [command, app, executable, seal_file] if command == "verify" =>
            Ok(Operation::Verify {
                app: app.clone(),
                executable: PathBuf::from(executable),
                seal_file: PathBuf::from(seal_file),
            }),
        _ => bail!(
            "Uso:\n  disk-seal inspect [RUTA-EJECUTABLE]\n  \
             disk-seal create APP VERSION RUTA-EJECUTABLE ARCHIVO-SELLO\n  \
             disk-seal verify APP RUTA-EJECUTABLE ARCHIVO-SELLO"
        ),
    }
}

fn execute(op: Operation) -> Result<()> {
    match op {
        Operation::Inspect { executable } => {
            let info = inspect_storage(&executable)?;
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        Operation::Create { app, version, executable, seal_file } => {
            let seal = InstallationSeal::create(
                &app, &version, &executable, SealPolicy::portable_usb(),
            )?;
            let executable_parent = executable.parent().context("ejecutable sin directorio")?;
            let target_parent = seal_file.parent().unwrap_or_else(|| Path::new("."));
            // Seal must live on the same volume as the protected executable.
            // Comparing a canonicalized directory prevents writing the seal
            // to an unrelated network or local disk.
            let exe_parent = executable_parent.canonicalize()?;
            let seal_parent = target_parent.canonicalize()?;
            #[cfg(windows)]
            {
                let exe_drive = exe_parent.components().next()
                    .context("ruta de ejecutable inválida")?;
                let seal_drive = seal_parent.components().next()
                    .context("ruta de sello inválida")?;
                anyhow::ensure!(
                    exe_drive == seal_drive,
                    "el sello debe almacenarse en el mismo volumen que el ejecutable"
                );
            }
            let _ = (exe_parent, seal_parent);
            seal.save_new(&seal_file)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "created",
                "installation_id": seal.installation_id,
                "seal": seal_file,
                "application_id": seal.application_id,
            }))?);
        }
        Operation::Verify { app, executable, seal_file } => {
            let seal = InstallationSeal::load(&seal_file)?;
            let verified = seal.verify_for_application(&app, &executable)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "valid",
                "installation_id": verified.installation_id,
                "created_at": verified.created_at,
                "identity_sources": verified.identity_sources,
            }))?);
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = parse(&env::args().skip(1).collect::<Vec<_>>()).and_then(execute) {
        eprintln!("disk-seal: {error:#}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsupported_subcommands() {
        assert!(parse(&["activate".into()]).is_err());
        assert!(parse(&["create".into(), "sst".into()]).is_err());
    }

    #[test]
    fn parses_portable_create_and_verify() {
        let create = vec![
            "create".into(), "sst".into(), "1.0".into(), "E:\\sst.exe".into(),
            "E:\\data\\installation.seal".into(),
        ];
        assert!(matches!(parse(&create).unwrap(), Operation::Create { .. }));
        let verify = vec![
            "verify".into(), "sst".into(), "E:\\sst.exe".into(),
            "E:\\data\\installation.seal".into(),
        ];
        assert!(matches!(parse(&verify).unwrap(), Operation::Verify { .. }));
    }
}
