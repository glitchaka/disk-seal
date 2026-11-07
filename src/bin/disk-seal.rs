//! Provisioning utility. Actual license ISSUANCE belongs only to the trusted
//! administrator environment; this executable never contains a private key.
use std::{env, path::PathBuf, process, fs};
use anyhow::{bail, ensure, Result};
use disk_seal::{
    authority_store::{generate_authority_files, load_authority_key},
    provision::create_authorized_copy,
    SignedLicense,
    inspect_storage, new_installation_id, personalize_executable,
    read_executable_id, verify_authorized_installation, InstallationSeal, SealPolicy,
};

enum Operation {
    Inspect(PathBuf),
    NewId,
    Keygen { private: PathBuf, public: PathBuf },
    Provision {
        app: String, version: String, template: PathBuf, destination: PathBuf,
        assigned_to: String, private: PathBuf,
    },
    Issue {
        app: String, executable: PathBuf, seal: PathBuf,
        assigned_to: String, private: PathBuf, license: PathBuf,
    },
    Personalize { template: PathBuf, destination: PathBuf, id: String },
    Create { app: String, version: String, executable: PathBuf, seal: PathBuf },
    VerifyStorage { app: String, executable: PathBuf, seal: PathBuf },
    VerifySigned {
        app: String, executable: PathBuf, seal: PathBuf,
        license: PathBuf, public_key: [u8; 32],
    },
}

fn parse_hex_public_key(value: &str) -> Result<[u8; 32]> {
    ensure!(value.len() == 64, "la clave pública requiere 64 caracteres hexadecimales");
    let mut key = [0u8; 32];
    for (i, pair) in value.as_bytes().chunks(2).enumerate() {
        key[i] = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    Ok(key)
}

fn parse(args: &[String]) -> Result<Operation> {
    match args {
        [cmd] if cmd == "inspect" =>
            Ok(Operation::Inspect(env::current_exe()?)),
        [cmd, exe] if cmd == "inspect" =>
            Ok(Operation::Inspect(PathBuf::from(exe))),
        [cmd] if cmd == "new-id" => Ok(Operation::NewId),
        [cmd, private, public] if cmd == "keygen" =>
            Ok(Operation::Keygen {
                private: PathBuf::from(private), public: PathBuf::from(public),
            }),
        [cmd, app, version, template, dest, assigned, private] if cmd == "provision" =>
            Ok(Operation::Provision {
                app: app.to_owned(), version: version.to_owned(),
                template: PathBuf::from(template), destination: PathBuf::from(dest),
                assigned_to: assigned.to_owned(), private: PathBuf::from(private),
            }),
        [cmd, app, exe, seal, assigned, private, license] if cmd == "issue" =>
            Ok(Operation::Issue {
                app: app.to_owned(), executable: PathBuf::from(exe),
                seal: PathBuf::from(seal), assigned_to: assigned.to_owned(),
                private: PathBuf::from(private), license: PathBuf::from(license),
            }),
        [cmd, template, dest, id] if cmd == "personalize" =>
            Ok(Operation::Personalize {
                template: PathBuf::from(template), destination: PathBuf::from(dest),
                id: id.to_owned(),
            }),
        [cmd, app, version, exe, seal] if cmd == "create" =>
            Ok(Operation::Create {
                app: app.to_owned(), version: version.to_owned(),
                executable: PathBuf::from(exe), seal: PathBuf::from(seal),
            }),
        [cmd, app, exe, seal] if cmd == "verify-storage" =>
            Ok(Operation::VerifyStorage {
                app: app.to_owned(), executable: PathBuf::from(exe),
                seal: PathBuf::from(seal),
            }),
        [cmd, app, exe, seal, license, public] if cmd == "verify" =>
            Ok(Operation::VerifySigned {
                app: app.to_owned(), executable: PathBuf::from(exe),
                seal: PathBuf::from(seal), license: PathBuf::from(license),
                public_key: parse_hex_public_key(public)?,
            }),
        _ => bail!(
            "Uso:\n  disk-seal inspect [EJECUTABLE]\n  disk-seal new-id\n  \
             disk-seal keygen CLAVE-PRIVADA-DPAPI CLAVE-PUBLICA\n  \
             disk-seal provision APP VERSION PLANTILLA EXE-USB TITULAR CLAVE-PRIVADA-DPAPI\n  \
             disk-seal issue APP EXE-USB SELLO TITULAR CLAVE-PRIVADA-DPAPI LICENCIA\n  \
             disk-seal personalize PLANTILLA DESTINO DS-ID\n  \
             disk-seal create APP VERSION EJECUTABLE-PERSONALIZADO SELLO-BINARIO\n  \
             disk-seal verify-storage APP EJECUTABLE SELLO-BINARIO  (diagnóstico, NO autoriza)\n  \
             disk-seal verify APP EJECUTABLE SELLO-BINARIO LICENCIA CLAVE-PUBLICA-HEX"
        ),
    }
}

fn run(op: Operation) -> Result<()> {
    match op {
        Operation::Inspect(path) => {
            println!("{}", serde_json::to_string_pretty(&inspect_storage(&path)?)?);
        }
        Operation::NewId => println!("{}", new_installation_id()),
        Operation::Keygen { private, public } => {
            let public_hex = generate_authority_files(&private, &public)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "authority_created",
                "private_key_dpapi": private,
                "public_key_file": public,
                "public_key_hex": public_hex,
            }))?);
        }
        Operation::Provision { app, version, template, destination, assigned_to, private } => {
            let copy = create_authorized_copy(
                &app, &version, &template, &destination, &assigned_to, &private
            )?;
            println!("{}", serde_json::to_string_pretty(&copy)?);
        }
        Operation::Issue { app, executable, seal, assigned_to, private, license } => {
            let key = load_authority_key(&private)?;
            let seal_obj = InstallationSeal::load_binary(&seal)?;
            ensure!(seal_obj.application_id == app &&
                    read_executable_id(&executable)? == seal_obj.installation_id,
                    "ID del ejecutable, aplicación y sello no coinciden");
            seal_obj.verify_for_application(&app, &executable)?;
            let bytes = fs::read(&seal)?;
            let signed = SignedLicense::issue(&bytes, &assigned_to, &key)?;
            signed.save_new(&license)?;
            let verified = verify_authorized_installation(
                &executable, &seal, &license, &app, key.verifying_key().as_bytes()
            );
            if let Err(error) = verified {
                let _ = fs::remove_file(&license);
                return Err(error);
            }
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "authorized",
                "installation_id": seal_obj.installation_id,
                "assigned_to": assigned_to,
                "license_path": license,
            }))?);
        }
        Operation::Personalize { template, destination, id } => {
            personalize_executable(&template, &destination, &id)?;
            println!("{}", read_executable_id(&destination)?);
        }
        Operation::Create { app, version, executable, seal } => {
            // An installer must stage files on the USB itself. The ID is read
            // from the executable, rather than invented in a separate file.
            let pinned = InstallationSeal::create_for_personalized_executable(
                &app, &version, &executable, SealPolicy::portable_usb(),
            )?;
            pinned.save_binary_new(&seal)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "pending_signature",
                "installation_id": pinned.installation_id,
                "seal_path": seal,
            }))?);
        }
        Operation::VerifyStorage { app, executable, seal } => {
            let pinned = InstallationSeal::load_binary(&seal)?;
            ensure!(read_executable_id(&executable)? == pinned.installation_id,
                "el ejecutable y el sello tienen ID distintos");
            let found = pinned.verify_for_application(&app, &executable)?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "storage_only_not_authorized",
                "installation_id": found.installation_id,
            }))?);
        }
        Operation::VerifySigned { app, executable, seal, license, public_key } => {
            let found = verify_authorized_installation(
                &executable, &seal, &license, &app, &public_key,
            )?;
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "authorized",
                "installation_id": found.installation_id,
            }))?);
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = parse(&env::args().skip(1).collect::<Vec<_>>()).and_then(run) {
        eprintln!("disk-seal: {error:#}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_installation_id_is_parsed() {
        assert!(matches!(parse(&["new-id".into()]).unwrap(), Operation::NewId));
        assert!(parse(&["personalize".into(), "a".into()]).is_err());
    }

    #[test]
    fn parse_provisioning_and_protected_validation() {
        let create = vec![
            "create".into(), "sst".into(), "1.0".into(),
            "E:\\sst.exe".into(), "E:\\installation.seal".into(),
        ];
        assert!(matches!(parse(&create).unwrap(), Operation::Create { .. }));
        let verify = vec![
            "verify".into(), "sst".into(), "E:\\sst.exe".into(),
            "E:\\installation.seal".into(), "E:\\license.bin".into(),
            "11".repeat(32),
        ];
        assert!(matches!(parse(&verify).unwrap(), Operation::VerifySigned { .. }));
    }

    #[test]
    fn parses_authority_and_new_copy_commands() {
        assert!(matches!(
            parse(&["keygen".into(), "private.dskey".into(), "public.hex".into()]).unwrap(),
            Operation::Keygen { .. }
        ));
        assert!(matches!(
            parse(&["provision".into(), "horror-me".into(), "0.4.1".into(),
                "C:\\master.exe".into(), "E:\\HorrorMe.exe".into(),
                "Juan".into(), "C:\\keys\\private.dskey".into()]).unwrap(),
            Operation::Provision { .. }
        ));
        assert!(parse(&["provision".into(), "horror-me".into()]).is_err());
    }

    #[test]
    fn rejects_invalid_public_key() {
        assert!(parse_hex_public_key("short").is_err());
        assert!(parse_hex_public_key(&"xx".repeat(32)).is_err());
    }
}
