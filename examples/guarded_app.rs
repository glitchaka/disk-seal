//! Minimal example: a separate executable uses disk-seal without SST.
//! Compile unsigned, personalize, then Authenticode-sign the delivered image.
use std::{env, path::Path, process};
use disk_seal::{read_executable_id, verify_authorized_installation};

fn hex_public_key(text: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(text.len() == 64, "se requieren 64 dígitos hex para la clave pública");
    let mut out = [0u8; 32];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let value = std::str::from_utf8(chunk)?;
        out[index] = u8::from_str_radix(value, 16)?;
    }
    Ok(out)
}

fn run() -> anyhow::Result<()> {
    let executable = env::current_exe()?;
    let args = env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command] if command == "identity" => {
            println!("{}", read_executable_id(&executable)?);
        }
        [command, app, seal, license, public] if command == "verify" => {
            // In a real application embed the trusted key at build time:
            // never let the end user provide an arbitrary verifier key.
            let key = hex_public_key(public)?;
            let valid = verify_authorized_installation(
                &executable, Path::new(seal), Path::new(license), app, &key,
            )?;
            println!("Instalación autorizada: {}", valid.installation_id);
        }
        _ => anyhow::bail!(
            "Uso: guarded_app identity\n\
             Uso: guarded_app verify APP ARCHIVO-SELLO LICENCIA CLAVE-PUBLICA-HEX"
        ),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Aplicación protegida: {error:#}");
        process::exit(1);
    }
}
