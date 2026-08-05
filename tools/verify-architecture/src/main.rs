//! `psk architecture verify` (Struktur 27.6) - duenner CLI-Wrapper um
//! `verify_architecture::check_architecture_bundle` (siehe lib.rs fuer die
//! eigentliche Pruefung und ihre Zitate).

use std::path::PathBuf;
use std::process::ExitCode;

use verify_architecture::{check_architecture_bundle, ARCHITECTURE_FILES_YAML};

fn workspace_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
            return dir;
        }
        if !dir.pop() {
            panic!("keine Workspace-Wurzel (Cargo.toml + .git) gefunden");
        }
    }
}

fn main() -> ExitCode {
    let root = workspace_root();

    let check = match check_architecture_bundle(&root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verify-architecture: FAIL — {e}");
            return ExitCode::FAILURE;
        }
    };

    if !check.schema_conformant() {
        for (name, errors) in &check.schema_failures {
            eprintln!("verify-architecture: SCHEMA-FAIL {name}:");
            for e in errors {
                eprintln!("    - {e}");
            }
        }
        eprintln!(
            "verify-architecture: {} von {} Registern nicht schemakonform.",
            check.schema_failures.len(),
            ARCHITECTURE_FILES_YAML.len()
        );
        return ExitCode::FAILURE;
    }
    eprintln!(
        "verify-architecture: alle {} Register strukturell schemakonform.",
        ARCHITECTURE_FILES_YAML.len()
    );

    if !check.missing.is_empty() {
        eprintln!(
            "verify-architecture: {} von {} erwarteten Bundle-Dateien fehlen: {}",
            check.missing.len(),
            check.total_expected,
            check.missing.join(", ")
        );
        return ExitCode::FAILURE;
    }

    match &check.stored_architecture_id {
        None => {
            eprintln!(
                "verify-architecture: NOCH NICHT VERSIEGELT — architecture_id ist null. Berechneter Wert: {}",
                check.computed_architecture_id
            );
            ExitCode::SUCCESS
        }
        Some(stored) => {
            if check.matches() {
                eprintln!(
                    "verify-architecture: PASS — architecture_id stimmt ueberein ({}).",
                    check.computed_architecture_id
                );
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "verify-architecture: FAIL — architecture_id weicht ab. Gespeichert: {stored}, berechnet: {}",
                    check.computed_architecture_id
                );
                ExitCode::FAILURE
            }
        }
    }
}
