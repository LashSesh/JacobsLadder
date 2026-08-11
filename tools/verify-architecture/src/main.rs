//! `psk architecture verify` (Struktur 27.6) - duenner CLI-Wrapper um
//! `verify_architecture::check_architecture_bundle` (siehe lib.rs fuer die
//! eigentliche Pruefung und ihre Zitate).

use std::path::PathBuf;
use std::process::ExitCode;

use verify_architecture::{
    check_architecture_bundle, check_second_layer_binding, check_second_layer_seals,
    ARCHITECTURE_FILES_YAML, SECOND_LAYER_REGISTERS,
};

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

    // Zweitschicht (QPM/NRAII): geprueft, aber NICHT in I_A - eigene
    // Identitaeten, und `shared-identity-in-certificate` ist dort ein
    // blockierender Negativtest. Was `binds_to` behauptet, muss halten.
    match check_second_layer_binding(&root) {
        Ok(problems) if problems.is_empty() => {
            eprintln!(
                "verify-architecture: Zweitschicht — {} Register, alle Bindungen an PSK-RA aufgeloest (nicht in I_A).",
                SECOND_LAYER_REGISTERS.len()
            );
        }
        Ok(problems) => {
            eprintln!("verify-architecture: FAIL — Zweitschichtbindung:");
            for p in &problems {
                eprintln!("    - {p}");
            }
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("verify-architecture: FAIL — Zweitschicht nicht pruefbar: {e}");
            return ExitCode::FAILURE;
        }
    }

    // QPM Regel 0.2 (Zwei eigene Locks, kein gemeinsamer): die
    // Bindungspruefung oben stellt fest, dass eine Behauptung haelt -
    // nicht, dass niemand sie ausgetauscht hat. Dafuer die Siegel.
    match check_second_layer_seals(&root) {
        Ok(seals) => {
            let mut abweichung = false;
            for (identity, computed, stored) in &seals {
                if computed.to_string() == *stored {
                    eprintln!("verify-architecture: {identity} = {computed} (Siegel stimmt).");
                } else {
                    eprintln!(
                        "verify-architecture: FAIL — {identity} weicht ab. Gespeichert: {stored}, berechnet: {computed}"
                    );
                    abweichung = true;
                }
            }
            if abweichung {
                return ExitCode::FAILURE;
            }
        }
        Err(e) => {
            eprintln!("verify-architecture: FAIL — Zweitschichtsiegel: {e}");
            return ExitCode::FAILURE;
        }
    }

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
