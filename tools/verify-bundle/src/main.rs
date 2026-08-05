//! `psk constitution verify <bundle>` (Struktur 27.6) - duenner CLI-Wrapper
//! um `verify_bundle::check_constitution_bundle` (siehe lib.rs fuer die
//! eigentliche Pruefung und ihre Zitate).
//!
//! Was diese Pruefung NICHT tut: gegen `declared_ancestor_constitution_id`
//! (aa10aa5a...) vergleichen. Dieser Wert ist laut OBL-009 unreachable -
//! kein eingebettetes Bundle, widerspruechliche Digest-Saetze zwischen
//! CPSK Kapitel 44.1 und Kapitel F. Er wird informativ ausgegeben, nie
//! als Pruefziel verwendet.

use std::path::PathBuf;
use std::process::ExitCode;

use verify_bundle::check_constitution_bundle;

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
    let mut args = std::env::args().skip(1);
    let root = workspace_root();
    let bundle = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("constitution"));

    let check = match check_constitution_bundle(&bundle) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("verify-bundle: FAIL — {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(status) = &check.declared_ancestor_status {
        eprintln!("verify-bundle: Hinweis — declared_ancestor_constitution_id: {status} (OBL-009, nicht Pruefziel)");
    }

    if !check.missing.is_empty() {
        eprintln!(
            "verify-bundle: {} von {} in normative_files gelisteten Dateien fehlen: {}",
            check.missing.len(),
            check.total_normative_files,
            check.missing.join(", ")
        );
    }

    match &check.stored_constitution_id {
        None => {
            eprintln!(
                "verify-bundle: NOCH NICHT VERSIEGELT — constitution_id ist null. \
                 Berechneter Wert ueber {} vorhandene Datei(en): {}",
                check.present_count, check.computed_constitution_id
            );
            if check.missing.is_empty() {
                eprintln!(
                    "verify-bundle: vollstaendiger Dateisatz vorhanden — bereit zum Versiegeln."
                );
            }
            ExitCode::SUCCESS
        }
        Some(stored) => {
            if check.matches() {
                eprintln!(
                    "verify-bundle: PASS — constitution_id stimmt ueberein ({}).",
                    check.computed_constitution_id
                );
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "verify-bundle: FAIL — constitution_id weicht ab. Gespeichert: {stored}, berechnet: {}",
                    check.computed_constitution_id
                );
                ExitCode::FAILURE
            }
        }
    }
}
