//! `psk refinement verify` (Struktur 27.6) - duenner CLI-Wrapper um
//! `verify_refinement::{check_core_fidelity, read_refinement_map}` (siehe
//! lib.rs fuer die eigentliche Pruefung und ihre Zitate).

use std::path::PathBuf;
use std::process::ExitCode;

use verify_refinement::{check_core_fidelity, read_refinement_map};

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

    if let Err(e) = check_core_fidelity(&root) {
        eprintln!("verify-refinement: FAIL — {e}");
        return ExitCode::FAILURE;
    }
    eprintln!(
        "verify-refinement: PASS — FSM-THOUGHT (8) und FSM-FIELD (7) spiegeln C_PSK Anhang D wortgetreu; \
         RA-EXT-THOUGHT-01/RA-EXT-FIELD-01 korrekt in ra_extensions gefuehrt."
    );

    let doc = match read_refinement_map(&root) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("verify-refinement: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !doc.internally_consistent() {
        eprintln!(
            "verify-refinement: FAIL — coverage-Felder inkonsistent (mapped={}, unmapped={}, concrete_transitions={}, complete={})",
            doc.coverage.mapped, doc.coverage.unmapped, doc.coverage.concrete_transitions, doc.coverage.complete
        );
        return ExitCode::FAILURE;
    }

    if doc.blocks_on_unmapped() {
        eprintln!(
            "verify-refinement: FAIL_PSK — {} unabgebildete konkrete Transition(en) (T-REF-001, I-ARCH-013)",
            doc.coverage.unmapped
        );
        return ExitCode::FAILURE;
    }

    eprintln!(
        "verify-refinement: PASS — {} konkrete Transitionen, {} abgebildet, 0 offen.",
        doc.coverage.concrete_transitions, doc.coverage.mapped
    );
    ExitCode::SUCCESS
}
