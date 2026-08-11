//! `verify-test-ratchet`: zaehlt je Paket die real vorhandenen Tests
//! (`cargo test -- --list`, ohne sie auszufuehren) und bricht ab, sobald
//! eine Zahl unter ihre eingetragene Untergrenze faellt.
//!
//! ## Anlass
//!
//! `.github/workflows/ci.yml` traegt dieses Muster bereits je Stufe (siehe
//! dortigen Kopfkommentar). Es fehlte aber an zwei Stellen, und beide
//! wurden real: (1) es lief nur in der Pipeline, also NACH dem Commit;
//! (2) es deckte nur die Pakete ab, die eine CI-Stufe zufaellig nennt -
//! `psk-scheduler` war nicht darunter.
//!
//! Der Fall trat ein: beim Umschreiben eines Testmoduls verschwand
//! `the_record_digests_of_those_same_two_runs_do_differ` (psk-scheduler)
//! spurlos. Die Suite blieb gruen - eine geloeschte Pruefung meldet sich
//! nicht -, und aufgefallen ist es nur, weil ein `use`-Import dadurch
//! ungenutzt wurde und Clippy ihn anmerkte. Auf diesen Zufall darf sich
//! nichts verlassen: dieser Zaehler deckt deshalb JEDES modultragende
//! Paket ab und laeuft lokal vor dem Commit, nicht erst danach.
//!
//! ## Warum Literale und kein automatischer Abgleich
//!
//! Dieselbe Begruendung wie in ci.yml: "ein Ratchet ist eine normative
//! Untergrenze, die NICHT automatisch mitwandern soll, wenn jemand Tests
//! entfernt - genau umgekehrt zu einem beschreibenden Zaehler." Ein
//! Werkzeug, das die Untergrenze aus dem Istzustand ableitet, kann
//! definitionsgemaess nie fehlschlagen.
//!
//! Die Grenzen unten liegen bewusst auf dem Stand ihrer Eintragung, nicht
//! darueber: sie steigen nur, wenn jemand sie ausdruecklich anhebt.

use std::collections::BTreeMap;
use std::process::{Command, ExitCode};

/// Paket -> Mindestanzahl realer Tests. Eingetragen beim Bau dieses
/// Werkzeugs; Erhoehung ist eine bewusste Entscheidung, kein Automatismus.
const FLOORS: &[(&str, usize)] = &[
    ("psk-types", 40),
    ("psk-canon", 23),
    ("psk-trace", 39),
    ("psk-anchor", 21),
    ("psk-thought", 33),
    ("psk-fields", 42),
    ("psk-dependency", 12),
    ("psk-adversarial", 29),
    ("psk-closure", 20),
    ("psk-witness", 22),
    ("psk-gate", 20),
    ("psk-effect", 29),
    ("psk-reconciliation", 14),
    ("psk-topology", 28),
    ("psk-ir", 8),
    ("psk-scheduler", 45),
    ("psk-lifecycle", 20),
    ("psk-contract", 22),
    ("psk-certify", 32),
    ("psk-observe", 6),
    ("psk-conformance", 89),
    ("psk-cli", 1),
    ("psk-ipc", 5),
    // NRAII-RA, L0 bis L3. Von den 45 sind sechs
    // `compile_fail`-Doctests: die Nichttraversalschranke (L0) und die
    // Konstruktionsschranke des kanonischen Zustands (L1) SIND die
    // Nachweise, und sie zaehlen hier mit, weil `cargo test -- --list`
    // sie auffuehrt. Faellt einer weg - etwa weil jemand `Traversable`
    // fuer den Nullanker implementiert oder das Feld von
    // `CanonicalState` oeffentlich macht -, sinkt die Zahl, und diese
    // Grenze meldet es.
    ("psk-nraii", 45),
];

/// Zaehlt die von `cargo test -- --list` gemeldeten Tests eines Pakets.
/// `--list` fuehrt nichts aus; jede Zeile eines Tests endet auf ": test".
fn count_tests(package: &str) -> Result<usize, String> {
    let output = Command::new(env!("CARGO"))
        .args(["test", "-p", package, "--locked", "--", "--list"])
        .output()
        .map_err(|e| format!("{package}: cargo nicht startbar: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "{package}: `cargo test -- --list` scheiterte ({})\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| line.ends_with(": test"))
        .count())
}

fn main() -> ExitCode {
    let mut counted: BTreeMap<&str, usize> = BTreeMap::new();
    let mut problems: Vec<String> = Vec::new();

    for (package, floor) in FLOORS {
        match count_tests(package) {
            Ok(found) => {
                counted.insert(package, found);
                if found < *floor {
                    problems.push(format!(
                        "{package}: {found} Tests, Untergrenze {floor} - es sind {} verschwunden",
                        floor - found
                    ));
                }
            }
            Err(e) => problems.push(e),
        }
    }

    let total: usize = counted.values().sum();
    for (package, found) in &counted {
        let floor = FLOORS
            .iter()
            .find(|(p, _)| p == package)
            .map(|(_, f)| *f)
            .unwrap_or(0);
        let marker = if *found > floor { " (+)" } else { "" };
        eprintln!("    {package}: {found} (>= {floor}){marker}");
    }

    if problems.is_empty() {
        eprintln!(
            "verify-test-ratchet: PASS — {total} Tests in {} Paketen, keine Untergrenze unterschritten.",
            counted.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("verify-test-ratchet: FAIL —");
        for p in &problems {
            eprintln!("    - {p}");
        }
        ExitCode::FAILURE
    }
}
