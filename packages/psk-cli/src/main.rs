//! `psk` - CLI-Vertrag (Struktur 27.6, Vertrag 27.7). Die Subkommandoform
//! unten spiegelt Struktur 27.6 woertlich, damit `psk --help` den vollen
//! vorgesehenen Vertrag zeigt, auch wo eine Realisierung noch fehlt -
//! Vertrag 27.7 verlangt technische Erzwingung ausserhalb eines
//! Sprachmodells, nicht dass jedes Kommando schon vollstaendig ist.
//!
//! Real implementiert: `constitution verify`, `architecture verify`,
//! `refinement verify`, `anchor seal`, `golden-run` (mit `--independent`
//! fuer I8, siehe `cmd_golden_run_independent`), `conformance run`.
//!
//! `golden-run` ist KEINE interne Testroute, sondern ein dauerhaftes,
//! eigenstaendiges Vertragsverb - Definition 24.2 benennt den Golden Run
//! als eigenes Ding ("ein versiegelter End-to-End-Lauf"), nicht als
//! Unterfall einer Konformitaetsklassenpruefung, und Tabelle 23.2 macht
//! ihn zur VORAUSSETZUNG hoeherer Klassen (C2: "Replay-valid R2-Replay
//! UND Golden Runs bestanden") statt zu ihrem Ergebnis. Es waere deshalb
//! falsch, ihn unter `conformance run --class golden` zu verstecken:
//! `--class` waehlt eine Konformitaetsklasse C0..C5 aus Tabelle 23.2 aus,
//! "golden" ist keine solche Klasse. `golden-run` ist ausserdem bewusst
//! NICHT `run <task>`: es fuehrt Anker bis Zertifikat in EINEM
//! Prozessaufruf komplett aus (Regel 24.3), statt einen `<run-id>` zu
//! erzeugen, den ein spaeterer `psk inspect <run-id>`-Aufruf wiederfinden
//! muesste (siehe naechster Absatz zur fehlenden Run-Ablage). `conformance
//! run` fuehrt separat die echte T-*-Testsuite aus (psk-conformance,
//! deren eigene Golden-Run-Tests `golden-run` als Bibliotheksfunktion
//! wiederverwenden) - kein Duplikat, zwei verschiedene Zwecke.
//!
//! Noch nicht real (Befund, siehe `not_yet_implemented`): `run`, `inspect`,
//! `replay`, `effect plan`, `effect apply`, `reconcile`, `certify`,
//! `residue list`, `export` - alle brauchen entweder eine plattenpersistente,
//! ueber `<run-id>` adressierbare Ablage (nicht gebaut) oder Eingaben
//! (z.B. ein serialisiertes Token bei `effect apply`), die aus einem
//! vorherigen, hier nicht gespeicherten Lauf stammen wuerden.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

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

fn print_usage() {
    eprintln!(
        "psk - PSK-RA Referenzimplementierung (Struktur 27.6)\n\n\
         Realisiert:\n  \
         psk constitution verify [bundle]     // prueft I_C gegen Lock\n  \
         psk architecture verify              // prueft I_A gegen Lock\n  \
         psk refinement verify                // prueft refinement_map.yaml + FSM-Treue\n  \
         psk anchor seal <workspace>           // erzeugt AnchorSnapshot\n  \
         psk golden-run [sandbox-path]         // Regel 24.3, Schritte 1-13 + I7-Replay\n  \
         psk golden-run [sandbox-path] --independent  // + I8: zweiter echter Prozess\n  \
         psk conformance run                   // fuehrt die 37 T-* Tests aus\n\n\
         In Struktur 27.6 vorgesehen, hier noch nicht realisiert (keine\n\
         plattenpersistente <run-id>-Ablage):\n  \
         psk run <task> --anchor <id> --profile readonly|shadow|sandbox|reference\n  \
         psk inspect <run-id> [--object <id>] [--phase <name>]\n  \
         psk replay <run-id> [--independent]\n  \
         psk effect plan <run-id>\n  \
         psk effect apply <token> --sandbox\n  \
         psk reconcile <run-id>\n  \
         psk certify <run-id>\n  \
         psk residue list <run-id>\n  \
         psk export bundle|report|certificate <run-id>"
    );
}

fn not_yet_implemented(command: &str) -> ExitCode {
    eprintln!(
        "psk {command}: in Struktur 27.6 vorgesehen, in dieser Referenzimplementierung noch nicht \
         realisiert - es fehlt eine plattenpersistente, ueber <run-id> adressierbare Ablage ueber \
         einen Prozessaufruf hinaus. Siehe `psk` ohne Argumente fuer die real implementierten Kommandos."
    );
    ExitCode::FAILURE
}

fn cmd_constitution_verify(bundle: Option<&str>) -> ExitCode {
    let root = workspace_root();
    let bundle_path = bundle
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("constitution"));
    match verify_bundle::check_constitution_bundle(&bundle_path) {
        Ok(check) => {
            if let Some(status) = &check.declared_ancestor_status {
                eprintln!(
                    "psk constitution verify: Hinweis — declared_ancestor_constitution_id: {status} (OBL-009, nicht Pruefziel)"
                );
            }
            match &check.stored_constitution_id {
                None => {
                    eprintln!(
                        "psk constitution verify: NOCH NICHT VERSIEGELT — berechnet: {}",
                        check.computed_constitution_id
                    );
                    ExitCode::SUCCESS
                }
                Some(stored) => {
                    if check.matches() {
                        eprintln!(
                            "psk constitution verify: PASS — {}",
                            check.computed_constitution_id
                        );
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "psk constitution verify: FAIL — gespeichert {stored}, berechnet {}",
                            check.computed_constitution_id
                        );
                        ExitCode::FAILURE
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("psk constitution verify: FAIL — {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_architecture_verify() -> ExitCode {
    let root = workspace_root();
    match verify_architecture::check_architecture_bundle(&root) {
        Ok(check) => {
            if !check.schema_conformant() {
                for (name, errors) in &check.schema_failures {
                    eprintln!("psk architecture verify: SCHEMA-FAIL {name}:");
                    for e in errors {
                        eprintln!("    - {e}");
                    }
                }
                return ExitCode::FAILURE;
            }
            if !check.missing.is_empty() {
                eprintln!(
                    "psk architecture verify: FAIL — {} Dateien fehlen: {}",
                    check.missing.len(),
                    check.missing.join(", ")
                );
                return ExitCode::FAILURE;
            }
            match &check.stored_architecture_id {
                None => {
                    eprintln!(
                        "psk architecture verify: NOCH NICHT VERSIEGELT — berechnet: {}",
                        check.computed_architecture_id
                    );
                    ExitCode::SUCCESS
                }
                Some(stored) => {
                    if check.matches() {
                        eprintln!(
                            "psk architecture verify: PASS — {}",
                            check.computed_architecture_id
                        );
                        ExitCode::SUCCESS
                    } else {
                        eprintln!(
                            "psk architecture verify: FAIL — gespeichert {stored}, berechnet {}",
                            check.computed_architecture_id
                        );
                        ExitCode::FAILURE
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("psk architecture verify: FAIL — {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_refinement_verify() -> ExitCode {
    let root = workspace_root();
    if let Err(e) = verify_refinement::check_core_fidelity(&root) {
        eprintln!("psk refinement verify: FAIL — {e}");
        return ExitCode::FAILURE;
    }
    let doc = match verify_refinement::read_refinement_map(&root) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("psk refinement verify: FAIL — {e}");
            return ExitCode::FAILURE;
        }
    };
    if !doc.internally_consistent() || doc.blocks_on_unmapped() {
        eprintln!(
            "psk refinement verify: FAIL — mapped={} unmapped={} concrete={} complete={}",
            doc.coverage.mapped,
            doc.coverage.unmapped,
            doc.coverage.concrete_transitions,
            doc.coverage.complete
        );
        return ExitCode::FAILURE;
    }
    eprintln!(
        "psk refinement verify: PASS — FSM-Treue bestaetigt, {} von {} konkreten Transitionen abgebildet.",
        doc.coverage.mapped, doc.coverage.concrete_transitions
    );
    ExitCode::SUCCESS
}

fn cmd_anchor_seal(workspace: &str) -> ExitCode {
    let workspace_path = Path::new(workspace);
    if !workspace_path.is_dir() {
        eprintln!("psk anchor seal: {workspace} ist kein Verzeichnis");
        return ExitCode::FAILURE;
    }
    let observed_at = psk_types::DualTime {
        tau_i: 0,
        tau_e: chrono_like_timestamp(),
        clock_ref: psk_types::ClockRef("psk-cli".into()),
        uncertainty_ns: 0,
    };
    let config = observer_local_fs::ObserverConfig::new(workspace_path);
    let record = match observer_local_fs::observe(&config, observed_at.clone()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("psk anchor seal: Beobachtung fehlgeschlagen — {e}");
            return ExitCode::FAILURE;
        }
    };
    let provenance = psk_anchor::bind_provenance(
        &record,
        psk_types::objects::AdapterId("observer-local-fs".into()),
        psk_types::Digest::sha256(b"psk-cli-observer"),
        "filesystem-read".into(),
    );
    let snapshot = psk_anchor::seal_anchor(psk_anchor::AnchorInputs {
        observations: vec![psk_types::objects::Observation(format!(
            "{} Dateien unter {} beobachtet",
            record.file_hashes.len(),
            workspace_path.display()
        ))],
        provenance,
        uncertainty: psk_anchor::no_declared_uncertainty(psk_types::objects::UncertaintyModelId(
            "none-declared".into(),
        )),
        context: psk_types::objects::ContextRef("psk-cli".into()),
        time: observed_at,
        validity: psk_types::objects::Validity {
            freshness_predicate: psk_types::objects::PredicateExpr("always".into()),
            expires_at_tau_i: u64::MAX,
        },
        boundary: psk_types::objects::ScopeExpr(workspace_path.display().to_string()),
    });
    match snapshot {
        Ok(a) => {
            eprintln!(
                "psk anchor seal: PASS — id={:?} digest={} files={}",
                a.id,
                a.digest,
                record.file_hashes.len()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("psk anchor seal: FAIL — {e:?}");
            ExitCode::FAILURE
        }
    }
}

/// Kein `chrono`-Abhaengigkeit fuer einen einzelnen Zeitstempel - `DualTime.
/// tau_e` ist laut Struktur 7.1 eine ISO-8601-Projektion, nicht
/// identitaetsbildend (`tau_i` traegt die kanonische Zeit). Ein fester
/// Platzhalter waere falsch (keine echte Wanduhrzeit); diese Funktion liest
/// die reale Systemzeit ueber `SystemTime`, ohne eine neue Kalenderbibliothek
/// einzufuehren.
fn chrono_like_timestamp() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("unix:{secs}")
}

fn default_sandbox_path() -> PathBuf {
    std::env::temp_dir().join(format!("psk-golden-run-cli-{}", std::process::id()))
}

/// Fuehrt den Golden Run inklusive I7-Replay aus (`run_golden_run_with_
/// certificate` laeuft bereits zweimal INNERHALB dieses Prozesses) und
/// meldet menschenlesbar auf stderr. `--independent`/I8 baut auf diesem
/// Ergebnis auf, statt es zu wiederholen - siehe `cmd_golden_run_independent`.
fn run_and_report(
    root: &Path,
    sandbox_path: &Path,
) -> Result<psk_conformance::GoldenRunCertification, psk_types::PskError> {
    let result = psk_conformance::run_golden_run_with_certificate(root, sandbox_path)?;
    eprintln!(
        "psk golden-run: Bootgate={:?} PatchGate={:?} Reconciliation={:?}/{:?}",
        result.first.boot_gate.decision,
        result.first.patch_gate.decision,
        result.first.reconciliation.verdict,
        result.first.reconciliation.fact_promotion,
    );
    eprintln!(
        "psk golden-run: Replay canonical_digest_match={} gate_sequence_match={} byte_identical_artifacts={}",
        result.replay_check.canonical_digest_match,
        result.replay_check.gate_sequence_match,
        result.replay_check.byte_identical_artifacts,
    );
    eprintln!(
        "psk golden-run: PASS — Zertifikat conformance_class={:?} replay_class={:?}",
        result.certificate.conformance_class, result.certificate.replay_class
    );
    Ok(result)
}

/// Der isolierte Kandidatenlauf (Algorithmus Revisionsvorschlag:
/// build_in_isolation, getrennter Prozess). Der Kandidat unterscheidet
/// sich vom aktiven System um EIN Delta der Klasse Tests-und-
/// Falsifikatoren: das im Elternlauf entdeckte Gegenmodell als stehender
/// Falsifikator. Dieser Prozess fuehrt beides aus:
///
/// 1. den Delta-Falsifikator des Kandidaten - Korpus laden, Widersprueche
///    bestimmen, pruefen, dass der erwartete Gegenbeleg gefunden wird -
///    und meldet `falsifier=PASS|FAIL`;
/// 2. den vollen Golden Run im eigenen Prozess und meldet
///    `digest=<trace_head>` - der Elternprozess vergleicht ihn mit seinem
///    eigenen Kopf (unabhaengiger Replay des Kandidaten).
///
/// BEWUSST `run_golden_run` (ein Lauf), nicht die Zertifizierung: die
/// enthaelt seit dem CRA-Bau selbst den Self-Compile-Schritt, und ein
/// Kind, das sie riefe, spawnte sein eigenes Enkelkind - Rekursion statt
/// Isolation.
fn cmd_candidate_check(sandbox: &str, expected_countermodel: &str) -> ExitCode {
    let root = workspace_root();
    let sandbox_path = PathBuf::from(sandbox);

    // Identische Startzustaende wie der Elternlauf: reset, dann laufen.
    let _ = std::fs::remove_dir_all(&sandbox_path);

    let corpus_root = root.join("domains/jacobs-ladder-reference/corpus");
    let falsifier_pass = (|| -> Result<bool, psk_types::PskError> {
        let reqs = psk_conformance::load_requirements(&corpus_root)?;
        let contradictions = psk_conformance::identify_contradictions(&reqs)?;
        let countermodels = psk_conformance::falsifier_countermodels(&contradictions);
        Ok(countermodels.iter().any(|c| c.0 == expected_countermodel))
    })();
    match falsifier_pass {
        Ok(true) => println!("falsifier=PASS"),
        Ok(false) => println!("falsifier=FAIL"),
        Err(e) => {
            eprintln!("psk candidate-check: Falsifikator nicht auswertbar - {e:?}");
            println!("falsifier=FAIL");
        }
    }

    match psk_conformance::run_golden_run(&root, &sandbox_path) {
        Ok(report) => {
            println!("digest={}", report.trace_head);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("psk candidate-check: Kandidatenlauf FAIL - {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_golden_run(sandbox: Option<&str>) -> ExitCode {
    let root = workspace_root();
    let sandbox_path = sandbox
        .map(PathBuf::from)
        .unwrap_or_else(default_sandbox_path);

    match run_and_report(&root, &sandbox_path) {
        // Struktur 22.7: `final_canonical_digest` ist der repraesentative
        // kanonische Zustandsdigest ueber Schritte 2-13 - genau das, was
        // I8 unabhaengig reproduziert sehen will. Allein auf stdout (die
        // eprintln-Meldungen oben bleiben auf stderr), damit ein Elternprozess
        // (siehe `cmd_golden_run_independent`) ihn trivial einlesen kann.
        Ok(result) => {
            println!("{}", result.replay_manifest.final_canonical_digest);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("psk golden-run: FAIL — {e:?}");
            ExitCode::FAILURE
        }
    }
}

/// I8 (Phasentabelle 32.1: "Independent Replay ... Zweiter Prozess oder
/// Rechner reproduziert die kanonischen Resultate.", Klasse C5). Woertlich
/// erfuellt durch einen ECHTEN zweiten Betriebssystemprozess (nicht nur
/// einen zweiten Funktionsaufruf im selben Prozess - das leistet bereits
/// I7s `run_golden_run_with_certificate`), der denselben kanonischen
/// Zustandsdigest reproduziert. Das Kriterium ist Uebereinstimmung, nicht
/// PASS: ein HOLD an Schritt 1 (M00/M02/M04 real noch nicht gebaut, siehe
/// psk-conformance/src/golden_run.rs Modulkopf) erfuellt I8 genauso, wenn
/// beide Prozesse unabhaengig voneinander zum selben HOLD mit demselben
/// Digest kommen.
fn cmd_golden_run_independent(sandbox: Option<&str>) -> ExitCode {
    let root = workspace_root();
    let sandbox_path = sandbox
        .map(PathBuf::from)
        .unwrap_or_else(default_sandbox_path);

    eprintln!("psk golden-run --independent: erster (dieser) Prozess laeuft...");
    let first_digest = match run_and_report(&root, &sandbox_path) {
        Ok(result) => result.replay_manifest.final_canonical_digest,
        Err(e) => {
            eprintln!("psk golden-run --independent: FAIL — erster Prozess — {e:?}");
            return ExitCode::FAILURE;
        }
    };

    // Reset auf denselben Ausgangszustand wie beim ersten Prozess - siehe
    // psk-conformance/src/golden_run.rs's Begruendung fuer denselben Reset
    // zwischen den beiden INTERNEN Replay-Laeufen: Schritt 2 beobachtet den
    // Sandboxinhalt, Schritt 10 veraendert ihn, also braucht ein fairer
    // zweiter Lauf denselben Startzustand, nicht nur denselben Pfad.
    if let Err(e) = std::fs::remove_dir_all(&sandbox_path) {
        if e.kind() != std::io::ErrorKind::NotFound {
            eprintln!(
                "psk golden-run --independent: FAIL — konnte Sandbox nicht zuruecksetzen — {e}"
            );
            return ExitCode::FAILURE;
        }
    }

    eprintln!("psk golden-run --independent: zweiter, echter Kindprozess startet...");
    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("psk golden-run --independent: FAIL — eigenen Pfad nicht ermittelbar — {e}");
            return ExitCode::FAILURE;
        }
    };
    let output = std::process::Command::new(exe)
        .arg("golden-run")
        .arg(&sandbox_path)
        .output();
    let output = match output {
        Ok(o) => o,
        Err(e) => {
            eprintln!("psk golden-run --independent: FAIL — Kindprozess nicht startbar — {e}");
            return ExitCode::FAILURE;
        }
    };
    // Der Kindprozess meldet seinerseits menschenlesbar auf stderr -
    // durchreichen, damit beide Laeufe fuer den Bediener sichtbar sind.
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    if !output.status.success() {
        eprintln!("psk golden-run --independent: FAIL — Kindprozess scheiterte");
        return ExitCode::FAILURE;
    }
    let second_digest = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if second_digest == first_digest.to_string() {
        eprintln!(
            "psk golden-run --independent: PASS (I8) — zweiter, unabhaengiger Prozess reproduziert denselben kanonischen Zustandsdigest ({first_digest})"
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "psk golden-run --independent: FAIL (I8) — Digests weichen ab. Erster Prozess: {first_digest}, zweiter Prozess: {second_digest}"
        );
        ExitCode::FAILURE
    }
}

fn cmd_conformance_run() -> ExitCode {
    let status = std::process::Command::new(env!("CARGO"))
        .args(["test", "-p", "psk-conformance"])
        .current_dir(workspace_root())
        .status();
    match status {
        Ok(s) if s.success() => ExitCode::SUCCESS,
        Ok(_) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("psk conformance run: konnte `cargo test` nicht starten — {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();

    match refs.as_slice() {
        ["constitution", "verify"] => cmd_constitution_verify(None),
        ["constitution", "verify", bundle] => cmd_constitution_verify(Some(bundle)),
        ["architecture", "verify"] => cmd_architecture_verify(),
        ["refinement", "verify"] => cmd_refinement_verify(),
        ["anchor", "seal", workspace] => cmd_anchor_seal(workspace),
        ["golden-run"] => cmd_golden_run(None),
        ["golden-run", "--independent"] => cmd_golden_run_independent(None),
        ["golden-run", "--independent", sandbox] => cmd_golden_run_independent(Some(sandbox)),
        ["golden-run", sandbox, "--independent"] => cmd_golden_run_independent(Some(sandbox)),
        ["golden-run", sandbox] => cmd_golden_run(Some(sandbox)),
        ["candidate-check", sandbox, expected_countermodel] => {
            cmd_candidate_check(sandbox, expected_countermodel)
        }
        ["conformance", "run"] => cmd_conformance_run(),
        ["conformance", "run", "--class", _class] => cmd_conformance_run(),
        ["run", ..] => not_yet_implemented("run"),
        ["inspect", ..] => not_yet_implemented("inspect"),
        ["replay", ..] => not_yet_implemented("replay"),
        ["effect", "plan", ..] => not_yet_implemented("effect plan"),
        ["effect", "apply", ..] => not_yet_implemented("effect apply"),
        ["reconcile", ..] => not_yet_implemented("reconcile"),
        ["certify", ..] => not_yet_implemented("certify"),
        ["residue", "list", ..] => not_yet_implemented("residue list"),
        ["export", ..] => not_yet_implemented("export"),
        _ => {
            print_usage();
            ExitCode::FAILURE
        }
    }
}
