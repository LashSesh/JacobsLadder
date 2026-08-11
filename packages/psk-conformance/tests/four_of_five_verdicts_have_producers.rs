//! QPM-6, Schicht 2: vier der fuenf Verdikte der Ergebnisordnung
//! (QPM Struktur 4.2 (Ergebnisordnung)) sind real erzeugbar - UNKNOWN,
//! OUT_OF_SCOPE und INVALID mit Erzeugerpfaden, dazu die beiden
//! Gate-Achsenwerte. KNOWN und AMBIGUOUS bleiben ohne Erzeuger: beide
//! sind per Definition Katalogtreffer, und ein Katalog ist nicht
//! registriert - das ist der benannte Grund, aus dem die QPM-Leiter
//! nach dieser Schicht ruht.
//!
//! Jeder Positivbefund traegt seine Gegenprobe: derselbe Lauf, ungestoert,
//! landet NICHT im jeweiligen Verdikt.

use psk_conformance::{IdentityVerdict, RunGate};

/// INVALID-Erzeuger, Trace- und Provenienzseite (QPM Struktur 4.2 (Ergebnisordnung):
/// "Provenienz-, Gate-, Trace- oder Replaybruch").
///
/// Die beiden Bruecharten sind VERSCHIEDEN und werden verschieden
/// benannt - dieselbe Trennung, die Regel 7.42 (Zwei Digests je Segment)
/// in die Segmentdigests legt: eine inhaltliche Aenderung bricht die
/// Kette (Trace), eine Aenderung an tau_e bricht die
/// Aufzeichnungsintegritaet (Provenienz), ohne die Kette zu beruehren.
#[test]
fn a_tampered_trace_yields_invalid_and_names_the_break() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-inv-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let mut run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    // Gegenprobe zuerst: der ungestoerte Lauf ist NICHT invalide.
    let clean = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_eq!(clean.verdict, IdentityVerdict::Unknown);
    assert!(psk_conformance::evidence_breaks(&run).is_empty());

    // Trace-Bruch: eine inhaltliche Aenderung an einem mittleren Segment.
    let k = run.trace_segments.len() / 2;
    let untouched_payload = run.trace_segments[k].payload_digest;
    run.trace_segments[k].payload_digest = psk_types::Digest::sha256(b"tampered");
    let tampered = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_eq!(tampered.verdict, IdentityVerdict::Invalid);
    assert!(
        tampered.verdict_reason.contains("Trace-Bruch"),
        "der Bruch ist benannt: {}",
        tampered.verdict_reason
    );
    run.trace_segments[k].payload_digest = untouched_payload;

    // Provenienz-Bruch: NUR die Wanduhr eines Segments aendern. Die
    // Kettenpruefung sieht das seit v1.0.20 bewusst nicht mehr - die
    // Aufzeichnungsintegritaet MUSS es sehen.
    run.trace_segments[k].time.tau_e = "2031-01-01T00:00:00.000000000Z".to_string();
    let forged = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_eq!(forged.verdict, IdentityVerdict::Invalid);
    assert!(
        forged.verdict_reason.contains("Provenienz-Bruch"),
        "die Faelschung der Aufzeichnung ist als Provenienzbruch benannt: {}",
        forged.verdict_reason
    );

    // QPM Regel 4.3 (Zwei orthogonale Statusachsen): das Verdikt kippt,
    // die Gate-Achse bleibt eigenstaendig - die Masse ist weiter verbucht.
    assert_eq!(forged.run_gate, RunGate::Pass);
    println!("Trace-Bruch:      {}", tampered.verdict_reason);
    println!("Provenienz-Bruch: {}", forged.verdict_reason);
}

/// INVALID-Erzeuger, Gateseite: ein Lauf, dessen eigenes Bootgate FAIL
/// meldet, traegt keine Identitaetsfrage.
#[test]
fn a_failed_gate_in_the_evidence_yields_invalid() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-gate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let mut run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    let clean = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_ne!(clean.verdict, IdentityVerdict::Invalid);

    run.boot_gate.decision = psk_types::objects::GateReportDecisionKind::Fail;
    let broken = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_eq!(broken.verdict, IdentityVerdict::Invalid);
    assert!(
        broken.verdict_reason.contains("Gate-Bruch"),
        "{}",
        broken.verdict_reason
    );
}

/// INVALID-Erzeuger, Taktabgleich: so viele `tick.closed`-Siegel wie
/// Takte - die Zahl, die QPM-3 als Zyklusindex misst, hier als
/// Bruchbedingung.
#[test]
fn a_tick_count_mismatch_yields_invalid() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-tick-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let mut run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    run.ticks += 1;
    let broken = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_eq!(broken.verdict, IdentityVerdict::Invalid);
    assert!(
        broken.verdict_reason.contains("Taktsiegel"),
        "{}",
        broken.verdict_reason
    );
}

/// OUT_OF_SCOPE-Erzeuger (QPM Regel 3.3 (Scope ist explizit, nie universell)
/// Satz 1: "declared_channels MUSS vollständig sein"): ein Kanal, der
/// weder deklariert noch begruendet ausgenommen ist, ist eine
/// Abwesenheit - und macht den Scope-Vertrag unerfuellt.
#[test]
fn an_unaccounted_channel_yields_out_of_scope() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-oos-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    // Gegenprobe: unter dem echten Profil ist jeder der neun Kanaele
    // verbucht, und der Lauf steht auf UNKNOWN.
    let clean = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    assert_eq!(clean.verdict, IdentityVerdict::Unknown);

    // Ein Wurzelverzeichnis, dessen Profil den spectrum-Kanal WEDER
    // deklariert NOCH ausnimmt - die Zeile fehlt ersatzlos.
    let profile_rel = "domains/jacobs-ladder-reference/domain_profile.yaml";
    let text = std::fs::read_to_string(root.join(profile_rel)).expect("Profil lesbar");
    let gutted: String = text
        .lines()
        .filter(|l| !l.trim_start().starts_with("spectrum:"))
        .collect::<Vec<_>>()
        .join("\n");
    assert_ne!(gutted, text, "die spectrum-Zeile war da und ist jetzt weg");

    let gutted_root = std::env::temp_dir().join(format!("psk-qpm-oos-root-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&gutted_root);
    std::fs::create_dir_all(gutted_root.join("domains/jacobs-ladder-reference"))
        .expect("Wurzel anlegbar");
    std::fs::write(gutted_root.join(profile_rel), gutted).expect("Profil schreibbar");

    let out = psk_conformance::observe_golden_run(&run, &gutted_root).expect("QPM-Beobachtung");
    assert_eq!(out.verdict, IdentityVerdict::OutOfScope);
    assert!(
        out.verdict_reason.contains("spectrum"),
        "der fehlende Kanal ist benannt: {}",
        out.verdict_reason
    );
    // Die Gate-Achse bleibt unabhaengig: die Messung selbst ging auf.
    assert_eq!(out.run_gate, RunGate::Pass);
    println!("OUT_OF_SCOPE: {}", out.verdict_reason);
}

/// Die UNKNOWN-Deckelung ist GEMESSEN, nicht vorweggenommen: das
/// Verdikt des Referenzlaufs kommt aus dem Ergebnis der Abfragestufe
/// (QPM-OBL-002, Leerform), und das Artefakt zeigt dieses Ergebnis.
#[test]
fn the_capping_is_measured_at_the_query_not_presumed() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-cap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let qpm = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");

    // Die Stufe hat stattgefunden und ihr Ergebnis steht im Artefakt:
    // keine Abfrage, mit benanntem Weg dorthin.
    let psk_conformance::CatalogQuery::NotQueried { reason } = &qpm.catalog_query else {
        panic!("ohne registriertes Woerterbuch kann keine Abfrage stattgefunden haben");
    };
    assert!(reason.contains("catalog_ref"));

    // Das Verdikt IST die Entscheidung ueber diesem Ergebnis - nicht
    // eine zweite, parallel gefuehrte Ableitung.
    let (verdict, reason) = psk_conformance::open_set_decide(&qpm.catalog_query);
    assert_eq!(qpm.verdict, verdict);
    assert_eq!(qpm.verdict_reason, reason);

    // Und die Scope-Politik sagt dasselbe VORHER (Typaussage), was die
    // Stufe NACHHER misst - beide Formen existieren, die Messung traegt.
    assert_eq!(qpm.scope.ceiling(), psk_fields::ScopeCeiling::ForcedUnknown);
    assert!(qpm.verdict_reason.contains("keine Abfrage"));
}

/// QPM Regel 3.17 (Zwei Weisen, UNKNOWN zu sein), am Artefakt: der
/// Referenzlauf steht in Lage 2 - keine Abfrage, Scope-Deckelung, KEIN
/// UnknownRecord. Lage 1 ("katalogfremd") setzt einen Katalogstand
/// voraus; die Entscheidung ueber ihr haelt die Lagen auseinander.
#[test]
fn the_reference_run_is_unknown_by_capping_not_by_query() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-lage-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let qpm = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");

    // Lage 2, woertlich: "das Verdikt ist UNKNOWN, weil nichts geprueft
    // wurde, nicht weil etwas geprueft und nicht gefunden wurde."
    assert_eq!(qpm.verdict, IdentityVerdict::Unknown);
    assert!(qpm.verdict_reason.contains("keine Abfrage"));
    assert!(
        !qpm.verdict_reason.contains("katalogfremd"),
        "Lage 1 behauptete eine Abfrage, die nicht stattfand: {}",
        qpm.verdict_reason
    );

    // Die Gegenlage, als Entscheidung ueber konstruiertem Abfrageergebnis:
    // ein geprueft-und-nichts-passte traegt den anderen Grund.
    let queried = psk_conformance::CatalogQuery::Queried {
        catalog_digest: psk_types::Digest::sha256(b"ein-katalogstand"),
        candidates: vec![],
    };
    let (v, r) = psk_conformance::open_set_decide(&queried);
    assert_eq!(v, IdentityVerdict::Unknown);
    assert!(r.contains("katalogfremd"));
    assert_ne!(
        r, qpm.verdict_reason,
        "die zwei Weisen fallen nicht zusammen"
    );
}

fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
        assert!(dir.pop(), "keine Workspace-Wurzel");
    }
    dir
}
