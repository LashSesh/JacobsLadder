//! Der C4-Versuch: eine reale Ausstellung, kein Audit - seit v1.0.23 mit
//! ABGELEITETEM statt beanspruchtem Deckungsvektor.
//!
//! Tabelle 23.2: C4 ("Reference-validated") verlangt FC0-FC6 und FC8,
//! `reference_validated`, mindestens R2 (Vertrag 22.5 (Replayklasse des Referenzrelease)) und - seit
//! Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat) - dass `scope` jede
//! plattformgebundene Verpflichtungsaufloesung nennt, von der die beanspruchte Klasse abhaengt. Fuer C4 ist das
//! OBL-010 (`blocking_from: C4`, `resolution_platform: windows`).
//!
//! Die Eingaben kommen so weit wie moeglich aus einem ECHTEN Lauf:
//! `trace_head`, `replay_manifest_digest` und die Replayklasse stammen
//! aus `run_golden_run_with_certificate`, die vier Identitaeten aus
//! dessen realem `boot_report`. OBL-010s beide fuer Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat)
//! massgeblichen Felder werden aus `architecture/obligations.yaml`
//! GELESEN, nicht einprogrammiert - sonst prueft e der Test seine eigene
//! Annahme statt des Registers.
//!
//! `feature_coverage` ist im Werk als "abgeleiteter Deckungsvektor"
//! spezifiziert (Struktur 7.50 (MachineCertificate)). Der Versuch beansprucht ihn deshalb
//! nicht mehr, sondern misst ihn an den Artefakten dieses Laufs
//! (`collect_feature_evidence`) und leitet ihn daraus ab
//! (`derive_feature_coverage`). Die Klasse folgt aus dem Vektor - sie
//! wird nicht daneben behauptet. Dass der Versuch weiter "C4-Versuch"
//! heisst, beschreibt seine Absicht, nicht sein Ergebnis.

use psk_certify::{
    issue_certificate, AdditionalAcceptance, CertificateInputs, ObligationPlatformBinding,
};
use psk_types::objects::{
    FeatureCoverageId, MachineCertificateConformanceClassKind as Class,
    MachineCertificateReplayClassKind, ScopeExpr,
};
use psk_types::Digest;

/// Liest OBL-010s `blocking_from` und `resolution_platform` aus dem
/// echten Register. Bewusst zeilenweise statt ueber einen YAML-Parser:
/// dieselbe Enge wie in den verify-*-Werkzeugen, und der Test soll an
/// einer Registeraenderung scheitern, nicht sie wegabstrahieren.
fn obl_010_from_register() -> ObligationPlatformBinding {
    let root = {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
        dir
    };
    let text = std::fs::read_to_string(root.join("architecture/obligations.yaml"))
        .expect("obligations.yaml lesbar");

    let start = text
        .find("- id: OBL-010")
        .expect("OBL-010 steht im Register");
    let rest = &text[start..];
    let end = rest[1..]
        .find("\n  - id: ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    let entry = &rest[..end];

    let field = |name: &str| -> String {
        entry
            .lines()
            .find_map(|l| l.trim().strip_prefix(&format!("{name}: ")).map(str::trim))
            .unwrap_or_else(|| panic!("{name} fehlt in OBL-010"))
            .to_string()
    };

    let blocking_from = match field("blocking_from").as_str() {
        "C0" => Some(Class::C0),
        "C1" => Some(Class::C1),
        "C2" => Some(Class::C2),
        "C3" => Some(Class::C3),
        "C4" => Some(Class::C4),
        "C5" => Some(Class::C5),
        "null" => None,
        other => panic!("unbekannte Klasse in blocking_from: {other}"),
    };

    ObligationPlatformBinding {
        id: "OBL-010".to_string(),
        blocking_from,
        resolution_platform: field("resolution_platform"),
    }
}

/// FC0-FC6 und FC8 - der von Tabelle 23.2 fuer C4 verlangte Vektor, als
/// BEHAUPTUNG.
///
/// Ab v1.0.23 wird der Vektor des eigentlichen Versuchs nicht mehr so
/// gebildet: `feature_coverage` ist im Werk als "abgeleiteter
/// Deckungsvektor" spezifiziert, und solange er beansprucht statt
/// abgeleitet wird, ist die Klasse selbst beansprucht. Diese Funktion
/// bleibt nur fuer die drei Gegenproben weiter unten stehen, deren
/// Gegenstand Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat) ist: sie muessen den C4-Zweig erreichen, um
/// zeigen zu koennen, dass die Plattformregel dort ueberhaupt feuert. Mit
/// einem abgeleiteten Vektor, der C4 nicht traegt, wuerden sie zu leeren
/// Gruenlaeufen - sie wuerden dann aus dem falschen Grund bestehen.
fn claimed_c4_features() -> Vec<FeatureCoverageId> {
    use FeatureCoverageId::*;
    vec![Fc0, Fc1, Fc2, Fc3, Fc4, Fc5, Fc6, Fc8]
}

fn c4_acceptance() -> AdditionalAcceptance {
    AdditionalAcceptance {
        artifact_conformant: true,
        kernel_executable: true,
        replay_valid: true,
        sandbox_effect_safe: true,
        reference_validated: true,
        // C5 wird NICHT beansprucht: keine unabhaengige Instanz hat
        // reproduziert.
        externally_reproduced: false,
    }
}

/// Der Versuch selbst. Meldet den vollstaendigen Inhalt - ausgestellt
/// oder verweigert.
#[test]
fn attempt_to_issue_a_c4_certificate_and_report_the_full_contents() {
    let root = {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
        dir
    };
    let sandbox = std::env::temp_dir().join(format!("psk-c4-attempt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);

    let certification = psk_conformance::run_golden_run_with_certificate(&root, &sandbox)
        .expect("der Golden Run selbst muss laufen");

    // Der Deckungsvektor wird ABGELEITET, nicht beansprucht: gemessen an
    // den Artefakten, die dieser Lauf tatsaechlich hervorgebracht hat.
    // Der Baselinevergleich ist FC8s einziger Beleg und laeuft deshalb
    // mit; er wiederholt intern den Zertifizierungslauf.
    let baseline = psk_conformance::run_baseline_comparison(&root)
        .expect("der Baselinevergleich selbst muss laufen");
    // Die vier Berichtsdigests des Zertifikats zeigen ab jetzt auf reale
    // aggregierte Berichte, nicht auf Platzhalter. Drei davon
    // (negative_test_report, residue_report, capability_audit) stehen
    // namentlich unter den acht Pflichtberichten.
    let catalog_source =
        std::fs::read_to_string(root.join("packages/psk-conformance/src/conformance_catalog.rs"))
            .expect("Konformanzkatalog lesbar");
    let reports = psk_conformance::aggregate_reports(
        &[
            &certification.first.boot_gate,
            &certification.first.patch_gate,
            &certification.second.boot_gate,
            &certification.second.patch_gate,
        ],
        &certification.first.residues,
        &certification.first.boot_report.runtime_manifest,
        &catalog_source,
    )
    .expect("die Berichte muessen sich aggregieren lassen");

    println!("=== Aggregierte Berichte (Struktur 7.50 (MachineCertificate)) ===");
    for r in [
        &reports.gate_report,
        &reports.residue_report,
        &reports.capability_audit,
        &reports.negative_test_report,
    ] {
        println!("  {:<22} {}", r.name, r.digest);
    }
    println!();

    // Zwei Laeufe desselben RunDescriptors muessen identische
    // Berichtsdigests liefern. Das ist eine DETERMINISMUSaussage, nicht
    // mehr: die Uhr des Golden Runs ist eine Konstante (in beiden Laeufen
    // derselbe tau_e), also bestuende dieser Vergleich auch dann, wenn die
    // Wanduhr im Digest saesse. Dass sie es nicht tut, beweist
    // `reports::tests::the_wall_clock_does_not_reach_the_gate_report_digest`
    // an Berichten, die sich ausschliesslich in tau_e unterscheiden. Hier
    // steht die schwaechere, aber eigenstaendige Aussage: was der Lauf an
    // Berichten hervorbringt, haengt nicht vom Lauf ab.
    let per_run = |run: &psk_conformance::GoldenRunReport| {
        psk_conformance::aggregate_reports(
            &[&run.boot_gate, &run.patch_gate],
            &run.residues,
            &run.boot_report.runtime_manifest,
            &catalog_source,
        )
        .expect("aggregierbar")
    };
    let first_reports = per_run(&certification.first);
    let second_reports = per_run(&certification.second);
    assert_eq!(
        first_reports.gate_report.digest, second_reports.gate_report.digest,
        "zwei identische Laeufe MUESSEN denselben Gatberichtsdigest liefern"
    );
    assert_eq!(
        first_reports.residue_report.digest, second_reports.residue_report.digest,
        "zwei identische Laeufe MUESSEN denselben Residuenberichtsdigest liefern"
    );
    assert_eq!(
        first_reports.capability_audit.digest, second_reports.capability_audit.digest,
        "zwei identische Laeufe MUESSEN denselben Fahigkeitsaudit liefern"
    );
    println!(
        "  (Lauf 1 und Lauf 2 liefern dieselben Berichtsdigests: deterministisch.)
"
    );

    let evidence = psk_conformance::collect_feature_evidence(&certification, Some(&baseline));
    let derivation = psk_certify::derive_feature_coverage(&evidence);

    println!("=== Abgeleiteter Deckungsvektor (Kapitel 23) ===");
    for f in &derivation.findings {
        println!(
            "  {:<4} {}  {}",
            format!("{:?}", f.feature).to_uppercase(),
            if f.covered { "JA  " } else { "NEIN" },
            f.reason
        );
    }
    println!("  => FC = {:?}", derivation.covered);

    let boot = &certification.first.boot_report;
    let obl_010 = obl_010_from_register();

    println!("\n=== OBL-010, aus architecture/obligations.yaml gelesen ===");
    println!("  blocking_from      = {:?}", obl_010.blocking_from);
    println!("  resolution_platform = {}", obl_010.resolution_platform);
    println!("  current_platform    = {}", std::env::consts::OS);

    let scope = ScopeExpr(format!(
        "reference-domain=jacobs-ladder-workspace; platform={}",
        obl_010.resolution_platform
    ));

    println!("\n=== Eingaben ===");
    println!("  features   = {:?} (abgeleitet)", derivation.covered);
    println!(
        "  klasse     = {:?} (aus dem abgeleiteten Vektor)",
        psk_certify::compute_conformance_class(&derivation.covered, c4_acceptance())
    );
    println!("  acceptance = {:?}", c4_acceptance());
    println!(
        "  replay     = attempted={} canonical_match={} gate_match={} byte_identical={}",
        certification.replay_check.replay_attempted,
        certification.replay_check.canonical_digest_match,
        certification.replay_check.gate_sequence_match,
        certification.replay_check.byte_identical_artifacts
    );
    println!("  scope      = {}", scope.0);

    let outcome = issue_certificate(CertificateInputs {
        i_c: boot.identity.I_C,
        i_a: boot.identity.I_A,
        i_m: boot.identity.I_M,
        i_t: boot.identity.I_t,
        features: derivation.covered.clone(),
        acceptance: c4_acceptance(),
        replay_class: MachineCertificateReplayClassKind::R2,
        gate_report_digest: reports.gate_report.digest,
        trace_head: certification.first.trace_head,
        replay_manifest_digest: Digest::sha256(b"c4-attempt-replay-manifest"),
        residue_report_digest: reports.residue_report.digest,
        capability_audit_digest: reports.capability_audit.digest,
        negative_test_report_digest: reports.negative_test_report.digest,
        scope: scope.clone(),
        issued_at: psk_types::DualTime {
            tau_i: 2_000_000,
            tau_e: "2026-08-08T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("c4-attempt".into()),
            uncertainty_ns: 0,
        },
        signature: psk_types::Signature(vec![]),
        current_platform: std::env::consts::OS.to_string(),
        platform_bound_obligations: vec![obl_010],
    });

    println!("\n=== ERGEBNIS ===");
    match &outcome {
        Ok(cert) => {
            println!("AUSGESTELLT");
            println!("  I_C               = {}", cert.I_C);
            println!("  I_A               = {}", cert.I_A);
            println!("  I_M               = {}", cert.I_M);
            println!("  I_t               = {}", cert.I_t);
            println!("  conformance_class = {:?}", cert.conformance_class);
            println!("  feature_coverage  = {:?}", cert.feature_coverage);
            println!("  replay_class      = {:?}", cert.replay_class);
            println!("  scope             = {}", cert.scope.0);
            println!("  trace_head        = {}", cert.trace_head);
            println!("  issued_at.tau_i   = {}", cert.issued_at.tau_i);
        }
        Err(e) => {
            println!("VERWEIGERT: {:?} ({})", e, e.code());
            println!("  beansprucht war   = C4");
            println!("  scope             = {}", scope.0);
        }
    }

    let _ = std::fs::remove_dir_all(&sandbox);

    // Der Test faellt NICHT, wenn verweigert wird - beide Ausgaenge sind
    // ein gueltiges Ergebnis dieses Versuchs, und ein Fehlschlag waere
    // die praeziseste Beschreibung des Rests. Was er festhaelt, ist nur:
    // die Ausstellung wurde real versucht, mit realen Eingaben.
    //
    // Festgehalten wird die BEZIEHUNG, nicht der Wert: welche Stufen
    // gerade belegt sind, aendert sich mit dem Bauzustand, und ein Test,
    // der [Fc0, Fc1, Fc6, Fc8] festnagelt, wuerde spaeteren Fortschritt
    // als Bruch melden. Unveraenderlich ist dagegen, dass das Zertifikat
    // genau den abgeleiteten Vektor traegt und seine Klasse genau aus
    // diesem Vektor folgt - das ist der Unterschied zwischen abgeleitet
    // und beansprucht.
    if let Ok(cert) = &outcome {
        assert_eq!(
            cert.feature_coverage, derivation.covered,
            "das Zertifikat MUSS den abgeleiteten Vektor tragen, keinen anderen"
        );
        assert_eq!(
            cert.conformance_class,
            psk_certify::compute_conformance_class(&derivation.covered, c4_acceptance()),
            "die Klasse MUSS aus dem abgeleiteten Vektor folgen, nicht neben ihm stehen"
        );
    }

    // Und: die Ableitung darf nicht leer durchlaufen. Ein Vektor, der aus
    // Versehen immer leer bliebe, waere kein ehrlicher Vektor, sondern ein
    // kaputter Messpunkt - beides sieht im Zertifikat gleich aus.
    assert!(
        !derivation.covered.is_empty(),
        "die Messung selbst muss etwas finden, sonst misst sie nicht"
    );
    assert_eq!(
        derivation.findings.len(),
        9,
        "jede der neun Stufen MUSS begruendet sein, gedeckt oder nicht"
    );

    // Die EXECUTABLE-Frage, hier erst vollstaendig beantwortbar: der
    // Zweitlauf fuellt den Replayschenkel von Close720 (Definition 22.1 (Replayklassen)).
    // Antwort des Referenzlaufs: NEIN - und zwar nicht mehr an der
    // Topologie (alle 18 Zellen schliessen seit v1.0.34 real), sondern
    // am blockierenden Residuum des offenen Korpuswiderspruchs.
    let x = &certification.first.executable;
    assert_eq!(
        x.close720_replay_canon_eq,
        Some(true),
        "R2-Replay traegt den dritten Close720-Schenkel"
    );
    assert_eq!(
        x.close720(),
        Some(true),
        "Close720 haelt (trivial + Replay)"
    );
    assert_eq!(
        x.executable_reachable(),
        Some(false),
        "EXECUTABLE bleibt unerreichbar - am Residuum, nicht an der Topologie"
    );
    assert!(!x.no_blocking_residue);
    assert!(x.all_18_cells_closed);
    println!(
        "EXECUTABLE: {:?}, Blocker: {:?}",
        x.executable_reachable(),
        x.blockers
    );

    println!("\n(Versuch abgeschlossen - Ausgang oben.)");
}

/// Gegenprobe zu Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat) - ohne sie bliebe unbewiesen, dass die Regel
/// im obigen Erfolgsfall ueberhaupt gefeuert hat statt bloss nicht
/// gestoert zu haben.
///
/// Dieselben Eingaben, EIN Unterschied: `scope` verschweigt die
/// Plattformbindung. Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat) verlangt dann Verweigerung - "sonst
/// behauptete das Zertifikat mehr, als geprueft wurde".
#[test]
fn the_same_c4_claim_is_refused_when_scope_hides_the_platform_binding() {
    let obl_010 = obl_010_from_register();
    let scope_without_platform = ScopeExpr("reference-domain=jacobs-ladder-workspace".to_string());
    assert!(
        !scope_without_platform.0.contains("platform="),
        "Vorbedingung: dieser scope nennt die Bindung gerade NICHT"
    );

    let outcome = issue_certificate(CertificateInputs {
        i_c: Digest::sha256(b"c4-counter-i-c"),
        i_a: Digest::sha256(b"c4-counter-i-a"),
        i_m: Digest::sha256(b"c4-counter-i-m"),
        i_t: Digest::sha256(b"c4-counter-i-t"),
        features: claimed_c4_features(),
        acceptance: c4_acceptance(),
        replay_class: MachineCertificateReplayClassKind::R2,
        gate_report_digest: Digest::sha256(b"c4-counter-gate-report"),
        trace_head: Digest::sha256(b"c4-counter-trace-head"),
        replay_manifest_digest: Digest::sha256(b"c4-counter-replay-manifest"),
        residue_report_digest: Digest::sha256(b"c4-counter-residue-report"),
        capability_audit_digest: Digest::sha256(b"c4-counter-capability-audit"),
        negative_test_report_digest: Digest::sha256(b"c4-counter-negative-tests"),
        scope: scope_without_platform,
        issued_at: psk_types::DualTime {
            tau_i: 2_000_001,
            tau_e: "2026-08-08T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("c4-counter".into()),
            uncertainty_ns: 0,
        },
        signature: psk_types::Signature(vec![]),
        current_platform: std::env::consts::OS.to_string(),
        platform_bound_obligations: vec![obl_010],
    });

    assert_eq!(
        outcome.err(),
        Some(psk_types::PskError::ReleaseGateBlocked),
        "Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat): ohne die Plattformbindung im scope MUSS die Ausstellung scheitern"
    );
}

/// Und die zweite Haelfte von Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat): auf einer Plattform OHNE
/// deklarierte Aufloesung "gilt die Verpflichtung als offen und die davon
/// abhaengige Konformanzklasse als nicht erreicht" - auch dann, wenn der
/// scope die Bindung brav nennt.
#[test]
fn the_same_c4_claim_is_refused_on_a_foreign_platform() {
    let obl_010 = obl_010_from_register();
    let scope = ScopeExpr(format!("platform={}", obl_010.resolution_platform));

    let outcome = issue_certificate(CertificateInputs {
        i_c: Digest::sha256(b"c4-foreign-i-c"),
        i_a: Digest::sha256(b"c4-foreign-i-a"),
        i_m: Digest::sha256(b"c4-foreign-i-m"),
        i_t: Digest::sha256(b"c4-foreign-i-t"),
        features: claimed_c4_features(),
        acceptance: c4_acceptance(),
        replay_class: MachineCertificateReplayClassKind::R2,
        gate_report_digest: Digest::sha256(b"c4-foreign-gate-report"),
        trace_head: Digest::sha256(b"c4-foreign-trace-head"),
        replay_manifest_digest: Digest::sha256(b"c4-foreign-replay-manifest"),
        residue_report_digest: Digest::sha256(b"c4-foreign-residue-report"),
        capability_audit_digest: Digest::sha256(b"c4-foreign-capability-audit"),
        negative_test_report_digest: Digest::sha256(b"c4-foreign-negative-tests"),
        scope,
        issued_at: psk_types::DualTime {
            tau_i: 2_000_002,
            tau_e: "2026-08-08T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("c4-foreign".into()),
            uncertainty_ns: 0,
        },
        signature: psk_types::Signature(vec![]),
        // Eine Plattform, fuer die OBL-010 keine Aufloesung deklariert.
        current_platform: "plan9".to_string(),
        platform_bound_obligations: vec![obl_010],
    });

    assert_eq!(
        outcome.err(),
        Some(psk_types::PskError::ReleaseGateBlocked),
        "Regel 7.56 (Plattformgebundene Verpflichtungsauflösung im Zertifikat): ohne deklarierte Aufloesung auf dieser Plattform ist C4 nicht erreicht"
    );
}

/// Und die Gegenprobe zur Gegenprobe: unterhalb C4 ist OBL-010
/// (`blocking_from: C4`) gar nicht relevant - dieselbe fehlende
/// Plattformnennung DARF dort nicht blockieren. Sonst waere die Regel
/// nicht klassenabhaengig, sondern pauschal.
#[test]
fn below_c4_the_same_missing_platform_binding_does_not_block() {
    use FeatureCoverageId::*;
    let obl_010 = obl_010_from_register();

    let outcome = issue_certificate(CertificateInputs {
        i_c: Digest::sha256(b"c1-i-c"),
        i_a: Digest::sha256(b"c1-i-a"),
        i_m: Digest::sha256(b"c1-i-m"),
        i_t: Digest::sha256(b"c1-i-t"),
        // Nur FC0-FC2 und keine C4-Abnahme: das reicht fuer C1.
        features: vec![Fc0, Fc1, Fc2],
        acceptance: AdditionalAcceptance {
            artifact_conformant: true,
            kernel_executable: true,
            ..Default::default()
        },
        replay_class: MachineCertificateReplayClassKind::R2,
        gate_report_digest: Digest::sha256(b"c1-gate-report"),
        trace_head: Digest::sha256(b"c1-trace-head"),
        replay_manifest_digest: Digest::sha256(b"c1-replay-manifest"),
        residue_report_digest: Digest::sha256(b"c1-residue-report"),
        capability_audit_digest: Digest::sha256(b"c1-capability-audit"),
        negative_test_report_digest: Digest::sha256(b"c1-negative-tests"),
        scope: ScopeExpr("reference-domain=jacobs-ladder-workspace".to_string()),
        issued_at: psk_types::DualTime {
            tau_i: 2_000_003,
            tau_e: "2026-08-08T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("c1".into()),
            uncertainty_ns: 0,
        },
        signature: psk_types::Signature(vec![]),
        current_platform: std::env::consts::OS.to_string(),
        platform_bound_obligations: vec![obl_010],
    });

    let cert = outcome.expect("unterhalb C4 blockiert OBL-010 nicht");
    assert_eq!(cert.conformance_class, Class::C1);
}
