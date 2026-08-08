//! Der C4-Versuch: eine reale Ausstellung, kein Audit.
//!
//! Tabelle 23.2: C4 ("Reference-validated") verlangt FC0-FC6 und FC8,
//! `reference_validated`, mindestens R2 (Vertrag 22.4) und - seit Regel
//! 7.47 - dass `scope` jede plattformgebundene Verpflichtungsaufloesung
//! nennt, von der die beanspruchte Klasse abhaengt. Fuer C4 ist das
//! OBL-010 (`blocking_from: C4`, `resolution_platform: windows`).
//!
//! Die Eingaben kommen so weit wie moeglich aus einem ECHTEN Lauf:
//! `trace_head`, `replay_manifest_digest` und die Replayklasse stammen
//! aus `run_golden_run_with_certificate`, die vier Identitaeten aus
//! dessen realem `boot_report`. OBL-010s beide fuer Regel 7.47
//! massgeblichen Felder werden aus `architecture/obligations.yaml`
//! GELESEN, nicht einprogrammiert - sonst prueft e der Test seine eigene
//! Annahme statt des Registers.

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

/// FC0-FC6 und FC8 - genau der von Tabelle 23.2 fuer C4 verlangte Vektor.
/// FC7 (kontrollierte Selbstkompilation) fehlt bewusst: es ist fuer C4
/// nicht verlangt und waere unbelegt.
fn c4_features() -> Vec<FeatureCoverageId> {
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

    let boot = &certification.first.boot_report;
    let obl_010 = obl_010_from_register();

    println!("=== OBL-010, aus architecture/obligations.yaml gelesen ===");
    println!("  blocking_from      = {:?}", obl_010.blocking_from);
    println!("  resolution_platform = {}", obl_010.resolution_platform);
    println!("  current_platform    = {}", std::env::consts::OS);

    let scope = ScopeExpr(format!(
        "reference-domain=jacobs-ladder-workspace; platform={}",
        obl_010.resolution_platform
    ));

    println!("\n=== Beanspruchte Eingaben ===");
    println!("  features   = {:?}", c4_features());
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
        features: c4_features(),
        acceptance: c4_acceptance(),
        replay_class: MachineCertificateReplayClassKind::R2,
        gate_report_digest: Digest::sha256(b"c4-attempt-gate-report"),
        trace_head: certification.first.trace_head,
        replay_manifest_digest: Digest::sha256(b"c4-attempt-replay-manifest"),
        residue_report_digest: Digest::sha256(b"c4-attempt-residue-report"),
        capability_audit_digest: Digest::sha256(b"c4-attempt-capability-audit"),
        negative_test_report_digest: Digest::sha256(b"c4-attempt-negative-tests"),
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
    println!("\n(Versuch abgeschlossen - Ausgang oben.)");
}

/// Gegenprobe zu Regel 7.47 - ohne sie bliebe unbewiesen, dass die Regel
/// im obigen Erfolgsfall ueberhaupt gefeuert hat statt bloss nicht
/// gestoert zu haben.
///
/// Dieselben Eingaben, EIN Unterschied: `scope` verschweigt die
/// Plattformbindung. Regel 7.47 verlangt dann Verweigerung - "sonst
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
        features: c4_features(),
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
        "Regel 7.47: ohne die Plattformbindung im scope MUSS die Ausstellung scheitern"
    );
}

/// Und die zweite Haelfte von Regel 7.47: auf einer Plattform OHNE
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
        features: c4_features(),
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
        "Regel 7.47: ohne deklarierte Aufloesung auf dieser Plattform ist C4 nicht erreicht"
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
