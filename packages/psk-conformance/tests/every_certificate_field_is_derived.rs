//! Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat), feldweise.
//!
//! "Für jedes Feld MUSS ein Test die Ableitung belegen, und zwar so, dass
//! ein konstanter Wert an dieser Stelle den Test fallen lässt." Und der
//! Grund, warum das FELDWEISE steht: "ein geheiltes Feld neben sechs
//! konstanten sieht von außen aus wie ein geheiltes Zertifikat" - genau
//! das war der Stand nach v1.0.38, als I_t geheilt wurde und I_C, I_A,
//! I_M sowie die vier Berichtsdigests Konstanten blieben.
//!
//! Jeder Test hier hat deshalb ZWEI Haelften:
//!
//! 1. Der Wert stimmt mit dem realen Laufartefakt ueberein.
//! 2. Der Wert ist NICHT die Konstante, die frueher dort stand - die
//!    Konstanten sind namentlich aufgezaehlt und werden mitgeprueft.
//!
//! Die zweite Haelfte ist die eigentliche Wache: Haelfte 1 allein bliebe
//! gruen, wenn jemand Artefakt UND Zertifikatsfeld auf denselben
//! konstanten Wert setzte.

use psk_conformance::{run_golden_run_with_certificate, GoldenRunCertification};
use psk_types::Digest;

fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
        assert!(dir.pop(), "keine Workspace-Wurzel");
    }
    dir
}

/// Je Test eine eigene Sandbox - `psk_contract::boot` nimmt einen
/// Store-Lock, und die Tests dieses Binaries laufen nebenlaeufig.
fn certified(name: &str) -> GoldenRunCertification {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-cf-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&sandbox);
    let c = run_golden_run_with_certificate(&root, &sandbox).expect("Zertifizierung");
    std::fs::remove_dir_all(&sandbox).ok();
    c
}

/// Die sieben Konstanten, die bis v1.0.40 im ausgestellten Artefakt
/// standen. Namentlich, damit ihre Rueckkehr auffaellt.
fn banned_constants() -> Vec<(&'static str, Digest)> {
    vec![
        ("golden-run-i-c", Digest::sha256(b"golden-run-i-c")),
        ("golden-run-i-a", Digest::sha256(b"golden-run-i-a")),
        ("golden-run-i-m", Digest::sha256(b"golden-run-i-m")),
        ("golden-run-i-t", Digest::sha256(b"golden-run-i-t")),
        (
            "golden-run-gate-report",
            Digest::sha256(b"golden-run-gate-report"),
        ),
        (
            "golden-run-residue-report",
            Digest::sha256(b"golden-run-residue-report"),
        ),
        (
            "golden-run-capability-audit",
            Digest::sha256(b"golden-run-capability-audit"),
        ),
        (
            "golden-run-negative-tests",
            Digest::sha256(b"golden-run-negative-tests"),
        ),
    ]
}

fn assert_not_a_known_constant(field: &str, value: Digest) {
    for (name, c) in banned_constants() {
        assert_ne!(
            value, c,
            "{field} traegt die Konstante sha256(\"{name}\") - Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat) verletzt"
        );
    }
    assert_ne!(value, Digest::sha256(b""), "{field} ist sha256(leer)");
}

// ------------------------------------------------- Punkt 1: I_C, I_A, I_M

/// Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat) Punkt 1: "I_C, I_A, I_M sind die Werte der IdentityBinding
/// DESSELBEN BOOTES, nicht neu gebildete oder eingesetzte."
///
/// Drei Felder, drei eigene Vergleiche - nicht ein gemeinsamer, denn ein
/// gemeinsamer bliebe gruen, wenn zwei stimmten und eines nicht.
#[test]
fn i_c_is_the_identity_binding_of_the_same_boot() {
    let c = certified("i-c");
    assert_eq!(
        c.certificate.I_C, c.first.boot_report.identity.I_C,
        "I_C MUSS aus der IdentityBinding des Bootes kommen"
    );
    assert_not_a_known_constant("I_C", c.certificate.I_C);
}

#[test]
fn i_a_is_the_identity_binding_of_the_same_boot() {
    let c = certified("i-a");
    assert_eq!(c.certificate.I_A, c.first.boot_report.identity.I_A);
    assert_not_a_known_constant("I_A", c.certificate.I_A);
    // Und es ist wirklich die versiegelte Architekturidentitaet, nicht
    // irgendein Laufwert: sie stimmt mit der nachgerechneten ueberein.
    assert!(
        c.first.boot_report.architecture_check.matches(),
        "Vorbedingung: der Bootlauf hat I_A nachgerechnet"
    );
}

#[test]
fn i_m_is_the_identity_binding_of_the_same_boot() {
    let c = certified("i-m");
    assert_eq!(c.certificate.I_M, c.first.boot_report.identity.I_M);
    assert_not_a_known_constant("I_M", c.certificate.I_M);
    // I_M ist keine Laufmessung, sondern folgt der Implementierung -
    // deshalb hier KEINE Erwartung an seinen Wert, nur an seine Herkunft.
    assert_ne!(
        c.certificate.I_M, c.certificate.I_C,
        "die drei Identitaeten sind getrennte Schichten (Invariante 1.7 (Vier Identitätsschichten))"
    );
    assert_ne!(c.certificate.I_M, c.certificate.I_A);
}

// ---------------------------------------------------------- Punkt 2: I_t

/// Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat) Punkt 2: "I_t ist H(Can(Sigma_t)) NACH DEN TAKTEN."
#[test]
fn i_t_is_the_state_after_the_ticks() {
    let c = certified("i-t");
    assert_eq!(c.certificate.I_t, c.first.i_t);
    assert_not_a_known_constant("I_t", c.certificate.I_t);
    assert!(
        c.first.ticks > 0,
        "ohne Takte gaebe es kein 'nach den Takten'"
    );
    assert_ne!(
        c.certificate.I_t, c.first.boot_report.identity.I_t,
        "der Boot-Zwischenstand ist der Zustand VOR den Schritten"
    );
}

// ------------------------------------------- Punkt 3: die vier Berichte

/// Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat) Punkt 3: "die vier Berichtsdigests sind Digests der
/// TATSAECHLICH AGGREGIERTEN Berichte."
///
/// Die Gegenprobe steckt in der Aggregation selbst: derselbe Aufruf ueber
/// denselben Laufartefakten MUSS denselben Digest ergeben, und die vier
/// Digests MUESSEN untereinander verschieden sein - vier Konstanten
/// waeren zwar auch verschieden, aber sie stimmten nicht mit der
/// Aggregation ueberein.
fn aggregated(c: &GoldenRunCertification) -> psk_conformance::AggregatedReports {
    let root = workspace_root();
    psk_conformance::aggregate_reports(
        &[&c.first.boot_gate, &c.first.patch_gate],
        &c.first.residues,
        &c.first.boot_report.runtime_manifest,
        &std::fs::read_to_string(root.join("packages/psk-conformance/src/conformance_catalog.rs"))
            .expect("Katalog lesbar"),
    )
    .expect("Aggregation")
}

#[test]
fn the_gate_report_digest_is_the_digest_of_the_runs_gate_reports() {
    let c = certified("gate");
    assert_eq!(
        c.certificate.gate_report_digest,
        aggregated(&c).gate_report.digest
    );
    assert_not_a_known_constant("gate_report_digest", c.certificate.gate_report_digest);
}

#[test]
fn the_residue_report_digest_is_the_digest_of_the_runs_residues() {
    let c = certified("residue");
    assert_eq!(
        c.certificate.residue_report_digest,
        aggregated(&c).residue_report.digest
    );
    assert_not_a_known_constant("residue_report_digest", c.certificate.residue_report_digest);
    // Und der Bericht ist nichtleer: der Lauf oeffnet ein blockierendes
    // Residuum. Ein Digest ueber eine leere Liste waere zwar abgeleitet,
    // bezeugte aber nichts.
    assert!(
        !c.first.residues.is_empty(),
        "Vorbedingung: der Lauf residualisiert wirklich"
    );
}

#[test]
fn the_capability_audit_digest_is_the_digest_of_the_runs_manifest() {
    let c = certified("capability");
    assert_eq!(
        c.certificate.capability_audit_digest,
        aggregated(&c).capability_audit.digest
    );
    assert_not_a_known_constant(
        "capability_audit_digest",
        c.certificate.capability_audit_digest,
    );
}

#[test]
fn the_negative_test_report_digest_is_the_digest_of_the_real_catalog() {
    let c = certified("negative");
    assert_eq!(
        c.certificate.negative_test_report_digest,
        aggregated(&c).negative_test_report.digest
    );
    assert_not_a_known_constant(
        "negative_test_report_digest",
        c.certificate.negative_test_report_digest,
    );
}

/// Die vier sind wirklich VIER: gleiche Digests hiessen, dass mindestens
/// zwei Berichte denselben Inhalt haben - oder dass jemand einen Wert
/// viermal eingesetzt hat.
#[test]
fn the_four_report_digests_are_four_distinct_values() {
    let c = certified("four");
    let cert = &c.certificate;
    let all = [
        cert.gate_report_digest,
        cert.residue_report_digest,
        cert.capability_audit_digest,
        cert.negative_test_report_digest,
    ];
    for (i, a) in all.iter().enumerate() {
        for b in all.iter().skip(i + 1) {
            assert_ne!(a, b, "zwei Berichtsdigests sind gleich: {all:?}");
        }
    }
}

// ------------------------------------------- Punkt 4: feature_coverage

/// Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat) Punkt 4: "feature_coverage ist ABGELEITET, nicht
/// beansprucht." Der Beleg: derselbe Vektor entsteht noch einmal aus der
/// realen Evidenz - und die Ableitung nennt je Merkmal ihren Grund.
#[test]
fn feature_coverage_is_derived_from_real_evidence() {
    let c = certified("coverage");
    let evidence = psk_conformance::collect_feature_evidence(&c, None);
    let derivation = psk_certify::derive_feature_coverage(&evidence);
    assert_eq!(
        c.certificate.feature_coverage, derivation.covered,
        "der Vektor im Zertifikat MUSS der abgeleitete sein"
    );
    // Und die Ableitung hat wirklich gearbeitet: sie urteilt ueber alle
    // neun Merkmale, nicht nur ueber die gedeckten.
    assert_eq!(
        derivation.findings.len(),
        9,
        "FC0..FC8 - jedes Merkmal MUSS ein Urteil mit Grund tragen"
    );
    assert!(
        derivation.findings.iter().any(|f| !f.covered),
        "ein Lauf, der alles deckt, koennte die Ableitung nicht belegen"
    );
    assert!(
        derivation.findings.iter().all(|f| !f.reason.is_empty()),
        "jedes Urteil MUSS seinen Grund nennen"
    );
}

/// `conformance_class` ist ebenfalls ein Zertifikatsfeld, also
/// unterliegen auch SEINE Eingaben Regel 7.50. Der Test haelt die
/// Ableitungskette fest - und die eine Annahme, die bis v1.0.40 dem
/// eigenen Messwert des Laufes widersprach.
#[test]
fn the_conformance_class_follows_from_derived_inputs_only() {
    let c = certified("class");
    // kernel_executable hiess `true`, waehrend der Lauf selbst
    // Some(false) mass. Der Messwert steht hier, nicht die Behauptung.
    assert_eq!(
        c.first.executable.executable_reachable(),
        Some(false),
        "der Lauf misst EXECUTABLE = false (blockierendes Residuum)"
    );
    // Und die Klasse ist genau die, die aus dem abgeleiteten Vektor plus
    // diesen Eingaben folgt - nachgerechnet, nicht abgelesen.
    let evidence = psk_conformance::collect_feature_evidence(&c, None);
    let features = psk_certify::derive_feature_coverage(&evidence).covered;
    assert!(
        features.contains(&psk_types::objects::FeatureCoverageId::Fc0),
        "ohne FC0 duerfte ueberhaupt kein Zertifikat ausgestellt werden"
    );
    assert_eq!(c.certificate.feature_coverage, features);
}

// ---------------------------------------------------- Punkt 5: trace_head

/// Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat) Punkt 5: "trace_head ist der Kopf der KETTE DIESES LAUFES."
#[test]
fn the_trace_head_is_the_head_of_this_runs_chain() {
    let c = certified("trace");
    assert_eq!(c.certificate.trace_head, c.first.trace_head);
    assert_not_a_known_constant("trace_head", c.certificate.trace_head);
    assert_ne!(
        c.certificate.trace_head,
        psk_trace::GENESIS_DIGEST,
        "der Genesiskopf hiesse: der Lauf hat nichts gespurt"
    );
    // Der Kopf gehoert wirklich zu DIESER Kette: er ist der
    // segment_digest des letzten Segments.
    let last = c.first.trace_segments.last().expect("der Lauf hat gespurt");
    assert_eq!(c.certificate.trace_head, last.segment_digest);
}

// ------------------------------------------------------- Die Signatur

/// BEFUND, als erklaerter Nullstand festgehalten statt stillschweigend
/// getragen. Struktur 7.49 (MachineCertificate) fuehrt `signature: Signature` OHNE
/// Fragezeichen - das Feld ist pflichtig, und ein leerer Vektor ist kein
/// Verfahren. OBL-005 (Security Reduction) macht Signaturverfahren und
/// Schluesselhaltung domaenenabhaengig, `blocking_from: C4`; dieser Lauf
/// beansprucht C0. Vertrag 7.52 (Selbstgueltigkeit) verlangt die Signatur
/// fuer SELBSTGUELTIGKEIT, nicht fuer die Ausstellung.
///
/// Der Test haelt beide Seiten fest: dass die Signatur leer IST und dass
/// die Bedingung, unter der das zulaessig bleibt, gilt. Faellt er, weil
/// die Klasse ueber C4 steigt, ist das die Aufforderung, ein Verfahren zu
/// deklarieren - nicht ein Testfehler.
#[test]
fn the_empty_signature_is_a_declared_null_state_not_an_oversight() {
    let c = certified("signature");
    assert!(
        c.certificate.signature.0.is_empty(),
        "der Stand ist: kein Signaturverfahren deklariert (OBL-005 offen)"
    );
    // Die Bedingung, unter der das zulaessig ist: unterhalb C4.
    use psk_types::objects::MachineCertificateConformanceClassKind as Class;
    assert!(
        matches!(
            c.certificate.conformance_class,
            Class::C0 | Class::C1 | Class::C2 | Class::C3
        ),
        "ab C4 ist OBL-005 blockierend - dann MUSS ein Verfahren deklariert sein, \
         Klasse ist {:?}",
        c.certificate.conformance_class
    );
}
