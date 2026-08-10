//! Das ausgestellte Zertifikat traegt den I_t DES LAUFS.
//!
//! Anlass: bis v1.0.38 stand hier `Digest::sha256(b"golden-run-i-t")` -
//! eine Konstante an der Stelle einer der vier Systemidentitaeten, und
//! damit ein Zertifikat, das keinen Zustand bezeugt. Fuenfte Instanz der
//! Erfindungsklasse nach Objektzahlen, Testzahl, Kollisionszahl und
//! Registerrueckverweisen - die erste im ausgestellten Artefakt.
//!
//! Die Gegenprobe auf der Zustandsseite (zwei Laufzustaende mit
//! verschiedener Taktzahl MUESSEN verschiedene I_t haben) steht in
//! psk-scheduler/tests/i_t_sees_the_tick_count.rs, wo `sigma_digest`
//! lebt.

use psk_types::Digest;

/// : das Zertifikat
/// traegt den I_t DES LAUFS, nicht irgendeinen Wert.
#[test]
fn the_certificate_carries_the_runs_own_identity() {
    let root = {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel");
        }
        dir
    };
    let sandbox = std::env::temp_dir().join(format!("psk-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let cert =
        psk_conformance::run_golden_run_with_certificate(&root, &sandbox).expect("Zertifizierung");

    // Der Wert stammt aus dem realen Laufzustand (Boot-Schritt 12).
    assert_eq!(
        cert.certificate.I_t, cert.first.boot_report.identity.I_t,
        "das Zertifikat MUSS den I_t des Laufs tragen"
    );
    // Und ist nicht der frueher eingesetzte Literalwert.
    assert_ne!(
        cert.certificate.I_t,
        Digest::sha256(b"golden-run-i-t"),
        "die Konstante darf nicht zurueckkehren"
    );
    // Auch keine andere naheliegende Konstante.
    assert_ne!(cert.certificate.I_t, Digest::sha256(b""));
    println!("Zertifikat I_t = {}", cert.certificate.I_t);
}
