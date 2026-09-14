//! Das ausgestellte Zertifikat traegt den I_t DES LAUFS.
//!
//! Anlass: bis v1.0.38 stand hier `Digest::sha256(b"golden-run-i-t")` -
//! eine Konstante an der Stelle einer der vier Systemidentitaeten, und
//! damit ein Zertifikat, das keinen Zustand bezeugt. Fuenfte Instanz der
//! Erfindungsklasse nach Objektzahlen, Testzahl, Kollisionszahl und
//! Registerrueckverweisen - die erste im ausgestellten Artefakt.
//!
//! Seit der Taktumverdrahtung ist der bezeugte Zustand der NACH den
//! Takten - Regel 24.4 (Der Golden Run läuft unter tick): "das Zertifikat
//! weist I_t = H(Can(Sigma_t)) aus, und Sigma_t ist der Zustand nach den
//! Takten". Der fruehere ehrliche Zwischenstand (Boot-Sigma, Zustand VOR
//! den Schritten) DARF nicht zurueckkehren: er war ueber einen anderen
//! Zustand gebildet als den, den das Zertifikat meint.
//!
//! Die Gegenprobe auf der Zustandsseite (zwei Laufzustaende mit
//! verschiedener Taktzahl MUESSEN verschiedene I_t haben) steht in
//! psk-scheduler/tests/i_t_sees_the_tick_count.rs, wo `sigma_digest`
//! lebt.

use psk_types::Digest;

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

    // Der Wert ist der Digest des Laufzustands NACH den Takten
    // (GoldenRunReport.i_t), Regel 24.4 (Der Golden Run läuft unter tick).
    assert_eq!(
        cert.certificate.I_t, cert.first.i_t,
        "das Zertifikat MUSS den I_t des Laufs tragen"
    );
    // Der Lauf ist wirklich getaktet - ohne Takte gaebe es keinen
    // Zustand "nach den Takten", den der Wert bezeugen koennte.
    assert!(cert.first.ticks > 0, "tick_no MUSS gestiegen sein");
    // Nicht der Boot-Zwischenstand: das Boot-Sigma ist der Zustand VOR
    // den Schritten, und ein Zustand, der die Arbeit traegt, hat einen
    // anderen Digest als einer, der sie noch vor sich hat.
    assert_ne!(
        cert.certificate.I_t, cert.first.boot_report.identity.I_t,
        "der Boot-Zwischenstand darf nicht zurueckkehren"
    );
    // Und nicht der frueher eingesetzte Literalwert.
    assert_ne!(
        cert.certificate.I_t,
        Digest::sha256(b"golden-run-i-t"),
        "die Konstante darf nicht zurueckkehren"
    );
    // Auch keine andere naheliegende Konstante.
    assert_ne!(cert.certificate.I_t, Digest::sha256(b""));
    println!("Zertifikat I_t = {}", cert.certificate.I_t);
}
