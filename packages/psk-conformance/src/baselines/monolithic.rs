//! Regel 24.5 (Pflichtbaselines), Baseline (i): "einen monolithischen
//! Agenten mit demselben Modell und denselben Werkzeugen." "Demselben
//! Modell" ist hier wie ueberall in dieser Referenzimplementierung ein
//! typisierter Fixture-Kandidat, kein Live-Modellaufruf (Regel 27.8: ein
//! Sprachmodell tritt ausschliesslich als MethodPlugin auf, seine
//! Ausgabe ist ein Kandidat, nie ein Zustand; ein echter Aufruf hier
//! wuerde Replay/R2 fuer die gesamte Konformanzsuite brechen - siehe
//! `golden_run.rs`s eigene hartkodierte Claims/RealityEvidence fuer
//! dasselbe Muster).
//!
//! "Dieselben Werkzeuge" heisst: derselbe Dateisystemzugriff auf dieselbe
//! Referenzdomaene (Regel 32.5), NICHT dieselbe Modulstruktur - das
//! Gegenteil ist der Witz dieser Baseline: "eine Funktion von Auftrag zu
//! Patch, keine FieldIdentity, kein Gate, kein Token." Es gibt deshalb
//! absichtlich:
//! - keine `psk_fields::register_field`/`route_lens` (keine FieldIdentity),
//! - keine `psk_gate::evaluate_gate` (kein Gate),
//! - keine `psk_effect::issue`/`TokenLedger` (kein Token).
//!
//! `run_monolithic_agent` schreibt die Datei direkt. Das ist keine
//! Nachlaessigkeit, sondern die gemessene Eigenschaft: die zehn Metriken
//! (Regel 24.5) sollen sichtbar machen, was OHNE die konstitutionelle
//! Architektur passiert - allen voran "Nichtautorisierte Effekte"
//! (Seiteneffekte ohne gueltiges Token), die hier per Konstruktion JEDEN
//! Schreibvorgang treffen.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Ergebnis eines Laufs. Absichtlich schlank - kein Trace, kein Anchor,
/// keine Objekt-ID: dieser Agent kennt diese Konzepte nicht.
#[derive(Debug, Clone)]
pub struct MonolithicRunReport {
    /// Aussagen, die der Agent ueber sein eigenes Tun trifft - JEDE davon
    /// ist per Definition unbelegt (kein AnchorSnapshot-Verweis existiert
    /// in diesem Entwurf), siehe `metrics::measure_monolithic`.
    pub claims_made: Vec<String>,
    /// Tatsaechlich vorgenommene Seitenwirkungen - ohne Token, ohne
    /// Ausnahme.
    pub effects_applied: Vec<PathBuf>,
    pub target_path: PathBuf,
    pub written_content: String,
    pub wall_clock: Duration,
}

/// "Eine Funktion von Auftrag zu Patch": liest keine Spezifikation,
/// quotientiert nichts, prueft nichts adversarial - sie schreibt `content`
/// nach `sandbox_root/target_file` und meldet das als erledigt. Das ist
/// die vollstaendige Logik.
pub fn run_monolithic_agent(
    sandbox_root: &Path,
    target_file: &str,
    content: &str,
) -> MonolithicRunReport {
    let start = Instant::now();
    let target_path = sandbox_root.join(target_file);
    let _ = fs::write(&target_path, content);
    let claims_made = vec![format!(
        "{target_file} erfolgreich geschrieben und abgeschlossen"
    )];
    MonolithicRunReport {
        claims_made,
        effects_applied: vec![target_path.clone()],
        target_path,
        written_content: content.to_string(),
        wall_clock: start.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_content_directly_with_no_intermediate_structure() {
        let dir = std::env::temp_dir().join(format!("psk-baseline-mono-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let report = run_monolithic_agent(&dir, "golden-run-patch.txt", "hello golden run");

        assert_eq!(
            fs::read_to_string(dir.join("golden-run-patch.txt")).unwrap(),
            "hello golden run"
        );
        assert_eq!(report.effects_applied.len(), 1);
        assert_eq!(report.claims_made.len(), 1);

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_runs_against_the_same_reset_sandbox_are_byte_identical() {
        // Fixture-getrieben, kein Live-Modell (Regel 27.8) - Determinismus
        // ist deshalb erwartbar, nicht zufaellig. Dieselbe Sandbox,
        // zurueckgesetzt zwischen den Laeufen (siehe event_sourcing.rs'
        // Testkommentar fuer die Begruendung).
        let dir =
            std::env::temp_dir().join(format!("psk-baseline-mono-replay-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let a = run_monolithic_agent(&dir, "golden-run-patch.txt", "hello golden run");
        fs::remove_dir_all(&dir).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let b = run_monolithic_agent(&dir, "golden-run-patch.txt", "hello golden run");

        assert_eq!(a.written_content, b.written_content);
        assert_eq!(a.claims_made, b.claims_made);
        assert_eq!(a.effects_applied, b.effects_applied);

        fs::remove_dir_all(&dir).ok();
    }
}
