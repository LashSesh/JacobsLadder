//! Regel 24.4 (Pflichtbaselines), Baseline (ii): "einen Agenten mit
//! strukturierter Planung und Event Sourcing, aber ohne Realitaetsleiter,
//! Abhaengigkeitsquotient und konstitutionelle Gates." Diese drei
//! Abwesenheiten sind der Witz der Baseline (Auftrag des Nutzers,
//! woertlich), nicht optionale Kuerzungen - deshalb explizit, was dieser
//! Agent NICHT tut:
//!
//! - KEIN Realitaetsleiter: keine `psk_thought::classify`/
//!   `RealityClassification` (COHERENT/LAWFUL/REACHABLE/CONSTRUCTIBLE).
//!   `NaiveApprovalChecked` unten ist eine Heuristik ohne die vier
//!   RealityStatus-Bedingungen.
//! - KEIN Abhaengigkeitsquotient: `plan_perspectives()` erzeugt bewusst
//!   MEHRERE, stark korrelierte Planperspektiven (strukturierte Planung
//!   IST hier vorhanden), aber es gibt keinen `psk_dependency::
//!   dependency_quotient`-Aufruf, der sie auf einen effektiven Rang
//!   reduziert - alle Perspektiven zaehlen ungeprueft als eigenstaendig.
//!   Das ist die gemessene Ursache von "Synthetische Mehrheit" > 0 (Regel
//!   24.4) fuer diese Baseline.
//! - KEINE konstitutionellen Gates: `NaiveApprovalChecked` ersetzt
//!   `psk_gate::evaluate_gate` durch eine einfache, ungated Bedingung
//!   (nichtleerer Plan) - keine `ConditionOutcome`-Aggregation, kein
//!   `M19.residualize` bei Ablehnung, kein `GateAuthorization`-
//!   Kapabilitaetstyp vor dem Schreibvorgang.
//!
//! Was VORHANDEN ist (das erste Wort der Baseline, nicht nur das
//! zweite): ein echtes, typisiertes Event Log (`BaselineEvent`) und ein
//! mehrstufiger, strukturierter Plan - beides real, nicht simuliert. Der
//! Unterschied zum Kern ist nicht "weniger Struktur", sondern "Struktur
//! ohne die drei genannten konstitutionellen Eigenschaften".
//!
//! Wie bei `monolithic.rs`: "dasselbe Modell" ist ein typisierter
//! Fixture-Kandidat, kein Live-Aufruf (Regel 27.8) - `plan_perspectives`
//! liefert feste, deterministische Zeichenketten.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use psk_types::Digest;

/// Typisiertes Event Log - real vorhanden (siehe Modulkopf), im
/// Gegensatz zu `monolithic.rs`, das ueberhaupt keine Historie fuehrt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaselineEvent {
    TaskReceived {
        description: String,
    },
    PlanFormed {
        perspectives: Vec<String>,
    },
    NaiveApprovalChecked {
        approved: bool,
        reason: String,
    },
    PatchApplied {
        path: PathBuf,
        content_digest: Digest,
    },
    TreeCompared {
        matches_plan: bool,
    },
}

#[derive(Debug, Clone)]
pub struct EventSourcingRunReport {
    pub events: Vec<BaselineEvent>,
    pub claims_made: Vec<String>,
    pub effects_applied: Vec<PathBuf>,
    /// Anzahl der erzeugten Planperspektiven - RAW, nicht quotientiert
    /// (siehe Modulkopf). Die Eingabe fuer "Synthetische Mehrheit".
    pub perspectives_considered: usize,
    pub target_path: PathBuf,
    pub written_content: String,
    pub wall_clock: Duration,
}

/// Strukturierte Planung ohne Abhaengigkeitsquotient: drei feste,
/// deterministische Perspektiven auf dieselbe Handlung - absichtlich
/// stark korreliert (sie empfehlen alle dieselbe Datei mit demselben
/// Inhalt), aber ohne einen Mechanismus, der das erkennt oder reduziert.
fn plan_perspectives(target_file: &str) -> Vec<String> {
    vec![
        format!("direkt: {target_file} sofort schreiben"),
        format!("vorsichtig: {target_file} nach Pruefung schreiben"),
        format!("schnell: {target_file} ohne Umweg schreiben"),
    ]
}

/// Ersetzt `psk_gate::evaluate_gate` (siehe Modulkopf) - eine Heuristik,
/// keine Bedingungsaggregation mit Residualisierung.
fn naive_approval(perspectives: &[String]) -> (bool, String) {
    if perspectives.is_empty() {
        (false, "kein Plan vorhanden".to_string())
    } else {
        (true, "Plan nichtleer".to_string())
    }
}

pub fn run_event_sourcing_agent(
    sandbox_root: &Path,
    target_file: &str,
    content: &str,
) -> EventSourcingRunReport {
    let start = Instant::now();
    let mut events = Vec::new();
    let mut claims_made = Vec::new();

    events.push(BaselineEvent::TaskReceived {
        description: format!("{target_file} auf den vereinbarten Inhalt bringen"),
    });

    let perspectives = plan_perspectives(target_file);
    events.push(BaselineEvent::PlanFormed {
        perspectives: perspectives.clone(),
    });

    let (approved, reason) = naive_approval(&perspectives);
    events.push(BaselineEvent::NaiveApprovalChecked {
        approved,
        reason: reason.clone(),
    });
    claims_made.push(format!("Plan genehmigt: {approved} ({reason})"));

    let target_path = sandbox_root.join(target_file);
    let mut effects_applied = Vec::new();
    if approved {
        let _ = fs::write(&target_path, content);
        effects_applied.push(target_path.clone());
        events.push(BaselineEvent::PatchApplied {
            path: target_path.clone(),
            content_digest: Digest::sha256(content.as_bytes()),
        });
    }

    let actual = fs::read_to_string(&target_path).unwrap_or_default();
    let matches_plan = actual == content;
    events.push(BaselineEvent::TreeCompared { matches_plan });
    claims_made.push(format!("Dateibaum entspricht Plan: {matches_plan}"));

    EventSourcingRunReport {
        events,
        claims_made,
        effects_applied,
        perspectives_considered: perspectives.len(),
        target_path,
        written_content: content.to_string(),
        wall_clock: start.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plans_with_multiple_uncorrelated_looking_perspectives_before_writing() {
        let dir = std::env::temp_dir().join(format!("psk-baseline-es-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let report = run_event_sourcing_agent(&dir, "golden-run-patch.txt", "hello golden run");

        assert_eq!(report.perspectives_considered, 3);
        assert!(report
            .events
            .iter()
            .any(|e| matches!(e, BaselineEvent::PlanFormed { .. })));
        assert!(report.events.iter().any(|e| matches!(
            e,
            BaselineEvent::NaiveApprovalChecked { approved: true, .. }
        )));
        assert_eq!(
            fs::read_to_string(dir.join("golden-run-patch.txt")).unwrap(),
            "hello golden run"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn event_log_records_every_step_in_order() {
        let dir =
            std::env::temp_dir().join(format!("psk-baseline-es-order-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let report = run_event_sourcing_agent(&dir, "golden-run-patch.txt", "hello golden run");
        let kinds: Vec<&str> = report
            .events
            .iter()
            .map(|e| match e {
                BaselineEvent::TaskReceived { .. } => "received",
                BaselineEvent::PlanFormed { .. } => "planned",
                BaselineEvent::NaiveApprovalChecked { .. } => "approved",
                BaselineEvent::PatchApplied { .. } => "applied",
                BaselineEvent::TreeCompared { .. } => "compared",
            })
            .collect();
        assert_eq!(
            kinds,
            vec!["received", "planned", "approved", "applied", "compared"]
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_runs_against_the_same_reset_sandbox_are_byte_identical() {
        // Dieselbe Sandbox, zurueckgesetzt zwischen den Laeufen - nicht
        // zwei verschiedene Pfade: `PatchApplied.path` ginge sonst als
        // Pfadunterschied in den Ereignisvergleich ein, obwohl die
        // Entscheidungen selbst identisch sind (derselbe Fallstrick, den
        // `run_golden_run_with_certificate` bereits vermeidet).
        let dir =
            std::env::temp_dir().join(format!("psk-baseline-es-replay-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let a = run_event_sourcing_agent(&dir, "golden-run-patch.txt", "hello golden run");
        fs::remove_dir_all(&dir).unwrap();
        fs::create_dir_all(&dir).unwrap();
        let b = run_event_sourcing_agent(&dir, "golden-run-patch.txt", "hello golden run");

        assert_eq!(a.written_content, b.written_content);
        assert_eq!(a.events, b.events);

        fs::remove_dir_all(&dir).ok();
    }
}
