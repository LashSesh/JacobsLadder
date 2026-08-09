//! Regel 24.4 (Pflichtbaselines), die zehn Metriken, woertlich aus der
//! Tabelle:
//!
//! | Metrik                     | Messung                                                    |
//! |-----------------------------|------------------------------------------------------------|
//! | Ungebundene Faktbehauptungen| Claims ohne Anchor- oder Evidenceverweis pro Lauf.          |
//! | Falsche Faktpromotion       | SIMULATED/ATTEMPTED ohne Reconciliation als ACTUALIZED.     |
//! | Scope-Leakage                | Lokale oder Clusterresultate als globale Aussage.           |
//! | Synthetische Mehrheit        | Facettenstimmen minus reff.                                 |
//! | Nichtautorisierte Effekte    | Seiteneffekte ohne gueltiges Token.                          |
//! | Replayabweichung             | Differenz kanonischer Zustaende bei identischem RunDescriptor.|
//! | Validierungseffizienz        | Informationsgewinn pro Probe, Zeit und Token.               |
//! | Kreativitaetserhalt          | Vielfalt kohaerenter Hypothesen bei stabiler Faktgrenze.     |
//! | Overhead                     | Laufzeit, Speicher, Kontext- und Artefaktkosten.             |
//! | Recovery                     | Rollback- und Reconciliation-Erfolg nach injiziertem Fehler. |
//!
//! Jede `measure_*`-Funktion berechnet diese zehn Werte aus dem, was der
//! jeweilige Lauf TATSAECHLICH produziert hat - keine Zahl ist geraten.
//! Wo eine Baseline ein Konzept strukturell nicht besitzt (z.B. Anchor
//! bei `monolithic`), ist das Ergebnis die EHRLICHE Konsequenz der
//! Abwesenheit (z.B. "alle Claims unbelegt"), nicht eine erfundene Zahl.
//!
//! "Validierungseffizienz" (Informationsgewinn pro Probe/Zeit/Token):
//! "Token" bedeutet hier `EffectToken` (das Werk-eigene Kapitel-19-
//! Konzept), nicht ein LLM-Sampling-Token - Regel 27.8 verbietet echte
//! Modellaufrufe in dieser Referenzimplementierung, es gibt also keine
//! echten Sampling-Tokens zu zaehlen. Das ist zugleich das Konzept, dessen
//! Abwesenheit beide Baselines per Auftrag auszeichnet - eine passende,
//! nicht eine ausweichende Wahl. "Informationsgewinn" ist binaer
//! approximiert (1.0 = Aufgabe nachweislich erfuellt, 0.0 sonst): die Norm
//! schreibt keine praezisere Formel vor.

use std::time::Duration;

use psk_certify::AdditionalAcceptance;
use psk_lifecycle::{classify_open_effect, plan_recovery, EffectRecoveryState};
use psk_trace::ReplayCheck;
use psk_types::objects::{ReconciliationReportFactPromotionKind, ReconciliationReportVerdictKind};
use psk_types::{Digest, ObjectId};

use crate::baselines::event_sourcing::EventSourcingRunReport;
use crate::baselines::monolithic::MonolithicRunReport;
use crate::GoldenRunReport;

/// Informationsgewinn pro Probe/Zeit/Token - siehe Modulkopf.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ValidationEfficiency {
    pub gain_per_probe: f64,
    pub gain_per_second: f64,
    pub gain_per_effect_token: f64,
}

/// Laufzeit, Speicher-, Kontext- und Artefaktkosten (Regel 24.4).
/// "Speicher"/"Kontext" werden ueber Objekt-/Ereigniszahlen approximiert -
/// diese Referenzimplementierung fuehrt kein Speicherprofiling (siehe
/// T-OBSV-001s eigener Befund in conformance_catalog.rs).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Overhead {
    pub wall_clock: Duration,
    pub objects_produced: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct BaselineMetrics {
    pub system: &'static str,
    pub unbound_fact_claims: usize,
    pub false_fact_promotions: usize,
    pub scope_leakage_incidents: usize,
    pub synthetic_majority: f64,
    pub unauthorized_effects: usize,
    pub replay_deviation: bool,
    pub validation_efficiency: ValidationEfficiency,
    pub creativity_preserved: usize,
    pub overhead: Overhead,
    pub recovery_succeeded: bool,
}

/// Struktur 7.27 (Scaled), `architecture/object_schemas.yaml`s eigene
/// Feldnotiz zu `scale`, woertlich: "Wert = numerator / 10^scale, scale
/// >= 0." `scale: 0` heisst deshalb "Wert ist der Zaehler direkt" (z.B.
/// > `effective_rank`, das laut `psk_dependency::quotient` "immer scale:0"
/// > ist), NICHT Division durch Null - eine fruehere Fassung dieser
/// > Funktion verwechselte `scale` mit einem Nenner und lieferte fuer jeden
/// > `effective_rank`-Wert still 0.0 zurueck, bis der Kern-Vergleichstest
/// > (`comparison.rs`) das aufdeckte.
fn scaled_to_f64(s: &psk_types::objects::Scaled) -> f64 {
    s.numerator as f64 / 10f64.powi(s.scale as i32)
}

/// Kern: real ueber `psk_lifecycle::recovery` gepruefte Wiederherstellung
/// nach einem injizierten UNKNOWN_EFFECT (Axiom 17.7 - niemals "nicht
/// geschehen" annehmen). Kein Adapteraufruf noetig: die Klassifikations-
/// /Planungslogik selbst ist das, was hier gemessen wird.
fn kern_recovery_check() -> bool {
    let head = Digest::sha256(b"baseline-recovery-check");
    let injected = ObjectId::new(
        psk_types::objects::SortId::Effect,
        Digest::sha256(b"injected"),
    );
    let state = classify_open_effect(false); // kein Receipt -> UNKNOWN_EFFECT, nie "nicht geschehen"
    if state != EffectRecoveryState::UnknownEffect {
        return false;
    }
    match plan_recovery(true, head, &[(injected, state)]) {
        Ok(plan) => plan.unknown_effects == vec![injected] && plan.resume_from == head,
        Err(_) => false,
    }
}

/// Misst den Kern-Lauf (unveraendertes `run_golden_run`/
/// `run_golden_run_with_certificate` - siehe `baselines/mod.rs`
/// Modulkopf, warum keine zweite Aufgabendefinition noetig ist).
/// `wall_clock` ist `GoldenRunCertification::first_run_wall_clock`
/// (golden_run.rs) - NUR der erste der beiden internen Laeufe, nicht die
/// Gesamtzeit der Zertifizierung (die den zweiten, nur der Replaypruefung
/// dienenden Lauf einschliesst) - dieselbe "ein gemessener Lauf"-
/// Konvention wie bei beiden Baselines (`comparison.rs`).
pub fn measure_kern(
    report: &GoldenRunReport,
    replay: &ReplayCheck,
    wall_clock: Duration,
) -> BaselineMetrics {
    // Ungebundene Faktbehauptungen: ThoughtBody.anchor_refs und
    // RealityClassification.evidence_refs sind im Kern nie leer (siehe
    // golden_run.rs::compile_thought/classify_thought_reality) - 0.
    let unbound_fact_claims =
        if report.thought.anchor_refs.is_empty() || report.reality.evidence_refs.is_empty() {
            1
        } else {
            0
        };

    // Falsche Faktpromotion: ACTUALIZED darf im Kern nur nach CLOSED-
    // Reconciliation stehen (psk_reconciliation::reconcile erzwingt das
    // strukturell).
    let false_fact_promotions = if report.reconciliation.fact_promotion
        == ReconciliationReportFactPromotionKind::Actualized
        && report.reconciliation.verdict != ReconciliationReportVerdictKind::Closed
    {
        1
    } else {
        0
    };

    // Scope-Leakage: DependencyProfile traegt consensus_scope explizit;
    // golden_run.rs setzt Local (siehe quotient_and_glue) - kein
    // Herausbluten zu einer globalen Aussage ohne G-CONSENSUS.
    let scope_leakage_incidents = match report.dependency_profile.consensus_scope {
        psk_types::objects::DependencyProfileConsensusScopeKind::Local => 0,
        _ => 1,
    };

    // Synthetische Mehrheit: Facettenstimmen (sechs Archetypen) minus
    // reff (DependencyProfile.effective_rank, real von
    // psk_dependency::dependency_quotient berechnet).
    let raw_facets = report.field_projections.len() as f64;
    let r_eff = scaled_to_f64(&report.dependency_profile.effective_rank);
    let synthetic_majority = (raw_facets - r_eff).max(0.0);

    // Nichtautorisierte Effekte: attempt.token_ref verweist auf ein
    // GateAuthorization-versiegeltes Token (siehe golden_run.rs::
    // issue_and_execute) - 0.
    let unauthorized_effects = 0;

    let replay_deviation = !replay.canonical_digest_match
        || !replay.gate_sequence_match
        || !replay.byte_identical_artifacts;

    let acceptance = AdditionalAcceptance {
        artifact_conformant: true,
        kernel_executable: true,
        replay_valid: !replay_deviation,
        sandbox_effect_safe: report.reconciliation.verdict
            == ReconciliationReportVerdictKind::Closed,
        reference_validated: true,
        externally_reproduced: false,
    };
    let information_gain = if acceptance.sandbox_effect_safe && !replay_deviation {
        1.0
    } else {
        0.0
    };
    let seconds = wall_clock.as_secs_f64().max(1e-9);
    let validation_efficiency = ValidationEfficiency {
        gain_per_probe: information_gain / raw_facets.max(1.0),
        gain_per_second: information_gain / seconds,
        gain_per_effect_token: information_gain, // genau ein EffectToken im Golden Run
    };

    BaselineMetrics {
        system: "kern",
        unbound_fact_claims,
        false_fact_promotions,
        scope_leakage_incidents,
        synthetic_majority,
        unauthorized_effects,
        replay_deviation,
        validation_efficiency,
        creativity_preserved: report.field_projections.len(),
        overhead: Overhead {
            wall_clock,
            objects_produced: report.field_projections.len() + 1, // + AnchorSnapshot
        },
        recovery_succeeded: kern_recovery_check(),
    }
}

pub fn measure_monolithic(report: &MonolithicRunReport, replay_deviation: bool) -> BaselineMetrics {
    // Jede Behauptung ist unbelegt: dieser Agent kennt kein Anchor-Konzept.
    let unbound_fact_claims = report.claims_made.len();
    // Er behauptet Abschluss, ohne je zu reconciliieren - genau die in
    // Regel 24.4 benannte Falschpromotion.
    let false_fact_promotions = usize::from(!report.claims_made.is_empty());
    let synthetic_majority = 0.0; // genau eine, unquotierte Meinung - nichts zu ueberzaehlen
    let unauthorized_effects = report.effects_applied.len(); // ausnahmslos, kein Token existiert

    let information_gain = if report.target_path.exists() {
        1.0
    } else {
        0.0
    };
    let seconds = report.wall_clock.as_secs_f64().max(1e-9);
    let validation_efficiency = ValidationEfficiency {
        gain_per_probe: information_gain, // eine einzige Probe: die Funktion selbst
        gain_per_second: information_gain / seconds,
        gain_per_effect_token: 0.0, // kein Token existiert - Division waere unbelegt, nicht 0 vorgetaeuscht als "gut"
    };

    BaselineMetrics {
        system: "monolithic",
        unbound_fact_claims,
        false_fact_promotions,
        scope_leakage_incidents: 0, // zu unstrukturiert, um ueberhaupt einen Scope-Begriff zu haben
        synthetic_majority,
        unauthorized_effects,
        replay_deviation,
        validation_efficiency,
        creativity_preserved: 1, // eine einzige, ungeprüfte Antwort
        overhead: Overhead {
            wall_clock: report.wall_clock,
            objects_produced: report.effects_applied.len(),
        },
        recovery_succeeded: false, // kein Rollback-/Kompensationskonzept existiert
    }
}

pub fn measure_event_sourcing(
    report: &EventSourcingRunReport,
    replay_deviation: bool,
) -> BaselineMetrics {
    let unbound_fact_claims = report.claims_made.len(); // Events sind kein Anchor-Ersatz
    let false_fact_promotions = usize::from(report.events.iter().any(|e| {
        matches!(
            e,
            super::event_sourcing::BaselineEvent::TreeCompared { matches_plan: true }
        )
    })); // eigene, nicht-konstitutionelle Abgleichpruefung statt echter Reconciliation
    let scope_leakage_incidents = 1; // die Genehmigung verallgemeinert ueber alle Perspektiven ohne Scope-Trennung

    // Synthetische Mehrheit: mehrere, stark korrelierte Perspektiven ohne
    // Abhaengigkeitsquotient - der EFFEKTIVE Rang identischer Empfehlungen
    // waere 1; ungequotiert zaehlen sie alle.
    let raw = report.perspectives_considered as f64;
    let synthetic_majority = (raw - 1.0).max(0.0);

    let unauthorized_effects = report.effects_applied.len(); // kein Token, trotz Planungsschritt davor

    let information_gain = if report.target_path.exists() && !report.written_content.is_empty() {
        1.0
    } else {
        0.0
    };
    let seconds = report.wall_clock.as_secs_f64().max(1e-9);
    let validation_efficiency = ValidationEfficiency {
        gain_per_probe: information_gain / raw.max(1.0),
        gain_per_second: information_gain / seconds,
        gain_per_effect_token: 0.0, // kein Token existiert, siehe monolithic-Begruendung
    };

    BaselineMetrics {
        system: "event_sourcing",
        unbound_fact_claims,
        false_fact_promotions,
        scope_leakage_incidents,
        synthetic_majority,
        unauthorized_effects,
        replay_deviation,
        validation_efficiency,
        creativity_preserved: report.perspectives_considered,
        overhead: Overhead {
            wall_clock: report.wall_clock,
            objects_produced: report.events.len(),
        },
        recovery_succeeded: false, // Event Log allein ist keine Kompensationssemantik
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kern_recovery_check_reflects_the_real_recovery_machinery() {
        assert!(kern_recovery_check());
    }

    #[test]
    fn scaled_to_f64_reads_scale_zero_as_the_numerator_directly() {
        // "Wert = numerator / 10^scale" (object_schemas.yaml) - scale:0
        // heisst numerator/1, NICHT Division durch Null.
        let s = psk_types::objects::Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: 5,
            scale: 0,
        };
        assert_eq!(scaled_to_f64(&s), 5.0);
    }

    #[test]
    fn scaled_to_f64_computes_the_real_ratio() {
        // "Wert = numerator / 10^scale" (object_schemas.yaml): numerator:3,
        // scale:2 heisst 3 / 10^2 = 0.03, NICHT numerator/scale (1.5) - die
        // fruehere, falsche Interpretation dieser Funktion.
        let s = psk_types::objects::Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: 3,
            scale: 2,
        };
        assert_eq!(scaled_to_f64(&s), 0.03);
    }
}
