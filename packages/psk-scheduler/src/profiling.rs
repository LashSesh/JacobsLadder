//! Profilingschalter (T-OBSV-001, I-ARCH-015:
//! "profiling_and_logging_do_not_alter_canonical_digest").
//!
//! ## Zwei unabhaengige Schutzschichten, absichtlich beide
//!
//! **1. Strukturell: Profilingdaten liegen NICHT in `Sigma`.** `tick()`
//! nimmt `&mut Profiling` als eigenen Parameter entgegen; kein Feld von
//! `Sigma` traegt je einen Messwert. Damit kann ein - heute noch gar nicht
//! existierender, siehe unten - Zustandsdigest `I_t = H(Can(Sigma_t))`
//! Profilingdaten nicht einmal dann aufnehmen, wenn er falsch gebaut
//! wuerde: sie sind nicht Teil des Werts, den er hasht.
//!
//! **2. Registergestuetzt: das Feld heisst `runtime_metrics`.**
//! `architecture/volatile_fields.yaml` fuehrt `*.runtime_metrics` bereits
//! als volatil; `pi_vol` (Definition 6.5) entfernt es rekursiv und in
//! jeder Tiefe vor der Identitaetsbildung. Sollte ein Bericht die
//! Messwerte je in ein serialisiertes Objekt einbetten, bleibt die
//! Objekt-ID unveraendert, waehrend der `record_digest` abweichen DARF -
//! genau die Trennung aus Definition 6.6/6.7. Kein neuer Mechanismus,
//! keine Sonderbehandlung in `dispatch()`.
//!
//! Schicht 1 allein wuerde genuegen, solange Profiling wirklich nur hier
//! entsteht; Schicht 2 allein wuerde genuegen, solange jeder kuenftige
//! Digest `identity_projection` statt `can` benutzt. Beide zusammen
//! ueberleben, dass eine der beiden Annahmen spaeter bricht.
//!
//! ## Ein Codepfad, nicht zwei
//!
//! `record_*` ist bei `enabled: false` ein No-op, aber es wird IMMER
//! aufgerufen - `tick()` hat keinen zweiten, profilingfreien Zweig. Zwei
//! getrennte Pfade wuerden den T-OBSV-001-Test entwerten: er verglaeche
//! dann zwei verschiedene Implementierungen statt zu zeigen, dass
//! dieselbe Implementierung mit eingeschaltetem Profiling denselben
//! kanonischen Zustand erzeugt.
//!
//! ## Befund: es gibt (noch) keinen Sigma-Digest
//!
//! Geprueft, weil die Gefahr real waere: `Sigma` leitet nur `Debug,
//! Clone` ab, nicht `Serialize` - es ist derzeit gar nicht
//! kanonisierbar, und keine Funktion im Workspace bildet einen Digest
//! ueber `Sigma`. `psk_contract::identity_binder::runtime_state_digest()`
//! (Regel 6.10, `I_t = H(Can(Sigma_t))`) liefert ausdruecklich
//! `trace.head()` als ehrlichen Bootzeit-Platzhalter. Die Frage "schliesst
//! euer Sigma-Digest volatile Felder aus?" ist damit heute nicht
//! beantwortbar, sondern offen - und genau deshalb steht Schicht 1 oben
//! an erster Stelle: sie haengt nicht davon ab, wie dieser Digest einmal
//! gebaut wird.

use psk_types::Phase;

/// Messwerte einer einzelnen Phase innerhalb eines Takts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct PhaseMetric {
    /// `Phase` selbst ist nicht `Serialize` (ein reiner Laufzeitbegriff,
    /// kein Kapitel-7-Objekt) - deshalb sein stabiler Bezeichner.
    #[serde(rename = "phase")]
    pub phase_label: &'static str,
    pub items_dispatched: u64,
    pub items_budget_skipped: u64,
}

/// Der Profilingschalter samt gesammelter Messwerte.
///
/// Das Feld heisst `runtime_metrics`, damit `pi_vol` es ueberall
/// entfernt, wo es je serialisiert eingebettet wuerde (siehe Modulkopf).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Profiling {
    #[serde(skip)]
    enabled: bool,
    runtime_metrics: Vec<PhaseMetric>,
}

impl Profiling {
    /// Profiling aus - `record_*` bleibt wirkungslos, der Aufrufpfad
    /// bleibt derselbe.
    pub fn off() -> Self {
        Profiling {
            enabled: false,
            runtime_metrics: Vec::new(),
        }
    }

    /// Profiling ein.
    pub fn on() -> Self {
        Profiling {
            enabled: true,
            runtime_metrics: Vec::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn runtime_metrics(&self) -> &[PhaseMetric] {
        &self.runtime_metrics
    }

    /// Haelt die Bilanz einer abgeschlossenen Phase fest. Bei
    /// ausgeschaltetem Profiling ein No-op - aber ein aufgerufenes.
    pub(crate) fn record_phase(
        &mut self,
        phase: Phase,
        items_dispatched: u64,
        items_budget_skipped: u64,
    ) {
        if !self.enabled {
            return;
        }
        self.runtime_metrics.push(PhaseMetric {
            phase_label: phase.label(),
            items_dispatched,
            items_budget_skipped,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_disabled_switch_records_nothing() {
        let mut p = Profiling::off();
        p.record_phase(Phase::Execute, 3, 1);
        assert!(!p.is_enabled());
        assert!(p.runtime_metrics().is_empty());
    }

    #[test]
    fn an_enabled_switch_records_what_it_was_told() {
        let mut p = Profiling::on();
        p.record_phase(Phase::Execute, 3, 1);
        assert_eq!(p.runtime_metrics().len(), 1);
        assert_eq!(p.runtime_metrics()[0].phase_label, "execute");
        assert_eq!(p.runtime_metrics()[0].items_dispatched, 3);
        assert_eq!(p.runtime_metrics()[0].items_budget_skipped, 1);
    }

    #[test]
    fn the_metrics_field_is_named_runtime_metrics_so_pi_vol_finds_it() {
        // Der Feldname IST der Schutzmechanismus (volatile_fields.yaml:
        // "*.runtime_metrics") - eine Umbenennung wuerde ihn still
        // aushebeln, deshalb ist er hier festgenagelt.
        let mut p = Profiling::on();
        p.record_phase(Phase::Observe, 1, 0);
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            json.contains("\"runtime_metrics\""),
            "Feldname muss runtime_metrics bleiben: {json}"
        );
    }
}
