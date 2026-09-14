//! M07, Prognosepersistenz (Struktur 20.11 (Forecast) OBJ-FCT, Regel 20.12,
//! Vertrag 20.13 (Prognosepersistenz)) - PSK-RA v1.0.22.
//!
//! Regel 20.12 woertlich: "horizon, generation_basis, validity_window und
//! anchor_ref sind nach Erzeugung unveraenderlich. Eine spaetere
//! Beobachtung erzeugt ausschliesslich einen neuen Eintrag in
//! evaluations; sie DARF NICHT ein bestehendes Feld aendern und DARF
//! NICHT einen bestehenden Eintrag ersetzen. Die Durchsetzung erfolgt
//! strukturell: evaluations ist append-only wie der Trace, und die
//! uebrigen Felder besitzen keinen Schreibpfad nach Konstruktion."
//!
//! ## Warum der generierte Typ dafuer nicht genuegt (Befund)
//!
//! `psk_types::objects::Forecast` traegt - wie jedes generierte
//! Kapitel-7-Objekt - ausschliesslich `pub`-Felder (Codegen-Konvention
//! fuer Serde und paketuebergreifende Ergonomie, siehe
//! tools/psk-codegen/src/objects.rs). Auf dem nackten Typ ist
//! `forecast.horizon = ...` deshalb ein gewoehnlicher Ausdruck, und
//! "besitzen keinen Schreibpfad nach Konstruktion" waere eine blosse
//! Namenskonvention - dieselbe Lage, die T-OWN-001 fuer die
//! Konstruktionsseite festhaelt.
//!
//! `SealedForecast` schliesst das fuer DIESES Objekt, mit dem Muster, das
//! `ResidueLedger`/`TraceStore` bereits tragen: das Objekt liegt in einem
//! privaten Feld, Lesezugriff geht ueber `&`-Getter, und der einzige
//! veraendernde Weg ist `evaluate()`, das ausschliesslich anhaengt. Was
//! Regel 20.12 verbietet, ist damit nicht dokumentiert, sondern nicht
//! ausdrueckbar - `T-FORECAST-001` prueft genau das, per `compile_fail`.

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    Forecast, ForecastEvaluation, ForecastEvaluationVerdictKind, HorizonSpec, SortId, TimeWindow,
};
use psk_types::{Digest, DualTime, ObjectId, PskError, TraceRef};

/// Die Sorte, unter der eine Prognose adressiert wird - dieselbe
/// Ableitung wie bei `THOUGHT_SORT`/`CLASSIFICATION_SORT`: M07 ist Owner
/// von OBJ-FCT (object_registry.yaml) und fuehrt seine Objekte unter
/// seinen eigenen Sorten. Der Realitaetshorizont (S-HOR) ist die
/// naechstliegende: eine Prognose IST eine Aussage ueber den Horizont.
const FORECAST_SORT: SortId = SortId::Horizon;

/// Eingaben fuer `create`. `id` und `evaluations` fehlen: die ID folgt aus
/// dem Inhalt, und Bewertungen entstehen ausschliesslich spaeter ueber
/// `evaluate` - eine Prognose wird nicht mit bereits vorhandener
/// Bewertung geboren.
pub struct ForecastInputs {
    pub horizon: HorizonSpec,
    pub generation_basis: Vec<ObjectId>,
    pub validity_window: TimeWindow,
    pub anchor_ref: ObjectId,
    pub claim_refs: Vec<ObjectId>,
    pub trace_ref: TraceRef,
}

/// Eine erzeugte Prognose. Die vier von Regel 20.12 geschuetzten Felder
/// sind nach der Konstruktion nicht mehr erreichbar; `evaluations` waechst
/// ausschliesslich ueber `evaluate`.
///
/// T-FORECAST-001 (`overwrite_forecast_after_observation -> FAIL`): die
/// Zusicherung ist die Abwesenheit eines Schreibpfads, und die folgenden
/// Doctests machen sie mechanisch pruefbar - dasselbe Beweismuster wie
/// `ResidueLedger` (T-TRACE-001) und `GateAuthorization`.
///
/// Der Horizont laesst sich nicht ueberschreiben:
/// ```compile_fail
/// # use psk_thought::{SealedForecast, ForecastInputs};
/// # use psk_types::objects::{HorizonSpec, TimeWindow, SortId};
/// # use psk_types::{Digest, ObjectId, TraceRef};
/// let mut f = SealedForecast::create(ForecastInputs {
///     horizon: HorizonSpec("PT1H".into()),
///     generation_basis: vec![],
///     validity_window: TimeWindow("PT1H".into()),
///     anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"a")),
///     claim_refs: vec![],
///     trace_ref: TraceRef(Digest::sha256(b"t")),
/// })
/// .unwrap();
/// f.horizon = HorizonSpec("PT99H".into());
/// ```
///
/// Der damalige Anker ebenso wenig:
/// ```compile_fail
/// # use psk_thought::{SealedForecast, ForecastInputs};
/// # use psk_types::objects::{HorizonSpec, TimeWindow, SortId};
/// # use psk_types::{Digest, ObjectId, TraceRef};
/// let mut f = SealedForecast::create(ForecastInputs {
///     horizon: HorizonSpec("PT1H".into()),
///     generation_basis: vec![],
///     validity_window: TimeWindow("PT1H".into()),
///     anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"a")),
///     claim_refs: vec![],
///     trace_ref: TraceRef(Digest::sha256(b"t")),
/// })
/// .unwrap();
/// f.anchor_ref = ObjectId::new(SortId::Anchor, Digest::sha256(b"spaeter"));
/// ```
///
/// Und eine bestehende Bewertung laesst sich nicht ersetzen - `evaluations()`
/// gibt nur einen unveraenderlichen Ausschnitt:
/// ```compile_fail
/// # use psk_thought::{SealedForecast, ForecastInputs};
/// # use psk_types::objects::{HorizonSpec, TimeWindow, SortId};
/// # use psk_types::{Digest, ObjectId, TraceRef};
/// let mut f = SealedForecast::create(ForecastInputs {
///     horizon: HorizonSpec("PT1H".into()),
///     generation_basis: vec![],
///     validity_window: TimeWindow("PT1H".into()),
///     anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"a")),
///     claim_refs: vec![],
///     trace_ref: TraceRef(Digest::sha256(b"t")),
/// })
/// .unwrap();
/// f.evaluations().clear();
/// ```
///
/// Positivkontrolle - ohne sie waeren die drei Doctests oben wertlos: ein
/// `compile_fail` besteht auch, wenn der Aufbau aus einem ganz anderen
/// Grund nicht uebersetzt. Derselbe Aufbau uebersetzt hier und laeuft;
/// was oben scheitert, scheitert also am fehlenden Schreibpfad und an
/// nichts sonst:
/// ```
/// # use psk_thought::{SealedForecast, ForecastInputs};
/// # use psk_types::objects::{HorizonSpec, TimeWindow, SortId};
/// # use psk_types::{Digest, ObjectId, TraceRef};
/// let f = SealedForecast::create(ForecastInputs {
///     horizon: HorizonSpec("PT1H".into()),
///     generation_basis: vec![],
///     validity_window: TimeWindow("PT1H".into()),
///     anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"a")),
///     claim_refs: vec![],
///     trace_ref: TraceRef(Digest::sha256(b"t")),
/// })
/// .unwrap();
/// assert_eq!(f.horizon().0, "PT1H");
/// assert!(f.evaluations().is_empty());
/// ```
#[derive(Debug, Clone, PartialEq)]
pub struct SealedForecast {
    inner: Forecast,
}

impl SealedForecast {
    /// Erzeugt eine Prognose. Danach gibt es keinen Weg mehr, `horizon`,
    /// `generation_basis`, `validity_window` oder `anchor_ref` zu
    /// veraendern (Regel 20.12 (Prognosen werden bewertet, nicht umgeschrieben)).
    pub fn create(inputs: ForecastInputs) -> Result<Self, PskError> {
        let draft = Forecast {
            schema: "psk.forecast/1.0".to_string(),
            id: ObjectId::new(FORECAST_SORT, Digest::sha256(b"")), // Platzhalter
            horizon: inputs.horizon,
            generation_basis: inputs.generation_basis,
            validity_window: inputs.validity_window,
            anchor_ref: inputs.anchor_ref,
            claim_refs: inputs.claim_refs,
            evaluations: Vec::new(),
            trace_ref: inputs.trace_ref,
        };
        let id = compute_identity(&draft)?;
        Ok(SealedForecast {
            inner: Forecast { id, ..draft },
        })
    }

    /// Vertrag 20.13 (Prognosepersistenz): "Spaetere Beobachtungen DARF die Prognose bewerten,
    /// DARF NICHT aber rueckwirkend in eine scheinbar korrekte Prognose
    /// umschreiben." Genau ein Anhaengen, kein Ersetzen - dieselbe Form
    /// wie `TraceStore::append`.
    pub fn evaluate(
        &mut self,
        observed_ref: ObjectId,
        verdict: ForecastEvaluationVerdictKind,
        evaluated_at: DualTime,
    ) {
        self.inner.evaluations.push(ForecastEvaluation {
            observed_ref,
            verdict,
            evaluated_at,
        });
    }

    pub fn id(&self) -> ObjectId {
        self.inner.id
    }
    pub fn horizon(&self) -> &HorizonSpec {
        &self.inner.horizon
    }
    pub fn generation_basis(&self) -> &[ObjectId] {
        &self.inner.generation_basis
    }
    pub fn validity_window(&self) -> &TimeWindow {
        &self.inner.validity_window
    }
    pub fn anchor_ref(&self) -> ObjectId {
        self.inner.anchor_ref
    }
    pub fn claim_refs(&self) -> &[ObjectId] {
        &self.inner.claim_refs
    }
    pub fn evaluations(&self) -> &[ForecastEvaluation] {
        &self.inner.evaluations
    }

    /// Lesender Zugriff auf das ganze Objekt - fuer Kanonisierung und
    /// Trace. Bewusst `&`: eine Kopie herauszugeben waere kein Leck (der
    /// Empfaenger veraendert dann seine eigene), aber `&` macht auch das
    /// gar nicht erst noetig.
    pub fn as_object(&self) -> &Forecast {
        &self.inner
    }
}

fn compute_identity(draft: &Forecast) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    object_id(FORECAST_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::ClockRef;

    fn sample_time(tau_i: u64) -> DualTime {
        DualTime {
            tau_i,
            tau_e: "2026-08-08T00:00:00.000000000Z".into(),
            clock_ref: ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample() -> SealedForecast {
        SealedForecast::create(ForecastInputs {
            horizon: HorizonSpec("PT24H".into()),
            generation_basis: vec![ObjectId::new(SortId::Context, Digest::sha256(b"basis"))],
            validity_window: TimeWindow("PT24H".into()),
            anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor")),
            claim_refs: vec![ObjectId::new(SortId::Context, Digest::sha256(b"claim"))],
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        })
        .unwrap()
    }

    #[test]
    fn a_new_forecast_carries_all_four_mandatory_fields_and_no_evaluation() {
        // Vertrag 20.13 (Prognosepersistenz): Horizont, Erzeugungsbasis, Gueltigkeitsfenster
        // und der damalige Anker MUESSEN gespeichert sein.
        let f = sample();
        assert_eq!(f.horizon().0, "PT24H");
        assert_eq!(f.generation_basis().len(), 1);
        assert_eq!(f.validity_window().0, "PT24H");
        assert_eq!(f.anchor_ref().sort, SortId::Anchor);
        assert!(f.evaluations().is_empty(), "unbewertet geboren");
    }

    #[test]
    fn t_forecast_001_a_later_observation_only_appends_and_never_replaces() {
        // Regel 20.12 / Vertrag 20.13: bewerten ja, umschreiben nein.
        let mut f = sample();
        let before = f.as_object().clone();

        f.evaluate(
            ObjectId::new(SortId::Receipt, Digest::sha256(b"obs-1")),
            ForecastEvaluationVerdictKind::Refuted,
            sample_time(1),
        );
        f.evaluate(
            ObjectId::new(SortId::Receipt, Digest::sha256(b"obs-2")),
            ForecastEvaluationVerdictKind::Confirmed,
            sample_time(2),
        );

        // Die vier geschuetzten Felder sind unveraendert ...
        assert_eq!(f.horizon(), &before.horizon);
        assert_eq!(f.generation_basis(), &before.generation_basis[..]);
        assert_eq!(f.validity_window(), &before.validity_window);
        assert_eq!(f.anchor_ref(), before.anchor_ref);

        // ... und die erste Bewertung steht noch da, unersetzt.
        assert_eq!(f.evaluations().len(), 2);
        assert_eq!(
            f.evaluations()[0].verdict,
            ForecastEvaluationVerdictKind::Refuted,
            "eine spaetere Bewertung DARF eine fruehere nicht ueberschreiben - \
             genau die rueckwirkend korrekt erscheinende Prognose, die Vertrag 20.13 verbietet"
        );
        assert_eq!(
            f.evaluations()[1].verdict,
            ForecastEvaluationVerdictKind::Confirmed
        );
    }

    #[test]
    fn the_identity_does_not_move_when_an_evaluation_is_appended() {
        // Die Prognose bleibt DIESELBE Prognose, auch bewertet - sonst
        // waere jede Bewertung faktisch eine neue Aussage.
        let mut f = sample();
        let id_before = f.id();
        f.evaluate(
            ObjectId::new(SortId::Receipt, Digest::sha256(b"obs")),
            ForecastEvaluationVerdictKind::Inconclusive,
            sample_time(1),
        );
        assert_eq!(f.id(), id_before);
    }

    #[test]
    fn creation_is_deterministic() {
        assert_eq!(sample().id(), sample().id());
    }
}
