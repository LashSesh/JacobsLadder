//! M07 RealityTyper: klassifiziert einen ThoughtBody und emittiert das
//! Ergebnis als eigenstaendiges Objekt `RealityClassification` (Struktur
//! 7.11, OBJ-RCL) ueber P09 an M23.
//!
//! Regel 7.12 (Klassifikation ist ein eigenes Objekt): "M07 DARF NICHT in
//! den ThoughtBody schreiben. Die Klassifikation verlaesst M07
//! ausschliesslich als RealityClassification ueber P09." Deshalb nimmt
//! `classify` den Koerper nur als unveraenderliche Referenz.
//!
//! Das Feld `reachability` traegt die von Definition 5.11 verlangte
//! Dreiteilung: `refuted` setzt bezeugte Nichterreichbarkeit voraus und ist
//! die einzige Auspraegung, unter der `imaginary` gelten kann; `unexamined`
//! fuehrt zu UNKNOWN und DARF NICHT zu IMAGINARY.
//!
//! `RealityEvidence` ist nach Vertrag 27.2 (Domaenengelieferte opake
//! Eingaben) einer der drei Typen, die der Kern absichtlich ohne Grammatik
//! fuehrt: "Sie werden ueber DomainProfile oder MethodPlugin geliefert und
//! im Kern nur typisiert weitergereicht. Das ist keine Luecke, sondern die
//! Erweiterungsgrenze nach Prinzip 4.3." Die dort genannte dritte Pflicht -
//! "Ein fehlendes oder nicht anwendbares Plug-in erzeugt UNKNOWN
//! beziehungsweise ein Residuum, DARF NICHT eine Vorgabewahl" - ist der
//! Grund, warum `classify_reality` keinen Default-Zweig hat.

use psk_types::objects::{
    FactStatus, PluginId, RealityClassification, RealityClassificationReachabilityKind,
    RealityStatus, SortId, ThoughtBody,
};
use psk_types::{Digest, DualTime, ObjectId, PskError, TraceRef};

/// Die Evidenz, auf der eine Klassifikation beruht - domaenengeliefert
/// (Vertrag 27.2), hier nur typisiert entgegengenommen.
///
/// Axiom 5.6 (Realitaetsleiter): R_act <= R_con <= R_rea <= R_law <= R_coh.
/// Die Leiter ist damit monoton: was aktualisiert ist, ist auch kohaerent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RealityEvidence {
    /// In sich widerspruchsfrei (R_coh).
    pub coherent: bool,
    /// Mit den geltenden Gesetzen vereinbar (R_law).
    pub lawful: bool,
    /// Konstruierbar (R_con).
    pub constructible: bool,
    /// Tatsaechlich aktualisiert (R_act).
    pub actualized: bool,
    /// R_rea, dreiwertig statt zweiwertig: Struktur 7.11 fuehrt genau diese
    /// Unterscheidung als eigenes Feld, weil `unexamined` und `refuted`
    /// verschiedene Folgen haben (Regel 7.12).
    pub reachability: RealityClassificationReachabilityKind,
}

impl Default for RealityEvidence {
    /// Der Anfangszustand ist "nichts festgestellt": kein positives Merkmal
    /// und die Erreichbarkeit ungeprueft. Das ist bewusst kein neutraler
    /// Nullwert, sondern der einzige Zustand, aus dem `classify_reality`
    /// UNKNOWN liefert (Vertrag 27.2, Pflicht 3).
    fn default() -> Self {
        RealityEvidence {
            coherent: false,
            lawful: false,
            constructible: false,
            actualized: false,
            reachability: RealityClassificationReachabilityKind::Unexamined,
        }
    }
}

impl RealityEvidence {
    /// R_rea gilt nur bei bezeugter Erreichbarkeit. `unexamined` ist kein
    /// schwaches Ja, sondern gar keine Aussage.
    pub fn reachable(&self) -> bool {
        self.reachability == RealityClassificationReachabilityKind::Witnessed
    }
}

/// Definition 5.7: klassifiziert nach der hoechsten erreichten Sprosse der
/// Realitaetsleiter. UNKNOWN ist dabei ein wirksamer Status mit
/// Promotionssperre, kein fehlender Wert (Vertrag 7.13) - er entsteht,
/// sobald nicht einmal Kohaerenz festgestellt ist.
///
/// Kein Default-Zweig auf einen positiven Status: OBL-002 ("Ein Verfahren,
/// das UNKNOWN vermeidet, ist nicht konform") und Vertrag 27.2, Pflicht 3
/// ("Ein Default-Zweig auf einen positiven Status ist ein
/// Konformitaetsdefekt") verlangen beide dasselbe.
pub fn classify_reality(evidence: &RealityEvidence) -> RealityStatus {
    if evidence.actualized {
        RealityStatus::Actualized
    } else if evidence.constructible {
        RealityStatus::Constructible
    } else if evidence.reachable() {
        RealityStatus::Reachable
    } else if evidence.lawful {
        RealityStatus::Lawful
    } else if evidence.coherent {
        RealityStatus::Coherent
    } else {
        RealityStatus::Unknown
    }
}

/// Definition 5.11 (Ankerrelativ imaginaer):
/// `imaginary(x,a) :<=> reality_status(x) in {COHERENT, LAWFUL} and not reachable(x,a)`.
///
/// Regel 7.12 praezisiert die Nichterreichbarkeit: nur `refuted` traegt sie
/// bezeugt. `unexamined` "fuehrt zu UNKNOWN und DARF NICHT zu IMAGINARY".
/// IMAGINARY ist KEIN Wert von RealityStatus oder FactStatus, sondern ein
/// daraus abgeleitetes Praedikat - deshalb ein bool und kein Statuswert.
pub fn is_imaginary(
    status: RealityStatus,
    reachability: RealityClassificationReachabilityKind,
) -> bool {
    matches!(status, RealityStatus::Coherent | RealityStatus::Lawful)
        && reachability == RealityClassificationReachabilityKind::Refuted
}

/// Was M07 zur Klassifikation braucht und nicht selbst feststellen kann.
pub struct ClassificationInputs {
    /// Anker, relativ zu dem klassifiziert wird (Struktur 7.11).
    pub anchor_ref: ObjectId,
    pub evidence: RealityEvidence,
    /// Belege; "leer nur bei UNKNOWN" (Struktur 7.11).
    pub evidence_refs: Vec<ObjectId>,
    /// Das MethodPlugin, das die Evidenz geliefert hat (Vertrag 27.2).
    /// None bedeutet: kein Plug-in beteiligt - dann MUSS die Klassifikation
    /// UNKNOWN ergeben, siehe `classify`.
    pub method_ref: Option<PluginId>,
    pub residue_refs: Vec<ObjectId>,
    pub trace_ref: TraceRef,
    pub classified_at: DualTime,
}

fn compute_identity(draft: &RealityClassification) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?;
    psk_canon::object_id(CLASSIFICATION_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// Die Sorte, unter der eine RealityClassification adressiert wird.
///
/// Abgeleitet, nicht zitiert - dieselbe Lage wie bei THOUGHT_SORT in
/// `thought.rs`: sort_registry.yaml ordnet Sorten Modulen zu, nicht
/// Objekten. M07 ist Owner genau einer Sorte (S-HOR Horizon) und besitzt
/// genau ein Objekt (RealityClassification, Kapitel 3.2). Daraus folgt die
/// Zuordnung eindeutig; das Werk stellt sie nirgends woertlich fest.
const CLASSIFICATION_SORT: SortId = SortId::Horizon;

/// M07: klassifiziert einen ThoughtBody und gibt das Ergebnis als
/// eigenstaendiges Objekt zurueck (Regel 7.12). Der Koerper wird nur
/// gelesen.
///
/// `facticity` bleibt auf dem Anfangswert des Koerpers: jede
/// Faktizitaetspromotion ueber SPECIFIED hinaus verlangt ein Gate
/// (Invariante 5.9: "Jede Promotion MUSS einen benannten Konstruktor, einen
/// GateReport und einen TraceSegment besitzen"), und Gates entstehen erst
/// mit M14 in WP11 (Phase I6).
///
/// Vertrag 27.2, Pflicht 3: ohne MethodPlugin darf keine positive
/// Klassifikation entstehen - eine Vorgabewahl waere genau der dort
/// verbotene Fall.
pub fn classify(
    body: &ThoughtBody,
    inputs: ClassificationInputs,
) -> Result<RealityClassification, PskError> {
    let reality_status = classify_reality(&inputs.evidence);

    if inputs.method_ref.is_none() && reality_status != RealityStatus::Unknown {
        return Err(PskError::UnboundNondeterminismOrDivergence);
    }
    if reality_status != RealityStatus::Unknown && inputs.evidence_refs.is_empty() {
        // Struktur 7.11: "Grundlage; leer nur bei UNKNOWN".
        return Err(PskError::UnsupportedReachability);
    }

    let draft = RealityClassification {
        schema: "psk.reality-classification/1.0".to_string(),
        id: ObjectId::new(CLASSIFICATION_SORT, Digest::sha256(b"")), // Platzhalter
        thought_ref: body.id,
        anchor_ref: inputs.anchor_ref,
        reality_status,
        facticity: body.facticity,
        reachability: inputs.evidence.reachability,
        evidence_refs: inputs.evidence_refs,
        method_ref: inputs.method_ref,
        residue_refs: inputs.residue_refs,
        trace_ref: inputs.trace_ref,
        classified_at: inputs.classified_at,
    };

    let id = compute_identity(&draft)?;
    Ok(RealityClassification { id, ..draft })
}

/// Invariante 5.9 (Keine implizite Promotion), woertlich:
/// SIMULATED !=> ACTUALIZED, SELECTED !=> OBSERVED, ATTEMPTED !=> ACTUALIZED,
/// POSSIBLE !=> ACTUALIZED. Diese vier Kanten sind auch die `forbidden`-Liste
/// von FSM-THOUGHT.
pub fn is_implicit_promotion(from: FactStatus, to: FactStatus) -> bool {
    matches!(
        (from, to),
        (FactStatus::Simulated, FactStatus::Actualized)
            | (FactStatus::Selected, FactStatus::Observed)
            | (FactStatus::Attempted, FactStatus::Actualized)
            | (FactStatus::Possible, FactStatus::Actualized)
    )
}

/// Die EINZIGE Stelle, die ueber eine Faktpromotion entscheidet -
/// T-UNKNOWN-001 / Vertrag 7.13.
///
/// Zwei Sperren, eine Wache:
///
/// 1. **UNKNOWN sperrt jede Promotion, unabhaengig vom FactStatus.**
///    Vertrag 7.13 woertlich: UNKNOWN ist "ein wirksamer Status mit
///    Promotionssperre, kein fehlender Wert". Genau das macht diese Zeile
///    wirksam statt beschreibend - zuvor produzierte `classify_reality`
///    UNKNOWN korrekt, aber nichts hinderte einen spaeteren Schritt
///    daran, DAVON WEG zu promovieren.
/// 2. Invariante 5.9s vier implizite Promotionen (siehe
///    `is_implicit_promotion`), wie bisher.
///
/// **Warum eine Wache und nicht zwei:** M18 (`psk_reconciliation::
/// reconcile`) leitete seine `fact_promotion` frueher selbst ab. Zwei
/// getrennte Entscheidungsstellen driften auseinander - dieselbe
/// Ueberlegung, aus der `dispatch`/`dispatch_stateless` sich EINE
/// Match-Tabelle teilen (psk-scheduler). M18 ruft deshalb seit
/// T-UNKNOWN-001 diese Funktion auf, statt eine eigene Ableitung zu
/// fuehren; die dafuer noetige Signaturerweiterung ist der Preis dafuer,
/// dass eine blockierende Invariante nicht nur halb durchgesetzt ist.
pub fn check_promotion(
    from: FactStatus,
    to: FactStatus,
    reality_status: RealityStatus,
) -> Result<(), PskError> {
    if reality_status == RealityStatus::Unknown {
        // Die Sperre gilt fuer JEDE Promotion - auch fuer eine, die
        // Invariante 5.9 fuer sich genommen erlauben wuerde.
        return Err(PskError::SurfaceInvariantCollapse);
    }
    if is_implicit_promotion(from, to) {
        Err(PskError::SurfaceInvariantCollapse)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::ClockRef;
    use RealityClassificationReachabilityKind as Reach;

    fn evidence_up_to_lawful() -> RealityEvidence {
        RealityEvidence {
            coherent: true,
            lawful: true,
            ..Default::default()
        }
    }

    fn sample_inputs(evidence: RealityEvidence) -> ClassificationInputs {
        ClassificationInputs {
            anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor")),
            evidence,
            evidence_refs: vec![ObjectId::new(SortId::Witness, Digest::sha256(b"ev"))],
            method_ref: Some(PluginId("reality-typer/1".into())),
            residue_refs: vec![],
            trace_ref: TraceRef(Digest::sha256(b"trace")),
            classified_at: DualTime {
                tau_i: 1,
                tau_e: "2026-08-04T00:00:00.000000000Z".into(),
                clock_ref: ClockRef("test-clock".into()),
                uncertainty_ns: 0,
            },
        }
    }

    fn sample_body() -> ThoughtBody {
        use psk_types::objects::{
            Claim, ClaimDirectionalityKind, ClaimExpr, Lineage, UncertaintyBlock,
        };
        crate::compile_thought(crate::ThoughtInputs {
            anchor_refs: vec![ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor"))],
            unanchored: false,
            claim: Claim {
                text: "egal".into(),
                formal: ClaimExpr("formal(x)".into()),
                directionality: ClaimDirectionalityKind::Internal,
            },
            models: vec![],
            trajectories: vec![],
            uncertainty: UncertaintyBlock("none".into()),
            consequences: vec![],
            lineage: Lineage("root".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        })
        .unwrap()
    }

    #[test]
    fn unknown_when_not_even_coherent() {
        // Vertrag 7.13: UNKNOWN ist ein wirksamer Status, kein fehlender Wert.
        assert_eq!(
            classify_reality(&RealityEvidence::default()),
            RealityStatus::Unknown
        );
    }

    #[test]
    fn unexamined_reachability_does_not_reach() {
        // Regel 7.12: unexamined ist keine Erreichbarkeitsaussage.
        let e = RealityEvidence {
            coherent: true,
            lawful: true,
            reachability: Reach::Unexamined,
            ..Default::default()
        };
        assert_eq!(classify_reality(&e), RealityStatus::Lawful);
        assert!(!e.reachable());
    }

    #[test]
    fn ladder_reports_the_highest_reached_rung() {
        let mut e = RealityEvidence {
            coherent: true,
            ..Default::default()
        };
        assert_eq!(classify_reality(&e), RealityStatus::Coherent);
        e.lawful = true;
        assert_eq!(classify_reality(&e), RealityStatus::Lawful);
        e.reachability = Reach::Witnessed;
        assert_eq!(classify_reality(&e), RealityStatus::Reachable);
        e.constructible = true;
        assert_eq!(classify_reality(&e), RealityStatus::Constructible);
        e.actualized = true;
        assert_eq!(classify_reality(&e), RealityStatus::Actualized);
    }

    #[test]
    fn imaginary_requires_refuted_not_merely_unexamined() {
        // Regel 7.12: "refuted setzt bezeugte Nichterreichbarkeit voraus,
        // unexamined fuehrt zu UNKNOWN und DARF NICHT zu IMAGINARY."
        assert!(is_imaginary(RealityStatus::Coherent, Reach::Refuted));
        assert!(
            !is_imaginary(RealityStatus::Coherent, Reach::Unexamined),
            "ein bloss ungeprueftes Feld DARF NICHT IMAGINARY ergeben"
        );
        assert!(!is_imaginary(RealityStatus::Coherent, Reach::Witnessed));
    }

    #[test]
    fn imaginary_only_applies_to_coherent_or_lawful() {
        assert!(is_imaginary(RealityStatus::Lawful, Reach::Refuted));
        assert!(!is_imaginary(RealityStatus::Unknown, Reach::Refuted));
        assert!(!is_imaginary(RealityStatus::Reachable, Reach::Refuted));
        assert!(!is_imaginary(RealityStatus::Actualized, Reach::Refuted));
    }

    #[test]
    fn imaginary_is_not_a_status_value() {
        // Definition 5.11: IMAGINARY DARF NICHT ein Wert von RealityStatus
        // oder FactStatus sein. Die geschlossenen Mengen bleiben bei 6 bzw. 9.
        assert_eq!(RealityStatus::ALL.len(), 6);
        assert_eq!(FactStatus::ALL.len(), 9);
        assert!(RealityStatus::from_id("IMAGINARY").is_none());
        assert!(FactStatus::from_id("IMAGINARY").is_none());
    }

    #[test]
    fn classification_is_a_separate_object_referencing_the_body() {
        // Regel 7.12: M07 schreibt nicht in den ThoughtBody.
        let body = sample_body();
        let before = body.clone();
        let cls = classify(&body, sample_inputs(evidence_up_to_lawful())).unwrap();
        assert_eq!(body, before, "der ThoughtBody DARF NICHT veraendert werden");
        assert_eq!(cls.thought_ref, body.id);
        assert_eq!(cls.reality_status, RealityStatus::Lawful);
        assert_eq!(cls.facticity, body.facticity);
    }

    #[test]
    fn missing_plugin_may_not_yield_a_positive_status() {
        // Vertrag 27.2, Pflicht 3: keine Vorgabewahl ohne Plug-in.
        let body = sample_body();
        let mut inputs = sample_inputs(evidence_up_to_lawful());
        inputs.method_ref = None;
        assert_eq!(
            classify(&body, inputs),
            Err(PskError::UnboundNondeterminismOrDivergence)
        );
    }

    #[test]
    fn unknown_without_plugin_is_the_permitted_outcome() {
        let body = sample_body();
        let mut inputs = sample_inputs(RealityEvidence::default());
        inputs.method_ref = None;
        inputs.evidence_refs.clear();
        let cls = classify(&body, inputs).unwrap();
        assert_eq!(cls.reality_status, RealityStatus::Unknown);
        assert!(cls.evidence_refs.is_empty());
    }

    #[test]
    fn positive_status_needs_evidence_refs() {
        // Struktur 7.11: "Grundlage; leer nur bei UNKNOWN".
        let body = sample_body();
        let mut inputs = sample_inputs(evidence_up_to_lawful());
        inputs.evidence_refs.clear();
        assert_eq!(
            classify(&body, inputs),
            Err(PskError::UnsupportedReachability)
        );
    }

    #[test]
    fn classification_is_deterministic() {
        let body = sample_body();
        let a = classify(&body, sample_inputs(evidence_up_to_lawful())).unwrap();
        let b = classify(&body, sample_inputs(evidence_up_to_lawful())).unwrap();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn invariante_5_9_forbids_the_four_implicit_promotions() {
        assert!(is_implicit_promotion(
            FactStatus::Simulated,
            FactStatus::Actualized
        ));
        assert!(is_implicit_promotion(
            FactStatus::Selected,
            FactStatus::Observed
        ));
        assert!(is_implicit_promotion(
            FactStatus::Attempted,
            FactStatus::Actualized
        ));
        assert!(is_implicit_promotion(
            FactStatus::Possible,
            FactStatus::Actualized
        ));
        // Der regulaere Weg ueber OBSERVED bleibt erlaubt.
        assert!(!is_implicit_promotion(
            FactStatus::Observed,
            FactStatus::Actualized
        ));
    }

    #[test]
    fn check_promotion_fails_closed() {
        assert_eq!(
            check_promotion(
                FactStatus::Simulated,
                FactStatus::Actualized,
                RealityStatus::Actualized
            ),
            Err(PskError::SurfaceInvariantCollapse)
        );
        assert_eq!(
            check_promotion(
                FactStatus::Observed,
                FactStatus::Actualized,
                RealityStatus::Actualized
            ),
            Ok(())
        );
    }

    #[test]
    fn t_unknown_001_unknown_bars_every_promotion_regardless_of_fact_status() {
        // Vertrag 7.13: "ein wirksamer Status mit Promotionssperre, kein
        // fehlender Wert". Geprueft ueber ALLE neun FactStatus-Werte als
        // Ausgang und die beiden realen Promotionsziele - eine Sperre,
        // die nur fuer manche Ausgangswerte gilt, waere keine.
        for from in FactStatus::ALL {
            for to in [FactStatus::Observed, FactStatus::Actualized] {
                assert_eq!(
                    check_promotion(from, to, RealityStatus::Unknown),
                    Err(PskError::SurfaceInvariantCollapse),
                    "UNKNOWN MUSS {from:?} -> {to:?} sperren"
                );
            }
        }
    }

    #[test]
    fn a_non_unknown_status_still_allows_the_permitted_promotion() {
        // Gegenprobe: ohne sie waere die Wache auch dann gruen, wenn sie
        // schlicht alles sperrte - dann pruefte der Test oben nichts
        // ueber UNKNOWN, sondern nur ueber eine kaputte Wache.
        for status in RealityStatus::ALL {
            let expected = if status == RealityStatus::Unknown {
                Err(PskError::SurfaceInvariantCollapse)
            } else {
                Ok(())
            };
            assert_eq!(
                check_promotion(FactStatus::Observed, FactStatus::Actualized, status),
                expected,
                "nur UNKNOWN sperrt, {status:?} nicht"
            );
        }
    }
}
