//! M14 AuthorityConsequenceGate (Kapitel 18).
//!
//! Definition 18.1 (Gate erster Ordnung): "G: D -> {FAIL, HOLD, PASS} x
//! GateReport. G ist partiell: Unentscheidbarkeit liefert HOLD, niemals
//! PASS." Definition 18.2 (Gate zweiter Ordnung) erweitert das um eine
//! gemeinsame Schliessbarkeitspruefung mehrerer Relationen. Axiom 18.3
//! (Fail closed): "Fehlende oder unentscheidbare blocking Voraussetzungen
//! erzeugen HOLD oder FAIL, niemals implizites PASS."
//!
//! Algorithmus 18.6 (Gate-Auswertung), woertlich:
//! ```text
//! function evaluate_gate(gate_id, inputs, rd) -> GateReport:
//!     digests = [ H(Can(i)) for i in inputs ]
//!     policy = gate_policy(gate_id)
//!     reasons = []
//!     for cond in policy.blocking_conditions:
//!         r = eval(cond, inputs)
//!         match r:
//!             UNDECIDABLE -> reasons.append(cond); decision = HOLD
//!             FALSE       -> reasons.append(cond); decision = FAIL; break
//!             TRUE        -> continue
//!     if no reasons: decision = PASS
//!     if gate.order == 2:
//!         seam = M11.seam_report(inputs)
//!         if not seam.compatible: decision = min(decision, HOLD)
//!     report = GateReport{ gate_id, order, digests, decision, reasons, ... }
//!     M19.append(report)  // ueber P33, synchron
//!     if decision != PASS: M19.residualize(report)
//!     return report
//! ```
//!
//! `M19.append`/`M19.residualize` sind Teil DIESER Funktion, nicht optional
//! und nicht Aufgabe des Aufrufers - drei unabhaengige Stellen fordern
//! woertlich dasselbe: Algorithmus 18.6 selbst (obiger Auszug), die
//! Synchronitaetsregel ("P28 und P33 sind stets synchron: eine
//! Zustandsaenderung DARF NICHT vor ihrer Traceschreibung sichtbar
//! werden") und I-ARCH-006 (severity: blocking) als globale Invariante.
//! `evaluate_gate` haengt deshalb auf `psk-trace` ab (kein verbotener
//! Kante laut module_map.yaml) und nimmt `&mut TraceStore`/`&mut
//! ResidueLedger` als Parameter, demselben Muster wie
//! `psk_reconciliation::reconcile`s `&mut ResidueLedger`-Parameter.
//! `origin_module` fuer beides wird NICHT vom Aufrufer verlangt, sondern
//! aus `gate_id` ueber `owner_of` abgeleitet (gate_registry.yaml `owner`-
//! Feld, 22 Eintraege, unten woertlich uebernommen) - dieselbe Sorte
//! Ratchet-Argument wie bei `OBJECT_COUNT`: eine feste, registerabgeleitete
//! Zuordnung soll nicht von jedem Aufrufer erneut (und potenziell
//! inkonsistent) angegeben werden koennen.
//!
//! Weder `architecture/gate_registry.yaml` (22 PSK-RA-Gates, order/owner/
//! target) noch `constitution/gate_policy.yaml` (9 CPSK-Gates) fuehren
//! `blocking_conditions` als benannte, einzeln auswertbare Praedikate -
//! beide tragen nur Freitext-Voraussetzungen ("Manifest, Digests, Schemas,
//! Register, blocking Obligations"). `eval(cond, inputs)` ist damit nicht
//! aus einem Register ableitbar, sondern liegt bei den Modulen, die die
//! jeweilige Voraussetzung tatsaechlich pruefen koennen (M07 fuer
//! Realitaetsbedingungen, M25 fuer Budget, M11 fuer Seams, ...). Diese
//! Funktion realisiert deshalb die AGGREGATION (die Schleife, die HOLD/
//! FAIL/PASS aus bereits getroffenen Einzelfeststellungen bildet), nicht
//! die Einzelpruefungen selbst - das entspricht demselben Muster wie
//! M09::route_lens (Aufloesung von aussen) und M12::classify_absence
//! (Okklusion von aussen).
//!
//! `M11.seam_report(inputs)` fuer JEDES Gate zweiter Ordnung zu lesen (auch
//! G-SELF-COMPILE, G-RELEASE - inhaltlich ohne M13-Zellbezug) waere eine
//! Ueberdehnung von psk_closure::compare_restrictions (das ausdruecklich
//! ueber M13Address-Zellen arbeitet, Struktur 7.28). Definition 18.2 spricht
//! allgemein von "gemeinsamer Schliessbarkeit ihrer Relationen" - gelesen
//! als: jedes Gate zweiter Ordnung liefert IRGENDEIN SeamReport-foermiges
//! Kompatibilitaetsurteil, nicht zwingend M11s spezifisches. `seam_compatible`
//! ist deshalb ein Parameter, kein interner M11-Aufruf.

use psk_canon::{can, Media};
use psk_trace::{ResidueLedger, SegmentInputs, TraceStore};
use psk_types::objects::{
    EventTypeId, GateId, GateReport, GateReportDecisionKind as Decision, ObligationExpr,
    ReasonCode, ReplayDescriptor, ResidueRecordSeverityKind, ResidueRecordTypeKind, ScopeExpr,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId, PskError, TraceRef};

/// gate_registry.yaml `owner`-Feld, woertlich (22 Gates) - siehe Modulkopf
/// fuer die Begruendung, warum dies hier statt als Aufrufer-Parameter
/// gefuehrt wird.
fn owner_of(gate_id: GateId) -> ModuleId {
    match gate_id {
        GateId::GBoot => ModuleId::AuthorityConsequenceGate,
        GateId::GProfile => ModuleId::AuthorityConsequenceGate,
        GateId::GSchedule => ModuleId::Scheduler,
        GateId::GRealityCoherent => ModuleId::RealityTyper,
        GateId::GLawful => ModuleId::RealityTyper,
        GateId::GReachable => ModuleId::RealityTyper,
        GateId::GConstructible => ModuleId::RealityTyper,
        GateId::GSimulation => ModuleId::AuthorityConsequenceGate,
        GateId::GSelection => ModuleId::AuthorityConsequenceGate,
        GateId::GConsensus => ModuleId::AuthorityConsequenceGate,
        GateId::GClosure => ModuleId::ClosureGlueEngine,
        GateId::GEffect => ModuleId::AuthorityConsequenceGate,
        GateId::GObservation => ModuleId::ExternalRecordIngress,
        GateId::GActualization => ModuleId::ReconciliationEngine,
        GateId::GResidue => ModuleId::TraceReplayResidueStore,
        GateId::GRetraction => ModuleId::TraceReplayResidueStore,
        GateId::GMorph => ModuleId::MorphogenesisController,
        GateId::GExcision => ModuleId::MorphogenesisController,
        GateId::GSelfCompile => ModuleId::CertificateReleaseEngine,
        GateId::GResume => ModuleId::LifecycleSupervisor,
        GateId::GShutdown => ModuleId::LifecycleSupervisor,
        GateId::GRelease => ModuleId::CertificateReleaseEngine,
    }
}

/// Ergebnis der Einzelpruefung EINER blockierenden Bedingung - von aussen
/// bestimmt (siehe Modulkopf), hier nur aggregiert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionOutcome {
    True,
    False(ReasonCode),
    Undecidable(ReasonCode),
}

/// Eingaben fuer `evaluate_gate`. `inputs`/`digests` sind bereits als
/// Digests hereingereicht (`H(Can(i))` je Eingabeobjekt) - eine generische
/// Serialisierung beliebiger Aufrufertypen an dieser Schnittstelle wuerde
/// erzwingen, was das Werk nicht verlangt.
pub struct GateInputs {
    pub gate_id: GateId,
    pub order: u8,
    pub input_digests: Vec<Digest>,
    /// In Pruefreihenfolge - die Reihenfolge bestimmt, welche Bedingung bei
    /// FALSE den Abbruch ausloest (Algorithmus 18.6: "break").
    pub conditions: Vec<ConditionOutcome>,
    /// Nur bei `order == 2` gelesen; Pflicht in diesem Fall (siehe unten).
    pub seam_compatible: Option<bool>,
    pub evidence_refs: Vec<ObjectId>,
    pub seam_report_refs: Vec<ObjectId>,
    pub replay_descriptor: ReplayDescriptor,
    pub decided_at: DualTime,
    pub trace_ref: TraceRef,
}

fn gate_report_sort() -> psk_types::objects::SortId {
    psk_types::objects::SortId::Gate
}

fn compute_identity(draft: &GateReport) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, Media::Json)?;
    psk_canon::object_id(gate_report_sort().id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// H(Can(i)) fuer einen einzelnen Eingang - Hilfsfunktion fuer Aufrufer, die
/// noch keinen Digest haben; `evaluate_gate` selbst nimmt bereits
/// berechnete Digests entgegen (siehe `GateInputs`).
pub fn digest_of(bytes: &[u8], media: Media) -> Result<Digest, PskError> {
    Ok(can(bytes, media)?.digest())
}

/// M14, Algorithmus 18.6: die Aggregationslogik.
///
/// Invariante 18.7 (Gatebericht immer): jede Auswertung liefert genau
/// einen GateReport, unabhaengig von der Entscheidung.
///
/// `trace`/`residues` sind Pflichtparameter, keine Option: Algorithmus
/// 18.6, die Synchronitaetsregel und I-ARCH-006 verlangen `M19.append`
/// unbedingt und `M19.residualize` bei jeder Nicht-PASS-Entscheidung, als
/// Teil DIESER Funktion (siehe Modulkopf).
pub fn evaluate_gate(
    inputs: GateInputs,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<GateReport, PskError> {
    if inputs.order == 2 && inputs.seam_report_refs.is_empty() {
        // Struktur 7.30: "seam_report_refs: [ObjectId] # Pflicht bei order = 2".
        return Err(PskError::UntypedInput);
    }
    if inputs.order == 2 && inputs.seam_compatible.is_none() {
        return Err(PskError::UntypedInput);
    }

    let mut reasons: Vec<ReasonCode> = Vec::new();
    // Axiom 18.3: ohne Bedingungen ueberhaupt (leere Menge) bleibt es bei
    // PASS - "keine Voraussetzung verletzt" ist von "eine fehlt" verschieden;
    // eine gaenzlich fehlende Bedingungsmenge ist Sache des Aufrufers
    // (policy_gate-Zuordnung), nicht dieser Funktion.
    let mut decision = Decision::Pass;
    for outcome in &inputs.conditions {
        match outcome {
            ConditionOutcome::True => continue,
            ConditionOutcome::Undecidable(code) => {
                reasons.push(code.clone());
                decision = Decision::Hold;
            }
            ConditionOutcome::False(code) => {
                reasons.push(code.clone());
                decision = Decision::Fail;
                break;
            }
        }
    }

    // "if gate.order == 2: ... if not seam.compatible: decision = min(decision, HOLD)"
    // - eine PASS-Entscheidung wird auf HOLD zurueckgenommen; eine bereits
    // schlechtere Entscheidung (HOLD/FAIL) bleibt unveraendert.
    if inputs.order == 2 && inputs.seam_compatible == Some(false) && decision == Decision::Pass {
        decision = Decision::Hold;
    }

    let draft = GateReport {
        schema: "psk.gate-report/1.0".to_string(),
        id: ObjectId::new(gate_report_sort(), Digest::sha256(b"")), // Platzhalter
        gate_id: inputs.gate_id,
        order: inputs.order,
        input_digests: inputs.input_digests,
        decision,
        reasons,
        evidence_refs: inputs.evidence_refs,
        residue_refs: Vec::new(),
        seam_report_refs: inputs.seam_report_refs,
        replay_descriptor: inputs.replay_descriptor,
        decided_at: inputs.decided_at,
        trace_ref: inputs.trace_ref,
    };
    let id = compute_identity(&draft)?;
    let report = GateReport { id, ..draft };

    // "M19.append(report) // ueber P33, synchron" - unbedingt, vor jeder
    // Rueckgabe, unabhaengig von `decision`.
    let payload_digest =
        Digest::sha256(&serde_json::to_vec(&report).map_err(|_| PskError::CanonicalizationFailed)?);
    let origin_module = owner_of(report.gate_id);
    trace.append(SegmentInputs {
        event_type: EventTypeId("gate.evaluated".into()),
        module: origin_module,
        port_id: None,
        object_refs: vec![report.id],
        payload_digest,
        time: report.decided_at.clone(),
        attestation: None,
    })?;

    // "if decision != PASS: M19.residualize(report)".
    if report.decision != Decision::Pass {
        let reason_text = report
            .reasons
            .iter()
            .map(|r| r.0.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        residues.open(psk_trace::ResidueInputs {
            r#type: ResidueRecordTypeKind::Type,
            origin_module,
            origin_object: report.id,
            scope: ScopeExpr(report.gate_id.id().to_string()),
            severity: if report.decision == Decision::Fail {
                ResidueRecordSeverityKind::Blocking
            } else {
                ResidueRecordSeverityKind::NonBlocking
            },
            open_obligation: ObligationExpr(format!(
                "resolve {} ({}): {reason_text}",
                report.gate_id.id(),
                match report.decision {
                    Decision::Hold => "HOLD",
                    Decision::Fail => "FAIL",
                    Decision::Pass => unreachable!("PASS bereits oben ausgeschlossen"),
                }
            )),
            allowed_followups: Vec::new(),
            opened_at: report.decided_at.clone(),
        })?;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::SortId;

    fn base_inputs(order: u8, conditions: Vec<ConditionOutcome>) -> GateInputs {
        GateInputs {
            gate_id: GateId::GEffect,
            order,
            input_digests: vec![Digest::sha256(b"in")],
            conditions,
            seam_compatible: if order == 2 { Some(true) } else { None },
            evidence_refs: vec![],
            seam_report_refs: if order == 2 {
                vec![ObjectId::new(SortId::Trace, Digest::sha256(b"seam"))]
            } else {
                vec![]
            },
            replay_descriptor: psk_types::objects::ReplayDescriptor("replay/1".into()),
            decided_at: DualTime {
                tau_i: 0,
                tau_e: "2026-08-04T00:00:00.000000000Z".into(),
                clock_ref: psk_types::ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        }
    }

    fn stores() -> (TraceStore, ResidueLedger) {
        (TraceStore::new(), ResidueLedger::new())
    }

    #[test]
    fn no_conditions_pass() {
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(base_inputs(1, vec![]), &mut trace, &mut residues).unwrap();
        assert_eq!(report.decision, Decision::Pass);
        assert!(report.reasons.is_empty());
    }

    #[test]
    fn all_true_conditions_pass() {
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(
            base_inputs(1, vec![ConditionOutcome::True, ConditionOutcome::True]),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(report.decision, Decision::Pass);
    }

    #[test]
    fn undecidable_holds_never_passes() {
        // Definition 18.1: "Unentscheidbarkeit liefert HOLD, niemals PASS."
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(
            base_inputs(
                1,
                vec![ConditionOutcome::Undecidable(ReasonCode("R-1".into()))],
            ),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(report.decision, Decision::Hold);
        assert_eq!(report.reasons, vec![ReasonCode("R-1".into())]);
    }

    #[test]
    fn false_condition_fails_and_stops_immediately() {
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(
            base_inputs(
                1,
                vec![
                    ConditionOutcome::Undecidable(ReasonCode("R-1".into())),
                    ConditionOutcome::False(ReasonCode("R-2".into())),
                    ConditionOutcome::True, // wird wegen `break` nie erreicht
                ],
            ),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(report.decision, Decision::Fail);
        // Beide vorherigen Gruende bleiben erhalten (Axiom 7.41-artig: nichts
        // verschwindet stillschweigend), aber es geht nicht weiter danach.
        assert_eq!(
            report.reasons,
            vec![ReasonCode("R-1".into()), ReasonCode("R-2".into())]
        );
    }

    #[test]
    fn false_always_wins_over_a_later_true() {
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(
            base_inputs(1, vec![ConditionOutcome::False(ReasonCode("R-1".into()))]),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(report.decision, Decision::Fail);
    }

    #[test]
    fn second_order_incompatible_seam_downgrades_pass_to_hold() {
        let (mut trace, mut residues) = stores();
        let mut inputs = base_inputs(2, vec![ConditionOutcome::True]);
        inputs.seam_compatible = Some(false);
        let report = evaluate_gate(inputs, &mut trace, &mut residues).unwrap();
        assert_eq!(report.decision, Decision::Hold);
    }

    #[test]
    fn second_order_incompatible_seam_does_not_upgrade_an_existing_fail() {
        let (mut trace, mut residues) = stores();
        let mut inputs = base_inputs(2, vec![ConditionOutcome::False(ReasonCode("R-1".into()))]);
        inputs.seam_compatible = Some(false);
        let report = evaluate_gate(inputs, &mut trace, &mut residues).unwrap();
        assert_eq!(
            report.decision,
            Decision::Fail,
            "min(FAIL, HOLD) darf FAIL nicht zu HOLD verbessern"
        );
    }

    #[test]
    fn second_order_gate_requires_seam_report_refs() {
        let (mut trace, mut residues) = stores();
        let mut inputs = base_inputs(2, vec![]);
        inputs.seam_report_refs.clear();
        assert_eq!(
            evaluate_gate(inputs, &mut trace, &mut residues),
            Err(PskError::UntypedInput)
        );
    }

    #[test]
    fn second_order_gate_requires_a_seam_compatibility_verdict() {
        let (mut trace, mut residues) = stores();
        let mut inputs = base_inputs(2, vec![]);
        inputs.seam_compatible = None;
        assert_eq!(
            evaluate_gate(inputs, &mut trace, &mut residues),
            Err(PskError::UntypedInput)
        );
    }

    #[test]
    fn every_evaluation_yields_exactly_one_report_regardless_of_decision() {
        // Invariante 18.7.
        for outcome in [
            ConditionOutcome::True,
            ConditionOutcome::False(ReasonCode("x".into())),
            ConditionOutcome::Undecidable(ReasonCode("x".into())),
        ] {
            let (mut trace, mut residues) = stores();
            let report = evaluate_gate(base_inputs(1, vec![outcome]), &mut trace, &mut residues);
            assert!(report.is_ok());
        }
    }

    #[test]
    fn evaluation_is_deterministic() {
        let (mut trace_a, mut residues_a) = stores();
        let (mut trace_b, mut residues_b) = stores();
        let a = evaluate_gate(
            base_inputs(1, vec![ConditionOutcome::True]),
            &mut trace_a,
            &mut residues_a,
        )
        .unwrap();
        let b = evaluate_gate(
            base_inputs(1, vec![ConditionOutcome::True]),
            &mut trace_b,
            &mut residues_b,
        )
        .unwrap();
        assert_eq!(a.id, b.id);
    }

    // ---- Neu: Algorithmus 18.6s M19.append/M19.residualize (T-RES-001) ----

    #[test]
    fn every_evaluation_appends_to_trace_regardless_of_decision() {
        // Algorithmus 18.6: "M19.append(report) // ueber P33, synchron" -
        // unbedingt, nicht nur bei Nicht-PASS.
        for outcome in [
            ConditionOutcome::True,
            ConditionOutcome::False(ReasonCode("x".into())),
            ConditionOutcome::Undecidable(ReasonCode("x".into())),
        ] {
            let (mut trace, mut residues) = stores();
            assert_eq!(trace.segments().len(), 0);
            let report =
                evaluate_gate(base_inputs(1, vec![outcome]), &mut trace, &mut residues).unwrap();
            assert_eq!(trace.segments().len(), 1);
            assert_eq!(trace.segments()[0].object_refs, vec![report.id]);
        }
    }

    #[test]
    fn non_pass_decisions_residualize() {
        // Algorithmus 18.6: "if decision != PASS: M19.residualize(report)".
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(
            base_inputs(
                1,
                vec![ConditionOutcome::Undecidable(ReasonCode("R-1".into()))],
            ),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(report.decision, Decision::Hold);
        assert_eq!(residues.all().len(), 1);
        assert_eq!(residues.all()[0].origin_object, report.id);
        assert_eq!(
            residues.all()[0].severity,
            psk_types::objects::ResidueRecordSeverityKind::NonBlocking
        );

        let (mut trace2, mut residues2) = stores();
        let fail_report = evaluate_gate(
            base_inputs(1, vec![ConditionOutcome::False(ReasonCode("R-2".into()))]),
            &mut trace2,
            &mut residues2,
        )
        .unwrap();
        assert_eq!(fail_report.decision, Decision::Fail);
        assert_eq!(residues2.all().len(), 1);
        assert_eq!(
            residues2.all()[0].severity,
            psk_types::objects::ResidueRecordSeverityKind::Blocking
        );
    }

    #[test]
    fn pass_decisions_do_not_residualize() {
        let (mut trace, mut residues) = stores();
        let report = evaluate_gate(base_inputs(1, vec![]), &mut trace, &mut residues).unwrap();
        assert_eq!(report.decision, Decision::Pass);
        assert!(residues.all().is_empty());
    }

    #[test]
    fn residue_origin_module_is_derived_from_the_gates_registered_owner() {
        // gate_registry.yaml: G-EFFECT -> M14.
        let (mut trace, mut residues) = stores();
        evaluate_gate(
            base_inputs(
                1,
                vec![ConditionOutcome::Undecidable(ReasonCode("R-1".into()))],
            ),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(
            residues.all()[0].origin_module,
            ModuleId::AuthorityConsequenceGate
        );
        assert_eq!(
            trace.segments()[0].module,
            ModuleId::AuthorityConsequenceGate
        );
    }
}
