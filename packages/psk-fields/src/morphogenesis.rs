//! M20 MorphogenesisController (Kapitel 12.5, Struktur 7.49).
//!
//! Anders als M14/M15 (wo M14 das Gate besitzt und M15 nur das Ergebnis
//! entgegennimmt) besitzt M20 G-MORPH UND G-EXCISION selbst
//! (`architecture/gate_registry.yaml`: beide `owner: M20`). Die
//! Auswertungslogik (Algorithmus 18.6) ist trotzdem dieselbe generische
//! Funktion wie bei M14 - `psk_gate::evaluate_gate` ist an keine
//! bestimmte Modul-Ownership gebunden (siehe die entsprechende Korrektur
//! im Kopfkommentar von `psk_types::automata::StepOutcome`). M20
//! importiert sie direkt, statt eine zweite Kopie der Aggregationslogik
//! zu schreiben.
//!
//! Vertrag 3.4 (Ownership-Exklusivitaet) bleibt gewahrt: M20 wertet das
//! Gate aus, aber nur M08 (`registry::complete_transition`) konstruiert
//! das neue FieldIdentity-Objekt. `decide_transition` ruft deshalb in
//! dasselbe Modul zurueck, statt die Konstruktion hier zu duplizieren.

use psk_gate::{evaluate_gate, ConditionOutcome, GateInputs};
use psk_trace::{ResidueLedger, TraceStore};
use psk_types::objects::{
    ExcisionCertificate, ExcisionCertificateIdentityEffectKind, FieldIdentity, GateId, GateReport,
    MapExpr, ReplayDescriptor, ScopeExpr,
};
use psk_types::{Digest, DualTime, ObjectId, PskError, TraceRef};

use crate::registry::{advance, complete_transition, LifecycleStep};

/// Ergebnis eines Morphogeneseversuchs: entweder das neue FieldIdentity
/// (Gate bestanden) oder der Bericht, der HOLD/FAIL begruendet.
/// `Ungegated` faengt den Fall ab, dass `operator` gar kein Gate verlangt
/// (quiesce/retire) - dafuer ist M20 nicht zustaendig, das ist reines M08
/// (`registry::advance`).
#[derive(Debug, Clone, PartialEq)]
pub enum MorphogenesisOutcome {
    Transitioned(Box<FieldIdentity>),
    Held(Box<GateReport>),
    Ungated,
}

fn gate_id_of(gate_name: &str) -> Result<GateId, PskError> {
    GateId::from_id(gate_name.trim_start_matches('"')).ok_or(PskError::MorphogenesisViolation)
}

/// order laut gate_registry.yaml: G-MORPH = 1, G-EXCISION = 2.
fn order_of(gate_id: GateId) -> u8 {
    match gate_id {
        GateId::GExcision => 2,
        _ => 1,
    }
}

/// Eingaben fuer einen Morphogeneseversuch. `conditions` sind die
/// Einzelfeststellungen zu den in `activation_requirements`
/// (constitution/state_machines.yaml#field) genannten Voraussetzungen -
/// `psk_fields::check_activation_requirements` liefert die strukturell
/// pruefbaren davon (M08 kennt sein eigenes Objekt), M20 wertet nur noch
/// aus. Bei `order == 2` (G-EXCISION) ist `seam_compatible` Pflicht -
/// siehe `psk_gate::evaluate_gate`.
pub struct MorphInputs {
    pub operator: &'static str,
    pub conditions: Vec<ConditionOutcome>,
    pub seam_compatible: Option<bool>,
    pub seam_report_refs: Vec<ObjectId>,
    pub input_digests: Vec<Digest>,
    pub evidence_refs: Vec<ObjectId>,
    pub replay_descriptor: ReplayDescriptor,
    pub decided_at: DualTime,
    pub trace_ref: TraceRef,
}

/// M20: versucht `inputs.operator` auf `field` anzuwenden. Ruft zuerst
/// FSM-FIELD (`registry::advance`) fuer die strukturelle Zulaessigkeit -
/// bei einer ungegateten Kante (quiesce/retire) liefert das bereits ein
/// fertiges Ergebnis, ohne dass M20 ueberhaupt ein Gate braucht.
pub fn decide_transition(
    field: &FieldIdentity,
    inputs: MorphInputs,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<MorphogenesisOutcome, PskError> {
    let step = advance(field, inputs.operator, &[])?;
    let (to, gate_name) = match step {
        LifecycleStep::Allowed(_) => return Ok(MorphogenesisOutcome::Ungated),
        LifecycleStep::RequiresGate { to, gate } => (to, gate),
    };

    let gate_id = gate_id_of(gate_name)?;
    let order = order_of(gate_id);
    let report = evaluate_gate(
        GateInputs {
            gate_id,
            order,
            input_digests: inputs.input_digests,
            conditions: inputs.conditions,
            seam_compatible: inputs.seam_compatible,
            evidence_refs: inputs.evidence_refs,
            seam_report_refs: inputs.seam_report_refs,
            replay_descriptor: inputs.replay_descriptor,
            decided_at: inputs.decided_at,
            trace_ref: inputs.trace_ref,
        },
        trace,
        residues,
    )?;

    if report.decision == psk_types::objects::GateReportDecisionKind::Pass {
        let new_field = complete_transition(field, to)?;
        Ok(MorphogenesisOutcome::Transitioned(Box::new(new_field)))
    } else {
        Ok(MorphogenesisOutcome::Held(Box::new(report)))
    }
}

/// Eingaben fuer eine Exzision, die WAS bereits feststehen muss (Region,
/// Grenze, Neuroutung, erhaltene Invarianten, Differenz, betroffene
/// Residuen) - M20 erfindet keinen dieser Inhalte, es stellt nur fest,
/// ob G-EXCISION dafuer besteht.
pub struct ExcisionInputs {
    pub region: Vec<ObjectId>,
    pub boundary: ScopeExpr,
    pub reconnect_projection: MapExpr,
    pub preservation_witness: Vec<ObjectId>,
    pub difference: psk_types::objects::DiffTree,
    pub residues: Vec<ObjectId>,
    pub identity_effect: ExcisionCertificateIdentityEffectKind,
    /// Pflicht bei `identity_effect == DeclaredSuccessor` (Struktur 7.49).
    pub successor_id: Option<Digest>,
    pub trace_ref: TraceRef,
}

fn excision_sort() -> psk_types::objects::SortId {
    psk_types::objects::SortId::Branch
}

fn compute_excision_identity(draft: &ExcisionCertificate) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?;
    psk_canon::object_id(excision_sort().id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// Struktur 7.49: "successor_id ... Pflicht bei DECLARED_SUCCESSOR."
fn check_successor_id(inputs: &ExcisionInputs) -> Result<(), PskError> {
    let declared_without_successor = inputs.identity_effect
        == ExcisionCertificateIdentityEffectKind::DeclaredSuccessor
        && inputs.successor_id.is_none();
    if declared_without_successor {
        Err(PskError::UntypedInput)
    } else {
        Ok(())
    }
}

/// M20: stellt fest, ob G-EXCISION fuer `field` besteht, und konstruiert
/// bei PASS das ExcisionCertificate. `field` selbst wird nicht
/// zurueckgegeben - Exzision ist eine Kantenbeschraenkung des Automaten
/// ("*", to: EXCISED), keine gewoehnliche Transition, die M08 fortfuehrt;
/// die Fortsetzung als neues FieldIdentity mit `lifecycle: EXCISED` folgt
/// bei Bedarf ueber `decide_transition(field, { operator: "excise", ...})`
/// separat.
pub fn decide_excision(
    field: &FieldIdentity,
    excision: ExcisionInputs,
    gate_inputs: MorphInputs,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<Option<ExcisionCertificate>, PskError> {
    check_successor_id(&excision)?;

    let outcome = decide_transition(field, gate_inputs, trace, residues)?;
    match outcome {
        MorphogenesisOutcome::Transitioned(_) => {
            let draft = ExcisionCertificate {
                schema: "psk.excision/1.0".to_string(),
                id: ObjectId::new(excision_sort(), Digest::sha256(b"")), // Platzhalter
                region: excision.region,
                boundary: excision.boundary,
                reconnect_projection: excision.reconnect_projection,
                preservation_witness: excision.preservation_witness,
                difference: excision.difference,
                residues: excision.residues,
                identity_effect: excision.identity_effect,
                successor_id: excision.successor_id,
                trace_ref: excision.trace_ref,
            };
            let id = compute_excision_identity(&draft)?;
            Ok(Some(ExcisionCertificate { id, ..draft }))
        }
        MorphogenesisOutcome::Held(_) | MorphogenesisOutcome::Ungated => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{register_field, FieldRegistrationInputs};
    use psk_types::objects::{
        ArchetypeId, BoundarySpec, BudgetSpec, DomainExpr, FieldIdentityLifecycleKind, LensSpec,
        Lineage, OpId, QuestionSpec, ReasonCode, RollbackSpec, SortId, TimeWindow, WitnessPolicy,
    };

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-04T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_field() -> FieldIdentity {
        register_field(
            ArchetypeId::Explorer,
            FieldRegistrationInputs {
                domain: DomainExpr("lokaler Projektordner".into()),
                lens: LensSpec("explorer-lens/1".into()),
                operators: vec![OpId::Project],
                questions: vec![QuestionSpec("wo sind Kandidaten?".into())],
                witness_rules: WitnessPolicy("mind. 1 Zeuge".into()),
                boundaries: BoundarySpec("read-only".into()),
                gates: vec![GateId::GMorph],
                time_window: TimeWindow("PT1H".into()),
                lineage: Lineage("root".into()),
                dependency_profile_ref: ObjectId::new(SortId::Dependency, Digest::sha256(b"dep")),
                budget: BudgetSpec("10 Einheiten".into()),
                rollback: RollbackSpec("Snapshot vorher".into()),
                system_identity: Digest::sha256(b"system-identity-not-a-field"),
            },
        )
        .unwrap()
    }

    fn stores() -> (TraceStore, ResidueLedger) {
        (TraceStore::new(), ResidueLedger::new())
    }

    fn morph_inputs(conditions: Vec<ConditionOutcome>, operator: &'static str) -> MorphInputs {
        // "excise" ist die einzige Kante zu G-EXCISION (order 2) - order-2-
        // Gates verlangen laut psk_gate::evaluate_gate zwingend
        // seam_compatible und mindestens eine seam_report_refs-Referenz.
        let is_order_two = operator == "excise";
        MorphInputs {
            operator,
            conditions,
            seam_compatible: is_order_two.then_some(true),
            seam_report_refs: if is_order_two {
                vec![ObjectId::new(SortId::Trace, Digest::sha256(b"seam"))]
            } else {
                vec![]
            },
            input_digests: vec![Digest::sha256(b"in")],
            evidence_refs: vec![],
            replay_descriptor: ReplayDescriptor("replay/1".into()),
            decided_at: sample_time(),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        }
    }

    #[test]
    fn ungated_operator_is_reported_as_such_not_evaluated() {
        let proposed = sample_field();
        let active = FieldIdentity {
            lifecycle: FieldIdentityLifecycleKind::Active,
            ..proposed
        };
        let (mut trace, mut residues) = stores();
        let outcome = decide_transition(
            &active,
            morph_inputs(vec![], "quiesce"),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(outcome, MorphogenesisOutcome::Ungated);
    }

    #[test]
    fn all_conditions_true_passes_g_morph_and_transitions() {
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let outcome = decide_transition(
            &field,
            morph_inputs(vec![ConditionOutcome::True], "activate"),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        match outcome {
            MorphogenesisOutcome::Transitioned(f) => {
                assert_eq!(f.lifecycle, FieldIdentityLifecycleKind::Active);
                assert_ne!(f.id, field.id, "Lebenszyklus ist Teil von Can()");
            }
            other => panic!("erwartet Transitioned, bekam {other:?}"),
        }
    }

    #[test]
    fn a_false_condition_holds_the_field_at_its_current_state() {
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let outcome = decide_transition(
            &field,
            morph_inputs(
                vec![ConditionOutcome::False(ReasonCode("no-gain".into()))],
                "activate",
            ),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        match outcome {
            MorphogenesisOutcome::Held(report) => {
                assert_eq!(
                    report.decision,
                    psk_types::objects::GateReportDecisionKind::Fail
                );
                assert_eq!(report.gate_id, GateId::GMorph);
            }
            other => panic!("erwartet Held, bekam {other:?}"),
        }
        // T-RES-001: eine FAIL-Entscheidung muss residualisiert sein.
        assert_eq!(residues.all().len(), 1);
    }

    #[test]
    fn excise_uses_g_excision_not_g_morph() {
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let outcome = decide_transition(
            &field,
            morph_inputs(vec![ConditionOutcome::True], "excise"),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        match outcome {
            MorphogenesisOutcome::Transitioned(f) => {
                assert_eq!(f.lifecycle, FieldIdentityLifecycleKind::Excised);
            }
            other => panic!("erwartet Transitioned, bekam {other:?}"),
        }
    }

    fn sample_excision_inputs(
        identity_effect: ExcisionCertificateIdentityEffectKind,
        successor_id: Option<Digest>,
    ) -> ExcisionInputs {
        ExcisionInputs {
            region: vec![ObjectId::new(
                SortId::FieldIdentity,
                Digest::sha256(b"region"),
            )],
            boundary: ScopeExpr("excised-scope".into()),
            reconnect_projection: MapExpr("identity".into()),
            preservation_witness: vec![],
            difference: psk_types::objects::DiffTree("removed field".into()),
            residues: vec![],
            identity_effect,
            successor_id,
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        }
    }

    #[test]
    fn excision_certificate_is_constructed_on_pass() {
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let cert = decide_excision(
            &field,
            sample_excision_inputs(ExcisionCertificateIdentityEffectKind::Unchanged, None),
            morph_inputs(vec![ConditionOutcome::True], "excise"),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert!(cert.is_some());
    }

    #[test]
    fn excision_certificate_is_absent_on_hold() {
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let cert = decide_excision(
            &field,
            sample_excision_inputs(ExcisionCertificateIdentityEffectKind::Unchanged, None),
            morph_inputs(
                vec![ConditionOutcome::Undecidable(ReasonCode("pending".into()))],
                "excise",
            ),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert!(cert.is_none());
    }

    #[test]
    fn declared_successor_without_successor_id_is_rejected() {
        // Struktur 7.49: successor_id ist Pflicht bei DECLARED_SUCCESSOR.
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let result = decide_excision(
            &field,
            sample_excision_inputs(
                ExcisionCertificateIdentityEffectKind::DeclaredSuccessor,
                None,
            ),
            morph_inputs(vec![ConditionOutcome::True], "excise"),
            &mut trace,
            &mut residues,
        );
        assert_eq!(result, Err(PskError::UntypedInput));
    }

    #[test]
    fn declared_successor_with_successor_id_is_accepted() {
        let field = sample_field();
        let (mut trace, mut residues) = stores();
        let cert = decide_excision(
            &field,
            sample_excision_inputs(
                ExcisionCertificateIdentityEffectKind::DeclaredSuccessor,
                Some(Digest::sha256(b"successor")),
            ),
            morph_inputs(vec![ConditionOutcome::True], "excise"),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert!(cert.is_some());
    }
}
