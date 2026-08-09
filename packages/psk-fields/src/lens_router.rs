//! M09 SpectralLensRouter: wendet die Spektrallinse Pi_lambda einer aktiven
//! FieldIdentity auf ein Urbild an und erzeugt entweder genau eine
//! FieldProjection (Struktur 7.14, OBJ-PRJ) oder - wenn die Linse nicht
//! anwendbar ist - einen ResidueRecord des Typs `scope` plus PSK-E013
//! (Regel 7.16, Vertrag C5).
//!
//! `LensSpec` hat im Kern keine Grammatik, und das ist seit v1.0.7
//! ausdruecklich entschieden statt offen: Vertrag 27.2 (Domaenengelieferte
//! opake Eingaben) fuehrt LensSpec, PredicateExpr und RealityEvidence als
//! die drei Typen, die "im Kern absichtlich ohne Grammatik" sind - "der
//! Kern entscheidet, dass eine Linse aufloest, nicht wie". Sie kommen ueber
//! DomainProfile oder MethodPlugin und werden hier nur typisiert
//! weitergereicht; sie sind "keine offenen Implementierungsverpflichtungen
//! im Sinne von OBL-001-OBL-007", weshalb Invariante 33.8 unberuehrt
//! bleibt. Deshalb nimmt diese Funktion die Aufloesung als Eingabe
//! (`ProjectionInputs::resolved`) entgegen, statt sie zu berechnen.
//!
//! Die drei Pflichten aus Vertrag 27.2 greifen hier so: Reinheit und
//! Determinismusdeklaration liegen beim liefernden Plug-in (Pflicht 1 und
//! 2, Verstoss = PSK-E015); Pflicht 3 ("Ein fehlendes oder nicht
//! anwendbares Plug-in erzeugt UNKNOWN beziehungsweise ein Residuum, DARF
//! NICHT eine Vorgabewahl") ist genau der Fall der leeren Aufloesung und
//! wird hier als ResidueRecord(scope) erfuellt, nicht als stillschweigende
//! Vorgabe.
//!
//! Was diese Funktion beitraegt, ist der Teil, den das Werk bindend macht:
//! die Alles-oder-Ausschuss-Entscheidung (Regel 7.16, ein `visible` DARF
//! NICHT leer sein) und die vollstaendige, nie-lueckenhafte Fuehrung von
//! `occluded` (Regel 7.17) - `occluded` wird aus der Kandidatenmenge MINUS
//! der Aufloesung berechnet, nie vom Aufrufer entgegengenommen, damit ein
//! stillschweigendes Auslassen strukturell unmoeglich ist.
//!
//! ResidueRecord gehoert laut object_registry.yaml exklusiv M19
//! (TraceReplayResidueStore), nicht M09 - dieselbe Form wie schon bei
//! RealityClassification/M07 (psk-thought) und ExternalRecord/M17
//! (psk-anchor): die Regel, die M09 zum Erzeugen verpflichtet (Regel
//! 7.16), und die Ownership-Tabelle, die M19 als Sorten-Eigner fuehrt
//! (S-RES), widersprechen sich nicht - M09 konstruiert den Wert als
//! unmittelbare Antwort auf die nicht anwendbare Linse, M19 ist das
//! dauerhafte Ledger, in dem er lebt (lifetime L-PERSIST, memory
//! residual). Ein Port von M09 nach M19 fuer ResidueRecord ist nicht
//! Teil von WP07 (M08/M09) und wird hier nicht behauptet.

use psk_canon::{identity_projection, object_id, record_digest, Media};
use psk_types::objects::{
    DistinctionSpec, FieldIdentity, FieldProjection, IRNodeId, ObligationExpr, RealityStatus,
    ResidueRecord, ResidueRecordSeverityKind, ResidueRecordStateKind, ResidueRecordTypeKind,
    ScopeExpr, ScopeSpec, SortId, SourceRef, TickId,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId, PskError};
use std::collections::BTreeSet;

/// Eingaben fuer einen Routingversuch. `candidates` ist die
/// Sortenmenge/Knotenmenge des Urbildes, auf die die Linse ueberhaupt
/// angewandt wird; `resolved` ist die Teilmenge, die sie tatsaechlich
/// aufloest (domaenenspezifisch bestimmt, siehe Modulkopf). `opened_at`
/// wird nur im ResidueRecord-Zweig gebraucht.
pub struct ProjectionInputs {
    pub source_refs: Vec<ObjectId>,
    pub candidates: Vec<IRNodeId>,
    pub resolved: Vec<IRNodeId>,
    pub distinctions: Vec<DistinctionSpec>,
    pub source_provenance: Vec<SourceRef>,
    pub reality_view: RealityStatus,
    pub scope: ScopeSpec,
    pub tick: TickId,
    pub opened_at: DualTime,
}

/// Ergebnis von `route_lens`: entweder die verlangte FieldProjection
/// (Regel 7.16: nie mit leerem `visible`), oder - wenn die Linse nicht
/// anwendbar ist - der laut Vertrag C5 verlangte ResidueRecord.
#[derive(Debug, Clone, PartialEq)]
pub enum LensOutcome {
    Projected(FieldProjection),
    NotApplicable(ResidueRecord),
}

fn compute_object_id(
    bytes_without_id: &[u8],
    sort: SortId,
) -> Result<(ObjectId, Digest), PskError> {
    let projected = identity_projection(bytes_without_id, Media::Json)?;
    let oid: ObjectId = object_id(sort.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok((oid, record_digest(bytes_without_id, Media::Json)?))
}

fn strip_id(value: &impl serde::Serialize) -> Result<Vec<u8>, PskError> {
    let mut json = serde_json::to_value(value).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = json
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("id");
    serde_json::to_vec(&json).map_err(|_| PskError::CanonicalizationFailed)
}

/// M09: klassifiziert `inputs.candidates` anhand von `inputs.resolved` in
/// `visible`/`occluded` (Reihenfolge = Reihenfolge in `candidates`, damit
/// deterministisch) und liefert entweder eine FieldProjection oder - falls
/// `visible` leer bliebe - einen ResidueRecord(scope) (Regel 7.16).
///
/// `field` MUSS aktiv sein, um ueberhaupt projiziert zu werden (Vertrag
/// C5: "Fuer jede aktive FieldIdentity"); diese Funktion prueft das nicht
/// selbst, weil "aktiv" ein Laufzeitzustand der Pass-Iteration ist
/// (welche FieldIdentities gerade als aktiv gelten), nicht ein aus der
/// Struktur ableitbares Praedikat, das M09 kennen muesste.
pub fn route_lens(
    field: &FieldIdentity,
    inputs: ProjectionInputs,
) -> Result<LensOutcome, PskError> {
    let resolved: BTreeSet<&IRNodeId> = inputs.resolved.iter().collect();
    let mut visible = Vec::new();
    let mut occluded = Vec::new();
    for candidate in &inputs.candidates {
        if resolved.contains(candidate) {
            visible.push(candidate.clone());
        } else {
            occluded.push(candidate.clone());
        }
    }

    if visible.is_empty() {
        return build_residue(field, inputs, occluded).map(LensOutcome::NotApplicable);
    }

    let draft = FieldProjection {
        schema: "psk.field-projection/1.0".to_string(),
        id: ObjectId::new(SortId::Projection, Digest::sha256(b"")), // Platzhalter
        field_ref: field.id,
        source_refs: inputs.source_refs,
        lens_ref: field.lens.clone(),
        scope: inputs.scope,
        visible,
        occluded,
        distinctions: inputs.distinctions,
        source_provenance: inputs.source_provenance,
        reality_view: inputs.reality_view,
        tick: inputs.tick,
    };

    let bytes = strip_id(&draft)?;
    let (id, _record) = compute_object_id(&bytes, SortId::Projection)?;
    Ok(LensOutcome::Projected(FieldProjection { id, ..draft }))
}

/// Regel 7.16 / Vertrag C5: der ResidueRecord, der an die Stelle einer
/// nicht entstehenden FieldProjection tritt. `occluded` ist zu diesem
/// Zeitpunkt bereits die volle Kandidatenmenge (kein Element wurde
/// aufgeloest) - sie fliesst nicht in ResidueRecord ein (dessen Struktur
/// 7.38 kein `occluded`-Feld kennt), belegt hier aber, dass der Aufrufer
/// tatsaechlich nichts verschwiegen hat.
fn build_residue(
    field: &FieldIdentity,
    inputs: ProjectionInputs,
    occluded: Vec<IRNodeId>,
) -> Result<ResidueRecord, PskError> {
    debug_assert_eq!(
        occluded.len(),
        inputs.candidates.len(),
        "bei leerem visible muss occluded == candidates sein"
    );
    let draft = ResidueRecord {
        schema: "psk.residue/1.0".to_string(),
        id: ObjectId::new(SortId::Residue, Digest::sha256(b"")), // Platzhalter
        r#type: ResidueRecordTypeKind::Scope,
        origin_module: ModuleId::SpectralLensRouter,
        origin_object: field.id,
        scope: ScopeExpr(inputs.scope.0),
        severity: ResidueRecordSeverityKind::NonBlocking,
        open_obligation: ObligationExpr(format!(
            "PSK-E013: Linse {} (Feld {}) ist auf die vorliegende Kandidatenmenge nicht anwendbar",
            field.lens.0, field.id
        )),
        allowed_followups: Vec::new(),
        opened_at: inputs.opened_at,
        closed_by: None,
        state: ResidueRecordStateKind::Open,
    };

    let bytes = strip_id(&draft)?;
    let (id, _record) = compute_object_id(&bytes, SortId::Residue)?;
    Ok(ResidueRecord { id, ..draft })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{register_field, FieldRegistrationInputs};
    use psk_types::objects::{
        ArchetypeId, BoundarySpec, BudgetSpec, DomainExpr, GateId, LensSpec, Lineage, OpId,
        QuestionSpec, RollbackSpec, TimeWindow, WitnessPolicy,
    };
    use psk_types::ClockRef;

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

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 1,
            tau_e: "2026-08-04T00:00:00.000000000Z".into(),
            clock_ref: ClockRef("test-clock".into()),
            uncertainty_ns: 0,
        }
    }

    fn base_inputs(candidates: Vec<&str>, resolved: Vec<&str>) -> ProjectionInputs {
        ProjectionInputs {
            source_refs: vec![ObjectId::new(SortId::Context, Digest::sha256(b"thought"))],
            candidates: candidates.into_iter().map(|s| IRNodeId(s.into())).collect(),
            resolved: resolved.into_iter().map(|s| IRNodeId(s.into())).collect(),
            distinctions: Vec::new(),
            source_provenance: Vec::new(),
            reality_view: RealityStatus::Unknown,
            scope: ScopeSpec("candidate-scan".into()),
            tick: TickId("tick-1".into()),
            opened_at: sample_time(),
        }
    }

    #[test]
    fn resolved_nodes_become_visible_rest_becomes_occluded() {
        let field = sample_field();
        let inputs = base_inputs(vec!["n1", "n2", "n3"], vec!["n2"]);
        let outcome = route_lens(&field, inputs).unwrap();
        match outcome {
            LensOutcome::Projected(proj) => {
                assert_eq!(proj.visible, vec![IRNodeId("n2".into())]);
                assert_eq!(
                    proj.occluded,
                    vec![IRNodeId("n1".into()), IRNodeId("n3".into())]
                );
                assert_eq!(proj.field_ref, field.id);
            }
            other => panic!("erwartet Projected, bekam {other:?}"),
        }
    }

    #[test]
    fn empty_resolution_yields_scope_residue_not_empty_projection() {
        // Regel 7.16: "Eine FieldProjection mit leerem visible ist
        // unzulaessig: Es gibt keine leere Projektion, sondern nur eine
        // ausgebliebene."
        let field = sample_field();
        let inputs = base_inputs(vec!["n1", "n2"], vec![]);
        let outcome = route_lens(&field, inputs).unwrap();
        match outcome {
            LensOutcome::NotApplicable(residue) => {
                assert_eq!(residue.r#type, ResidueRecordTypeKind::Scope);
                assert_eq!(residue.origin_module, ModuleId::SpectralLensRouter);
                assert_eq!(residue.origin_object, field.id);
                assert_eq!(residue.severity, ResidueRecordSeverityKind::NonBlocking);
                assert_eq!(residue.state, ResidueRecordStateKind::Open);
            }
            other => panic!("erwartet NotApplicable, bekam {other:?}"),
        }
    }

    #[test]
    fn no_candidates_at_all_also_yields_residue() {
        let field = sample_field();
        let inputs = base_inputs(vec![], vec![]);
        assert!(matches!(
            route_lens(&field, inputs).unwrap(),
            LensOutcome::NotApplicable(_)
        ));
    }

    #[test]
    fn occluded_is_never_silently_dropped() {
        // Regel 7.17: "occluded MUSS vollstaendig gefuehrt werden." occluded
        // wird hier aus candidates \ resolved berechnet, nicht vom
        // Aufrufer uebernommen - ein zu klein geratenes occluded ist
        // strukturell unmoeglich.
        let field = sample_field();
        let inputs = base_inputs(vec!["n1", "n2", "n3", "n4"], vec!["n1", "n4"]);
        match route_lens(&field, inputs).unwrap() {
            LensOutcome::Projected(proj) => {
                assert_eq!(proj.visible.len() + proj.occluded.len(), 4);
                assert_eq!(
                    proj.occluded,
                    vec![IRNodeId("n2".into()), IRNodeId("n3".into())]
                );
            }
            other => panic!("erwartet Projected, bekam {other:?}"),
        }
    }

    #[test]
    fn reality_view_is_a_copy_never_a_promotion() {
        // Regel 7.15: reality_status/facticity des Urbildes DARF NICHT
        // durch eine Projektion veraendert werden - reality_view ist eine
        // vom Aufrufer bereitgestellte Sicht, keine hier berechnete.
        let field = sample_field();
        let mut inputs = base_inputs(vec!["n1"], vec!["n1"]);
        inputs.reality_view = RealityStatus::Lawful;
        match route_lens(&field, inputs).unwrap() {
            LensOutcome::Projected(proj) => assert_eq!(proj.reality_view, RealityStatus::Lawful),
            other => panic!("erwartet Projected, bekam {other:?}"),
        }
    }

    #[test]
    fn routing_is_deterministic() {
        let field = sample_field();
        let a = route_lens(&field, base_inputs(vec!["n1", "n2"], vec!["n1"])).unwrap();
        let b = route_lens(&field, base_inputs(vec!["n1", "n2"], vec!["n1"])).unwrap();
        assert_eq!(a, b);
    }
}
