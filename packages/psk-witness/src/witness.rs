//! M12 WitnessEngine (Kapitel 21.1).
//!
//! Vertrag 21.2 (Scopegebundener Konsens): "Ein Konsensobjekt MUSS seinen
//! Scope als local, cluster, system oder external tragen. Eine
//! Scopeerweiterung benoetigt einen expliziten Gate- und Witnessuebergang
//! ueber G-CONSENSUS."
//!
//! Invariante 21.3 (Keine Scope-Leakage): "Ein lokales oder Clusterresultat
//! DARF NICHT als systemweite oder externe Aussage emittiert werden.
//! Verletzung erzeugt FAIL und T-SCOPE-001-Fehlschlag."
//!
//! Invariante 11.12 (Okklusionsdisziplin): "Das Ausbleiben eines erwarteten
//! Witness ist nur dann Evidenz, wenn Erwartung, Kanal, Zeitfenster und
//! Okklusion selbst tracegebunden sind. Spurenlose Abwesenheit ist UNKNOWN,
//! kein Gegenbeweis." Das ist der Kern der Negativzeugen: ein Gegenbeleg
//! entsteht nicht dadurch, dass etwas fehlt, sondern dadurch, dass sein
//! Fehlen bezeugt ist.

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    ClassId, DependencyProfile, DependencyProfileConsensusScopeKind as ConsensusScope,
    EvidenceObject, EvidenceObjectStatusKind, EvidenceObjectTypeKind, MethodRef, ScopeExpr, SortId,
};
use psk_types::{Digest, ObjectId, PskError, Signature, TraceRef};

/// Eingaben fuer ein EvidenceObject (Struktur 7.24). `hash` und `id` fehlen:
/// beide leiten sich aus dem Inhalt ab.
pub struct EvidenceInputs {
    pub r#type: EvidenceObjectTypeKind,
    pub scope: ScopeExpr,
    pub input: Vec<Digest>,
    pub output: Digest,
    pub method: MethodRef,
    pub trace_ref: TraceRef,
    pub signature: Option<Signature>,
    pub status: EvidenceObjectStatusKind,
    /// "aus DependencyProfile abgeleitet" (Struktur 7.24). Nicht frei
    /// waehlbar - siehe `independence_class_of`.
    pub independence_class: ClassId,
}

const EVIDENCE_SORT: SortId = SortId::Witness;

/// Die Unabhaengigkeitsklasse einer Facette, abgeleitet aus dem
/// Abhaengigkeitsquotienten: der Index ihrer Quotientenklasse in
/// `DependencyProfile.quotient_classes`.
///
/// Struktur 7.24 sagt zu `independence_class` nur "aus DependencyProfile
/// abgeleitet", ohne die Ableitung zu nennen. Die Quotientenklasse ist die
/// einzige Groesse im Profil, die Facetten in Unabhaengigkeitsgruppen
/// teilt - genau das, was Regel 12.4 braucht ("independence_class != der
/// Klasse des Erzeugers"). Ableitung dokumentiert, nicht zitiert.
pub fn independence_class_of(profile: &DependencyProfile, facet: &ObjectId) -> Option<ClassId> {
    profile
        .quotient_classes
        .iter()
        .position(|class| class.contains(facet))
        .map(|i| ClassId(format!("qc-{i}")))
}

fn compute_evidence_identity(draft: &EvidenceObject) -> Result<(ObjectId, Digest), PskError> {
    // `id` und `hash` sind beide selbstreferenziell und bleiben im Vorbild
    // aussen vor - dasselbe Muster wie AnchorSnapshot.digest (Struktur 7.4)
    // und TraceSegment.segment_digest (Struktur 7.39).
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("id");
    obj.remove("hash");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;

    let projected = identity_projection(&bytes, Media::Json)?;
    let id: ObjectId = object_id(EVIDENCE_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok((id, psk_canon::can(&bytes, Media::Json)?.digest()))
}

/// M12: konstruiert ein EvidenceObject.
pub fn make_evidence(inputs: EvidenceInputs) -> Result<EvidenceObject, PskError> {
    let draft = EvidenceObject {
        schema: "psk.evidence/1.0".to_string(),
        id: ObjectId::new(EVIDENCE_SORT, Digest::sha256(b"")), // Platzhalter
        r#type: inputs.r#type,
        scope: inputs.scope,
        input: inputs.input,
        output: inputs.output,
        method: inputs.method,
        trace_ref: inputs.trace_ref,
        hash: Digest::sha256(b""), // Platzhalter
        signature: inputs.signature,
        status: inputs.status,
        independence_class: inputs.independence_class,
    };
    let (id, hash) = compute_evidence_identity(&draft)?;
    Ok(EvidenceObject { id, hash, ..draft })
}

/// Die vier Belege, die Invariante 11.12 fuer einen Negativzeugen verlangt.
/// Alle vier MUESSEN tracegebunden sein - deshalb traegt jeder ein
/// `TraceRef` und nicht bloss ein `bool`.
pub struct OcclusionEvidence {
    /// Die Erwartung: welcher Witness haette auftreten sollen.
    pub expectation: TraceRef,
    /// Der Kanal, ueber den er aufgetreten waere.
    pub channel: TraceRef,
    /// Das Zeitfenster, in dem er erwartet wurde.
    pub time_window: TraceRef,
    /// Die Okklusion selbst: dass und warum er ausblieb.
    pub occlusion: TraceRef,
}

/// Ergebnis der Okklusionspruefung. `Unknown` ist ein Ergebnis, kein
/// Fehlerfall: "Spurenlose Abwesenheit ist UNKNOWN, kein Gegenbeweis."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbsenceVerdict {
    /// Alle vier Bindungen liegen vor: das Ausbleiben ist Evidenz und darf
    /// als `counterexample` gefuehrt werden.
    Counterexample,
    /// Mindestens eine Bindung fehlt. Kein Gegenbeweis.
    Unknown,
}

/// Invariante 11.12 (Okklusionsdisziplin). Fehlt eine der vier Bindungen,
/// ist das Ergebnis UNKNOWN - und der Aufrufer, der es dennoch als
/// Gegenbeleg fuehrt, laeuft in `typed_absence` gegen PSK-E005.
pub fn classify_absence(evidence: Option<&OcclusionEvidence>) -> AbsenceVerdict {
    match evidence {
        Some(_) => AbsenceVerdict::Counterexample,
        None => AbsenceVerdict::Unknown,
    }
}

/// Erzeugt aus einem bezeugten Ausbleiben einen Negativzeugen.
///
/// Ohne die vier Bindungen entsteht KEIN Gegenbeleg, sondern PSK-E005
/// (occlusion_without_trace). Das ist die "Okklusionstypisierung" aus dem
/// WP09-Lieferobjekt: das Ausbleiben bekommt einen Typ, statt stillschweigend
/// als Widerlegung zu gelten.
pub fn typed_absence(
    evidence: Option<&OcclusionEvidence>,
    scope: ScopeExpr,
    method: MethodRef,
    independence_class: ClassId,
) -> Result<EvidenceObject, PskError> {
    let Some(occ) = evidence else {
        return Err(PskError::OcclusionWithoutTrace);
    };
    make_evidence(EvidenceInputs {
        r#type: EvidenceObjectTypeKind::Counterexample,
        scope,
        // Die vier Bindungen sind die Eingaben des Negativzeugen: sie stehen
        // im Objekt, nicht nur im Kopf des Aufrufers.
        input: vec![
            occ.expectation.0,
            occ.channel.0,
            occ.time_window.0,
            occ.occlusion.0,
        ],
        output: occ.occlusion.0,
        method,
        trace_ref: occ.occlusion,
        signature: None,
        status: EvidenceObjectStatusKind::Occluded,
        independence_class,
    })
}

/// Ordnet die vier Scopes aus Vertrag 21.2. Eine Erweiterung ist jede
/// Bewegung nach oben.
fn scope_rank(s: ConsensusScope) -> u8 {
    match s {
        ConsensusScope::Local => 0,
        ConsensusScope::Cluster => 1,
        ConsensusScope::System => 2,
        ConsensusScope::External => 3,
    }
}

/// Invariante 21.3 (Keine Scope-Leakage): ein lokales oder Clusterresultat
/// DARF NICHT als systemweite oder externe Aussage emittiert werden.
///
/// Vertrag 21.2 laesst eine Erweiterung ausdruecklich zu - aber nur ueber
/// "einen expliziten Gate- und Witnessuebergang ueber G-CONSENSUS". Das
/// Gate gehoert M14 (WP11, Phase I6). Diese Funktion entscheidet es
/// deshalb nicht, sondern verlangt es als bereits getroffene Feststellung;
/// ohne sie faellt sie fail-closed.
pub fn check_scope_emission(
    established: ConsensusScope,
    emitted_as: ConsensusScope,
    g_consensus_passed: bool,
) -> Result<(), PskError> {
    if scope_rank(emitted_as) <= scope_rank(established) {
        return Ok(());
    }
    if g_consensus_passed {
        Ok(())
    } else {
        Err(PskError::SurfaceInvariantCollapse)
    }
}

/// Die sechs Groessen, aus denen Regel 21.4 Vertrauen ableitet - und nur
/// diese. "Vertrauen ist kein frei gesetzter Score."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TrustBasis {
    pub passed_witness_cycles: u32,
    pub replay_stable: bool,
    pub seams_coherent: bool,
    pub residue_history_clean: bool,
    pub calibrated: bool,
    /// r_eff aus dem DependencyProfile.
    pub independence_rank: u32,
}

/// Regel 21.4 (Evidence-bound Trust). Das Gewicht "DARF Gates priorisieren
/// oder Pruefaufwand steuern, DARF NICHT aber fehlende Evidence, fehlenden
/// Aussenrecord oder gescheiterte Reconciliation ersetzen" - deshalb ist
/// der Rueckgabewert ausdruecklich eine Priorisierungsgroesse und kein
/// Statuswert, und deshalb gibt es `check_trust_does_not_substitute`.
pub fn trust_weight(basis: &TrustBasis) -> u32 {
    let flags = [
        basis.replay_stable,
        basis.seams_coherent,
        basis.residue_history_clean,
        basis.calibrated,
    ]
    .iter()
    .filter(|b| **b)
    .count() as u32;
    basis
        .passed_witness_cycles
        .saturating_add(flags)
        .saturating_add(basis.independence_rank)
}

/// Fail-closed-Wache zu Regel 21.4, zweiter Satz. Kein Vertrauensgewicht,
/// wie hoch auch immer, ersetzt eine der drei genannten Fehlstellen.
pub fn check_trust_does_not_substitute(
    _trust: u32,
    evidence_present: bool,
    external_record_present: bool,
    reconciliation_succeeded: bool,
) -> Result<(), PskError> {
    if evidence_present && external_record_present && reconciliation_succeeded {
        Ok(())
    } else {
        Err(PskError::ActualizationWithoutReconciliation)
    }
}

/// Regel 12.4 (Splitoperator): "Ein Element DARF nur dann in invariant_core
/// eintreten, wenn mindestens ein EvidenceObject mit independence_class !=
/// der Klasse des Erzeugers vorliegt."
///
/// Zusammen mit Invariante 12.2 (Kein Selbstwitness) ist das die Wache
/// gegen die Echokammer auf Kapselebene - das Gegenstueck zu Invariante
/// 11.10 auf Projektionsebene.
pub fn has_independent_evidence(evidence: &[EvidenceObject], creator_class: &ClassId) -> bool {
    evidence.iter().any(|e| {
        e.independence_class != *creator_class && e.status == EvidenceObjectStatusKind::Valid
    })
}

/// Was M12 ueber P19 an M13 reicht. WitnessReport ist KEIN Kapitel-7-Objekt
/// (object_registry.yaml fuehrt es nicht); im Portregister ist es die
/// Nutzlast von P19. Die Felder sind genau das, was M13 fuer die
/// Validierungsplanung braucht.
#[derive(Debug, Clone, PartialEq)]
pub struct WitnessReport {
    pub evidence: Vec<EvidenceObject>,
    pub established_scope: ConsensusScope,
    pub trust: u32,
    /// Die offenen Punkte, die M13 in Schritte uebersetzt.
    pub open_obligations: Vec<psk_types::objects::ObligationExpr>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trace(seed: &[u8]) -> TraceRef {
        TraceRef(Digest::sha256(seed))
    }

    fn sample_occlusion() -> OcclusionEvidence {
        OcclusionEvidence {
            expectation: trace(b"erwartung"),
            channel: trace(b"kanal"),
            time_window: trace(b"fenster"),
            occlusion: trace(b"okklusion"),
        }
    }

    fn evidence(class: &str, status: EvidenceObjectStatusKind) -> EvidenceObject {
        make_evidence(EvidenceInputs {
            r#type: EvidenceObjectTypeKind::Measurement,
            scope: ScopeExpr("lokal".into()),
            input: vec![Digest::sha256(b"in")],
            output: Digest::sha256(b"out"),
            method: MethodRef("messung/1".into()),
            trace_ref: trace(b"t"),
            signature: None,
            status,
            independence_class: ClassId(class.into()),
        })
        .unwrap()
    }

    #[test]
    fn traceless_absence_is_unknown_not_counterevidence() {
        // Invariante 11.12 woertlich.
        assert_eq!(classify_absence(None), AbsenceVerdict::Unknown);
        assert_eq!(
            typed_absence(
                None,
                ScopeExpr("s".into()),
                MethodRef("m".into()),
                ClassId("qc-0".into())
            ),
            Err(PskError::OcclusionWithoutTrace)
        );
    }

    #[test]
    fn bound_absence_becomes_a_typed_counterexample() {
        let occ = sample_occlusion();
        assert_eq!(classify_absence(Some(&occ)), AbsenceVerdict::Counterexample);
        let e = typed_absence(
            Some(&occ),
            ScopeExpr("s".into()),
            MethodRef("m".into()),
            ClassId("qc-0".into()),
        )
        .unwrap();
        assert_eq!(e.r#type, EvidenceObjectTypeKind::Counterexample);
        assert_eq!(e.status, EvidenceObjectStatusKind::Occluded);
        // Alle vier Bindungen stehen im Objekt, nicht nur im Aufruf.
        assert_eq!(e.input.len(), 4);
    }

    #[test]
    fn local_result_may_not_be_emitted_as_external() {
        // Invariante 21.3, T-SCOPE-001.
        assert_eq!(
            check_scope_emission(ConsensusScope::Local, ConsensusScope::External, false),
            Err(PskError::SurfaceInvariantCollapse)
        );
        assert_eq!(
            check_scope_emission(ConsensusScope::Cluster, ConsensusScope::System, false),
            Err(PskError::SurfaceInvariantCollapse)
        );
    }

    #[test]
    fn narrowing_the_scope_is_always_allowed() {
        assert_eq!(
            check_scope_emission(ConsensusScope::External, ConsensusScope::Local, false),
            Ok(())
        );
        assert_eq!(
            check_scope_emission(ConsensusScope::System, ConsensusScope::System, false),
            Ok(())
        );
    }

    #[test]
    fn scope_expansion_needs_g_consensus() {
        // Vertrag 21.2: Erweiterung nur ueber expliziten Gateuebergang.
        assert_eq!(
            check_scope_emission(ConsensusScope::Local, ConsensusScope::System, true),
            Ok(())
        );
    }

    #[test]
    fn trust_never_substitutes_missing_evidence() {
        // Regel 21.4, zweiter Satz.
        let high = u32::MAX;
        assert_eq!(
            check_trust_does_not_substitute(high, false, true, true),
            Err(PskError::ActualizationWithoutReconciliation)
        );
        assert_eq!(
            check_trust_does_not_substitute(high, true, false, true),
            Err(PskError::ActualizationWithoutReconciliation)
        );
        assert_eq!(
            check_trust_does_not_substitute(high, true, true, false),
            Err(PskError::ActualizationWithoutReconciliation)
        );
        assert_eq!(check_trust_does_not_substitute(0, true, true, true), Ok(()));
    }

    #[test]
    fn trust_is_derived_only_from_the_six_named_quantities() {
        let none = TrustBasis::default();
        assert_eq!(trust_weight(&none), 0);
        let full = TrustBasis {
            passed_witness_cycles: 3,
            replay_stable: true,
            seams_coherent: true,
            residue_history_clean: true,
            calibrated: true,
            independence_rank: 2,
        };
        assert_eq!(trust_weight(&full), 3 + 4 + 2);
    }

    #[test]
    fn invariant_core_needs_evidence_from_another_class() {
        // Regel 12.4 / Invariante 12.2 (Kein Selbstwitness).
        let own = ClassId("qc-0".into());
        let self_only = vec![evidence("qc-0", EvidenceObjectStatusKind::Valid)];
        assert!(!has_independent_evidence(&self_only, &own));

        let with_other = vec![
            evidence("qc-0", EvidenceObjectStatusKind::Valid),
            evidence("qc-1", EvidenceObjectStatusKind::Valid),
        ];
        assert!(has_independent_evidence(&with_other, &own));
    }

    #[test]
    fn invalid_evidence_does_not_count_as_independent() {
        let own = ClassId("qc-0".into());
        let invalid = vec![evidence("qc-1", EvidenceObjectStatusKind::Invalid)];
        assert!(!has_independent_evidence(&invalid, &own));
    }

    #[test]
    fn evidence_hash_and_id_are_deterministic() {
        let a = evidence("qc-0", EvidenceObjectStatusKind::Valid);
        let b = evidence("qc-0", EvidenceObjectStatusKind::Valid);
        assert_eq!(a.id, b.id);
        assert_eq!(a.hash, b.hash);
    }

    #[test]
    fn independence_class_comes_from_the_quotient() {
        use psk_types::objects::{Matrix, RankMethodId, Scaled};
        let facet_a = ObjectId::new(SortId::Projection, Digest::sha256(b"a"));
        let facet_b = ObjectId::new(SortId::Projection, Digest::sha256(b"b"));
        let empty_matrix = Matrix {
            schema: "psk.matrix/1.0".into(),
            axis: vec![],
            scale: 0,
            values: vec![],
        };
        let profile = DependencyProfile {
            schema: "psk.dependency-profile/1.0".into(),
            id: ObjectId::new(SortId::Dependency, Digest::sha256(b"p")),
            sources: vec![],
            witness_matrix: empty_matrix.clone(),
            dependency_matrix: empty_matrix,
            effective_rank: Scaled {
                schema: "psk.scaled/1.0".into(),
                numerator: 2,
                scale: 0,
            },
            method: RankMethodId("quotient_class_count".into()),
            quotient_classes: vec![vec![facet_a], vec![facet_b]],
            consensus_scope: ConsensusScope::Local,
        };
        assert_eq!(
            independence_class_of(&profile, &facet_a),
            Some(ClassId("qc-0".into()))
        );
        assert_eq!(
            independence_class_of(&profile, &facet_b),
            Some(ClassId("qc-1".into()))
        );
        let unknown = ObjectId::new(SortId::Projection, Digest::sha256(b"x"));
        assert_eq!(independence_class_of(&profile, &unknown), None);
    }
}
