//! M24 AdversarialKernel (Kapitel 12), Paesse C7 und C8.
//!
//! Definition 12.1 (Adversarialer Kern): "C_adv = (Capsule, Split, Ratchet,
//! Support, Occlusion, ResidueFlow, Contraction, Recanon, Harden). M24
//! realisiert genau diese neun Operatoren und keine weiteren."
//!
//! Realisiert sind hier die Operatoren, deren tragende Module in I4
//! existieren: Capsule, Split, Ratchet, Support, Contraction. Occlusion
//! liegt bei M12 (`psk_witness::typed_absence`, Invariante 11.12);
//! ResidueFlow und Recanon setzen den Residuenspeicher M19 voraus (WP04,
//! Phase I5); Harden laeuft ueber P36 und das Gate G-SELF-COMPILE
//! (Invariante 12.12) und damit ueber M21 (WP15). Die vier bleiben
//! unimplementiert statt vorgetaeuscht - die Neunerliste ist damit nicht
//! erweitert, nur teilweise realisiert.

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    CandidateCapsule, CandidateCapsulePhaseKind as Phase, CandidateCapsuleStatusKind as Status,
    CapsuleId, EvidenceObject, FieldProjection, InvariantId, ReplayDescriptor, ScopeExpr, SortId,
    SurfaceDescriptor,
};
use psk_types::{Digest, ObjectId, PskError, TraceRef};

const CAPSULE_SORT: SortId = SortId::Branch;

/// Eingaben fuer `capsulate`. `phase`, `status` und `id` fehlen: die Phase
/// beginnt bei SEALED, der Status bei OPEN, die ID folgt aus dem Inhalt.
pub struct CapsuleInputs {
    pub surface: SurfaceDescriptor,
    pub replay: ReplayDescriptor,
    pub boundary: ScopeExpr,
    pub trace_ref: TraceRef,
    pub coupling: Vec<ObjectId>,
    /// Die Ratchet-Restmenge zu Beginn - die groesste, die diese Kapsel je
    /// haben wird (Invariante 12.6).
    pub allowed_next: Vec<CapsuleId>,
}

fn compute_identity(draft: &CandidateCapsule) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    object_id(CAPSULE_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

fn seal(draft: CandidateCapsule) -> Result<CandidateCapsule, PskError> {
    let id = compute_identity(&draft)?;
    Ok(CandidateCapsule { id, ..draft })
}

/// Operator 1, `capsulate(class: [FieldProjection]) -> CandidateCapsule`
/// (Schnittstelle 12.15).
///
/// Die Eingabe ist EINE Quotientenklasse aus dem DependencyProfile
/// (Algorithmus 11.19: `capsules = C7_adversarial_canonicalize(
/// profile.quotient_classes)`) - nicht eine beliebige Projektionsmenge.
/// `invariant_core` beginnt leer: Invarianten treten nur ueber `split` ein,
/// und nur mit unabhaengiger Evidenz (Regel 12.4).
pub fn capsulate(
    class: &[FieldProjection],
    inputs: CapsuleInputs,
) -> Result<CandidateCapsule, PskError> {
    seal(CandidateCapsule {
        schema: "psk.candidate-capsule/1.0".to_string(),
        id: ObjectId::new(CAPSULE_SORT, Digest::sha256(b"")), // Platzhalter
        surface: inputs.surface,
        invariant_core: Vec::new(),
        phase: Phase::Sealed,
        witnesses: class.iter().map(|p| p.id).collect(),
        replay: inputs.replay,
        boundary: inputs.boundary,
        trace_ref: inputs.trace_ref,
        coupling: inputs.coupling,
        allowed_next: inputs.allowed_next,
        status: Status::Open,
    })
}

/// Ergebnis von `split` (Operator 2): die behauptete Rolle und der
/// geprueft e Kern, getrennt.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitResult {
    pub surface: SurfaceDescriptor,
    pub invariant_core: Vec<InvariantId>,
    /// Die Invarianten, die NICHT eintreten durften, weil ihnen unabhaengige
    /// Evidenz fehlt. Sie verschwinden nicht still (Axiom 7.41, No Silent Loss).
    pub rejected: Vec<InvariantId>,
}

/// Operator 2, Regel 12.4 (Splitoperator): "Split zerlegt jede Kapsel in
/// surface (behauptete Rolle) und invariant_core (geprueft e Invarianten).
/// Ein Element DARF nur dann in invariant_core eintreten, wenn mindestens
/// ein EvidenceObject mit independence_class != der Klasse des Erzeugers
/// vorliegt."
///
/// Axiom 12.3 (Oberflaeche erzeugt keine Invarianz): eine behauptete Rolle
/// traegt nie von sich aus in den Kern. Deshalb wird `claimed` gegen die
/// Evidenz geprueft und nicht uebernommen.
///
/// `has_independent_evidence` kommt als bereits ENTSCHIEDENER Wert herein,
/// nicht als roher `EvidenceObject`/`ClassId`-Import aus psk-witness: M10/
/// M12 haben diese Frage frueher in der Pipeline laengst beantwortet
/// (`psk_witness::has_independent_evidence`, dieselbe Funktion, jetzt beim
/// AUFRUFER statt hier). Split() ist damit eine reine Funktion ihrer
/// deklarierten Eingaben - dasselbe Muster wie ueberall sonst im Werk fuer
/// domaenengelieferte Werte -, kein Live-Aufruf in ein fremdes Crate
/// (T-PORT-001-Befund, behoben statt eines neuen Ports).
pub fn split(
    capsule: &CandidateCapsule,
    claimed: &[InvariantId],
    has_independent_evidence: bool,
) -> SplitResult {
    let mut invariant_core = Vec::new();
    let mut rejected = Vec::new();
    for inv in claimed {
        if has_independent_evidence {
            invariant_core.push(inv.clone());
        } else {
            rejected.push(inv.clone());
        }
    }
    SplitResult {
        surface: capsule.surface.clone(),
        invariant_core,
        rejected,
    }
}

/// Operator 3, Definition 12.5 (Ratchet-Schritt):
/// `S_{n+1} = AllowedNext(G_n, S_n)`, `S_{n+1} ⊆ S_n`.
///
/// Invariante 12.6 (Monotone Kontraktion): "allowed_next ist ueber die
/// Lebensdauer einer Kapsel monoton fallend. Eine Vergroesserung ist
/// ausschliesslich als neuer Branch mit neuer ObjectId und neuer Lineage
/// zulaessig."
///
/// Deshalb nimmt `ratchet` keine neue Menge entgegen, sondern die Menge der
/// durch das Gate ueberlebenden Kandidaten, und schneidet sie mit der
/// bisherigen. Eine Vergroesserung ist so nicht ausdrueckbar - nicht bloss
/// verboten.
pub fn ratchet(
    capsule: &CandidateCapsule,
    survivors: &[CapsuleId],
    rounds_used: u32,
    ratchet_max_rounds: u32,
) -> Result<CandidateCapsule, PskError> {
    let keep: Vec<CapsuleId> = capsule
        .allowed_next
        .iter()
        .filter(|c| survivors.contains(c))
        .cloned()
        .collect();

    // Regel 12.7: "Die Terminierung ist durch das Budget ratchet_max_rounds
    // im RunDescriptor erzwungen; bei Erschoepfung wird die Kapsel RESIDUAL."
    let phase = if rounds_used >= ratchet_max_rounds {
        Phase::Residual
    } else {
        Phase::Ratcheted
    };

    seal(CandidateCapsule {
        allowed_next: keep,
        phase,
        ..capsule.clone()
    })
}

/// Fail-closed-Wache zu Invariante 12.6, fuer den Fall, dass eine Kapsel
/// nicht ueber `ratchet` entstanden ist: die Nachfolgemenge DARF nie
/// wachsen.
pub fn check_monotone_contraction(
    before: &CandidateCapsule,
    after: &CandidateCapsule,
) -> Result<(), PskError> {
    let grew = after
        .allowed_next
        .iter()
        .any(|c| !before.allowed_next.contains(c));
    if grew {
        // Eine Vergroesserung ist nur als NEUER Branch zulaessig - und dann
        // traegt sie eine andere ObjectId, ist also keine Fortsetzung.
        Err(PskError::MorphogenesisViolation)
    } else {
        Ok(())
    }
}

/// Vertrag 12.10 (Branch statt Umschreibung): "Eine gescheiterte
/// Spezifikation [...] DARF NICHT nachtraeglich so umgeschrieben werden,
/// als sei sie immer korrekt gewesen. Eine Reparatur erzeugt eine neue
/// Branch, neue ID, neue Tracekette und neue Konformitaetspruefung."
///
/// Die Wache prueft genau das: eine Reparatur, die dieselbe ID oder
/// dieselbe Tracekette behaelt, ist eine Umschreibung.
pub fn check_repair_is_a_branch(
    original: &CandidateCapsule,
    repaired: &CandidateCapsule,
) -> Result<(), PskError> {
    if repaired.id == original.id || repaired.trace_ref == original.trace_ref {
        Err(PskError::SelfAmendmentWithoutIdentity)
    } else {
        Ok(())
    }
}

/// Die fuenf Pfade aus Definition 11.11 (Perkolationssupport):
/// "Support(e) = 1 genau dann, wenn Gate-, Witness-, Replay-, Ressourcen-
/// und Kopplungspfad innerhalb des geltenden Horizonts definiert sind."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SupportPaths {
    pub gate: bool,
    pub witness: bool,
    pub replay: bool,
    pub resource: bool,
    pub coupling: bool,
}

/// Operator 4, Pass C8: `support(c, horizon) -> bool`.
/// Konjunktion aller fuenf - "genau dann, wenn".
pub fn support(paths: &SupportPaths) -> bool {
    paths.gate && paths.witness && paths.replay && paths.resource && paths.coupling
}

/// Pass C8 auf einer Kapsel: bei vollem Support geht sie nach SUPPORTED,
/// sonst nach RESIDUAL. Kein Zwischenweg - ein teilweise gestuetzter
/// Kandidat ist nicht gestuetzt.
pub fn check_support(
    capsule: &CandidateCapsule,
    paths: &SupportPaths,
) -> Result<CandidateCapsule, PskError> {
    seal(CandidateCapsule {
        phase: if support(paths) {
            Phase::Supported
        } else {
            Phase::Residual
        },
        ..capsule.clone()
    })
}

/// Invariante 12.14 (Nichttrivialitaet des Ueberlebens): "Ein Kandidat, der
/// nur unter Ausblendung eines Gegenmodells schliesst, ist nicht
/// adversarial geschlossen. Seine scheinbare Closure ist eine Projektion
/// mit verdeckter Obstruktion und erzeugt PSK-E003."
///
/// Definition 12.13: `A(M) = Close(M ∪ Countermodels(M) ∪ Stress(M))`. Die
/// Gegenmodelle sind Teil der Menge, ueber der geschlossen wird - nicht
/// etwas, das danach geprueft wird.
pub fn check_adversarial_closure(
    closes_without_countermodels: bool,
    closes_with_countermodels: bool,
) -> Result<(), PskError> {
    if closes_without_countermodels && !closes_with_countermodels {
        Err(PskError::SurfaceInvariantCollapse)
    } else {
        Ok(())
    }
}

/// Invariante 12.2 (Kein Selbstwitness): "Der Compiler DARF NICHT seine
/// eigenen Claims als unabhaengige Witnesses zaehlen. Eine Kapselbewertung,
/// deren einzige Evidenz aus derselben Modell- oder Ableitungsquelle
/// stammt, erhaelt r_eff = 1."
pub fn effective_rank_of(evidence: &[EvidenceObject]) -> usize {
    let classes: std::collections::BTreeSet<&String> =
        evidence.iter().map(|e| &e.independence_class.0).collect();
    classes.len().max(1)
}

/// Operator 7, `contract(caps) -> [CandidateCapsule]`. Behaelt die Kapseln,
/// die noch eine Nachfolgemenge haben oder bereits kristallisiert sind;
/// alles andere ist ausgeratscht.
///
/// Regel 12.7 (Selektionsdruck): "Der adversariale Kern versucht nicht,
/// einen Kandidaten sprachlich zu retten. Er maximiert die Chance, ihn
/// unter den deklarierten Invarianten zu widerlegen. Nur replaystabile
/// Reststrukturen DARF kristallisieren."
pub fn contract(capsules: &[CandidateCapsule]) -> Vec<CandidateCapsule> {
    capsules
        .iter()
        .filter(|c| !c.allowed_next.is_empty() || c.phase == Phase::Crystallized)
        .cloned()
        .collect()
}

/// Definition 12.8 (Residuenfluss): `HOLD -> RESIDUE -> Quarantine ->
/// Recanonicalization`. "Kein Scheitern DARF durch stilles Loeschen aus der
/// Lernhistorie entfernt werden."
///
/// Die zulaessige Nachfolgephase im Residuenfluss. `None` heisst: von hier
/// fuehrt kein Residuenweg weiter (der Fluss ist am Ende oder die Phase
/// gehoert nicht dazu).
pub fn residue_flow_next(phase: Phase) -> Option<Phase> {
    match phase {
        Phase::Residual => Some(Phase::Quarantined),
        // Recanonicalization erzeugt eine NEUE Kapsel (Vertrag 12.10:
        // neue Branch, neue ID) - kein Phasenuebergang derselben Kapsel.
        Phase::Quarantined => None,
        _ => None,
    }
}

/// Regel 12.11 (Zulaessige Selbstverhaertung): M24 DARF ausschliesslich
/// diese sechs Klassen veraendern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningClass {
    TestsAndFalsifiers,
    GateAndValidationPolicies,
    ReplayAndResiduePatterns,
    DependencyModels,
    SearchAndBranchStrategies,
    CalibrationProfilesWithinDeclaredBounds,
}

impl HardeningClass {
    pub const ALL: [HardeningClass; 6] = [
        HardeningClass::TestsAndFalsifiers,
        HardeningClass::GateAndValidationPolicies,
        HardeningClass::ReplayAndResiduePatterns,
        HardeningClass::DependencyModels,
        HardeningClass::SearchAndBranchStrategies,
        HardeningClass::CalibrationProfilesWithinDeclaredBounds,
    ];
}

/// Invariante 12.12 (Keine Selbstautorisierung): "Self-Hardening DARF NICHT
/// konstitutionelle Autoritaet, externe Faehigkeit oder Faktizitaet durch
/// Selbstdeklaration erzeugen. Jede Aenderung durchlaeuft P36 und das Gate
/// G-SELF-COMPILE."
///
/// Der Operator `harden` selbst gehoert zu M21/WP15; diese Wache haelt
/// schon jetzt fest, was er nie duerfen wird.
pub fn check_hardening_permitted(
    class: Option<HardeningClass>,
    g_self_compile_passed: bool,
) -> Result<HardeningClass, PskError> {
    let Some(class) = class else {
        // Ausserhalb der sechs Klassen: keine zulaessige Selbstverhaertung.
        return Err(PskError::SelfAmendmentWithoutIdentity);
    };
    if g_self_compile_passed {
        Ok(class)
    } else {
        Err(PskError::SelfAmendmentWithoutIdentity)
    }
}

/// Invariante 7.22 (Keine vorzeitige Oeffnung) ueber `status`: eine Kapsel
/// DARF nicht als CLOSED gefuehrt werden, solange sie nicht kristallisiert
/// oder abschliessend residual/quarantaeniert ist.
pub fn check_closure_state(capsule: &CandidateCapsule) -> Result<(), PskError> {
    let may_close = matches!(
        capsule.phase,
        Phase::Crystallized | Phase::Residual | Phase::Quarantined
    );
    if capsule.status == Status::Closed && !may_close {
        Err(PskError::SurfaceInvariantCollapse)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        ClassId, EvidenceObjectStatusKind, EvidenceObjectTypeKind, IRNodeId, LensSpec, MethodRef,
        RealityStatus, ScopeSpec, SourceRef, TickId,
    };

    fn projection(id: &str) -> FieldProjection {
        FieldProjection {
            schema: "psk.field-projection/1.0".into(),
            id: ObjectId::new(SortId::Projection, Digest::sha256(id.as_bytes())),
            field_ref: ObjectId::new(SortId::FieldIdentity, Digest::sha256(b"f")),
            source_refs: vec![],
            lens_ref: LensSpec("lens/1".into()),
            scope: ScopeSpec("s".into()),
            visible: vec![IRNodeId("n1".into())],
            occluded: vec![],
            distinctions: vec![],
            source_provenance: vec![SourceRef("q1".into())],
            reality_view: RealityStatus::Unknown,
            tick: TickId("t".into()),
        }
    }

    fn inputs(next: &[&str]) -> CapsuleInputs {
        CapsuleInputs {
            surface: SurfaceDescriptor("behauptete Rolle".into()),
            replay: ReplayDescriptor("replay/1".into()),
            boundary: ScopeExpr("lokal".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
            coupling: vec![],
            allowed_next: next.iter().map(|c| CapsuleId((*c).into())).collect(),
        }
    }

    fn capsule(next: &[&str]) -> CandidateCapsule {
        capsulate(&[projection("p1")], inputs(next)).unwrap()
    }

    /// Direktes Struct-Literal statt `psk_witness::make_evidence`: die
    /// echte, kanonische Identitaet (die `make_evidence` berechnet) spielt
    /// fuer diese Tests keine Rolle - weder `split()` (nimmt seit dem
    /// T-PORT-001-Fix gar kein `EvidenceObject` mehr entgegen) noch
    /// `effective_rank_of` (liest nur `independence_class`) pruefen `id`/
    /// `hash`. Ein Platzhalterdigest genuegt, ohne die psk-witness-
    /// Abhaengigkeit fuer einen einzigen Testwert zu behalten.
    fn evidence(class: &str) -> EvidenceObject {
        EvidenceObject {
            schema: "psk.evidence/1.0".into(),
            id: ObjectId::new(SortId::Witness, Digest::sha256(class.as_bytes())),
            r#type: EvidenceObjectTypeKind::Measurement,
            scope: ScopeExpr("s".into()),
            input: vec![Digest::sha256(b"i")],
            output: Digest::sha256(b"o"),
            method: MethodRef("m".into()),
            trace_ref: TraceRef(Digest::sha256(b"t")),
            hash: Digest::sha256(class.as_bytes()),
            signature: None,
            status: EvidenceObjectStatusKind::Valid,
            independence_class: ClassId(class.into()),
        }
    }

    #[test]
    fn a_new_capsule_is_sealed_with_an_empty_core() {
        // Axiom 12.3: Oberflaeche erzeugt keine Invarianz.
        let c = capsule(&["c1", "c2"]);
        assert_eq!(c.phase, Phase::Sealed);
        assert_eq!(c.status, Status::Open);
        assert!(c.invariant_core.is_empty());
    }

    #[test]
    fn claimed_invariants_need_independent_evidence_to_enter_the_core() {
        // Regel 12.4. `has_independent_evidence` ist seit dem T-PORT-001-
        // Fix ein deklarierter Parameter (vom Aufrufer via
        // `psk_witness::has_independent_evidence` entschieden, siehe
        // split()s Modulkopf) - `false` entspricht Evidenz aus derselben
        // Klasse wie der Erzeuger, `true` einer unabhaengigen Klasse.
        let c = capsule(&["c1"]);
        let claimed = vec![InvariantId("I-ARCH-001".into())];

        let self_only = split(&c, &claimed, false);
        assert!(self_only.invariant_core.is_empty());
        assert_eq!(
            self_only.rejected, claimed,
            "Abgewiesenes verschwindet nicht"
        );

        let independent = split(&c, &claimed, true);
        assert_eq!(independent.invariant_core, claimed);
        assert!(independent.rejected.is_empty());
    }

    #[test]
    fn ratchet_can_only_shrink() {
        // Definition 12.5: S_{n+1} subseteq S_n.
        let c = capsule(&["c1", "c2", "c3"]);
        let after = ratchet(
            &c,
            &[
                CapsuleId("c1".into()),
                CapsuleId("c9".into()), // war nie drin
            ],
            1,
            10,
        )
        .unwrap();
        assert_eq!(after.allowed_next, vec![CapsuleId("c1".into())]);
        assert_eq!(after.phase, Phase::Ratcheted);
    }

    #[test]
    fn ratchet_is_monotone_over_repeated_rounds() {
        // Invariante 12.6.
        let mut c = capsule(&["c1", "c2", "c3"]);
        let mut sizes = vec![c.allowed_next.len()];
        for (round, survivors) in [vec!["c1", "c2"], vec!["c1"], vec![]].iter().enumerate() {
            let ids: Vec<CapsuleId> = survivors.iter().map(|s| CapsuleId((*s).into())).collect();
            let next = ratchet(&c, &ids, round as u32, 10).unwrap();
            assert_eq!(check_monotone_contraction(&c, &next), Ok(()));
            sizes.push(next.allowed_next.len());
            c = next;
        }
        assert_eq!(sizes, vec![3, 2, 1, 0]);
    }

    #[test]
    fn growing_the_successor_set_is_rejected() {
        let before = capsule(&["c1"]);
        let after = CandidateCapsule {
            allowed_next: vec![CapsuleId("c1".into()), CapsuleId("c2".into())],
            ..before.clone()
        };
        assert_eq!(
            check_monotone_contraction(&before, &after),
            Err(PskError::MorphogenesisViolation)
        );
    }

    #[test]
    fn exhausting_the_round_budget_makes_the_capsule_residual() {
        // Regel 12.7, letzter Satz.
        let c = capsule(&["c1"]);
        let after = ratchet(&c, &[CapsuleId("c1".into())], 10, 10).unwrap();
        assert_eq!(after.phase, Phase::Residual);
    }

    #[test]
    fn support_requires_all_five_paths() {
        // Definition 11.11: "genau dann, wenn".
        let full = SupportPaths {
            gate: true,
            witness: true,
            replay: true,
            resource: true,
            coupling: true,
        };
        assert!(support(&full));
        for drop in 0..5 {
            let mut p = full;
            match drop {
                0 => p.gate = false,
                1 => p.witness = false,
                2 => p.replay = false,
                3 => p.resource = false,
                _ => p.coupling = false,
            }
            assert!(!support(&p), "ein fehlender Pfad muss Support brechen");
        }
    }

    #[test]
    fn partial_support_makes_the_capsule_residual_not_supported() {
        let c = capsule(&["c1"]);
        let partial = SupportPaths {
            gate: true,
            witness: true,
            replay: true,
            resource: true,
            coupling: false,
        };
        assert_eq!(check_support(&c, &partial).unwrap().phase, Phase::Residual);
    }

    #[test]
    fn closing_only_by_hiding_a_countermodel_is_not_adversarial_closure() {
        // Invariante 12.14, PSK-E003.
        assert_eq!(
            check_adversarial_closure(true, false),
            Err(PskError::SurfaceInvariantCollapse)
        );
        assert_eq!(check_adversarial_closure(true, true), Ok(()));
    }

    #[test]
    fn evidence_from_one_source_yields_rank_one() {
        // Invariante 12.2.
        assert_eq!(effective_rank_of(&[evidence("qc-0")]), 1);
        assert_eq!(
            effective_rank_of(&[evidence("qc-0"), evidence("qc-0"), evidence("qc-0")]),
            1
        );
        assert_eq!(effective_rank_of(&[evidence("qc-0"), evidence("qc-1")]), 2);
        // Auch ohne jede Evidenz nie 0 - "erhaelt r_eff = 1".
        assert_eq!(effective_rank_of(&[]), 1);
    }

    #[test]
    fn repair_must_be_a_new_branch_not_a_rewrite() {
        // Vertrag 12.10.
        let original = capsule(&["c1"]);
        let rewritten = CandidateCapsule {
            surface: SurfaceDescriptor("umgeschrieben".into()),
            ..original.clone()
        };
        assert_eq!(
            check_repair_is_a_branch(&original, &rewritten),
            Err(PskError::SelfAmendmentWithoutIdentity)
        );

        let branched = seal(CandidateCapsule {
            surface: SurfaceDescriptor("neuer Branch".into()),
            trace_ref: TraceRef(Digest::sha256(b"neue-kette")),
            ..original.clone()
        })
        .unwrap();
        assert_eq!(check_repair_is_a_branch(&original, &branched), Ok(()));
    }

    #[test]
    fn contraction_drops_exhausted_capsules() {
        let alive = capsule(&["c1"]);
        let exhausted = capsule(&[]);
        let crystallized = CandidateCapsule {
            phase: Phase::Crystallized,
            ..capsule(&[])
        };
        let kept = contract(&[alive.clone(), exhausted, crystallized.clone()]);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|c| c.id == alive.id));
        assert!(kept.iter().any(|c| c.phase == Phase::Crystallized));
    }

    #[test]
    fn residue_flow_follows_the_declared_order() {
        // Definition 12.8: RESIDUE -> Quarantine.
        assert_eq!(residue_flow_next(Phase::Residual), Some(Phase::Quarantined));
        // Recanonicalization ist eine neue Kapsel, kein Phasenschritt.
        assert_eq!(residue_flow_next(Phase::Quarantined), None);
        assert_eq!(residue_flow_next(Phase::Sealed), None);
    }

    #[test]
    fn hardening_outside_the_six_classes_is_rejected() {
        // Regel 12.11 / Invariante 12.12.
        assert_eq!(HardeningClass::ALL.len(), 6);
        assert_eq!(
            check_hardening_permitted(None, true),
            Err(PskError::SelfAmendmentWithoutIdentity)
        );
        assert_eq!(
            check_hardening_permitted(Some(HardeningClass::DependencyModels), false),
            Err(PskError::SelfAmendmentWithoutIdentity),
            "ohne G-SELF-COMPILE DARF keine Selbstverhaertung wirksam werden"
        );
        assert_eq!(
            check_hardening_permitted(Some(HardeningClass::DependencyModels), true),
            Ok(HardeningClass::DependencyModels)
        );
    }

    #[test]
    fn a_sealed_capsule_may_not_be_closed() {
        // Invariante 7.22 (Keine vorzeitige Oeffnung).
        let premature = CandidateCapsule {
            status: Status::Closed,
            ..capsule(&["c1"])
        };
        assert_eq!(
            check_closure_state(&premature),
            Err(PskError::SurfaceInvariantCollapse)
        );

        let done = CandidateCapsule {
            phase: Phase::Crystallized,
            status: Status::Closed,
            ..capsule(&[])
        };
        assert_eq!(check_closure_state(&done), Ok(()));
    }

    #[test]
    fn capsulation_is_deterministic() {
        let a = capsulate(&[projection("p1")], inputs(&["c1"])).unwrap();
        let b = capsulate(&[projection("p1")], inputs(&["c1"])).unwrap();
        assert_eq!(a.id, b.id);
    }
}
