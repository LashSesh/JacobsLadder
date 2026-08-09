//! M08 FieldRegistry: konstruiert FieldIdentity-Objekte (Struktur 7.14,
//! OBJ-FLD) und fuehrt sie durch FSM-FIELD (Automat 13.x,
//! `psk_types::automata::field`).
//!
//! Regel 32.7 (Feldfamilie der Referenzdomaene): "Genau sechs statische
//! Feldidentitaeten." Das geschlossene `ArchetypeId`-Register (Struktur
//! 7.14s Kommentar, sechs Werte) haelt diese Menge geschlossen - vor dieser
//! Korrektur generierte object_schemas.yaml `archetype` als freie
//! Zeichenkette (derselbe Fehlerklasse wie RealityStatus/FactStatus vor
//! WP06, siehe architecture/sort_registry.yaml#ArchetypeId).
//!
//! Aktivierung (PROPOSED -> ACTIVE) verlangt Gate G-MORPH, dessen Owner
//! laut architecture/gate_registry.yaml M20 (MorphogenesisController) ist -
//! nicht M14. M20 gehoert nicht zu I3/WP07 (Task-Scope: nur M08, M09) und
//! existiert noch nicht. `advance()` bildet die Transition daher exakt wie
//! im Automaten deklariert ab: ungegatete Kanten (quiesce, retire) liefern
//! sofort ein neues Objekt, gegatete Kanten (activate, propose_split,
//! propose_merge, fold, excise) liefern nur die Ankuendigung
//! (`RequiresGate`) - keine Autorisierung wird hier vorgetaeuscht.

use psk_canon::{identity_projection, object_id, record_digest, Media};
use psk_types::automata::field as field_fsm;
use psk_types::automata::StepOutcome;
use psk_types::objects::{
    ArchetypeId, BoundarySpec, BudgetSpec, DomainExpr, FieldIdentity, FieldIdentityLifecycleKind,
    GateId, LensSpec, Lineage, OpId, QuestionSpec, RollbackSpec, Scaled, SortId, TimeWindow,
    WitnessPolicy,
};
use psk_types::{Digest, ObjectId, PskError};

/// Eingaben fuer eine FieldIdentity-Konstruktion. `id`, `lifecycle` und
/// `marginal_gain` fehlen hier absichtlich: FSM-FIELD legt den
/// Anfangszustand fest (PROPOSED, `field_fsm::INITIAL`), und Delta-G ist
/// "zuletzt gemessener Wert" (Struktur 7.14) - vor der ersten Messung gibt
/// es keinen.
pub struct FieldRegistrationInputs {
    pub domain: DomainExpr,
    pub lens: LensSpec,
    pub operators: Vec<OpId>,
    pub questions: Vec<QuestionSpec>,
    pub witness_rules: WitnessPolicy,
    pub boundaries: BoundarySpec,
    pub gates: Vec<GateId>,
    pub time_window: TimeWindow,
    pub lineage: Lineage,
    pub dependency_profile_ref: ObjectId,
    pub budget: BudgetSpec,
    pub rollback: RollbackSpec,
    /// Die aktuelle Systemidentitaet (I_t), gegen die I-FIELD-001
    /// prueft - siehe `register_field`.
    ///
    /// Deklarierter Parameter, kein Selbstermitteln: M08 kann die
    /// Systemidentitaet nicht kennen, sie gehoert M04. Dasselbe Muster
    /// wie `has_independent_evidence` in M24, nachdem dort die
    /// Cargo-Abhaengigkeit auf psk-witness entfiel - kein neuer Port,
    /// keine neue Kante, der Aufrufer entscheidet die Frage, die er
    /// beantworten kann.
    pub system_identity: Digest,
}

/// Baut das JSON-Vorbild ohne die selbstreferenzielle `id` und bildet
/// daraus Objekt-ID (Definition 6.6, ueber pi_vol) und record_digest
/// (Definition 6.7). Gleiches Muster wie ThoughtBody (psk-thought) und
/// AnchorSnapshot (psk-anchor).
fn compute_identity(draft: &FieldIdentity) -> Result<(ObjectId, Digest), PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;

    let projected = identity_projection(&bytes, Media::Json)?;
    let oid: ObjectId = object_id(SortId::FieldIdentity.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok((oid, record_digest(&bytes, Media::Json)?))
}

/// M08: registriert eine neue FieldIdentity fuer den gegebenen Archetyp.
/// Lifecycle startet bei `field_fsm::INITIAL` (PROPOSED); `marginal_gain`
/// startet bei "0" (noch keine Messung).
/// I-FIELD-001 (`no_field_identity_equals_system_identity`,
/// severity: blocking) / R-FIELD-001 ("No field identity is treated as
/// the system identity") - T-FIELD-001s Mutation heisst
/// `set_system_identity_to_field_id`.
///
/// Geprueft wird an BEIDEN Schreibstellen, weil die Zeitachse beide
/// Richtungen offen laesst: bei `M04.bind()` koennen bereits Felder
/// existieren, nach `bind()` kommen neue hinzu. Hier die zweite Haelfte -
/// eine NEUE Feldidentitaet darf nicht gleich der aktuellen
/// Systemidentitaet sein; die erste liegt in
/// `psk_contract::identity_binder::bind`.
///
/// Bewusst NICHT in Sigma geprueft: das waere Feststellung nach Eintritt.
/// Die Invariante sagt "ist nicht identisch" - ein Zustand, der gar nicht
/// entstehen darf, nicht einer, den man hinterher bemerkt.
///
/// Verglichen wird der Digestanteil: `FieldIdentity.id` ist eine
/// `ObjectId` (`psk:S-FLD:<digest>`), die Systemidentitaet ein blosser
/// `Digest`. Gleichheit heisst hier: derselbe Digest - die Sortenhuelle
/// wuerde einen Vergleich sonst immer scheitern lassen und die Pruefung
/// wirkungslos machen.
pub fn register_field(
    archetype: ArchetypeId,
    inputs: FieldRegistrationInputs,
) -> Result<FieldIdentity, PskError> {
    let draft = FieldIdentity {
        schema: "psk.field-identity/1.0".to_string(),
        id: ObjectId::new(SortId::FieldIdentity, Digest::sha256(b"")), // Platzhalter
        domain: inputs.domain,
        lens: inputs.lens,
        operators: inputs.operators,
        questions: inputs.questions,
        witness_rules: inputs.witness_rules,
        boundaries: inputs.boundaries,
        gates: inputs.gates,
        time_window: inputs.time_window,
        lineage: inputs.lineage,
        lifecycle: state_to_lifecycle(field_fsm::INITIAL),
        archetype,
        dependency_profile_ref: inputs.dependency_profile_ref,
        budget: inputs.budget,
        rollback: inputs.rollback,
        marginal_gain: Scaled {
            schema: "psk.scaled/1.0".to_string(),
            numerator: 0,
            scale: 0,
        },
    };

    let (id, _record) = compute_identity(&draft)?;
    if id.digest == inputs.system_identity {
        return Err(PskError::SelfAmendmentWithoutIdentity);
    }
    Ok(FieldIdentity { id, ..draft })
}

/// Die im Register (`activation_requirements`,
/// constitution/state_machines.yaml#field) genannten sechs Bedingungen fuer
/// PROPOSED -> ACTIVE, soweit sie aus der FieldIdentity-Struktur selbst
/// pruefbar sind:
///
/// - `positive_marginal_gain`: `marginal_gain.numerator` > 0 (Scaled, seit
///   v1.0.8 - das Vorzeichen liegt vollstaendig im numerator, da
///   10^scale > 0 fuer scale >= 0 immer gilt; keine Gleitkommapruefung
///   mehr noetig).
/// - `scope_declared`: Struktur 7.14 fuehrt kein Feld namens `scope` -
///   gelesen als `domain` (D_lambda), das einzige Feld, das den
///   Wirkungsbereich eines Feldes beschreibt.
/// - `dependency_profile`: `dependency_profile_ref` ist nicht optional,
///   daher strukturell immer "gesetzt"; ob es auf ein tatsaechlich
///   berechnetes DependencyProfile zeigt (M10, das seinerseits erst nach
///   M09 im Pass laeuft, siehe Port P13->P14), ist von aussen zu bezeugen.
/// - `budget`, `rollback`, `lineage`: die jeweilige Zeichenkette ist nicht
///   leer.
///
/// Dies wertet KEIN Gate aus (G-MORPH gehoert M20, WP07 kennt nur M08/M09):
/// eine reine Bereitschaftspruefung, unabhaengig davon, wer die
/// Gate-Entscheidung spaeter trifft.
pub fn check_activation_requirements(
    field: &FieldIdentity,
    dependency_profile_bound: bool,
) -> Result<(), PskError> {
    let positive_marginal_gain = field.marginal_gain.numerator > 0;
    let scope_declared = !field.domain.0.trim().is_empty();
    let budget_declared = !field.budget.0.trim().is_empty();
    let rollback_declared = !field.rollback.0.trim().is_empty();
    let lineage_declared = !field.lineage.0.trim().is_empty();

    let all_met = positive_marginal_gain
        && scope_declared
        && dependency_profile_bound
        && budget_declared
        && rollback_declared
        && lineage_declared;

    if all_met {
        Ok(())
    } else {
        Err(PskError::MorphogenesisViolation)
    }
}

/// Regel 32.7, wortgetreue Rollenbeschreibung je Archetyp - nuetzlich fuer
/// Diagnose/Tooling, nicht Teil einer Struktur.
pub const fn archetype_role(archetype: ArchetypeId) -> &'static str {
    match archetype {
        ArchetypeId::Explorer => "lokalisiert Kandidaten",
        ArchetypeId::Historian => "rekonstruiert Versionen",
        ArchetypeId::Falsifier => "sucht Gegenbelege",
        ArchetypeId::Constructor => "erzeugt den Patch",
        ArchetypeId::Auditor => "prueft den Vertrag",
        ArchetypeId::Integrator => "verklebt oder erzeugt eine Obstruktion",
    }
}

fn state_to_lifecycle(s: field_fsm::State) -> FieldIdentityLifecycleKind {
    match s {
        field_fsm::State::Proposed => FieldIdentityLifecycleKind::Proposed,
        field_fsm::State::Active => FieldIdentityLifecycleKind::Active,
        field_fsm::State::Quiescent => FieldIdentityLifecycleKind::Quiescent,
        field_fsm::State::SplitPending => FieldIdentityLifecycleKind::SplitPending,
        field_fsm::State::MergePending => FieldIdentityLifecycleKind::MergePending,
        field_fsm::State::Folded => FieldIdentityLifecycleKind::Folded,
        field_fsm::State::Retired => FieldIdentityLifecycleKind::Retired,
        field_fsm::State::Excised => FieldIdentityLifecycleKind::Excised,
    }
}

fn lifecycle_to_state(l: FieldIdentityLifecycleKind) -> field_fsm::State {
    match l {
        FieldIdentityLifecycleKind::Proposed => field_fsm::State::Proposed,
        FieldIdentityLifecycleKind::Active => field_fsm::State::Active,
        FieldIdentityLifecycleKind::Quiescent => field_fsm::State::Quiescent,
        FieldIdentityLifecycleKind::SplitPending => field_fsm::State::SplitPending,
        FieldIdentityLifecycleKind::MergePending => field_fsm::State::MergePending,
        FieldIdentityLifecycleKind::Folded => field_fsm::State::Folded,
        FieldIdentityLifecycleKind::Retired => field_fsm::State::Retired,
        FieldIdentityLifecycleKind::Excised => field_fsm::State::Excised,
    }
}

/// Ergebnis eines Lebenszyklusschritts. Da `lifecycle` Teil von Can() ist
/// (volatile_fields.yaml schliesst es nicht aus), aendert jeder Uebergang
/// die Objekt-ID (Definition 6.6) - `Allowed` traegt deshalb ein
/// vollstaendig neues Objekt, keine Mutation. Die Verkettung zum
/// Vorgaenger ist Sache von `lineage` (Lin_lambda), nicht der ID.
#[derive(Debug, Clone, PartialEq)]
pub enum LifecycleStep {
    Allowed(Box<FieldIdentity>),
    RequiresGate {
        to: FieldIdentityLifecycleKind,
        gate: &'static str,
    },
}

/// Baut das Nachfolgeobjekt fuer einen Lebenszyklusschritt nach `to` - der
/// Teil, den sowohl der ungegatete Zweig von `advance()` als auch M20
/// (nach bestandenem G-MORPH/G-EXCISION, siehe `morphogenesis`-Modul)
/// braucht. Oeffentlich fuer M20: M20 wertet das Gate selbst aus
/// (`psk_gate::evaluate_gate`, Gate-Owner laut gate_registry.yaml), aber
/// nur M08 (dieses Modul) konstruiert FieldIdentity-Objekte - Vertrag 3.4
/// (Ownership-Exklusivitaet).
pub fn complete_transition(
    field: &FieldIdentity,
    to: FieldIdentityLifecycleKind,
) -> Result<FieldIdentity, PskError> {
    let draft = FieldIdentity {
        lifecycle: to,
        ..field.clone()
    };
    let (id, _record) = compute_identity(&draft)?;
    Ok(FieldIdentity { id, ..draft })
}

/// M08: versucht `operator` auf `field` anzuwenden. Nutzt FSM-FIELD
/// (`psk_types::automata::field::step`) fuer die strukturelle
/// Zulaessigkeit; wertet kein Gate aus (siehe Modulkopf). `enabled_ra_ext`
/// schaltet RA-Erweiterungen zu (Prinzip 4.3 C_PSK) - leer laesst nur den
/// Kern zu.
pub fn advance(
    field: &FieldIdentity,
    operator: &str,
    enabled_ra_ext: &[&str],
) -> Result<LifecycleStep, PskError> {
    let from = lifecycle_to_state(field.lifecycle);
    let outcome = field_fsm::step(from, operator, enabled_ra_ext)
        .map_err(|_| PskError::MorphogenesisViolation)?;

    Ok(match outcome {
        StepOutcome::RequiresGate { to, gate } => LifecycleStep::RequiresGate {
            to: state_to_lifecycle(to),
            gate,
        },
        StepOutcome::Allowed { to } => {
            let field = complete_transition(field, state_to_lifecycle(to))?;
            LifecycleStep::Allowed(Box::new(field))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> FieldRegistrationInputs {
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
        }
    }

    /// I-FIELD-001, zweite Schreibstelle (M08). Der Einzelfall ist
    /// gepruft; der Mengenfall NICHT - siehe conformance_catalog.rs.
    #[test]
    fn t_field_001_a_field_whose_id_equals_the_system_identity_is_refused() {
        // Die Feld-ID folgt aus dem Inhalt, ist also nicht frei setzbar.
        // Der Test dreht das um: er registriert einmal regulaer, nimmt die
        // entstandene ID als Systemidentitaet und registriert DASSELBE
        // Feld erneut - dann sind beide per Konstruktion gleich.
        let first = register_field(ArchetypeId::Explorer, sample_inputs()).unwrap();

        let mut colliding = sample_inputs();
        colliding.system_identity = first.id.digest;
        assert_eq!(
            register_field(ArchetypeId::Explorer, colliding),
            Err(PskError::SelfAmendmentWithoutIdentity),
            "I-FIELD-001: keine Feldidentitaet DARF gleich der Systemidentitaet sein"
        );
    }

    #[test]
    fn an_ordinary_system_identity_does_not_block_registration() {
        // Gegenprobe: ohne sie waere der Test oben auch gruen, wenn
        // register_field grundsaetzlich abwiese.
        assert!(register_field(ArchetypeId::Explorer, sample_inputs()).is_ok());
    }

    #[test]
    fn registration_starts_proposed_with_unmeasured_gain() {
        let field = register_field(ArchetypeId::Explorer, sample_inputs()).unwrap();
        assert_eq!(field.lifecycle, FieldIdentityLifecycleKind::Proposed);
        assert_eq!(field.marginal_gain.numerator, 0);
        assert_eq!(field.marginal_gain.scale, 0);
        assert_eq!(field.archetype, ArchetypeId::Explorer);
    }

    #[test]
    fn all_six_archetypes_are_registrable_and_distinct_ids() {
        // Regel 32.7: "Genau sechs statische Feldidentitaeten."
        assert_eq!(ArchetypeId::ALL.len(), 6);
        let ids: Vec<_> = ArchetypeId::ALL
            .iter()
            .map(|a| register_field(*a, sample_inputs()).unwrap().id)
            .collect();
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            6,
            "verschiedene Archetypen muessen verschiedene FieldIdentity-IDs ergeben"
        );
    }

    #[test]
    fn construction_is_deterministic() {
        let a = register_field(ArchetypeId::Auditor, sample_inputs()).unwrap();
        let b = register_field(ArchetypeId::Auditor, sample_inputs()).unwrap();
        assert_eq!(a.id, b.id);
    }

    #[test]
    fn activation_requirements_reject_unmeasured_gain() {
        let field = register_field(ArchetypeId::Integrator, sample_inputs()).unwrap();
        // marginal_gain ist "0" (noch nicht gemessen) - positive_marginal_gain
        // scheitert also selbst wenn alles andere erfuellt ist.
        assert_eq!(
            check_activation_requirements(&field, true),
            Err(PskError::MorphogenesisViolation)
        );
    }

    #[test]
    fn activation_requirements_pass_once_all_six_are_met() {
        let mut field = register_field(ArchetypeId::Integrator, sample_inputs()).unwrap();
        field.marginal_gain = Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: 42,
            scale: 2,
        };
        assert_eq!(check_activation_requirements(&field, true), Ok(()));
    }

    #[test]
    fn activation_requirements_reject_unbound_dependency_profile() {
        let mut field = register_field(ArchetypeId::Historian, sample_inputs()).unwrap();
        field.marginal_gain = Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: 1,
            scale: 0,
        };
        assert_eq!(
            check_activation_requirements(&field, false),
            Err(PskError::MorphogenesisViolation)
        );
    }

    #[test]
    fn activate_from_proposed_requires_g_morph() {
        let field = register_field(ArchetypeId::Falsifier, sample_inputs()).unwrap();
        assert_eq!(
            advance(&field, "activate", &[]).unwrap(),
            LifecycleStep::RequiresGate {
                to: FieldIdentityLifecycleKind::Active,
                gate: "G-MORPH",
            }
        );
    }

    #[test]
    fn excise_from_any_state_requires_g_excision() {
        let field = register_field(ArchetypeId::Constructor, sample_inputs()).unwrap();
        assert_eq!(
            advance(&field, "excise", &[]).unwrap(),
            LifecycleStep::RequiresGate {
                to: FieldIdentityLifecycleKind::Excised,
                gate: "G-EXCISION",
            }
        );
    }

    #[test]
    fn quiesce_and_retire_are_ungated_and_change_identity() {
        let proposed = register_field(ArchetypeId::Explorer, sample_inputs()).unwrap();
        // ACTIVE ist ohne G-MORPH nicht erreichbar (siehe oben) - fuer den
        // ungegateten Teil der Kette wird der Zustand hier als
        // Testfixture gesetzt, nicht ueber advance() erzeugt.
        let active = FieldIdentity {
            lifecycle: FieldIdentityLifecycleKind::Active,
            ..proposed.clone()
        };

        let quiesced = match advance(&active, "quiesce", &[]).unwrap() {
            LifecycleStep::Allowed(f) => f,
            other => panic!("quiesce ist ungegatet, erwartet Allowed, bekam {other:?}"),
        };
        assert_eq!(quiesced.lifecycle, FieldIdentityLifecycleKind::Quiescent);
        assert_ne!(
            quiesced.id, active.id,
            "lifecycle ist Teil von Can() - die ID DARF sich hier aendern"
        );

        let retired = match advance(&quiesced, "retire", &[]).unwrap() {
            LifecycleStep::Allowed(f) => f,
            other => panic!("retire ist ungegatet, erwartet Allowed, bekam {other:?}"),
        };
        assert_eq!(retired.lifecycle, FieldIdentityLifecycleKind::Retired);
    }

    #[test]
    fn reactivate_extension_is_off_by_default() {
        let quiescent = FieldIdentity {
            lifecycle: FieldIdentityLifecycleKind::Quiescent,
            ..register_field(ArchetypeId::Auditor, sample_inputs()).unwrap()
        };
        // RA-EXT-FIELD-01 (reactivate) ist Peripherie (Prinzip 4.3 C_PSK) -
        // ohne explizite Freischaltung existiert kein Weg von QUIESCENT
        // zurueck nach ACTIVE.
        assert!(advance(&quiescent, "reactivate", &[]).is_err());
        assert!(advance(&quiescent, "reactivate", &["RA-EXT-FIELD-01"]).is_ok());
    }

    #[test]
    fn illegal_transition_is_rejected() {
        let field = register_field(ArchetypeId::Explorer, sample_inputs()).unwrap();
        // PROPOSED -> RETIRED gibt es nicht direkt (nur ueber QUIESCENT).
        assert_eq!(
            advance(&field, "retire", &[]),
            Err(PskError::MorphogenesisViolation)
        );
    }
}
