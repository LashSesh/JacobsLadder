//! M06 ThoughtCompiler: konstruiert ThoughtBody-Objekte (Struktur 7.8,
//! OBJ-THB).
//!
//! Regel 5.10 (Schreibpfad der Statusfelder), Schritt 1: "M06 setzt
//! ThoughtBody.reality_status bei Konstruktion auf UNKNOWN und facticity
//! auf SPECIFIED. Andere Anfangswerte sind unzulaessig." Der Konstruktor
//! nimmt diese beiden Felder deshalb NICHT entgegen - sie sind nicht
//! waehlbar. "ThoughtBody ist nach Konstruktion unveraenderlich": es gibt
//! hier keine Setter, und M07 erhaelt den Koerper nur lesend (P08).
//!
//! Axiom 7.9 (Gedanke ist kein Satz): `claim.text` traegt Prosa, geht aber
//! nicht in Can() ein. Das erledigt pi_vol ueber den `non_canonical`-Eintrag
//! in architecture/volatile_fields.yaml (v1.0.6, Fehlerkorrektur Punkt 8) -
//! hier ist dafuer KEINE Sonderbehandlung noetig und es DARF auch keine
//! zweite geben.

use psk_canon::{identity_projection, object_id, record_digest, Media};
use psk_types::objects::{
    Claim, ConsequenceRef, FactStatus, Lineage, ModelRef, RealityStatus, SortId, ThoughtBody,
    TrajectoryRef, UncertaintyBlock,
};
use psk_types::{Digest, ObjectId, PskError, TraceRef};

/// Eingaben fuer eine ThoughtBody-Konstruktion. `reality_status` und
/// `facticity` fehlen hier absichtlich: Regel 5.10 legt sie fest, sie sind
/// keine Wahl des Aufrufers.
pub struct ThoughtInputs {
    pub anchor_refs: Vec<ObjectId>,
    /// Struktur 7.8: anchor_refs ">= 1, oder explizit unanchored:true".
    pub unanchored: bool,
    pub claim: Claim,
    pub models: Vec<ModelRef>,
    pub trajectories: Vec<TrajectoryRef>,
    pub uncertainty: UncertaintyBlock,
    pub consequences: Vec<ConsequenceRef>,
    pub lineage: Lineage,
    pub trace_ref: TraceRef,
}

/// Vertrag 11.6 (C3): "Fuer jeden Knoten mit directionality = external MUSS
/// eine Ankerreferenz existieren oder unanchored = true explizit gesetzt
/// sein." Struktur 7.8 verlangt dasselbe strukturell fuer jeden
/// ThoughtBody.
fn check_anchoring(inputs: &ThoughtInputs) -> Result<(), PskError> {
    if inputs.anchor_refs.is_empty() && !inputs.unanchored {
        return Err(PskError::MissingAnchor);
    }
    Ok(())
}

/// Die Sorte, unter der ein ThoughtBody adressiert wird.
///
/// Abgeleitet, nicht zitiert: architecture/sort_registry.yaml ordnet
/// Sorten MODULEN zu, nicht Objekten. M06 besitzt genau ein Objekt
/// (ThoughtBody, Kapitel 3.2) und ist Owner genau einer Sorte (S-CTX
/// Context) - daraus folgt die Zuordnung eindeutig. Das Werk stellt sie
/// nirgends woertlich fest; sollte es das spaeter tun, ist dies die eine
/// Stelle, die anzupassen waere.
const THOUGHT_SORT: SortId = SortId::Context;

/// Baut das JSON-Vorbild ohne die selbstreferenzielle `id` und bildet
/// daraus Objekt-ID (Definition 6.6, ueber pi_vol) und record_digest
/// (Definition 6.7). Gleiche Selbstreferenzaufloesung wie beim
/// AnchorSnapshot in psk-anchor.
fn compute_identity(draft: &ThoughtBody) -> Result<(ObjectId, Digest), PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;

    let projected = identity_projection(&bytes, Media::Json)?;
    let oid: ObjectId = object_id(THOUGHT_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok((oid, record_digest(&bytes, Media::Json)?))
}

/// M06: konstruiert einen ThoughtBody. Der zurueckgegebene Koerper ist
/// vollstaendig und unveraenderlich; `reality_status` ist UNKNOWN und
/// `facticity` ist SPECIFIED (Regel 5.10, Schritt 1).
///
/// Die Felder `witness_refs`, `validation_plan_ref` und `gate_refs` bleiben
/// leer bzw. None: ihre Erzeuger sind M12 (WP09, I4), M13 (WP09, I4) und
/// M14 (WP11, I6). Sie hier zu fuellen hiesse, Zeugnisse zu behaupten, die
/// es noch nicht gibt.
pub fn compile_thought(inputs: ThoughtInputs) -> Result<ThoughtBody, PskError> {
    check_anchoring(&inputs)?;

    let draft = ThoughtBody {
        schema: "psk.thought-body/1.0".to_string(),
        id: ObjectId::new(THOUGHT_SORT, Digest::sha256(b"")), // Platzhalter
        anchor_refs: inputs.anchor_refs,
        unanchored: inputs.unanchored,
        claim: inputs.claim,
        models: inputs.models,
        trajectories: inputs.trajectories,
        reality_status: RealityStatus::Unknown,
        facticity: FactStatus::Specified,
        witness_refs: Vec::new(),
        uncertainty: inputs.uncertainty,
        consequences: inputs.consequences,
        validation_plan_ref: None,
        gate_refs: Vec::new(),
        residue_refs: Vec::new(),
        lineage: inputs.lineage,
        trace_ref: inputs.trace_ref,
    };

    let (id, _record) = compute_identity(&draft)?;
    Ok(ThoughtBody { id, ..draft })
}

/// Der record_digest eines fertigen ThoughtBody (Definition 6.7) - ueber
/// das vollstaendige Objekt einschliesslich `claim.text`. Nicht
/// identitaetsbildend, nie Gate-Eingabe (Invariante 6.8).
pub fn thought_record_digest(body: &ThoughtBody) -> Result<Digest, PskError> {
    let bytes = serde_json::to_vec(body).map_err(|_| PskError::CanonicalizationFailed)?;
    record_digest(&bytes, Media::Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{ClaimDirectionalityKind, ClaimExpr};

    fn sample_claim(text: &str) -> Claim {
        Claim {
            text: text.to_string(),
            formal: ClaimExpr("formal(x)".into()),
            directionality: ClaimDirectionalityKind::Internal,
        }
    }

    fn sample_inputs(text: &str) -> ThoughtInputs {
        ThoughtInputs {
            anchor_refs: vec![ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor"))],
            unanchored: false,
            claim: sample_claim(text),
            models: vec![],
            trajectories: vec![],
            uncertainty: UncertaintyBlock("none".into()),
            consequences: vec![],
            lineage: Lineage("root".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        }
    }

    #[test]
    fn rule_5_10_initial_status_is_unknown_and_specified() {
        let body = compile_thought(sample_inputs("egal")).unwrap();
        assert_eq!(body.reality_status, RealityStatus::Unknown);
        assert_eq!(body.facticity, FactStatus::Specified);
    }

    #[test]
    fn axiom_7_8_claim_text_is_not_identity_forming() {
        // "Ein sprachlich identischer Satz DARF mehrere Gedankenkoerper
        // besitzen" - und umgekehrt aendert blosse Umformulierung die
        // Identitaet nicht, solange der kanonische Zustand gleich bleibt.
        let a = compile_thought(sample_inputs("Ein Satz.")).unwrap();
        let b = compile_thought(sample_inputs("Voellig anders formuliert.")).unwrap();
        assert_eq!(
            a.id, b.id,
            "claim.text DARF NICHT in die Objekt-ID eingehen (Axiom 7.9)"
        );
    }

    #[test]
    fn axiom_7_8_claim_text_still_lives_in_the_record_digest() {
        let a = compile_thought(sample_inputs("Ein Satz.")).unwrap();
        let b = compile_thought(sample_inputs("Voellig anders formuliert.")).unwrap();
        assert_ne!(
            thought_record_digest(&a).unwrap(),
            thought_record_digest(&b).unwrap(),
            "im record_digest bleibt claim.text enthalten"
        );
    }

    #[test]
    fn formal_claim_does_change_identity() {
        // Der kanonische Zustand ist claim.formal - der zaehlt sehr wohl.
        let mut inputs_b = sample_inputs("gleicher Text");
        inputs_b.claim.formal = ClaimExpr("formal(y)".into());
        let a = compile_thought(sample_inputs("gleicher Text")).unwrap();
        let b = compile_thought(inputs_b).unwrap();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn unanchored_must_be_explicit() {
        let mut inputs = sample_inputs("ohne Anker");
        inputs.anchor_refs.clear();
        inputs.unanchored = false;
        assert_eq!(compile_thought(inputs), Err(PskError::MissingAnchor));
    }

    #[test]
    fn explicitly_unanchored_is_accepted() {
        let mut inputs = sample_inputs("ohne Anker, aber erklaert");
        inputs.anchor_refs.clear();
        inputs.unanchored = true;
        let body = compile_thought(inputs).unwrap();
        assert!(body.unanchored);
        assert!(body.anchor_refs.is_empty());
    }

    #[test]
    fn later_phase_fields_stay_empty() {
        // witness_refs (M12/I4), validation_plan_ref (M13/I4), gate_refs
        // (M14/I6) duerfen in I3 nichts behaupten.
        let body = compile_thought(sample_inputs("x")).unwrap();
        assert!(body.witness_refs.is_empty());
        assert_eq!(body.validation_plan_ref, None);
        assert!(body.gate_refs.is_empty());
    }

    #[test]
    fn construction_is_deterministic() {
        let a = compile_thought(sample_inputs("x")).unwrap();
        let b = compile_thought(sample_inputs("x")).unwrap();
        assert_eq!(a.id, b.id);
    }
}
