//! Regel 5.9 (Kandidat und Gedankenkoerper): "Der normative Compilerlauf
//! fuehrt bis einschliesslich C2 die Groesse candidate, nicht ThoughtBody.
//! Ein Kandidat ist eine kanonisierte, sortierte Vorform ohne
//! Objektidentitaet; der ThoughtBody ist das kanonische Objekt und wird
//! fruehestens in C3 gepraegt, sobald der Anker vorliegt oder unanchored
//! ausdruecklich erklaert ist."
//!
//! Der Kandidat traegt deshalb genau drei Fortschrittsmarken - C1
//! (kanonischer Digest, normalize), C2 (Primaersorte, type), Praegung
//! (die ObjectId des gepraegten Koerpers, anchor: "Praegung ebendort") -
//! und KEINE eigene ObjectId: eine Vorform mit Identitaet waere bereits
//! ein Objekt, und Invariante 5.10 (Keine implizite Promotion) verlangt
//! fuer jeden Objektuebergang einen benannten Konstruktor. Der einzige
//! Konstruktor, der aus diesem Kandidaten ein Objekt macht, ist
//! `compile_thought` - die Praegung selbst.
//!
//! `Serialize` ohne `Deserialize`: der Kandidat lebt im Laufzustand Sigma
//! (Definition 13.1 (Laufzustand)) und geht damit in I_t ein; wie Sigma selbst entsteht
//! er nur durch Phasenarbeit, nie durch Einspielen eines fremden Werts.

use psk_types::objects::{
    Claim, ConsequenceRef, Lineage, ModelRef, SortId, TrajectoryRef, UncertaintyBlock,
};
use psk_types::{Digest, ObjectId};

/// Die Vorform aus Regel 5.9 (Kandidat und Gedankenkoerper). Die
/// Quellfelder sind dieselben, die die Praegung spaeter an
/// `ThoughtInputs` weiterreicht - ohne `anchor_refs`/`unanchored`/
/// `trace_ref`, denn genau die kommen erst mit der Praegung (Punkt 1 der
/// Regel: die Forderung "gilt ab der Praegung, nicht fuer den
/// Kandidaten. C1 und C2 verletzen sie nicht, sie beruehren sie nicht").
#[derive(Debug, Clone, serde::Serialize)]
pub struct Candidate {
    pub claim: Claim,
    pub models: Vec<ModelRef>,
    pub trajectories: Vec<TrajectoryRef>,
    pub uncertainty: UncertaintyBlock,
    pub consequences: Vec<ConsequenceRef>,
    pub lineage: Lineage,
    /// C1 (normalize): H(Can(Quellfelder)). None = noch nicht kanonisiert.
    pub canonical_digest: Option<Digest>,
    /// C2 (type): die bestimmte Primaersorte. None = noch nicht sortiert.
    /// Der Realitaetsstatus bleibt davon unberuehrt UNKNOWN - "UNKNOWN
    /// explizit markiert" (Definition 14.2 (Phasen-Modul-Bindung)) ist die Abwesenheit einer
    /// Klassifikation, kein Feld des Kandidaten.
    pub sort: Option<SortId>,
    /// Die Praegung (anchor-Phase, "Praegung ebendort"): ObjectId des
    /// gepraegten ThoughtBody. Kein Rueckverweis vom Koerper auf den
    /// Kandidaten - der Koerper ist inhaltsadressiert und kennt seine
    /// Vorform nicht (Punkt 2 der Regel).
    pub minted: Option<ObjectId>,
}

impl Candidate {
    /// Ein frisch deponierter Auftrag: alle drei Marken leer.
    pub fn new(
        claim: Claim,
        models: Vec<ModelRef>,
        trajectories: Vec<TrajectoryRef>,
        uncertainty: UncertaintyBlock,
        consequences: Vec<ConsequenceRef>,
        lineage: Lineage,
    ) -> Self {
        Candidate {
            claim,
            models,
            trajectories,
            uncertainty,
            consequences,
            lineage,
            canonical_digest: None,
            sort: None,
            minted: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::ClaimDirectionalityKind;

    fn sample() -> Candidate {
        Candidate::new(
            Claim {
                text: "ein Auftrag".into(),
                formal: psk_types::objects::ClaimExpr("f(x)".into()),
                directionality: ClaimDirectionalityKind::Internal,
            },
            vec![],
            vec![],
            UncertaintyBlock("none-declared".into()),
            vec![],
            Lineage("test".into()),
        )
    }

    #[test]
    fn a_fresh_candidate_carries_no_progress_marks() {
        let c = sample();
        assert!(c.canonical_digest.is_none());
        assert!(c.sort.is_none());
        assert!(c.minted.is_none());
    }

    /// Regel 5.9 (Kandidat und Gedankenkörper): der Kandidat hat keine Objektidentitaet. Strukturell
    /// belegt: der Typ hat kein `id`-Feld, und dieser Test haelt fest,
    /// dass seine Serialisierung keines enthaelt - ein spaeteres Feld
    /// dieses Namens fiele hier auf.
    #[test]
    fn a_candidate_has_no_object_identity() {
        let json = serde_json::to_value(sample()).unwrap();
        assert!(json.get("id").is_none());
    }
}
