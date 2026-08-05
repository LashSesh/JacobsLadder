//! M26 LifecycleSupervisor, Recovery (Kapitel 17.3, Algorithmus 17.6).
//!
//! Woertlich:
//! ```text
//! function recover(run_id) -> RecoveryPlan:
//!     head = M19.last_valid_trace_segment(run_id)
//!     require chain_valid(head) else QUARANTINE(run_id, PSK-E014)
//!     open_effects = scan_effects_between(head, end_of_trace)
//!     for e in open_effects:
//!         if has_receipt(e): state(e) = RECORDED
//!         else: state(e) = UNKNOWN_EFFECT   // NIEMALS "nicht geschehen"
//!     for e where state(e) == UNKNOWN_EFFECT:
//!         request_independent_observation(e)   // M17
//!         if still_unknown: quarantine(e)
//!     reopen_residues(run_id)
//!     return RecoveryPlan{ resume_from: head, unknown_effects: [...] }
//! ```
//!
//! Axiom 17.7 (Keine Annahme fehlender Wirkung): "Recovery DARF NICHT eine
//! fehlende Wirkung annehmen. Ein begonnener Effekt ohne eindeutigen
//! Receipt wird durch unabhaengige Aussenbeobachtung reconciliert oder
//! bleibt in UNKNOWN_EFFECT beziehungsweise Quarantaene." Das ist der Kern
//! dieses Moduls: `classify_open_effect` hat KEINEN dritten Ausgang
//! "nicht geschehen".
//!
//! `scan_effects_between`, `request_independent_observation` und
//! `reopen_residues` brauchen M16 (EffectBoundary), M17
//! (ExternalRecordIngress-Beobachtung) und M19s Residuenledger jeweils in
//! Betrieb - drei Module, von denen nur M19 mit WP04 real ist. Diese
//! Implementierung deckt deshalb die entscheidbaren Kernstuecke ab:
//! Kettenpruefung (`psk_trace::verify_chain`, hier referenziert, nicht
//! dupliziert), Effektklassifikation und Planzusammenstellung. Die
//! Orchestrierung selbst (`recover()` als Ganzes, mit echten M16/M17-
//! Aufrufen) bleibt unrealisiert, bis diese Module existieren.

use psk_types::{Digest, ObjectId, PskError};

/// `state(e)`: RECORDED oder UNKNOWN_EFFECT - absichtlich kein dritter
/// Wert fuer "nicht geschehen" (Axiom 17.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectRecoveryState {
    Recorded,
    UnknownEffect,
}

/// "if has_receipt(e): state(e) = RECORDED else: state(e) = UNKNOWN_EFFECT"
/// - woertlich, keine dritte Moeglichkeit.
pub fn classify_open_effect(has_receipt: bool) -> EffectRecoveryState {
    if has_receipt {
        EffectRecoveryState::Recorded
    } else {
        EffectRecoveryState::UnknownEffect
    }
}

/// Ergebnis von `recover()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryPlan {
    pub resume_from: Digest,
    pub unknown_effects: Vec<ObjectId>,
}

/// Baut den RecoveryPlan aus bereits klassifizierten offenen Effekten.
///
/// `chain_valid` entspricht `require chain_valid(head) else
/// QUARANTINE(run_id, PSK-E014)` - bei ungueltiger Kette wird nicht
/// geplant, sondern der Lauf quarantaeniert (PSK-E014,
/// trace_or_residue_violation).
pub fn plan_recovery(
    chain_valid: bool,
    resume_from: Digest,
    open_effects: &[(ObjectId, EffectRecoveryState)],
) -> Result<RecoveryPlan, PskError> {
    if !chain_valid {
        return Err(PskError::TraceOrResidueViolation);
    }
    let unknown_effects = open_effects
        .iter()
        .filter(|(_, state)| *state == EffectRecoveryState::UnknownEffect)
        .map(|(id, _)| *id)
        .collect();
    Ok(RecoveryPlan {
        resume_from,
        unknown_effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::SortId;

    fn effect(seed: &[u8]) -> ObjectId {
        ObjectId::new(SortId::Effect, Digest::sha256(seed))
    }

    #[test]
    fn a_receipted_effect_is_recorded_not_unknown() {
        assert_eq!(classify_open_effect(true), EffectRecoveryState::Recorded);
    }

    #[test]
    fn a_receiptless_effect_is_unknown_never_assumed_absent() {
        // Axiom 17.7, woertlich: es gibt keinen dritten Ausgang.
        assert_eq!(
            classify_open_effect(false),
            EffectRecoveryState::UnknownEffect
        );
    }

    #[test]
    fn invalid_chain_quarantines_instead_of_planning() {
        let head = Digest::sha256(b"head");
        assert_eq!(
            plan_recovery(false, head, &[]),
            Err(PskError::TraceOrResidueViolation)
        );
    }

    #[test]
    fn plan_carries_only_the_unknown_effects() {
        let head = Digest::sha256(b"head");
        let recorded = effect(b"a");
        let unknown = effect(b"b");
        let plan = plan_recovery(
            true,
            head,
            &[
                (recorded, EffectRecoveryState::Recorded),
                (unknown, EffectRecoveryState::UnknownEffect),
            ],
        )
        .unwrap();
        assert_eq!(plan.resume_from, head);
        assert_eq!(plan.unknown_effects, vec![unknown]);
    }

    #[test]
    fn no_open_effects_yields_an_empty_but_valid_plan() {
        let head = Digest::sha256(b"head");
        let plan = plan_recovery(true, head, &[]).unwrap();
        assert!(plan.unknown_effects.is_empty());
    }
}
