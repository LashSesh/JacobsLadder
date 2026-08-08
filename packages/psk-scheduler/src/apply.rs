//! `apply(state, result)` (Algorithmus 14.4): faltet ein `DispatchOutcome`
//! in `Sigma`.
//!
//! Nur die Sammlungen, die tatsaechlich eine der elf Sigma_t-Positionen
//! (oder `capsules`, siehe `sigma.rs`) sind, wachsen hier. Ergebnisse ohne
//! eigene Sigma-Position (Provenance, kanonisierte Bytes, FieldProjection/
//! ResidueRecord aus `route_lens`, DependencyProfile, ClosureReport,
//! ExternalReceipt, ReconciliationReport, die gesammelten offenen
//! ResidueRecord-IDs aus Archive) sind bereits ueber `result.trace_segments`
//! dauerhaft gespurt (von `tick()` vor diesem Aufruf angehaengt) - ihre
//! einzige Wirkung hier ist deshalb `Ok(())`, keine zusaetzliche, sonst
//! nirgends benannte Sigma-Sammlung.

use crate::{DispatchOutcome, Sigma};
use psk_types::PskError;

/// `state = apply(state, result)`. Nimmt `state` als `&mut` statt per Wert
/// zurueckzugeben - siehe `dispatch.rs`s Modulkopf: `dispatch()` mutiert
/// `state.trace`/`state.residues`/`state.gates_and_tokens.ledger` bereits
/// direkt (wo die aufgerufene Funktion das selbst verlangt), `apply()`
/// fuehrt diesen Stil fort statt ihn an einer Stelle zu brechen.
pub fn apply(state: &mut Sigma, outcome: DispatchOutcome) -> Result<(), PskError> {
    match outcome {
        DispatchOutcome::Observed(_) => {}
        DispatchOutcome::Normalized(_) => {}
        DispatchOutcome::ThoughtCompiled(body) => state.thoughts.push(body),
        DispatchOutcome::AnchorSealed(anchor) => state.anchors.push(anchor),
        DispatchOutcome::RealityClassified(classification) => {
            state.reality_horizon.push(classification)
        }
        DispatchOutcome::FieldRegistered(field) => state.fields.push(field),
        DispatchOutcome::LensRouted(_) => {}
        DispatchOutcome::DependencyQuotiented(_) => {}
        DispatchOutcome::CapsuleSealed(capsule) => state.capsules.push(capsule),
        DispatchOutcome::CapsuleRatcheted { capsule, .. } => {
            match state.capsules.iter_mut().find(|c| c.id == capsule.id) {
                Some(slot) => *slot = capsule,
                None => state.capsules.push(capsule),
            }
        }
        DispatchOutcome::ClosureEvaluated(_) => {}
        DispatchOutcome::GateEvaluated(report) => state.gates_and_tokens.reports.push(report),
        DispatchOutcome::TokenIssued(token) => {
            state.gates_and_tokens.ledger.register(&token);
            state.gates_and_tokens.issued.push(token);
        }
        DispatchOutcome::EffectExecuted(attempt) => state.effects.push(attempt),
        DispatchOutcome::EffectInvalidated { .. } => {}
        DispatchOutcome::ReceiptBuilt(_) => {}
        DispatchOutcome::Reconciled(_) => {}
        DispatchOutcome::ResiduesGathered(_) => {}
    }
    Ok(())
}
