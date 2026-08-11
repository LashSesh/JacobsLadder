//! `apply(state, result)` (Algorithmus 14.5 (Tick)): faltet ein `DispatchOutcome`
//! in `Sigma`.
//!
//! Eine fruehere Fassung liess Ergebnisse ohne eigene Sigma-Position
//! (Provenance, Projektionen, DependencyProfile, Receipts, ...) mit
//! `Ok(())` fallen - "ihre dauerhafte Spur ist der Trace". Diese
//! Begruendung ist durch die Rueckkehr zu Algorithmus 14.5 (Tick)s woertlicher
//! Form ueberholt: `select(phase, state)` leitet Folgearbeit aus dem
//! Zustand ab, also MUSS jedes Phasenprodukt, das eine spaetere Phase
//! braucht, in Sigma ankommen ("was nicht in Sigma steht, gehoert
//! dorthin, sonst waere es ein Zustand neben dem Zustand"). Neben den
//! Produktsammlungen setzt `apply` die Fortschrittsmarken der
//! Programmeintraege (record gebunden/versiegelt, Kandidat kanonisiert/
//! sortiert/gepraegt, Feld registriert/projiziert, Deponat ingressiert) -
//! genau die Marken, aus denen `select` das noch Anstehende liest.

use crate::{DispatchOutcome, Sigma};
use psk_types::PskError;

/// `state = apply(state, result)`. Nimmt `state` als `&mut` statt per Wert
/// zurueckzugeben - siehe `dispatch.rs`s Modulkopf: die schreibenden Arme
/// mutieren `state.trace`/`state.residues`/`state.gates_and_tokens.ledger`
/// bereits direkt (wo die aufgerufene Funktion das selbst verlangt),
/// `apply()` fuehrt diesen Stil fort statt ihn an einer Stelle zu brechen.
pub fn apply(state: &mut Sigma, outcome: DispatchOutcome) -> Result<(), PskError> {
    match outcome {
        DispatchOutcome::Observed { record, provenance } => {
            let entry = state
                .program
                .records
                .get_mut(record)
                .ok_or(PskError::UntypedInput)?;
            entry.provenance = Some(provenance);
        }
        DispatchOutcome::CandidateNormalized { candidate, digest } => {
            let c = state
                .candidates
                .get_mut(candidate)
                .ok_or(PskError::UntypedInput)?;
            c.canonical_digest = Some(digest);
        }
        DispatchOutcome::CandidateTyped { candidate, sort } => {
            let c = state
                .candidates
                .get_mut(candidate)
                .ok_or(PskError::UntypedInput)?;
            c.sort = Some(sort);
        }
        DispatchOutcome::AnchorSealed { record, anchor } => {
            let entry = state
                .program
                .records
                .get_mut(record)
                .ok_or(PskError::UntypedInput)?;
            entry.anchor_ref = Some(anchor.id);
            state.anchors.push(anchor);
        }
        DispatchOutcome::ThoughtMinted { candidate, body } => {
            let c = state
                .candidates
                .get_mut(candidate)
                .ok_or(PskError::UntypedInput)?;
            c.minted = Some(body.id);
            state.thoughts.push(body);
        }
        DispatchOutcome::RealityClassified(classification) => {
            state.reality_horizon.push(classification)
        }
        DispatchOutcome::FieldRegistered { entry, field } => {
            let e = state
                .program
                .field_family
                .get_mut(entry)
                .ok_or(PskError::UntypedInput)?;
            e.registered = Some(field.id);
            state.fields.push(field);
        }
        DispatchOutcome::LensRouted { entry, projection } => {
            let e = state
                .program
                .field_family
                .get_mut(entry)
                .ok_or(PskError::UntypedInput)?;
            e.projected = Some(projection.id);
            state.projections.push(projection);
        }
        DispatchOutcome::DependencyQuotiented(profile) => state.dependencies.push(profile),
        DispatchOutcome::Assembled(record) => state.assemblies.push(record),
        DispatchOutcome::Glued {
            assembly_index,
            cells,
            outcome,
        } => {
            state.cell_reports.push(crate::CellReportSet {
                assembly_index,
                reports: cells,
            });
            state.glue = Some(outcome);
        }
        DispatchOutcome::ContradictionsIdentified {
            contradictions,
            obstructions,
        } => {
            state.contradictions = Some(contradictions);
            state.obstructions.extend(obstructions);
        }
        DispatchOutcome::CapsuleSealed(capsules) => state.capsules.extend(capsules),
        DispatchOutcome::ChallengeResolved {
            sealed,
            capsule,
            record,
        } => {
            // Die Aufloesung veraendert die Kapsel inhaltlich (Phase,
            // allowed_next) und damit ihre inhaltsadressierte ID -
            // ersetzt wird am Platz der versiegelten, deren ID das
            // Arbeitselement trug.
            match state.capsules.iter_mut().find(|c| c.id == sealed) {
                Some(slot) => *slot = capsule,
                None => state.capsules.push(capsule),
            }
            state.challenges.push(record);
        }
        DispatchOutcome::ValidationChecked { obligations } => {
            state.validation_obligations = Some(obligations)
        }
        DispatchOutcome::ClosureEvaluated(report) => state.closure_reports.push(report),
        DispatchOutcome::CellsClosed {
            assembly_index,
            reports,
        } => state.cell_reports.push(crate::CellReportSet {
            assembly_index,
            reports,
        }),
        DispatchOutcome::GateEvaluated(report) => state.gates_and_tokens.reports.push(report),
        DispatchOutcome::TokenIssued(token) => {
            state.gates_and_tokens.ledger.register(&token);
            state.gates_and_tokens.issued.push(token);
        }
        DispatchOutcome::EffectExecuted(attempt) => state.effects.push(attempt),
        DispatchOutcome::EffectInvalidated { .. } => {}
        DispatchOutcome::ReceiptIngressed { deposit, receipt } => {
            let d = state
                .program
                .receipt_deposits
                .get_mut(deposit)
                .ok_or(PskError::UntypedInput)?;
            d.ingressed = true;
            state.receipts.push(receipt);
        }
        DispatchOutcome::Reconciled(report) => state.reconciliations.push(report),
        DispatchOutcome::ResiduesGathered(_) => {
            state.archive_watermark = state.residues.all().len() as u64;
        }
    }
    Ok(())
}
