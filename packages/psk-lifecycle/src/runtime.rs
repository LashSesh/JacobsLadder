//! M26 LifecycleSupervisor, FSM-RUNTIME-Uebergaenge (Automat 13.2).
//!
//! Anders als FieldIdentity (psk-fields::registry) traegt der Laufzustand
//! kein kanonisches Objekt mit eigener ObjectId - Sigma (Definition 13.1)
//! ist Laufzeitzustand, kein inhaltsadressiertes Kapitel-7-Objekt. Ein
//! Uebergang ist deshalb keine Neukonstruktion, sondern schlicht der neue
//! Zustandswert; es gibt hier keine Identitaet, die sich "aendern" koennte.
//!
//! Invariante 13.3 (Keine Textzustandsuebergaenge): "Kein Laufzeitzustand
//! DARF durch von einem Sprachmodell erzeugten Text erreicht oder
//! uebersprungen werden. Jeder Uebergang erfordert einen Operator und
//! einen GateReport." `advance` erzwingt das strukturell: es gibt keinen
//! Pfad zu einem neuen `State`, der nicht durch `step()` (also einen
//! benannten `operator`) lief.

use psk_types::automata::runtime as runtime_fsm;
use psk_types::automata::StepOutcome;
use psk_types::PskError;

pub use runtime_fsm::State as RuntimeState;

/// Ergebnis eines Uebergangsversuchs - siehe psk-fields::registry::LifecycleStep
/// fuer dasselbe Muster bei FieldIdentity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeStep {
    Allowed(RuntimeState),
    RequiresGate {
        to: RuntimeState,
        gate: &'static str,
    },
}

/// M26: versucht `operator` auf den aktuellen Laufzeitzustand anzuwenden.
/// FSM-RUNTIME fuehrt keine RA-Erweiterungen (Prinzip 4.3 C_PSK) - der
/// Kern ist hier vollstaendig.
pub fn advance(from: RuntimeState, operator: &str) -> Result<RuntimeStep, PskError> {
    match runtime_fsm::step(from, operator, &[]) {
        Ok(StepOutcome::Allowed { to }) => Ok(RuntimeStep::Allowed(to)),
        Ok(StepOutcome::RequiresGate { to, gate }) => Ok(RuntimeStep::RequiresGate { to, gate }),
        Err(_) => Err(PskError::MorphogenesisViolation),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_requires_g_boot() {
        assert_eq!(
            advance(runtime_fsm::INITIAL, "bind_identity"),
            Ok(RuntimeStep::RequiresGate {
                to: RuntimeState::Bound,
                gate: "G-BOOT"
            })
        );
    }

    #[test]
    fn resume_from_hold_requires_g_resume() {
        assert_eq!(
            advance(RuntimeState::Hold, "resume"),
            Ok(RuntimeStep::RequiresGate {
                to: RuntimeState::Ready,
                gate: "G-RESUME"
            })
        );
    }

    #[test]
    fn shutdown_from_any_state_requires_g_shutdown() {
        assert_eq!(
            advance(RuntimeState::Executing, "shutdown"),
            Ok(RuntimeStep::RequiresGate {
                to: RuntimeState::Stopped,
                gate: "G-SHUTDOWN"
            })
        );
    }

    #[test]
    fn booting_cannot_skip_straight_to_executing() {
        // FORBIDDEN: BOOTING->EXECUTING. Es gibt aber auch keine
        // deklarierte Transition mit diesem Ziel von BOOTING aus - beide
        // Ausschluesse (kein Operator, verbotene Kante) fuehren hier zum
        // selben Fehler.
        assert_eq!(
            advance(RuntimeState::Booting, "dispatch_tick"),
            Err(PskError::MorphogenesisViolation)
        );
    }

    #[test]
    fn fail_is_the_one_ungated_wildcard_transition() {
        assert_eq!(
            advance(RuntimeState::Executing, "fail"),
            Ok(RuntimeStep::Allowed(RuntimeState::Failed))
        );
    }
}
