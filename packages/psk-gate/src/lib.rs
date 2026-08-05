//! M14 AuthorityConsequenceGate.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP11 (I6): `evaluate` - Algorithmus 18.6 (Gate-Auswertung), Axiom 18.3
//! (Fail closed), Invariante 18.7 (Gatebericht immer). Pass C10
//! (Gate and Capability Binding, Vertrag 11.16) wird hier real.
//!
//! v1.0.10: `authorization` - GateAuthorization, der unfaelschbare
//! Nachweis eines bestandenen Gates (T-SEC-001/R-RA-009, Capability-
//! Erzwingung auf Substratebene statt per Konvention). Siehe dortigen
//! Modulkopf.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod evaluate;
pub use evaluate::{digest_of, evaluate_gate, ConditionOutcome, GateInputs};

mod authorization;
pub use authorization::{authorize, GateAuthorization};
