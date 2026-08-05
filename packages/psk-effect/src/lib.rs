//! M15 EffectTokenService, M16 EffectBoundary.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP11 (I6): `token` (M15 - EffectToken-Ausstellung nur bei bestandenem
//! Gate, Invariante 20.3; Idempotenzschluessel aus [run_id, port_id, seq]),
//! `consume` (FSM-TOKEN-Verbrauch, genau einmal). WP12 (I6): `boundary`
//! (M16 - EffectAdapter-Schnittstelle ohne Beobachtungsmethoden, Invariante
//! 20.2 als Ausfuehrungsschwelle). Adaptertrennung (Invariante 20.5) und
//! die forbidden_edges [M16,M15]/[M16,M17] siehe Modulkopf von `boundary`.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod token;
pub use token::{issue, IssueInputs};

mod consume;
pub use consume::{check_not_expired, TokenLedger, TokenState};

mod boundary;
pub use boundary::{execute_effect, EffectAdapter};
