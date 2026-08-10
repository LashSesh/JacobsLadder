//! M15 EffectTokenService, M16 EffectBoundary.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP11 (I6): `token` (M15 - EffectToken-Ausstellung nur bei bestandenem
//! Gate, Invariante 20.4; Idempotenzschluessel aus [run_id, port_id, seq]),
//! `consume` (FSM-TOKEN-Verbrauch, genau einmal). WP12 (I6): `boundary`
//! (M16 - EffectAdapter-Schnittstelle ohne Beobachtungsmethoden, Invariante
//! 20.4 als Ausfuehrungsschwelle). Adaptertrennung (Invariante 20.7 (Adaptertrennung)) und
//! die forbidden_edges [M16,M15]/[M16,M17] siehe Modulkopf von `boundary`.
//!
//! Boot-Realisierung (Algorithmus 17.1, Schritt 17): `registration`
//! (M15 - `register_only_versioned_operators_and_capabilities`).
//!
//! P24a (Prozesstopologie-Realisierung): `process_protocol` - P22/P37
//! ueber eine echte Prozessgrenze (Msg-Rahmen via psk-ipc), aufgerufen
//! sowohl vom `effect-local-fs`-Prozess als auch aus Tests in-process.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod token;
pub use token::{issue, IssueInputs};

mod consume;
pub use consume::{check_not_expired, TokenLedger, TokenState};

mod boundary;
pub use boundary::{execute_effect, EffectAdapter};

mod registration;
pub use registration::{register_only_versioned_operators_and_capabilities, OperatorRegistration};

mod process_adapter;
pub use process_adapter::{ExclusiveLine, ProcessEffectAdapter};

mod process_protocol;
pub use process_protocol::{
    serve_request, EffectApplyRequest, SCHEMA_APPLY_REQUEST, SCHEMA_TOKEN_INVALIDATE,
};
