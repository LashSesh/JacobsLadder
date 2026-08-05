//! M26 LifecycleSupervisor.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP14 (I5): `runtime` (FSM-RUNTIME-Uebergaenge, Automat 13.2, Invariante
//! 13.3 - kein Textzustandsuebergang), `recovery` (Algorithmus 17.6,
//! Axiom 17.7 - kein Ausgang "nicht geschehen"), `boot_policy` (Regel
//! 17.2, die vier festen Reaktionen). Algorithmus 17.1/17.4 (boot()/
//! shutdown() als Ganzes) orchestrieren M00-M04, M14, M15, M19, M21, von
//! denen ausserhalb dieses WP nur M19 real ist; diese Orchestrierung wird
//! hier nicht nachgebildet (siehe Modulkopf von `recovery`).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod runtime;
pub use runtime::{advance, RuntimeState, RuntimeStep};

mod recovery;
pub use recovery::{classify_open_effect, plan_recovery, EffectRecoveryState, RecoveryPlan};

mod boot_policy;
pub use boot_policy::{decide, BootOutcome, BootSituation};
