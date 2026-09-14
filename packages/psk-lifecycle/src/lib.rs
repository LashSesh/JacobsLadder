//! M26 LifecycleSupervisor.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP14 (I5): `runtime` (FSM-RUNTIME-Uebergaenge, Automat 13.2, Invariante
//! 13.3 - kein Textzustandsuebergang), `recovery` (Algorithmus 17.6,
//! Axiom 17.7 - kein Ausgang "nicht geschehen"), `boot_policy` (Regel
//! 17.2, die vier festen Reaktionen). Algorithmus 17.1/17.4 (boot()/
//! shutdown() als Ganzes) orchestrieren M00-M04, M14, M15, M19, M21 - die
//! Orchestrierung selbst realisiert `psk-contract::boot` (Algorithmus
//! 17.1, alle 21 Schritte), das M26s hier gefuehrte `boot_policy`/`runtime`
//! bereits real verwendet.
//!
//! P24a (Prozesstopologie-Realisierung): `process` (M26, `proc.control` -
//! spawnt Effekt-/Beobachterprozess als echte Kindprozesse, siehe dessen
//! Modulkopf fuer die v1.0.13-Praezisierung von Vertrag
//! Herkunftsbeglaubigung an der Prozessgrenze).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod runtime;
pub use runtime::{advance, RuntimeState, RuntimeStep};

mod recovery;
pub use recovery::{classify_open_effect, plan_recovery, EffectRecoveryState, RecoveryPlan};

mod boot_policy;
pub use boot_policy::{decide, BootOutcome, BootSituation};

mod process_common;
pub use process_common::sibling_binary_path;

// `ChildProcess` selbst ist plattformabhaengig (OBL-010, architecture/
// obligations.yaml, deklariert die reale Substraterzwingung bislang nur
// fuer Windows) - `#[path]` waehlt die Implementierung, die oeffentliche
// Oberflaeche (spawn/request/id/shutdown) bleibt auf beiden Zweigen
// identisch, siehe process_windows.rs bzw. process_unsupported.rs.
#[cfg(windows)]
#[path = "process_windows.rs"]
mod process;
#[cfg(not(windows))]
#[path = "process_unsupported.rs"]
mod process;
pub use process::ChildProcess;

#[cfg(windows)]
mod sandbox;
#[cfg(windows)]
pub use sandbox::{lock_down_token, set_directory_low_integrity};
