//! M25 Scheduler.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP14 (I5): `select` (Regel 14.5 - Prioritaetsordnung, total und
//! replaystabil), `budget` (Struktur 14.10/Vertrag 14.11 - Ressourcen- und
//! Risikobudgets, HOLD statt stillem Saettigen).
//!
//! v1.0.19-Umsetzung: Algorithmus 14.4 (Tick) selbst, jetzt real. `sigma`
//! (Sigma, Definition 13.1), `dispatch` (die Taktschleife ruft je Phase in
//! die real vorhandenen Modulfunktionen hinein - siehe dortigen Kopf fuer
//! die Empfaenger-Tabelle je Phase) und `tick` (die Schleife selbst,
//! `select`/`charge`/`dispatch`/`apply`/M19 zusammensetzend).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod select;
pub use select::{select, PriorityTier, SchedulableItem};

mod budget;
pub use budget::{
    charge, charge_risk, BudgetLedger, ChargeOutcome, ResourceClass, ResourceKind, RiskClass,
};

mod sigma;
pub use sigma::{GatesAndTokens, Sigma};

mod dispatch;
pub use dispatch::{dispatch, DispatchOutcome, DispatchResult, PendingWork};

mod apply;
pub use apply::apply;

mod tick;
pub use tick::{tick, QueuedItem};
