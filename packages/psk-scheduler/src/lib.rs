//! M25 Scheduler.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP14 (I5): `select` (Regel 14.5 - Prioritaetsordnung, total und
//! replaystabil), `budget` (Struktur 14.10/Vertrag 14.11 - Ressourcen- und
//! Risikobudgets, HOLD statt stillem Saettigen). Algorithmus 14.4 (Tick)
//! selbst - die Taktschleife ueber M25.select/M25.charge und dispatch() -
//! orchestriert ueber M19/M23 und weitere noch nicht gebaute Module und
//! wird hier nicht nachgebildet.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod select;
pub use select::{select, PriorityTier, SchedulableItem};

mod budget;
pub use budget::{
    charge, charge_risk, BudgetLedger, ChargeOutcome, ResourceClass, ResourceKind, RiskClass,
};
