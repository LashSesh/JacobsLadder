//! M18 ReconciliationEngine.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP13 (I6): `reconcile` - Algorithmus 20.9. FSM-EFFECT fuehrt
//! RECORDED->RECONCILED->ACTUALIZED bereits ueber G-ACTUALIZATION (seit
//! v1.0.4 Kernautomat); dieses Modul ist die Engine HINTER dem Gate, nicht
//! der Automat selbst.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod reconcile;
pub use reconcile::{plan_digest_of, reconcile, DiffOutcome, ReconcileInputs};
