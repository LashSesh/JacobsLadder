//! ObserverAdapter, getrennter Prozess (Struktur 26.1, Schnittstelle 20.3). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP05: `observe` liest die erste Referenzdomaene (Regel 32.4, lokaler
//! Projektordner, read-only) real vom Dateisystem.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod observe;
pub use observe::{observe, ObserveError, ObserverConfig};
