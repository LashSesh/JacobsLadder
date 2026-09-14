//! ObserverAdapter, getrennter Prozess (Struktur 26.1, Schnittstelle 20.5). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP05: `observe` liest die erste Referenzdomaene (Regel 32.5, lokaler
//! Projektordner, read-only) real vom Dateisystem.
//!
//! P24a (Prozesstopologie-Realisierung): `main.rs` macht dieses Crate zu
//! einem echten `[[bin]]`-Target - "getrennter Prozess" (Titelzeile oben)
//! ist damit real, nicht mehr nur die Zielbeschreibung. Vor P24a war
//! dieses Crate ein reines Library-Crate, ausschliesslich in-process aus
//! `psk-cli`/`psk-conformance` aufgerufen.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod observe;
pub use observe::{observe, observe_history, ObserveError, ObserverConfig};
