//! EffectAdapter, Sandbox (Struktur 26.1, Schnittstelle 20.3). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kein Portregister-Modul (siehe generierte port_stubs.rs unten): dieses
//! Paket implementiert nur die `EffectAdapter`-Schnittstelle (psk-effect)
//! fuer die Referenzdomaene, WP12/WP15. `apply` ist deshalb von Hand
//! verdrahtet, nicht generiert.

mod apply;
pub use apply::LocalFsAdapter;

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
