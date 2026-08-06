//! EffectAdapter, Sandbox (Struktur 26.1, Schnittstelle 20.5). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kein Portregister-Modul (siehe generierte port_stubs.rs unten): dieses
//! Paket implementiert nur die `EffectAdapter`-Schnittstelle (psk-effect)
//! fuer die Referenzdomaene, WP12/WP15. `apply` ist deshalb von Hand
//! verdrahtet, nicht generiert.
//!
//! P24a (Prozesstopologie-Realisierung): `main.rs` macht dieses Crate
//! zusaetzlich zu einem echten `[[bin]]`-Target - der Effektprozess aus
//! Regel Einzelrechnerbetrieb. Vor P24a war dieses Crate ein reines
//! Library-Crate, ausschliesslich in-process aufgerufen.

mod apply;
pub use apply::LocalFsAdapter;

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
