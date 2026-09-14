//! M27 ObservabilityProjector.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP15 (I7): `observe` - Persona (Axiom 7.20), ViewArtifact (Struktur
//! 7.1, Speicherklasse none), read-only Inspect ueber psk-trace.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod observe;
pub use observe::{inspect_residue, inspect_trace_head, Persona, ViewArtifact};
