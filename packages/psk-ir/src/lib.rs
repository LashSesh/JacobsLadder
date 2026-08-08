//! M23 IRCodec.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kapitel 10 (Zwischenrepraesentation): `ir_encode`/`ir_decode` (Algorithmus
//! 10.3) sind in `codec` real implementiert, inkl. T-IR-001
//! (Round-Trip-Pflicht).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod codec;
pub use codec::{compile_ir_bundle, ir_decode, ir_encode};
