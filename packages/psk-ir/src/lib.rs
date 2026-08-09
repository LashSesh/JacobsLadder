//! M23 IRCodec.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kapitel 10 (Zwischenrepraesentation): `ir_encode`/`ir_decode` (Algorithmus
//! 10.3) sind in `codec` real implementiert, inkl. T-IR-001
//! (Round-Trip-Pflicht). `assembly` baut den IRBundle-Kandidaten
//! (Definition 14.2, Compile) unter Regel 10.8 - die Kantenbedingungen
//! kommen von der Domaene, nicht von hier.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod codec;
pub use codec::{ir_decode, ir_encode};

mod assembly;
pub use assembly::{
    assemble_ir_bundle, AssemblyInputs, AssemblyOutcome, EdgeCandidate, EdgeConditionDeclarations,
    EdgeConditions, EdgeOmission,
};
