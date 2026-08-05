//! M19 TraceReplayResidueStore.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP04 (I5): `trace` (TraceSegment, Struktur 7.38 - hashverkettetes,
//! ausschliesslich anhaengendes Log, Invariante 4.8), `residue`
//! (ResidueRecord, Struktur 7.40 - Axiom 7.41 No Silent Loss), `run`
//! (RunDescriptor Struktur 7.42, ReplayManifest Struktur 22.5 - C11 wird
//! hier real). Pass C11 (TraceReplayEmission, Vertrag 11.18) besteht aus
//! genau diesen drei Teilen: RunDescriptor, ReplayManifest und der
//! vollstaendige IRBundle-Digest (letzterer entsteht erst mit einem
//! laufenden Compilerdurchlauf, ausserhalb von WP04s Scope).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod trace;
pub use trace::{verify_chain, SegmentInputs, TraceSegment, TraceStore, GENESIS_DIGEST};

mod residue;
pub use residue::{
    residue_digest, ResidueInputs, ResidueLedger, ResidueRecord, ResidueRecordSeverityKind,
    ResidueRecordTypeKind,
};

mod run;
pub use run::{
    build_replay_manifest, check_reference_release_class, determine_replay_class, open_run,
    DivergenceRecord, ExternalRecordRef, ReplayCheck, ReplayClass, ReplayManifest, RunDescriptor,
    RunInputs,
};
