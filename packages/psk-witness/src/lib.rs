//! M12 WitnessEngine, M13 ValidationPlanner.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP09 (I4): `witness` (M12 - EvidenceObject, Scopebindung nach Vertrag
//! 21.2/Invariante 21.3, Okklusionstypisierung nach Invariante 11.12,
//! Evidence-bound Trust nach Regel 21.4), `planner` (M13 - ValidationPlan
//! nach Struktur 21.5, Prioritaetsordnung nach Regel 21.6).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod witness;
pub use witness::{
    check_scope_emission, check_trust_does_not_substitute, classify_absence,
    has_independent_evidence, independence_class_of, make_evidence, trust_weight, typed_absence,
    AbsenceVerdict, EvidenceInputs, OcclusionEvidence, TrustBasis, WitnessReport,
};

mod planner;
pub use planner::{next_step, plan_validation, StepCandidate};
