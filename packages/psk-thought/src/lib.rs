//! M06 ThoughtCompiler, M07 RealityTyper.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP06: `thought` (M06, Konstruktion des ThoughtBody), `reality` (M07,
//! Klassifikation als eigenstaendiges Objekt). Der Schreibpfad folgt Regel
//! 5.10: der ThoughtBody ist nach Konstruktion unveraenderlich, der
//! geltende Status lebt im IRNode, und es gibt keinen Port M07 -> M06.
//! Seit v1.0.7 traegt RealityClassification eine eigene Feldstruktur
//! (Struktur 7.10, OBJ-RCL) und ist damit ein kanonisches Objekt, keine
//! blosse Portnutzlast mehr.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod thought;
pub use thought::{compile_thought, thought_record_digest, ThoughtInputs};

mod forecast;
pub use forecast::{ForecastInputs, SealedForecast};

mod reality;
pub use reality::{
    check_promotion, classify, classify_reality, is_imaginary, is_implicit_promotion,
    ClassificationInputs, RealityEvidence,
};
