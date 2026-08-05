//! M10 DependencyAnalyzer.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP08 (I4): `quotient` (M10, Pass C6 - Abhaengigkeitsquotient nach
//! Algorithmus 11.9, Anti-Echokammer nach Invariante 11.10).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod quotient;
pub use quotient::{
    check_independent_witness_count, dependency_quotient, QuotientInputs, RankMethod,
};
