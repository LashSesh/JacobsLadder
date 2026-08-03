//! M00 ConstitutionLoader, M02 ArtifactRegistry, M04 IdentityBinder.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
