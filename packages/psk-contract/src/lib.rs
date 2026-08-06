//! M00 ConstitutionLoader, M02 ArtifactRegistry, M04 IdentityBinder.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1).
//!
//! Boot-Realisierung (Algorithmus 17.1): `store_lock` (Schritt 1), `load`
//! (M00, Schritt 2), `artifact_registry` (M02, Schritt 3, deckt zugleich
//! den architekturseitigen Anteil von Schritt 7 sowie Schritte 10/11 ab),
//! `identity_binder` (M04, Schritte 12-13, inklusive `implementation_id`/
//! `runtime_state_digest`), `boot` (der vollstaendige 21-Schritt-
//! Orchestrator, Schritt 19 ueber `psk_gate::evaluate_gate` gegen
//! G-BOOT). M03 (SchemaValidator) ist laut module_map.yaml `package:
//! psk-types` - kein eigenes Modul hier, siehe `artifact_registry`s
//! Modulkopf.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod store_lock;
pub use store_lock::{acquire_store_lock, StoreLock};

mod load;
pub use load::{load, BundleImage};

mod artifact_registry;
pub use artifact_registry::{
    resolve_artifact_registry, resolve_artifact_registry_at, ArtifactRegistry,
};

mod identity_binder;
pub use identity_binder::{
    bind, build_digest, build_runtime_manifest, check_profile_binding, implementation_id,
    runtime_state_digest,
};

mod boot;
pub use boot::{boot, default_inputs, BootInputs, BootReport};
