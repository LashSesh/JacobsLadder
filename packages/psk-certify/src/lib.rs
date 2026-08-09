//! M21 CertificateReleaseEngine.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP15 (I7): `certify` - Konformanzleiter (Regel 23.1/Tabelle 23.2),
//! MachineCertificate (Struktur 7.48), G-RELEASE (eigenes Gate, ueber
//! `psk_gate::evaluate_gate`).
//!
//! Boot-Realisierung (Algorithmus 17.1, Schritt 18): `posture`
//! (M21 - `compute_release_and_operational_posture`, Definition 31.3).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod certify;
pub use certify::{
    check_minimum_replay_class, compute_conformance_class, evaluate_release_gate,
    issue_certificate, AdditionalAcceptance, CertificateInputs, ObligationPlatformBinding,
};

mod feature_coverage;
pub use feature_coverage::{
    derive_feature_coverage, CoverageDerivation, CoverageFinding, FeatureEvidence, ReplayEvidence,
};

mod posture;
pub use posture::{compute_release_and_operational_posture, PostureInputs};
