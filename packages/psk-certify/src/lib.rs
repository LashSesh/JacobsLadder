//! M21 CertificateReleaseEngine.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP15 (I7): `certify` - Konformanzleiter (Regel 23.1/Tabelle 23.2),
//! MachineCertificate (Struktur 7.46), G-RELEASE (eigenes Gate, ueber
//! `psk_gate::evaluate_gate`).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod certify;
pub use certify::{
    check_minimum_replay_class, compute_conformance_class, evaluate_release_gate,
    issue_certificate, AdditionalAcceptance, CertificateInputs,
};
