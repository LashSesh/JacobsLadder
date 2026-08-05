//! M17 ExternalRecordIngress: nimmt einen ExternalRecord unvermischt auf
//! und bindet Provenienz (Kapitel 3.2: "Außenrecords unvermischt aufnehmen
//! und provenienzbinden"), bevor er ueber P06 an M05 weitergereicht wird.
//!
//! "Unvermischt": diese Funktion aendert `record` nicht und mischt ihn mit
//! keinem anderen Record - sie fuegt ausschliesslich die Herkunftsangaben
//! hinzu, die Struktur 7.4 (Provenance) verlangt.

use psk_types::objects::{AdapterId, Provenance};
use psk_types::{Digest, PskError};

use crate::external_record::ExternalRecord;

/// Bindet die Provenienz eines ExternalRecord an die konkrete
/// Adapterinstanz, die ihn erzeugt hat. `input_digests` sind die
/// Dateihashes des Records selbst (Struktur 7.4: "MUSS != Effekt-
/// Adapteridentitaet" bezieht sich auf `observer_identity`, siehe
/// `check_observer_separation`).
pub fn bind_provenance(
    record: &ExternalRecord,
    source_adapter: AdapterId,
    observer_identity: Digest,
    method: String,
) -> Provenance {
    Provenance {
        source_adapter,
        observer_identity,
        method,
        input_digests: record
            .file_hashes
            .iter()
            .map(|f| f.content_digest)
            .collect(),
    }
}

/// Struktur 7.4, Provenance.observer_identity: "MUSS != Effekt-
/// Adapteridentitaet" (dieselbe Beobachtertrennung, die Invariante 7.34 fuer
/// ExternalReceipt.observer_identity vs. EffectAttempt.adapter verlangt).
/// `effect_adapter_identity` ist `None`, solange M16 (WP12, Phase I6) keine
/// Effektversuche erzeugt - dann ist die Bedingung vakuos erfuellt, nicht
/// geprueft.
pub fn check_observer_separation(
    observer_identity: Digest,
    effect_adapter_identity: Option<Digest>,
) -> Result<(), PskError> {
    match effect_adapter_identity {
        Some(effect_id) if effect_id == observer_identity => {
            Err(PskError::ActualizationWithoutReconciliation)
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_record::{FileObservation, ObservedPermissions};
    use psk_types::ClockRef;

    fn sample_record() -> ExternalRecord {
        ExternalRecord {
            file_hashes: vec![FileObservation {
                relative_path: "src/lib.rs".into(),
                content_digest: Digest::sha256(b"content"),
            }],
            git_commit: Some("deadbeef".into()),
            observed_at: psk_types::DualTime {
                tau_i: 1,
                tau_e: "2026-01-01T00:00:00Z".into(),
                clock_ref: ClockRef("host".into()),
                uncertainty_ns: 0,
            },
            permissions: ObservedPermissions { read_only: true },
            configuration_digest: Digest::sha256(b"config"),
            allowed_scope: "workspace-root".into(),
        }
    }

    #[test]
    fn bind_provenance_carries_file_hashes_as_input_digests() {
        let record = sample_record();
        let prov = bind_provenance(
            &record,
            AdapterId("observer-local-fs".into()),
            Digest::sha256(b"observer-identity"),
            "sha256_walk".into(),
        );
        assert_eq!(prov.input_digests, vec![Digest::sha256(b"content")]);
    }

    #[test]
    fn separation_check_passes_when_no_effect_adapter_known_yet() {
        assert_eq!(
            check_observer_separation(Digest::sha256(b"observer"), None),
            Ok(())
        );
    }

    #[test]
    fn separation_check_passes_when_identities_differ() {
        assert_eq!(
            check_observer_separation(Digest::sha256(b"observer"), Some(Digest::sha256(b"effect"))),
            Ok(())
        );
    }

    #[test]
    fn separation_check_fails_when_identities_collide() {
        let same = Digest::sha256(b"same-adapter");
        assert_eq!(
            check_observer_separation(same, Some(same)),
            Err(PskError::ActualizationWithoutReconciliation)
        );
    }
}
