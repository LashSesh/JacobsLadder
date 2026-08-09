//! M19 TraceReplayResidueStore, Laufteil: RunDescriptor (Struktur 7.45,
//! OBJ-RUN) und ReplayManifest (Struktur 22.5, OBJ-RPM).

use psk_canon::{can, Media};
use psk_types::objects::{
    CanonicalizationProfile, ComponentId, EnvironmentProfile, NDBudget, OpId, SemVer,
};
use psk_types::{Digest, PskError, RunId};
use std::collections::BTreeMap;

pub use psk_types::objects::RunDescriptor;

/// Eingaben fuer `open_run`. `digest` fehlt: er folgt aus den uebrigen
/// Feldern (Selbstreferenzausschluss, gleiches Muster wie AnchorSnapshot).
pub struct RunInputs {
    pub run_id: RunId,
    pub i_c: Digest,
    pub i_a: Digest,
    pub i_m: Digest,
    pub seed: [u8; 32],
    pub versions: BTreeMap<ComponentId, SemVer>,
    pub input_digests: Vec<Digest>,
    pub operators: Vec<OpId>,
    pub environment: EnvironmentProfile,
    pub time_window: psk_types::objects::TimeWindow,
    pub nondeterminism_budget: NDBudget,
    /// Regel 12.7 (v1.0.26): das Rundenbudget des adversarialen Ratchets,
    /// "im RunDescriptor erzwungen" - deklariert, nicht geraten.
    pub ratchet_max_rounds: u32,
    pub canon: CanonicalizationProfile,
}

fn compute_digest(without_own_digest: &RunDescriptor) -> Result<Digest, PskError> {
    let mut value =
        serde_json::to_value(without_own_digest).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("digest");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(can(&bytes, Media::Json)?.digest())
}

/// Bindet einen neuen Lauf (Boot-Schritt 12/13, `M04.bind` - hier nur die
/// RunDescriptor-Konstruktion, nicht die Identitaetsbindung selbst, die
/// M04/psk-contract gehoert).
pub fn open_run(inputs: RunInputs) -> Result<RunDescriptor, PskError> {
    let draft = RunDescriptor {
        schema: "psk.run-descriptor/1.0".to_string(),
        run_id: inputs.run_id,
        I_C: inputs.i_c,
        I_A: inputs.i_a,
        I_M: inputs.i_m,
        seed: inputs.seed,
        versions: inputs.versions,
        input_digests: inputs.input_digests,
        operators: inputs.operators,
        environment: inputs.environment,
        time_window: inputs.time_window,
        nondeterminism_budget: inputs.nondeterminism_budget,
        ratchet_max_rounds: inputs.ratchet_max_rounds,
        canon: inputs.canon,
        digest: Digest::sha256(b""), // Platzhalter
    };
    let digest = compute_digest(&draft)?;
    Ok(RunDescriptor { digest, ..draft })
}

pub use psk_types::objects::{
    DivergenceRecord, ExternalRecordRef, ReplayManifest,
    ReplayManifestAchievedClassKind as ReplayClass,
};

/// Definition 22.1 (Replayklassen), die Bedingungen fuer R1-R3 aus
/// Algorithmus 22.3s `ReplayResult` gelesen: `canonical_digest_match` und
/// `gate_sequence_match` sind seine beiden Felder; "byteidentische
/// Artefakte" (R3) ist danach ein WEITERER, in `ReplayResult` nicht
/// enthaltener Vergleich (Rohartefakte statt kanonischer Zustand) und
/// deshalb ein eigenes Feld hier.
///
/// R0 ("beschrieben, aber nicht maschinell rekonstruierbar") ist kein
/// Ergebnis eines Replayversuchs, sondern dessen Abwesenheit - deshalb
/// `replay_attempted`, nicht aus den beiden Matches ableitbar.
pub struct ReplayCheck {
    pub replay_attempted: bool,
    pub canonical_digest_match: bool,
    pub gate_sequence_match: bool,
    pub byte_identical_artifacts: bool,
}

/// Definition 22.1 als Entscheidungsfunktion.
pub fn determine_replay_class(check: &ReplayCheck) -> ReplayClass {
    if !check.replay_attempted {
        return ReplayClass::R0;
    }
    if !(check.canonical_digest_match && check.gate_sequence_match) {
        // "Objektgraph und Entscheidungen rekonstruierbar; Digests duerfen
        // abweichen" - R1 ist der Basisfall eines DURCHGEFUEHRTEN Replays.
        return ReplayClass::R1;
    }
    if check.byte_identical_artifacts {
        ReplayClass::R3
    } else {
        ReplayClass::R2
    }
}

/// Vertrag 22.2: "Ein Referenzrelease MUSS mindestens R2 erreichen."
pub fn check_reference_release_class(achieved: ReplayClass) -> Result<(), PskError> {
    if matches!(achieved, ReplayClass::R2 | ReplayClass::R3) {
        Ok(())
    } else {
        Err(PskError::UnboundNondeterminismOrDivergence)
    }
}

/// Baut das ReplayManifest (Struktur 22.5). Traegt - anders als
/// RunDescriptor - kein eigenes `digest`-Feld: sein Digest wird von
/// aussen ueber `record_digest`/Can() gebildet (siehe
/// MachineCertificate.replay_manifest_digest) und hier nicht vorweggenommen.
#[allow(clippy::too_many_arguments)]
pub fn build_replay_manifest(
    run_id: RunId,
    run_descriptor_digest: Digest,
    input_digests: Vec<Digest>,
    external_records: Vec<ExternalRecordRef>,
    trace_head: Digest,
    final_canonical_digest: Digest,
    gate_sequence_digest: Digest,
    check: &ReplayCheck,
    divergences: Vec<DivergenceRecord>,
) -> ReplayManifest {
    ReplayManifest {
        run_id,
        run_descriptor_digest,
        input_digests,
        external_records,
        trace_head,
        final_canonical_digest,
        gate_sequence_digest,
        achieved_class: determine_replay_class(check),
        divergences,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_inputs() -> RunInputs {
        RunInputs {
            run_id: RunId("run-0".into()),
            i_c: Digest::sha256(b"ic"),
            i_a: Digest::sha256(b"ia"),
            i_m: Digest::sha256(b"im"),
            seed: [7u8; 32],
            versions: BTreeMap::new(),
            input_digests: vec![Digest::sha256(b"input")],
            operators: vec![OpId::Replay],
            environment: EnvironmentProfile("test-env".into()),
            time_window: psk_types::objects::TimeWindow("PT1H".into()),
            nondeterminism_budget: NDBudget("none".into()),
            ratchet_max_rounds: 4,
            canon: CanonicalizationProfile("psk.canon/1.0".into()),
        }
    }

    #[test]
    fn run_descriptor_digest_is_self_referential_free() {
        let rd = open_run(sample_inputs()).unwrap();
        assert_ne!(rd.digest, Digest::sha256(b""));
    }

    #[test]
    fn run_descriptor_is_deterministic() {
        let a = open_run(sample_inputs()).unwrap();
        let b = open_run(sample_inputs()).unwrap();
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn different_seed_changes_the_digest() {
        let a = open_run(sample_inputs()).unwrap();
        let mut inputs_b = sample_inputs();
        inputs_b.seed = [9u8; 32];
        let b = open_run(inputs_b).unwrap();
        assert_ne!(a.digest, b.digest);
    }

    #[test]
    fn no_attempt_is_r0() {
        let check = ReplayCheck {
            replay_attempted: false,
            canonical_digest_match: false,
            gate_sequence_match: false,
            byte_identical_artifacts: false,
        };
        assert_eq!(determine_replay_class(&check), ReplayClass::R0);
    }

    #[test]
    fn attempted_but_diverging_is_r1() {
        let check = ReplayCheck {
            replay_attempted: true,
            canonical_digest_match: false,
            gate_sequence_match: true,
            byte_identical_artifacts: false,
        };
        assert_eq!(determine_replay_class(&check), ReplayClass::R1);
    }

    #[test]
    fn matching_canonical_state_and_gates_is_r2() {
        let check = ReplayCheck {
            replay_attempted: true,
            canonical_digest_match: true,
            gate_sequence_match: true,
            byte_identical_artifacts: false,
        };
        assert_eq!(determine_replay_class(&check), ReplayClass::R2);
    }

    #[test]
    fn additionally_byte_identical_is_r3() {
        let check = ReplayCheck {
            replay_attempted: true,
            canonical_digest_match: true,
            gate_sequence_match: true,
            byte_identical_artifacts: true,
        };
        assert_eq!(determine_replay_class(&check), ReplayClass::R3);
    }

    #[test]
    fn reference_release_requires_at_least_r2() {
        assert_eq!(
            check_reference_release_class(ReplayClass::R1),
            Err(PskError::UnboundNondeterminismOrDivergence)
        );
        assert_eq!(check_reference_release_class(ReplayClass::R2), Ok(()));
        assert_eq!(check_reference_release_class(ReplayClass::R3), Ok(()));
    }

    #[test]
    fn manifest_carries_the_determined_class() {
        let check = ReplayCheck {
            replay_attempted: true,
            canonical_digest_match: true,
            gate_sequence_match: true,
            byte_identical_artifacts: false,
        };
        let manifest = build_replay_manifest(
            RunId("run-0".into()),
            Digest::sha256(b"rd"),
            vec![],
            vec![],
            Digest::sha256(b"head"),
            Digest::sha256(b"final"),
            Digest::sha256(b"gates"),
            &check,
            vec![],
        );
        assert_eq!(manifest.achieved_class, ReplayClass::R2);
    }
}
