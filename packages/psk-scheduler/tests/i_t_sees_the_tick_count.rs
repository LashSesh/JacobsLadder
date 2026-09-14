//! Regel 6.10 (Vier Identitäten): "I_t = H(Can(Sigma_t))". Der Test macht eine Konstante an
//! dieser Stelle unmoeglich.
//!
//! Anlass: bis v1.0.38 stand im ausgestellten Zertifikat
//! `Digest::sha256(b"golden-run-i-t")` - eine Konstante an der Stelle
//! einer der vier Systemidentitaeten, und damit ein Zertifikat, das
//! keinen Zustand bezeugt. Fuenfte Instanz der Erfindungsklasse nach
//! Objektzahlen, Testzahl, Kollisionszahl und Registerrueckverweisen -
//! die erste im ausgestellten Artefakt.

use psk_scheduler::{BudgetLedger, Sigma};
use psk_types::objects::{
    CapabilityMatrixRef, ProfileId, RuntimeManifest, RuntimeManifestDeterminismClassKind, Scaled,
};
use psk_types::{Digest, RunId};

fn manifest() -> RuntimeManifest {
    RuntimeManifest {
        schema: "psk.runtime-manifest/1.0".into(),
        constitution_id: Digest::sha256(b"c"),
        architecture_id: Digest::sha256(b"a"),
        implementation_id: Digest::sha256(b"m"),
        profile: ProfileId::Reference,
        capability_matrix: CapabilityMatrixRef("cap/1".into()),
        build_digest: Digest::sha256(b"build"),
        operator_versions: Default::default(),
        adapter_versions: Default::default(),
        determinism_class: RuntimeManifestDeterminismClassKind::R0,
        max_depth: 0,
    }
}

fn budget() -> BudgetLedger {
    BudgetLedger::open(
        RunId("i-t-test".into()),
        1_000,
        1_000,
        1_000,
        1_000,
        1_000,
        1_000,
        1_000,
        Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: 100,
            scale: 2,
        },
    )
}

/// Die vom Auftraggeber benannte Bedingung: zwei Laufzustaende mit
/// VERSCHIEDENER Taktzahl MUESSEN verschiedene I_t haben.
///
/// Eine Konstante bestuende diesen Test nicht - sie waere fuer beide
/// gleich. Damit ist der frueher eingesetzte Literalwert strukturell
/// ausgeschlossen, nicht bloss entfernt.
#[test]
fn two_states_with_different_tick_counts_have_different_identities() {
    let a = Sigma::new(manifest(), budget());
    let mut b = Sigma::new(manifest(), budget());
    b.tick_no = 1;

    let da = psk_scheduler::sigma_digest(&a).expect("I_t von a");
    let db = psk_scheduler::sigma_digest(&b).expect("I_t von b");
    assert_ne!(
        da, db,
        "I_t MUSS die Taktzahl sehen - sonst bezeugt es keinen Zustand"
    );

    // Und die Gegenprobe: derselbe Zustand ergibt denselben Wert.
    // Ohne sie waere die Ungleichheit oben auch mit einem Zufallswert
    // erreichbar, und I_t waere nicht reproduzierbar.
    let da2 = psk_scheduler::sigma_digest(&a).expect("I_t von a, erneut");
    assert_eq!(da, da2, "I_t MUSS reproduzierbar sein");
}
