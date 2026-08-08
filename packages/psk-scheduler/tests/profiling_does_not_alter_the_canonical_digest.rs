//! T-OBSV-001 (`architecture/ra_tests.yaml`: `{kind: property, run:
//! with_and_without_profiling, expect: identical_canonical_digest}`) und
//! I-ARCH-015 ("profiling_and_logging_do_not_alter_canonical_digest").
//!
//! Geprueft werden beide Schutzschichten aus `psk_scheduler::profiling`
//! getrennt voneinander, damit keine die andere verdeckt:
//!
//! 1. **strukturell** - zwei identische Laeufe, einer mit und einer ohne
//!    Profiling, erzeugen denselben kanonischen Zustand (Tracekopf,
//!    Objekt-IDs, Residuen). Das ist die im Register geforderte Eigenschaft.
//! 2. **registergestuetzt** - `pi_vol` entfernt ein eingebettetes
//!    `runtime_metrics`-Feld tatsaechlich vor der Identitaetsbildung,
//!    waehrend der `record_digest` abweicht (Definition 6.6/6.7). Ohne
//!    diesen zweiten Teil bliebe unbewiesen, dass der Feldname wirklich
//!    traegt und nicht nur zufaellig nirgends serialisiert wird.

use std::collections::BTreeMap;

use psk_canon::{identity_projection, record_digest, Media};
use psk_scheduler::{
    tick, BudgetLedger, PendingWork, PriorityTier, Profiling, QueuedItem, ResourceKind,
    SchedulableItem, Sigma,
};
use psk_trace::{open_run, RunDescriptor, RunInputs};
use psk_types::objects::{
    CanonicalizationProfile, CapabilityMatrixRef, Claim, ClaimDirectionalityKind, ClaimExpr,
    EnvironmentProfile, Lineage, NDBudget, ProfileId, RuntimeManifest,
    RuntimeManifestDeterminismClassKind, Scaled, SortId, UncertaintyBlock,
};
use psk_types::{ClockRef, Digest, DualTime, ObjectId, Phase, RunId, TraceRef};

fn time() -> DualTime {
    DualTime {
        tau_i: 0,
        tau_e: "2026-08-08T00:00:00.000000000Z".into(),
        clock_ref: ClockRef("test".into()),
        uncertainty_ns: 0,
    }
}

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
    }
}

/// Compute-Limit 1: das erste Element laeuft, das zweite faellt ins
/// Budgetresiduum - so deckt EIN Takt beide Zaehler ab
/// (`items_dispatched` und `items_budget_skipped`).
fn budget() -> BudgetLedger {
    BudgetLedger::open(
        RunId("run-0".into()),
        1,
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

fn run_descriptor() -> RunDescriptor {
    open_run(RunInputs {
        run_id: RunId("run-0".into()),
        i_c: Digest::sha256(b"ic"),
        i_a: Digest::sha256(b"ia"),
        i_m: Digest::sha256(b"im"),
        seed: [7u8; 32],
        versions: BTreeMap::new(),
        input_digests: vec![Digest::sha256(b"input")],
        operators: vec![],
        environment: EnvironmentProfile("test-env".into()),
        time_window: psk_types::objects::TimeWindow("PT1H".into()),
        nondeterminism_budget: NDBudget("none".into()),
        canon: CanonicalizationProfile("psk.canon/1.0".into()),
    })
    .unwrap()
}

fn thought_item(seed: &[u8]) -> QueuedItem {
    QueuedItem {
        schedulable: SchedulableItem {
            id: ObjectId::new(SortId::Context, Digest::sha256(seed)),
            tier: PriorityTier::RatchetingCapsule,
            expires_at_tau_i: None,
        },
        cost: (ResourceKind::Compute, 1),
        work: PendingWork::TypeThought(psk_thought::ThoughtInputs {
            anchor_refs: vec![ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor"))],
            unanchored: false,
            claim: Claim {
                text: String::from_utf8_lossy(seed).into_owned(),
                formal: ClaimExpr("formal(x)".into()),
                directionality: ClaimDirectionalityKind::Internal,
            },
            models: vec![],
            trajectories: vec![],
            uncertainty: UncertaintyBlock("none".into()),
            consequences: vec![],
            lineage: Lineage("root".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        }),
    }
}

fn queues() -> BTreeMap<Phase, Vec<QueuedItem>> {
    let mut q = BTreeMap::new();
    q.insert(Phase::Type, vec![thought_item(b"t1"), thought_item(b"t2")]);
    q
}

/// Fuehrt denselben Takt aus und gibt den kanonischen Zustand zurueck, den
/// I-ARCH-015 unveraendert verlangt.
fn run_once(profiling: &mut Profiling) -> (Digest, Vec<ObjectId>, Vec<ObjectId>, usize) {
    let mut sigma = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    tick(&mut sigma, &rd, queues(), time(), profiling).unwrap();

    let thought_ids: Vec<ObjectId> = sigma.thoughts.iter().map(|t| t.id).collect();
    let residue_ids: Vec<ObjectId> = sigma.residues.all().iter().map(|r| r.id).collect();
    (
        sigma.trace.head(),
        thought_ids,
        residue_ids,
        sigma.trace.segments().len(),
    )
}

#[test]
fn t_obsv_001_profiling_on_and_off_yield_the_identical_canonical_digest() {
    // Die im Testregister geforderte Eigenschaft selbst:
    // run: with_and_without_profiling -> expect: identical_canonical_digest.
    let mut off = Profiling::off();
    let mut on = Profiling::on();

    let (head_off, thoughts_off, residues_off, segments_off) = run_once(&mut off);
    let (head_on, thoughts_on, residues_on, segments_on) = run_once(&mut on);

    assert_eq!(
        head_off, head_on,
        "I-ARCH-015: der Tracekopf DARF sich durch Profiling nicht aendern"
    );
    assert_eq!(thoughts_off, thoughts_on, "Objekt-IDs muessen gleich sein");
    assert_eq!(residues_off, residues_on, "Residuen muessen gleich sein");
    assert_eq!(
        segments_off, segments_on,
        "Profiling DARF kein zusaetzliches Tracesegment erzeugen"
    );
}

#[test]
fn the_profiled_run_really_did_collect_something() {
    // Gegenprobe: ohne sie waere der Test oben auch dann gruen, wenn
    // `Profiling::on()` gar nichts aufzeichnete - dann verglichen wir
    // zweimal denselben unprofilierten Lauf.
    let mut off = Profiling::off();
    let mut on = Profiling::on();
    run_once(&mut off);
    run_once(&mut on);

    assert!(
        off.runtime_metrics().is_empty(),
        "ausgeschaltet DARF nichts gesammelt werden"
    );
    assert_eq!(
        on.runtime_metrics().len(),
        12,
        "eingeschaltet MUSS jede der zwoelf Phasen eine Bilanz tragen"
    );

    // Und die Zahlen sind echt, nicht null: ein Element lief, eines fiel
    // ins Budgetresiduum (Compute-Limit 1, zwei Elemente).
    let type_phase = on
        .runtime_metrics()
        .iter()
        .find(|m| m.phase_label == "type")
        .expect("die Type-Phase MUSS eine Bilanz haben");
    assert_eq!(type_phase.items_dispatched, 1);
    assert_eq!(type_phase.items_budget_skipped, 1);
}

#[test]
fn embedded_runtime_metrics_survive_in_the_record_digest_but_not_in_the_identity() {
    // Zweite Schutzschicht, an der ECHTEN Profilingstruktur gepruft:
    // `pi_vol` entfernt `runtime_metrics` vor der Identitaetsbildung
    // (Definition 6.5), der record_digest ueber das vollstaendige Objekt
    // behaelt es (Definition 6.7). Genau die Trennung aus v1.0.5.
    let mut on = Profiling::on();
    run_once(&mut on);
    assert!(!on.runtime_metrics().is_empty(), "Vorbedingung");

    let with_metrics = serde_json::to_vec(&serde_json::json!({
        "schema": "psk.some-object/1.0",
        "kept": "kanonischer Inhalt",
        "runtime_metrics": on.runtime_metrics(),
    }))
    .unwrap();
    let without_metrics = serde_json::to_vec(&serde_json::json!({
        "schema": "psk.some-object/1.0",
        "kept": "kanonischer Inhalt",
    }))
    .unwrap();

    let id_with = identity_projection(&with_metrics, Media::Json).unwrap();
    let id_without = identity_projection(&without_metrics, Media::Json).unwrap();
    assert_eq!(
        id_with, id_without,
        "pi_vol MUSS runtime_metrics vor der Identitaetsbildung entfernen"
    );

    let rec_with = record_digest(&with_metrics, Media::Json).unwrap();
    let rec_without = record_digest(&without_metrics, Media::Json).unwrap();
    assert_ne!(
        rec_with, rec_without,
        "der record_digest DARF abweichen - er sichert die vollstaendigen Bytes"
    );
}

#[test]
fn profiling_data_is_not_reachable_from_sigma_at_all() {
    // Erste Schutzschicht, strukturell: `tick` nimmt `Profiling` als
    // eigenen Parameter, und nichts davon landet in `Sigma`. Der Beweis
    // ist, dass ein voll ausgefuehrter Takt den Schalter fuellt, waehrend
    // derselbe Sigma-Wert bitgleich zu dem eines unprofilierten Laufs
    // bleibt (oben geprueft) - hier zusaetzlich: der Schalter ueberlebt
    // den Aufruf als getrennter Wert, er wurde nicht in Sigma verschoben.
    let mut sigma = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    let mut profiling = Profiling::on();
    tick(&mut sigma, &rd, queues(), time(), &mut profiling).unwrap();

    assert!(profiling.is_enabled());
    assert_eq!(profiling.runtime_metrics().len(), 12);
    // Sigmas eigene Sammlungen tragen ausschliesslich Kapitel-7-Objekte;
    // es gibt kein Feld, ueber das ein Messwert hierher gelangen koennte.
    assert_eq!(sigma.thoughts.len(), 1);
}
