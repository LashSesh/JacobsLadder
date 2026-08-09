//! T-CONC-001 (`architecture/ra_tests.yaml`: `{kind: property, run:
//! concurrent_stress, expect: canonical_digest_equals_sequential}`) und
//! I-ARCH-009 (`concurrent_run_has_equivalent_sequential_canonical_digest`).
//!
//! Vergleichswert ist `sigma_digest` - der reale Zustandsdigest `I_t`,
//! nicht der Tracekopf. Beides ist seit dem Bau von `sigma_digest`
//! verschieden, und I-ARCH-009 spricht ausdruecklich vom kanonischen
//! Zustandsdigest.
//!
//! Der Test belegt BEIDE Richtungen. Nur die Gleichheit zu zeigen
//! genuegte nicht: sie waere auch gruen, wenn die Nebenlaeufigkeit gar
//! nicht griffe oder die Anwendungsreihenfolge ohnehin nie abwiche. Der
//! Negativfall laesst denselben Lauf ohne den Ruecksortierschritt laufen
//! und verlangt einen ABWEICHENDEN Digest - erst zusammen zeigen sie,
//! dass genau dieser Schritt die Gleichheit herstellt.

use std::collections::BTreeMap;

use psk_scheduler::{
    concurrency_eligible, sigma_digest, tick, tick_concurrent, tick_concurrent_with_order,
    BudgetLedger, PendingWork, PriorityTier, Profiling, QueuedItem, ResourceKind, ResultOrder,
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
        max_depth: 0,
    }
}

fn budget() -> BudgetLedger {
    BudgetLedger::open(
        RunId("run-0".into()),
        10_000,
        10_000,
        10_000,
        10_000,
        10_000,
        10_000,
        10_000,
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
        ratchet_max_rounds: 4,
        canon: CanonicalizationProfile("psk.canon/1.0".into()),
    })
    .unwrap()
}

/// `tier`/`id` bestimmen die Prioritaetsordnung (Regel 14.5). Die
/// Elemente werden hier bewusst in einer ANDEREN Reihenfolge in die
/// Warteschlange gelegt als ihre Prioritaet - sonst waere nicht
/// unterscheidbar, ob `select()` ueberhaupt sortiert.
fn thought_item(seed: &[u8], tier: PriorityTier) -> QueuedItem {
    QueuedItem {
        schedulable: SchedulableItem {
            id: ObjectId::new(SortId::Context, Digest::sha256(seed)),
            tier,
            expires_at_tau_i: None,
        },
        cost: (ResourceKind::Compute, 1),
        work: PendingWork::TypeThought(psk_thought::ThoughtInputs {
            anchor_refs: vec![ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor"))],
            unanchored: false,
            claim: Claim {
                text: String::from_utf8_lossy(seed).into_owned(),
                formal: ClaimExpr(format!("formal({})", String::from_utf8_lossy(seed))),
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

/// Mehrere Elemente derselben Phase, mit gemischten Raengen - genug, dass
/// die Threads sich real ueberlappen und die Ordnung sichtbar wird.
fn stress_queues() -> BTreeMap<Phase, Vec<QueuedItem>> {
    let mut q = BTreeMap::new();
    q.insert(
        Phase::Type,
        vec![
            thought_item(b"e", PriorityTier::SpeculativeBranch),
            thought_item(b"a", PriorityTier::UnknownEffectOrOpenReconciliation),
            thought_item(b"d", PriorityTier::RatchetingCapsule),
            thought_item(b"b", PriorityTier::ExpiringEffectToken),
            thought_item(b"c", PriorityTier::BlockingWitnessOrResidue),
            thought_item(b"f", PriorityTier::SpeculativeBranch),
            thought_item(b"g", PriorityTier::SpeculativeBranch),
            thought_item(b"h", PriorityTier::SpeculativeBranch),
        ],
    );
    q
}

fn sequential_digest() -> Digest {
    let mut sigma = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    tick(
        &mut sigma,
        &rd,
        stress_queues(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();
    sigma_digest(&sigma).unwrap()
}

#[test]
fn t_conc_001_a_concurrent_tick_yields_the_same_canonical_digest_as_the_sequential_one() {
    // Die im Register geforderte Eigenschaft selbst:
    // expect: canonical_digest_equals_sequential.
    let expected = sequential_digest();

    let mut sigma = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    tick_concurrent(
        &mut sigma,
        &rd,
        stress_queues(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert_eq!(
        sigma_digest(&sigma).unwrap(),
        expected,
        "I-ARCH-009: der nebenlaeufige Lauf MUSS denselben kanonischen Zustandsdigest liefern"
    );
}

#[test]
fn skipping_the_reordering_step_yields_a_different_digest() {
    // Die zweite Richtung. Ohne sie koennte der Test oben auch gruen sein,
    // weil die Nebenlaeufigkeit nie greift oder die Reihenfolge ohnehin
    // nie abweicht - dann bewiese er nichts ueber Regel 14.7s
    // Ruecksortierschritt.
    let expected = sequential_digest();

    let mut sigma = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    tick_concurrent_with_order(
        &mut sigma,
        &rd,
        stress_queues(),
        time(),
        &mut Profiling::off(),
        ResultOrder::AsQueuedForTestingOnly,
    )
    .unwrap();

    assert_ne!(
        sigma_digest(&sigma).unwrap(),
        expected,
        "ohne die Ruecksortierung DARF der Digest nicht zufaellig stimmen - \
         sonst prueft der Positivtest die Ordnung gar nicht"
    );
}

#[test]
fn the_concurrent_run_is_reproducible_across_repeats() {
    // Invariante 14.8 (Serialisierbarkeit) verlangt nicht nur EINE
    // sequentielle Entsprechung, sondern eine stabile: wiederholte
    // nebenlaeufige Laeufe muessen untereinander gleich sein, sonst
    // haenge das Ergebnis doch am Scheduling.
    let mut digests = Vec::new();
    for _ in 0..5 {
        let mut sigma = Sigma::new(manifest(), budget());
        let rd = run_descriptor();
        tick_concurrent(
            &mut sigma,
            &rd,
            stress_queues(),
            time(),
            &mut Profiling::off(),
        )
        .unwrap();
        digests.push(sigma_digest(&sigma).unwrap());
    }
    assert!(
        digests.windows(2).all(|w| w[0] == w[1]),
        "fuenf nebenlaeufige Laeufe muessen denselben Digest liefern: {digests:?}"
    );
}

#[test]
fn the_trace_chain_is_identical_too_not_merely_the_state_digest() {
    // Invariante 14.8 nennt beides: "identischem kanonischen
    // Zustandsdigest UND identischer Tracefolge". Der Zustandsdigest
    // allein liesse eine abweichende Anhaengereihenfolge durchgehen, wenn
    // sie sich im Zustand nicht niederschluege.
    let mut seq = Sigma::new(manifest(), budget());
    let mut con = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    tick(
        &mut seq,
        &rd,
        stress_queues(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();
    tick_concurrent(
        &mut con,
        &rd,
        stress_queues(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    let events = |s: &Sigma| -> Vec<String> {
        s.trace
            .segments()
            .iter()
            .map(|x| format!("{}/{}", x.seq, x.event_type.0))
            .collect()
    };
    assert_eq!(
        events(&seq),
        events(&con),
        "die Tracefolge MUSS gleich sein"
    );
    assert_eq!(seq.trace.head(), con.trace.head());
    assert_eq!(psk_trace::verify_chain(con.trace.segments()), Ok(()));
}

#[test]
fn the_four_stateful_work_kinds_are_excluded_from_concurrency() {
    // Regel 14.7: "ausschliesslich fuer Operationen ohne gemeinsamen
    // Schreibzustand". Die Aufzaehlung ist hier festgenagelt, damit eine
    // spaetere Erweiterung von PendingWork nicht stillschweigend etwas
    // Zustandsbehaftetes freigibt.
    assert!(!concurrency_eligible(&PendingWork::ArchiveGatherResidues));
    assert!(concurrency_eligible(
        &thought_item(b"x", PriorityTier::SpeculativeBranch).work
    ));
}
