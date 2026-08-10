//! T-CONC-001 (`architecture/ra_tests.yaml`: `{kind: property, run:
//! concurrent_dispatch, expect: canonical_digest_equals_sequential}`) /
//! Regel 14.8 (Nebenläufigkeitsmodell) / Invariante 14.9 (Serialisierbarkeit).
//!
//! Die Saat: mehrere deponierte Records MIT gebundener Provenienz. Die
//! Anchor-Phase leitet daraus je ein `AnchorBind` ab - freigegebene,
//! voneinander unabhaengige Arbeit, deren ANWENDUNGSREIHENFOLGE aber
//! zaehlt (`apply` haengt jeden Anker an `Sigma.anchors` an). Genau die
//! Lage, die Regel 14.8 (Nebenläufigkeitsmodell)s Ruecksortierschritt ordnet: die abgeleiteten
//! Kennungen (Digests der Ableitungstags) sind gegen die Saatreihenfolge
//! effektiv verwuerfelt, also unterscheidet sich die Prioritaetsordnung
//! deterministisch von jeder anderen - und der Negativnachweis traegt
//! jedes Mal.

mod common;

use psk_effect::NoEffectLines;
use psk_scheduler::{
    concurrency_eligible, sigma_digest, tick, tick_concurrent, tick_concurrent_with_order,
    PendingWork, Profiling, ResultOrder, Sigma,
};
use psk_types::objects::ProfileId;
use psk_types::Digest;

fn seeded() -> Sigma {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    for seed in [b"e" as &[u8], b"a", b"d", b"b", b"c", b"f", b"g", b"h"] {
        common::seed_bound_record(&mut sigma, seed);
    }
    sigma
}

fn sequential_digest() -> Digest {
    let mut sigma = seeded();
    let rd = common::run_descriptor();
    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
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

    let mut sigma = seeded();
    let rd = common::run_descriptor();
    tick_concurrent(&mut sigma, &rd, common::time(), &mut Profiling::off()).unwrap();

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
    // nie abweicht - dann bewiese er nichts ueber Regel 14.8 (Nebenläufigkeitsmodell)s
    // Ruecksortierschritt.
    let expected = sequential_digest();

    let mut sigma = seeded();
    let rd = common::run_descriptor();
    tick_concurrent_with_order(
        &mut sigma,
        &rd,
        common::time(),
        &mut Profiling::off(),
        ResultOrder::ReversedForTestingOnly,
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
    // Invariante 14.9 (Serialisierbarkeit) verlangt nicht nur EINE
    // sequentielle Entsprechung, sondern eine stabile: wiederholte
    // nebenlaeufige Laeufe muessen untereinander gleich sein, sonst
    // haenge das Ergebnis doch am Scheduling.
    let mut digests = Vec::new();
    for _ in 0..5 {
        let mut sigma = seeded();
        let rd = common::run_descriptor();
        tick_concurrent(&mut sigma, &rd, common::time(), &mut Profiling::off()).unwrap();
        digests.push(sigma_digest(&sigma).unwrap());
    }
    assert!(
        digests.windows(2).all(|w| w[0] == w[1]),
        "fuenf nebenlaeufige Laeufe muessen denselben Digest liefern: {digests:?}"
    );
}

#[test]
fn the_trace_chain_is_identical_too_not_merely_the_state_digest() {
    // Invariante 14.9 (Serialisierbarkeit) nennt beides: "identischem kanonischen
    // Zustandsdigest UND identischer Tracefolge". Der Zustandsdigest
    // allein liesse eine abweichende Anhaengereihenfolge durchgehen, wenn
    // sie sich im Zustand nicht niederschluege.
    let mut seq = seeded();
    let mut con = seeded();
    let rd = common::run_descriptor();
    tick(
        &mut seq,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();
    tick_concurrent(&mut con, &rd, common::time(), &mut Profiling::off()).unwrap();

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
fn the_five_stateful_work_kinds_are_excluded_from_concurrency() {
    // Regel 14.8 (Nebenläufigkeitsmodell): "ausschliesslich fuer Operationen ohne gemeinsamen
    // Schreibzustand". Die Aufzaehlung ist hier festgenagelt, damit eine
    // spaetere Erweiterung von PendingWork nicht stillschweigend etwas
    // Zustandsbehaftetes freigibt.
    assert!(!concurrency_eligible(&PendingWork::ChallengeContradictions));
    assert!(!concurrency_eligible(&PendingWork::VerifyPatchGate));
    assert!(!concurrency_eligible(&PendingWork::ExecuteRun {
        token: None
    }));
    assert!(!concurrency_eligible(&PendingWork::Reconcile));
    assert!(!concurrency_eligible(&PendingWork::ArchiveGatherResidues));
    // Und die Gegenprobe: lesend-rechnende Arbeit IST freigegeben.
    assert!(concurrency_eligible(&PendingWork::Observe { record: 0 }));
    assert!(concurrency_eligible(&PendingWork::AnchorBind { record: 0 }));
}
