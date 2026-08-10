//! `I_t = H(Can(Sigma_t))` (Regel 6.10 (Vier Identitäten)) ueber echte Takte: wanduhrfrei
//! (Invariante 6.14 (Replayneutralität der Wanduhr)), deterministisch, zustandsempfindlich.

mod common;

use psk_canon::{record_digest, Media};
use psk_effect::NoEffectLines;
use psk_scheduler::{sigma_digest, tick, Profiling, Sigma};
use psk_types::objects::{ProfileId, SortId};
use psk_types::{Digest, ObjectId};

/// Ein vollstaendiger Takt ueber gesaeter Arbeit mit der angegebenen
/// Wanduhr.
fn run_with_wall_clock(wall_clock: &str, clock: &str) -> Sigma {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    common::seed_candidate(&mut sigma, "ein Gedanke");
    let rd = common::run_descriptor();
    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time_with(wall_clock, clock),
        &mut Profiling::off(),
    )
    .unwrap();
    sigma
}

#[test]
fn i_t_is_deterministic_for_the_identical_state() {
    let a = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    let b = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    assert_eq!(sigma_digest(&a).unwrap(), sigma_digest(&b).unwrap());
}

/// Regel 6.10 (Vier Identitäten) + Invariante 6.14 (Replayneutralität der Wanduhr), erfuellbar seit PSK-RA v1.0.20
/// (Fehlerkorrektur 24, Regel 7.41 (Zwei Digests je Segment)): `segment_digest` wendet `pi_vol` an,
/// `segment_record_digest` traegt die vollstaendigen Bytes.
#[test]
fn same_run_descriptor_and_inputs_yield_the_same_i_t_despite_a_different_wall_clock() {
    // Derselbe RunDescriptor, dieselben Eingaben, nur eine andere Wanduhr
    // (und ein anderer Uhrenbezeichner) - I_t MUSS gleich bleiben.
    let a = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    let b = run_with_wall_clock("2099-12-31T23:59:59.999999999Z", "host-b");

    assert_eq!(
        sigma_digest(&a).unwrap(),
        sigma_digest(&b).unwrap(),
        "die Wanduhr DARF NICHT in I_t eingehen (Invariante 6.14 (Replayneutralität der Wanduhr))"
    );
}

#[test]
fn the_record_digests_of_those_same_two_runs_do_differ() {
    // Die zweite Haelfte derselben Forderung - und die Gegenprobe zum
    // Test darueber: record_digest = H(Can(o)) ueber das VOLLSTAENDIGE
    // Sigma behaelt die Wanduhr. Ohne diesen Test bliebe unbewiesen, dass
    // sich die beiden Laeufe ueberhaupt unterscheiden; dann waere die
    // Gleichheit von I_t trivial statt aussagekraeftig.
    let a = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    let b = run_with_wall_clock("2099-12-31T23:59:59.999999999Z", "host-b");

    let bytes_a = serde_json::to_vec(&a).unwrap();
    let bytes_b = serde_json::to_vec(&b).unwrap();
    assert_ne!(
        record_digest(&bytes_a, Media::Json).unwrap(),
        record_digest(&bytes_b, Media::Json).unwrap(),
        "der record_digest DARF abweichen - er sichert die vollstaendigen Bytes"
    );
}

/// Regel 7.41 (Zwei Digests je Segment), beide Haelften an EINEM Segment gemessen - der Test, der
/// eine Rueckkehr zum alten Verhalten auffallen laesst: `segment_digest`
/// DARF `tau_e` nicht enthalten, `segment_record_digest` MUSS es. Ein
/// Test, der nur die erste Haelfte prueft, wuerde eine Implementierung
/// durchlassen, die `tau_e` ueberhaupt nicht mehr aufzeichnet.
#[test]
fn segment_digest_excludes_the_wall_clock_and_segment_record_digest_includes_it() {
    let a = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    let b = run_with_wall_clock("2099-12-31T23:59:59.999999999Z", "host-b");

    let (sa, sb) = (a.trace.segments(), b.trace.segments());
    assert_eq!(sa.len(), sb.len(), "Vorbedingung: gleich viele Segmente");
    assert!(!sa.is_empty(), "Vorbedingung: der Takt hat geschrieben");

    for (x, y) in sa.iter().zip(sb.iter()) {
        assert_eq!(
            x.segment_digest, y.segment_digest,
            "segment_digest ist identitaetsbildend und DARF tau_e nicht tragen (Regel 7.41 (Zwei Digests je Segment))"
        );
        assert_ne!(
            x.segment_record_digest, y.segment_record_digest,
            "segment_record_digest sichert die vollstaendigen Bytes und MUSS tau_e tragen (Regel 7.41 (Zwei Digests je Segment))"
        );
    }

    // Und die Kette selbst laeuft ueber den identitaetsbildenden Digest,
    // ist also ebenfalls wanduhrfrei.
    assert_eq!(a.trace.head(), b.trace.head());
}

#[test]
fn i_t_follows_a_real_state_change() {
    // Wenn sich der kanonische Zustand wirklich aendert, MUSS I_t folgen -
    // sonst waere der Digest gegen alles unempfindlich, nicht nur gegen
    // die Wanduhr.
    let one_tick = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");

    let mut two_ticks = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    common::seed_candidate(&mut two_ticks, "ein Gedanke");
    let rd = common::run_descriptor();
    for _ in 0..2 {
        tick(
            &mut two_ticks,
            &rd,
            &mut NoEffectLines,
            common::time_with("2026-08-08T00:00:00.000000000Z", "host-a"),
            &mut Profiling::off(),
        )
        .unwrap();
    }

    assert_ne!(
        sigma_digest(&one_tick).unwrap(),
        sigma_digest(&two_ticks).unwrap()
    );
}

#[test]
fn i_t_differs_from_the_trace_head_of_the_same_state() {
    // Invariante 1.7 (Vier Identitätsschichten): die vier Identitaetsschichten sind getrennt, keine
    // ersetzt eine andere. `IdentityBinding` bindet I_t UND trace_head -
    // sie duerfen nicht derselbe Wert sein.
    let sigma = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    assert_ne!(sigma_digest(&sigma).unwrap(), sigma.trace.head());
}

#[test]
fn the_token_ledger_serializes_its_declared_register_state_names() {
    // Der handgeschriebene Serialize-Impl (psk-effect::consume) haelt die
    // im Register deklarierten Namen fest, nicht Rusts Variantennamen -
    // sonst truege I_t einen Bezeichner, den kein Register fuehrt.
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    let token = psk_types::objects::EffectToken {
        schema: "psk.effect-token/1.0".into(),
        id: ObjectId::new(SortId::Capability, Digest::sha256(b"tok")),
        subject: psk_types::ModuleId::EffectBoundary,
        effect_class: psk_types::objects::EffectClassId("fs.write".into()),
        plan_digest: Digest::sha256(b"plan"),
        scope: psk_types::objects::ScopeExpr("sandbox".into()),
        capabilities: vec![],
        preconditions: vec![],
        budget: psk_types::objects::BudgetSpec("10".into()),
        expires_at_tau_i: 1_000,
        idempotency_key: "run-0/P22/1".into(),
        nonce: [0u8; 32],
        issuer_digest: Digest::sha256(b"issuer"),
        expected_receipt: psk_types::objects::ReceiptSpec("r/1".into()),
        rollback: psk_types::objects::EffectTokenRollbackKind::NoRollbackJustified,
        gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
    };
    sigma.gates_and_tokens.ledger.register(&token);

    let json = serde_json::to_string(&sigma).unwrap();
    assert!(
        json.contains("\"ISSUED\""),
        "der Registername MUSS in die Serialisierung gehen, nicht \"Issued\": {json}"
    );
}
