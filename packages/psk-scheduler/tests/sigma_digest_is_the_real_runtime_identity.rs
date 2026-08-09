//! `I_t = H(Can(Sigma_t))` (Regel 6.10, Vier Identitaeten) und Invariante
//! 6.14 (Replayneutralitaet der Wanduhr): "tau_e DARF NICHT in eine
//! Kanonisierung, einen Digest oder eine Gate-Entscheidung eingehen."
//!
//! Der tragende Nachweis ist der zweite Test: zwei Laeufe mit demselben
//! RunDescriptor und denselben Eingaben, die sich AUSSCHLIESSLICH in der
//! Wanduhr unterscheiden, liefern dasselbe `I_t`, waehrend ihre
//! `record_digest`s abweichen. Genau die Trennung aus Definition 6.6/6.7,
//! jetzt auf Sigma angewandt - und zugleich der Beleg, dass
//! `sigma_digest` ueber `identity_projection` und nicht ueber `can()`
//! gebildet wird: mit `can()` waere er rot.

use std::collections::BTreeMap;

use psk_canon::{record_digest, Media};
use psk_scheduler::{
    sigma_digest, tick, BudgetLedger, PendingWork, PriorityTier, Profiling, QueuedItem,
    ResourceKind, SchedulableItem, Sigma,
};
use psk_trace::{open_run, RunDescriptor, RunInputs};
use psk_types::objects::{
    CanonicalizationProfile, CapabilityMatrixRef, Claim, ClaimDirectionalityKind, ClaimExpr,
    EnvironmentProfile, Lineage, NDBudget, ProfileId, RuntimeManifest,
    RuntimeManifestDeterminismClassKind, Scaled, SortId, UncertaintyBlock,
};
use psk_types::{ClockRef, Digest, DualTime, ObjectId, Phase, RunId, TraceRef};

/// `tau_e`/`clock_ref`/`uncertainty_ns` sind die volatilen Felder von
/// DualTime; `tau_i` (der Kausalzaehler) ist ausdruecklich NICHT volatil
/// (`volatile_fields.yaml`, `not_removed`) und bleibt deshalb hier gleich.
fn time(wall_clock: &str, clock: &str) -> DualTime {
    DualTime {
        tau_i: 0,
        tau_e: wall_clock.into(),
        clock_ref: ClockRef(clock.into()),
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

fn budget() -> BudgetLedger {
    BudgetLedger::open(
        RunId("run-0".into()),
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

fn queues() -> BTreeMap<Phase, Vec<QueuedItem>> {
    let mut q = BTreeMap::new();
    q.insert(
        Phase::Type,
        vec![QueuedItem {
            schedulable: SchedulableItem {
                id: ObjectId::new(SortId::Context, Digest::sha256(b"t1")),
                tier: PriorityTier::RatchetingCapsule,
                expires_at_tau_i: None,
            },
            cost: (ResourceKind::Compute, 1),
            work: PendingWork::TypeThought(psk_thought::ThoughtInputs {
                anchor_refs: vec![ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor"))],
                unanchored: false,
                claim: Claim {
                    text: "ein Gedanke".into(),
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
        }],
    );
    q
}

/// Ein vollstaendiger Takt mit der angegebenen Wanduhr.
fn run_with_wall_clock(wall_clock: &str, clock: &str) -> Sigma {
    let mut sigma = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    tick(
        &mut sigma,
        &rd,
        queues(),
        time(wall_clock, clock),
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

/// Regel 6.10 + Invariante 6.14, jetzt erfuellbar.
///
/// Dieser Test war unter v1.0.19 rot und sichtbar uebersprungen: Struktur
/// 7.38 definierte `segment_digest` als `H(Can(alle vorstehenden Felder))`
/// mit `time: DualTime` darunter, sodass `tau_e` per Formel in jeden
/// Kettendigest und ueber `L_t` in `I_t` einging - zwei inhaltsgleiche
/// Laeufe erhielten verschiedene Zustandsdigests, R2 (Definition 22.1) war
/// strukturell unerreichbar und damit kein Referenzrelease moeglich
/// (Vertrag 22.4).
///
/// PSK-RA v1.0.20 (Fehlerkorrektur 24, Regel 7.40) hat das an der Quelle
/// aufgeloest, nach demselben Muster wie auf Objektebene: `segment_digest`
/// wendet jetzt `pi_vol` an, das neue `segment_record_digest` traegt die
/// vollstaendigen Bytes einschliesslich `tau_e`, und `verify_chain` prueft
/// beide. Die blockierende Invariante hat Vorrang vor der Feldformel - der
/// Widerspruch war ein Zweierwiderspruch, kein Abwaegen zwischen vier
/// gleichrangigen Stellen.
#[test]
fn same_run_descriptor_and_inputs_yield_the_same_i_t_despite_a_different_wall_clock() {
    // Regel 6.10 + Invariante 6.14: derselbe RunDescriptor, dieselben
    // Eingaben, nur eine andere Wanduhr (und ein anderer Uhrenbezeichner)
    // - I_t MUSS gleich bleiben.
    let a = run_with_wall_clock("2026-08-08T00:00:00.000000000Z", "host-a");
    let b = run_with_wall_clock("2099-12-31T23:59:59.999999999Z", "host-b");

    assert_eq!(
        sigma_digest(&a).unwrap(),
        sigma_digest(&b).unwrap(),
        "die Wanduhr DARF NICHT in I_t eingehen (Invariante 6.14)"
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

/// Regel 7.40, beide Haelften an EINEM Segment gemessen - der Test, der
/// eine Rueckkehr zum alten Verhalten auffallen laesst.
///
/// Vorher hielt an dieser Stelle ein Test den damaligen BEFUND fest (die
/// Kettendigests als einziger Wanduhrtraeger). Der Befund ist geschlossen;
/// was jetzt zu sichern ist, ist die Trennung selbst: `segment_digest`
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
            "segment_digest ist identitaetsbildend und DARF tau_e nicht tragen (Regel 7.40)"
        );
        assert_ne!(
            x.segment_record_digest, y.segment_record_digest,
            "segment_record_digest sichert die vollstaendigen Bytes und MUSS tau_e tragen (Regel 7.40)"
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

    let mut two_ticks = Sigma::new(manifest(), budget());
    let rd = run_descriptor();
    for _ in 0..2 {
        tick(
            &mut two_ticks,
            &rd,
            queues(),
            time("2026-08-08T00:00:00.000000000Z", "host-a"),
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
    // Invariante 1.7: die vier Identitaetsschichten sind getrennt, keine
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
    let mut sigma = Sigma::new(manifest(), budget());
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
