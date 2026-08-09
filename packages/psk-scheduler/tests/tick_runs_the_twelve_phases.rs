//! Algorithmus 14.4 (Tick) end-to-end gegen die realen Phasenempfaenger,
//! plus T-REPLAY-002s Negativnachweis (Regel 22.3: Replay laeuft unter
//! shadow).

use std::collections::BTreeMap;

use psk_scheduler::{
    tick, BudgetLedger, PendingWork, PriorityTier, Profiling, QueuedItem, ResourceKind,
    SchedulableItem, Sigma,
};
use psk_trace::{open_run, RunDescriptor, RunInputs};
use psk_types::objects::{
    AdapterId, BudgetSpec, CanonicalizationProfile, CapabilityId, CapabilityMatrixRef, Claim,
    ClaimDirectionalityKind, ClaimExpr, EffectAttempt, EffectClassId, EffectToken,
    EffectTokenRollbackKind, EnvironmentProfile, Lineage, NDBudget, PredicateExpr, ProfileId,
    ReceiptSpec, RuntimeManifest, RuntimeManifestDeterminismClassKind, Scaled, ScopeExpr, SortId,
    UncertaintyBlock,
};
use psk_types::{ClockRef, Digest, DualTime, ObjectId, Phase, PskError, RunId, TraceRef};

fn time() -> DualTime {
    DualTime {
        tau_i: 0,
        tau_e: "2026-08-08T00:00:00.000000000Z".into(),
        clock_ref: ClockRef("test".into()),
        uncertainty_ns: 0,
    }
}

fn manifest(profile: ProfileId) -> RuntimeManifest {
    RuntimeManifest {
        schema: "psk.runtime-manifest/1.0".into(),
        constitution_id: Digest::sha256(b"c"),
        architecture_id: Digest::sha256(b"a"),
        implementation_id: Digest::sha256(b"m"),
        profile,
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

fn tiny_budget() -> BudgetLedger {
    BudgetLedger::open(
        RunId("run-0".into()),
        0, // Compute sofort erschoepft
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

fn item(id_seed: &[u8], work: PendingWork) -> QueuedItem {
    QueuedItem {
        schedulable: SchedulableItem {
            id: ObjectId::new(SortId::Context, Digest::sha256(id_seed)),
            tier: PriorityTier::RatchetingCapsule,
            expires_at_tau_i: None,
        },
        cost: (ResourceKind::Compute, 1),
        work,
    }
}

fn thought_work() -> PendingWork {
    PendingWork::TypeThought(psk_thought::ThoughtInputs {
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
    })
}

#[test]
fn an_empty_tick_still_opens_seals_all_twelve_phases_and_closes() {
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), budget());
    let rd = run_descriptor();
    tick(
        &mut sigma,
        &rd,
        BTreeMap::new(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    // 1 tick.opened + 12 phase.sealed.* + 1 tick.closed
    assert_eq!(sigma.trace.segments().len(), 14);
    assert_eq!(sigma.trace.segments()[0].event_type.0, "tick.opened");
    assert_eq!(sigma.trace.segments()[13].event_type.0, "tick.closed");
    assert_eq!(sigma.tick_no, 1, "der Takt zaehlt hoch");
    assert_eq!(psk_trace::verify_chain(sigma.trace.segments()), Ok(()));
}

#[test]
fn the_twelve_phases_are_sealed_in_definition_14_1_order() {
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), budget());
    let rd = run_descriptor();
    tick(
        &mut sigma,
        &rd,
        BTreeMap::new(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    let sealed: Vec<String> = sigma
        .trace
        .segments()
        .iter()
        .filter_map(|s| {
            s.event_type
                .0
                .strip_prefix("phase.sealed.")
                .map(String::from)
        })
        .collect();
    assert_eq!(
        sealed,
        vec![
            "observe",
            "normalize",
            "type",
            "anchor",
            "project",
            "compile",
            "challenge",
            "verify",
            "execute",
            "observe_2",
            "reconcile",
            "archive",
        ]
    );
}

#[test]
fn a_type_phase_item_reaches_its_real_receiver_and_lands_in_sigma() {
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), budget());
    let rd = run_descriptor();
    let mut queues = BTreeMap::new();
    queues.insert(Phase::Type, vec![item(b"t1", thought_work())]);

    tick(&mut sigma, &rd, queues, time(), &mut Profiling::off()).unwrap();

    // M06 compile_thought hat real gelaufen: der ThoughtBody liegt in Sigma
    // und traegt Regel 5.10s Anfangswerte.
    assert_eq!(sigma.thoughts.len(), 1);
    assert_eq!(
        sigma.thoughts[0].reality_status,
        psk_types::objects::RealityStatus::Unknown
    );
    // und ein dispatch.type-Segment steht zwischen open und seal.
    assert!(sigma
        .trace
        .segments()
        .iter()
        .any(|s| s.event_type.0 == "dispatch.type"));
}

#[test]
fn an_exhausted_budget_opens_a_residue_and_skips_the_item() {
    // Algorithmus 14.4: "if budget.exhausted: M19.residue(item, kind:
    // budget); continue" - Vertrag 14.11, HOLD statt stillem Saettigen.
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), tiny_budget());
    let rd = run_descriptor();
    let mut queues = BTreeMap::new();
    queues.insert(Phase::Type, vec![item(b"t1", thought_work())]);

    tick(&mut sigma, &rd, queues, time(), &mut Profiling::off()).unwrap();

    assert!(
        sigma.thoughts.is_empty(),
        "das Element DARF bei erschoepftem Budget nicht ausgefuehrt werden"
    );
    assert_eq!(sigma.residues.all().len(), 1);
    assert_eq!(
        sigma.residues.all()[0].r#type,
        psk_types::objects::ResidueRecordTypeKind::Budget
    );
    assert!(!sigma
        .trace
        .segments()
        .iter()
        .any(|s| s.event_type.0 == "dispatch.type"));
    // Der Takt selbst laeuft trotzdem vollstaendig zu Ende.
    assert_eq!(sigma.trace.segments()[13].event_type.0, "tick.closed");
}

#[test]
fn a_phase_item_in_the_wrong_phase_is_rejected_not_silently_run() {
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), budget());
    let rd = run_descriptor();
    let mut queues = BTreeMap::new();
    // Ein Type-Element in der Compile-Phase.
    queues.insert(Phase::Compile, vec![item(b"t1", thought_work())]);

    assert_eq!(
        tick(&mut sigma, &rd, queues, time(), &mut Profiling::off()),
        Err(PskError::UntypedInput)
    );
}

#[test]
fn two_ticks_chain_into_one_verifiable_trace() {
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), budget());
    let rd = run_descriptor();
    tick(
        &mut sigma,
        &rd,
        BTreeMap::new(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();
    tick(
        &mut sigma,
        &rd,
        BTreeMap::new(),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert_eq!(sigma.tick_no, 2);
    assert_eq!(sigma.trace.segments().len(), 28);
    assert_eq!(psk_trace::verify_chain(sigma.trace.segments()), Ok(()));
}

// ------------------------------------------------------------ T-REPLAY-002

/// Ein Adapter, der protokolliert, ob er je aufgerufen wurde - der eigentliche
/// Nachweis fuer Invariante 22.6 (Replay ist effektfrei).
struct RecordingAdapter {
    applied: std::sync::atomic::AtomicBool,
}

impl psk_effect::EffectAdapter for RecordingAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("recording".into())
    }
    fn declared_effect_classes(&self) -> Vec<EffectClassId> {
        vec![EffectClassId("fs.write".into())]
    }
    fn required_capabilities(&self) -> Vec<CapabilityId> {
        vec![CapabilityId("fs.write.sandbox".into())]
    }
    fn prestate(&self, _scope: &ScopeExpr) -> Digest {
        Digest::sha256(b"pre")
    }
    fn apply(&self, token: &EffectToken, started_at: DualTime) -> EffectAttempt {
        self.applied
            .store(true, std::sync::atomic::Ordering::SeqCst);
        EffectAttempt {
            id: ObjectId::new(SortId::Effect, Digest::sha256(b"attempt")),
            token_ref: token.id,
            adapter: self.id(),
            prestate_digest: Digest::sha256(b"pre"),
            plan_digest: token.plan_digest,
            started_at,
            ended_at: None,
            outcome: psk_types::objects::EffectAttemptOutcomeKind::Completed,
            error: None,
            compensation_ref: None,
        }
    }
    fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt {
        attempt.clone()
    }
    fn is_reversible(&self, _token: &EffectToken) -> bool {
        true
    }
}

fn sample_token() -> EffectToken {
    EffectToken {
        schema: "psk.effect-token/1.0".into(),
        id: ObjectId::new(SortId::Capability, Digest::sha256(b"tok")),
        subject: psk_types::ModuleId::EffectBoundary,
        effect_class: EffectClassId("fs.write".into()),
        plan_digest: Digest::sha256(b"plan"),
        scope: ScopeExpr("sandbox".into()),
        capabilities: vec![CapabilityId("fs.write.sandbox".into())],
        preconditions: Vec::<PredicateExpr>::new(),
        budget: BudgetSpec("10".into()),
        expires_at_tau_i: 1_000,
        idempotency_key: "run-0/P22/1".into(),
        nonce: [0u8; 32],
        issuer_digest: Digest::sha256(b"issuer"),
        expected_receipt: ReceiptSpec("receipt/1".into()),
        rollback: EffectTokenRollbackKind::NoRollbackJustified,
        gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
    }
}

fn execute_queue(
    adapter: std::sync::Arc<RecordingAdapter>,
    token: &EffectToken,
) -> BTreeMap<Phase, Vec<QueuedItem>> {
    struct Shared(std::sync::Arc<RecordingAdapter>);
    impl psk_effect::EffectAdapter for Shared {
        fn id(&self) -> AdapterId {
            self.0.id()
        }
        fn declared_effect_classes(&self) -> Vec<EffectClassId> {
            self.0.declared_effect_classes()
        }
        fn required_capabilities(&self) -> Vec<CapabilityId> {
            self.0.required_capabilities()
        }
        fn prestate(&self, scope: &ScopeExpr) -> Digest {
            self.0.prestate(scope)
        }
        fn apply(&self, token: &EffectToken, started_at: DualTime) -> EffectAttempt {
            self.0.apply(token, started_at)
        }
        fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt {
            self.0.compensate(attempt)
        }
        fn is_reversible(&self, token: &EffectToken) -> bool {
            self.0.is_reversible(token)
        }
    }

    let mut queues = BTreeMap::new();
    queues.insert(
        Phase::Execute,
        vec![item(
            b"e1",
            PendingWork::ExecuteRun {
                token: token.clone(),
                current_tau_i: 10,
                started_at: time(),
                adapter: Box::new(Shared(adapter)),
            },
        )],
    );
    queues
}

#[test]
fn t_replay_002_under_shadow_the_token_is_invalidated_and_the_adapter_never_runs() {
    // Regel 22.3 (Replay laeuft unter shadow) + Invariante 22.6 (Replay ist
    // effektfrei): "Plan und Token werden erzeugt, aber sofort invalidiert",
    // Durchsetzung ueber die bestehende Tokeninvalidierung (P37).
    let mut sigma = Sigma::new(manifest(ProfileId::Shadow), budget());
    let rd = run_descriptor();
    let token = sample_token();
    sigma.gates_and_tokens.ledger.register(&token);

    let adapter = std::sync::Arc::new(RecordingAdapter {
        applied: std::sync::atomic::AtomicBool::new(false),
    });
    tick(
        &mut sigma,
        &rd,
        execute_queue(adapter.clone(), &token),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert!(
        !adapter.applied.load(std::sync::atomic::Ordering::SeqCst),
        "Invariante 22.6: ein Replay DARF NICHT einen realen Effekt ausloesen"
    );
    assert!(sigma.effects.is_empty(), "kein EffectAttempt unter shadow");
    assert_eq!(
        sigma.gates_and_tokens.ledger.state_of("run-0/P22/1"),
        Some(psk_effect::TokenState::Invalidated),
        "das Token MUSS ueber die bestehende Tokeninvalidierung entwertet sein"
    );
}

#[test]
fn under_readonly_the_token_is_likewise_invalidated() {
    // Regel 22.3: "Ein Replaylauf MUSS unter shadow ODER readonly
    // ausgefuehrt werden" - beide Profile fuehren keinen realen Effekt aus.
    let mut sigma = Sigma::new(manifest(ProfileId::Readonly), budget());
    let rd = run_descriptor();
    let token = sample_token();
    sigma.gates_and_tokens.ledger.register(&token);

    let adapter = std::sync::Arc::new(RecordingAdapter {
        applied: std::sync::atomic::AtomicBool::new(false),
    });
    tick(
        &mut sigma,
        &rd,
        execute_queue(adapter.clone(), &token),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert!(!adapter.applied.load(std::sync::atomic::Ordering::SeqCst));
    assert_eq!(
        sigma.gates_and_tokens.ledger.state_of("run-0/P22/1"),
        Some(psk_effect::TokenState::Invalidated)
    );
}

#[test]
fn under_reference_the_same_queue_does_run_the_adapter_for_real() {
    // Gegenprobe: ohne sie waere der Shadow-Test auch dann gruen, wenn
    // dispatch() den Adapter NIE aufriefe (z.B. wegen eines Tippfehlers im
    // Match-Arm) - das Profil muss den Unterschied machen, nicht ein
    // genereller Defekt.
    let mut sigma = Sigma::new(manifest(ProfileId::Reference), budget());
    let rd = run_descriptor();
    let token = sample_token();
    sigma.gates_and_tokens.ledger.register(&token);

    let adapter = std::sync::Arc::new(RecordingAdapter {
        applied: std::sync::atomic::AtomicBool::new(false),
    });
    tick(
        &mut sigma,
        &rd,
        execute_queue(adapter.clone(), &token),
        time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert!(
        adapter.applied.load(std::sync::atomic::Ordering::SeqCst),
        "unter reference MUSS der Adapter real laufen"
    );
    assert_eq!(sigma.effects.len(), 1);
    assert_eq!(
        sigma.gates_and_tokens.ledger.state_of("run-0/P22/1"),
        Some(psk_effect::TokenState::Consumed)
    );
}
