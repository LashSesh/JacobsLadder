//! Gemeinsame Saathelfer der Scheduler-Integrationstests: seit der
//! Taktumverdrahtung leiten die Takte ihre Arbeit aus Sigma ab
//! (`select(phase, state)`), also SAEEN die Tests Zustand - deponierte
//! Programmeintraege und Laufobjekte - statt Warteschlangen zu bauen.
#![allow(dead_code)]

use std::collections::BTreeMap;

use psk_scheduler::{BudgetLedger, PendingRecord, Sigma};
use psk_trace::{open_run, RunDescriptor, RunInputs};
use psk_types::objects::{
    CanonicalizationProfile, CapabilityMatrixRef, Claim, ClaimDirectionalityKind, ClaimExpr,
    ContextRef, EnvironmentProfile, GateId, GateReport, GateReportDecisionKind, Lineage, NDBudget,
    Observation, PredicateExpr, ProfileId, ReplayDescriptor, RuntimeManifest,
    RuntimeManifestDeterminismClassKind, Scaled, ScopeExpr, SortId, UncertaintyBlock,
    UncertaintyModelId, Validity,
};
use psk_types::{ClockRef, Digest, DualTime, ObjectId, RunId, TraceRef};

pub fn time() -> DualTime {
    time_with("2026-08-08T00:00:00.000000000Z", "test")
}

pub fn time_with(wall_clock: &str, clock: &str) -> DualTime {
    DualTime {
        tau_i: 0,
        tau_e: wall_clock.into(),
        clock_ref: ClockRef(clock.into()),
        uncertainty_ns: 0,
    }
}

pub fn manifest(profile: ProfileId) -> RuntimeManifest {
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

pub fn budget_with_compute(compute: u64) -> BudgetLedger {
    BudgetLedger::open(
        RunId("run-0".into()),
        compute,
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

pub fn budget() -> BudgetLedger {
    budget_with_compute(1_000)
}

pub fn run_descriptor() -> RunDescriptor {
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

/// Deponiert einen Auftragskandidaten (Regel 5.9 (Kandidat und Gedankenkörper)): normalize und type
/// leiten daraus Arbeit ab; die Praegung folgt nur, wenn auch ein Anker
/// entsteht.
pub fn seed_candidate(sigma: &mut Sigma, text: &str) {
    sigma.candidates.push(psk_thought::Candidate::new(
        Claim {
            text: text.into(),
            formal: ClaimExpr(format!("formal({text})")),
            directionality: ClaimDirectionalityKind::Internal,
        },
        vec![],
        vec![],
        UncertaintyBlock("none".into()),
        vec![],
        Lineage("root".into()),
    ));
}

fn sample_external_record(seed: &[u8]) -> psk_anchor::ExternalRecord {
    psk_anchor::ExternalRecord {
        file_hashes: vec![psk_anchor::FileObservation {
            relative_path: format!("{}.txt", String::from_utf8_lossy(seed)),
            content_digest: Digest::sha256(seed),
        }],
        git_commit: None,
        observed_at: time(),
        permissions: psk_anchor::ObservedPermissions { read_only: true },
        configuration_digest: Digest::sha256(b"config"),
        allowed_scope: "sandbox".into(),
    }
}

/// Deponiert ein Aussenrecord OHNE Provenienz - die Observe-Phase bindet,
/// die Anchor-Phase versiegelt.
pub fn seed_record(sigma: &mut Sigma, seed: &[u8]) {
    sigma.program.records.push(PendingRecord {
        record: sample_external_record(seed),
        source_adapter: psk_types::objects::AdapterId("observer-test".into()),
        observer_identity: Digest::sha256(b"observer"),
        method: "filesystem-read".into(),
        effect_adapter_identity: None,
        observations: vec![Observation(format!(
            "Beobachtung {}",
            String::from_utf8_lossy(seed)
        ))],
        uncertainty_model: UncertaintyModelId("none-declared".into()),
        context: ContextRef("test".into()),
        validity: Validity {
            freshness_predicate: PredicateExpr(format!(
                "corpus_digest == {}",
                Digest::sha256(seed)
            )),
            expires_at_tau_i: u64::MAX,
        },
        boundary: ScopeExpr("sandbox".into()),
        provenance: None,
        anchor_ref: None,
    });
}

/// Deponiert ein Aussenrecord MIT bereits gebundener Provenienz - fuer
/// Tests, deren Arbeit in der Anchor-Phase beginnen soll.
pub fn seed_bound_record(sigma: &mut Sigma, seed: &[u8]) {
    seed_record(sigma, seed);
    let entry = sigma.program.records.last_mut().unwrap();
    entry.provenance = Some(psk_anchor::bind_provenance(
        &entry.record,
        entry.source_adapter.clone(),
        entry.observer_identity,
        entry.method.clone(),
    ));
}

/// Ein von Hand gebauter PASS-GateReport fuer G-EFFECT - saet die
/// Vorbedingung der Execute-Phase (Schritt 9), ohne die Verify-Phase zu
/// durchlaufen.
pub fn passed_effect_gate() -> GateReport {
    GateReport {
        schema: "psk.gate-report/1.0".into(),
        id: ObjectId::new(SortId::Gate, Digest::sha256(b"g-effect-pass")),
        gate_id: GateId::GEffect,
        order: 2,
        input_digests: vec![Digest::sha256(b"plan")],
        decision: GateReportDecisionKind::Pass,
        reasons: vec![],
        evidence_refs: vec![],
        residue_refs: vec![],
        seam_report_refs: vec![ObjectId::new(SortId::Trace, Digest::sha256(b"seam"))],
        replay_descriptor: ReplayDescriptor("test/1".into()),
        decided_at: time(),
        trace_ref: TraceRef(Digest::sha256(b"trace")),
    }
}

/// Ein deponierter Patchplan (IssueInputs) fuer die Execute-Phase.
pub fn patch_plan() -> psk_effect::IssueInputs {
    psk_effect::IssueInputs {
        effect_class: psk_types::objects::EffectClassId("fs.write.sandbox".into()),
        plan_digest: Digest::sha256(b"plan"),
        scope: ScopeExpr("patch.txt".into()),
        capabilities: vec![psk_types::objects::CapabilityId("fs.write.sandbox".into())],
        preconditions: vec![PredicateExpr("inhalt".into())],
        budget: psk_types::objects::BudgetSpec("1 Datei".into()),
        expires_at_tau_i: 1_000,
        run_id: RunId("run-0".into()),
        port_id: psk_types::PortId::P22,
        seq: 1,
        nonce: [7u8; 32],
        expected_receipt: psk_types::objects::ReceiptSpec("receipt/1".into()),
        rollback: psk_types::objects::EffectTokenRollbackKind::NoRollbackJustified,
    }
}
