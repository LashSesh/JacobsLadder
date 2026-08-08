//! P24a, End-to-End: M26 spawnt die realen Adapterbinaries als echte
//! Kindprozesse und tauscht ueber sie genau die fuenf Ports aus, die die
//! Prozessgrenze tatsaechlich ueberqueren (P22, P23, P37, P06, P24 -
//! `architecture/port_registry.yaml`). `CARGO_BIN_EXE_*` (gesetzt durch
//! die `dev-dependencies` auf `effect-local-fs`/`observer-local-fs` in
//! Cargo.toml) liefert die realen, gebauten Binarypfade - kein simulierter
//! Aufruf.

use std::fs;
use std::path::PathBuf;

use psk_anchor::{
    ExternalRecord, ObserveReceiptRequest, ObserveRecordRequest, SCHEMA_RECEIPT_REQUEST,
    SCHEMA_RECORD_REQUEST,
};
use psk_effect::{EffectApplyRequest, SCHEMA_APPLY_REQUEST, SCHEMA_TOKEN_INVALIDATE};
use psk_lifecycle::ChildProcess;
use psk_types::objects::{
    AdapterId, BudgetSpec, CapabilityId, EffectAttempt, EffectAttemptOutcomeKind, EffectClassId,
    EffectToken, EffectTokenRollbackKind, ExternalReceipt, PredicateExpr, ProvenanceBlock,
    ReceiptSpec, RollbackSpec, ScopeExpr, SortId,
};
use psk_types::{
    ClockRef, Digest, DualTime, MessageType, ModuleId, Msg, ObjectId, PortId, RunId, SchemaId,
    TraceRef, Ulid,
};

// `env!("CARGO_BIN_EXE_...")` funktioniert nur fuer paketeigene Bins
// (siehe psk-cli/tests/i8_independent_replay.rs) - Cargo setzt diese
// Variable NICHT fuer das Bin-Target eines ANDEREN Pakets, auch nicht
// als dev-dependency. `sibling_binary_path` (psk-lifecycle, Produktions-
// code) findet die real gebauten Binaries stattdessen im gemeinsamen
// Cargo-Ausgabeverzeichnis - erfordert, dass `effect-local-fs`/
// `observer-local-fs` vorher gebaut wurden (`cargo build --workspace`
// oder gezielt `-p effect-local-fs -p observer-local-fs`).
fn effect_local_fs_exe() -> PathBuf {
    psk_lifecycle::sibling_binary_path("effect-local-fs")
        .expect("effect-local-fs muss vorher gebaut worden sein")
}

fn observer_local_fs_exe() -> PathBuf {
    psk_lifecycle::sibling_binary_path("observer-local-fs")
        .expect("observer-local-fs muss vorher gebaut worden sein")
}

fn sample_time() -> DualTime {
    DualTime {
        tau_i: 1,
        tau_e: "2026-08-05T00:00:00.000000000Z".into(),
        clock_ref: ClockRef("test".into()),
        uncertainty_ns: 0,
    }
}

fn request_msg(port_id: PortId, schema_id: &str, payload: Vec<u8>) -> Msg {
    Msg {
        msg_id: Ulid(1),
        port_id,
        r#type: MessageType::Request,
        schema_id: SchemaId(schema_id.into()),
        producer: ModuleId::LifecycleSupervisor,
        consumer: ModuleId::EffectBoundary,
        run_id: RunId("spawn-and-request-test".into()),
        seq: 1,
        input_digests: vec![],
        created_at: sample_time(),
        trace_parent: TraceRef(Digest::sha256(b"trace")),
        payload_digest: Digest::sha256(&payload),
        payload,
        signature: None,
    }
}

#[test]
fn p22_and_p37_round_trip_through_a_real_child_process() {
    let sandbox = std::env::temp_dir().join(format!("psk-p24a-effect-{}", std::process::id()));
    let _ = fs::remove_dir_all(&sandbox);
    fs::create_dir_all(&sandbox).unwrap();

    let mut child = ChildProcess::spawn(
        &effect_local_fs_exe(),
        &[sandbox.to_str().unwrap()],
        Some(&sandbox),
    )
    .expect("effect-local-fs muss spawnbar sein");

    let token = EffectToken {
        schema: "psk.effect-token/1.0".into(),
        id: ObjectId::new(SortId::Capability, Digest::sha256(b"tok")),
        subject: ModuleId::EffectBoundary,
        effect_class: EffectClassId("fs.write.sandbox".into()),
        plan_digest: Digest::sha256(b"plan"),
        scope: ScopeExpr("patch.txt".into()),
        capabilities: vec![CapabilityId("fs.write.sandbox".into())],
        preconditions: vec![PredicateExpr("hello from a real child process".into())],
        budget: BudgetSpec("1 Datei".into()),
        expires_at_tau_i: 1000,
        idempotency_key: "spawn-and-request-test/P22/patch.txt".into(),
        nonce: [0u8; 32],
        issuer_digest: Digest::sha256(b"issuer"),
        expected_receipt: ReceiptSpec("receipt/1".into()),
        rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec("restore prior bytes".into())),
        gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
    };

    let apply_payload = serde_json::to_vec(&EffectApplyRequest {
        token,
        started_at: sample_time(),
    })
    .unwrap();
    let apply_response = child
        .request(&request_msg(
            PortId::P22,
            SCHEMA_APPLY_REQUEST,
            apply_payload,
        ))
        .expect("P22-Request muss beantwortet werden");

    assert_eq!(apply_response.port_id, PortId::P23);
    assert_eq!(apply_response.r#type, MessageType::Response);
    let attempt: EffectAttempt = serde_json::from_slice(&apply_response.payload).unwrap();
    assert_eq!(attempt.outcome, EffectAttemptOutcomeKind::Completed);

    // Der Beweis, dass es ein echter Kindprozess war: die Datei existiert
    // im Sandbox, geschrieben von EINEM ANDEREN OS-Prozess, nicht diesem
    // Testprozess.
    let written = fs::read_to_string(sandbox.join("patch.txt")).unwrap();
    assert_eq!(written, "hello from a real child process");

    let invalidate_response = child
        .request(&request_msg(
            PortId::P37,
            SCHEMA_TOKEN_INVALIDATE,
            Vec::new(),
        ))
        .expect("P37-Request muss beantwortet werden");
    assert_eq!(invalidate_response.port_id, PortId::P37);
    assert_eq!(invalidate_response.r#type, MessageType::Response);

    child.shutdown().expect("Kindprozess muss sauber beenden");
    fs::remove_dir_all(&sandbox).ok();
}

/// OBL-010 / Vertrag Capability-Erzwingung, real bewiesen statt strukturell
/// angenommen: `LocalFsAdapter::apply` (`effect-local-fs/src/apply.rs`)
/// validiert `token.scope.0` selbst NICHT gegen Pfadausbrueche - es bildet
/// blind `sandbox_root.join(&token.scope.0)`. Ein `scope` wie `"..\..\
/// escape.txt"` wuerde in reinem Anwendungscode also klaglos AUSSERHALB
/// des Sandbox-Verzeichnisses schreiben. Dieser Test faengt genau das ab,
/// ohne die Adapterlogik selbst zu aendern: die Substraterzwingung
/// (`ChildProcess::spawn`s Low-IL-Absenkung + `sandbox_root`s exklusive
/// Freigabe, siehe psk-lifecycle::sandbox) muss den Schreibversuch auf
/// Betriebssystemebene verweigern, obwohl der Anwendungscode ihn anstandslos
/// durchreicht - Vertrag Capability-Erzwingung wortgetreu: "Eine Erzwingung
/// allein durch Programmkonvention ist nicht konform."
#[test]
fn a_path_escape_outside_sandbox_root_is_denied_by_the_substrate_not_the_adapter() {
    let sandbox = std::env::temp_dir().join(format!("psk-p24a-escape-{}", std::process::id()));
    let _ = fs::remove_dir_all(&sandbox);
    fs::create_dir_all(&sandbox).unwrap();
    // Liegt EINE Ebene ueber `sandbox` - ausserhalb der Low-IL-Freigabe,
    // die `ChildProcess::spawn` ausschliesslich auf `sandbox` selbst legt.
    let escape_target =
        std::env::temp_dir().join(format!("psk-p24a-escape-target-{}.txt", std::process::id()));
    let _ = fs::remove_file(&escape_target);

    let mut child = ChildProcess::spawn(
        &effect_local_fs_exe(),
        &[sandbox.to_str().unwrap()],
        Some(&sandbox),
    )
    .expect("effect-local-fs muss spawnbar sein");

    let escape_scope = format!("..\\{}", escape_target.file_name().unwrap().to_str().unwrap());
    let token = EffectToken {
        schema: "psk.effect-token/1.0".into(),
        id: ObjectId::new(SortId::Capability, Digest::sha256(b"tok-escape")),
        subject: ModuleId::EffectBoundary,
        effect_class: EffectClassId("fs.write.sandbox".into()),
        plan_digest: Digest::sha256(b"plan"),
        scope: ScopeExpr(escape_scope),
        capabilities: vec![CapabilityId("fs.write.sandbox".into())],
        preconditions: vec![PredicateExpr("this must never reach disk".into())],
        budget: BudgetSpec("1 Datei".into()),
        expires_at_tau_i: 1000,
        idempotency_key: "spawn-and-request-test/P22/escape".into(),
        nonce: [1u8; 32],
        issuer_digest: Digest::sha256(b"issuer"),
        expected_receipt: ReceiptSpec("receipt/1".into()),
        rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec("restore prior bytes".into())),
        gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
    };

    let apply_payload = serde_json::to_vec(&EffectApplyRequest {
        token,
        started_at: sample_time(),
    })
    .unwrap();
    let apply_response = child
        .request(&request_msg(
            PortId::P22,
            SCHEMA_APPLY_REQUEST,
            apply_payload,
        ))
        .expect("P22-Request muss trotz Ausbruchsversuch beantwortet werden - kein Absturz");

    let attempt: EffectAttempt = serde_json::from_slice(&apply_response.payload).unwrap();
    assert_eq!(
        attempt.outcome,
        EffectAttemptOutcomeKind::Failed,
        "das Substrat (nicht der Adapter) muss den Schreibversuch ausserhalb von sandbox_root verweigern"
    );
    assert!(
        !escape_target.exists(),
        "die Ausbruchsdatei darf unter keinen Umstaenden entstanden sein: {escape_target:?}"
    );

    child.shutdown().expect("Kindprozess muss trotz verweigertem Schreibversuch sauber beenden");
    fs::remove_dir_all(&sandbox).ok();
    let _ = fs::remove_file(&escape_target);
}

#[test]
fn p06_and_p24_round_trip_through_a_real_child_process() {
    let root = std::env::temp_dir().join(format!("psk-p24a-observer-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("known-file.txt"), b"observed content").unwrap();

    let mut child = ChildProcess::spawn(&observer_local_fs_exe(), &[root.to_str().unwrap()], None)
        .expect("observer-local-fs muss spawnbar sein");

    let record_payload = serde_json::to_vec(&ObserveRecordRequest {
        observed_at: sample_time(),
    })
    .unwrap();
    let record_response = child
        .request(&request_msg(
            PortId::P06,
            SCHEMA_RECORD_REQUEST,
            record_payload,
        ))
        .expect("P06-Request muss beantwortet werden");
    assert_eq!(record_response.port_id, PortId::P06);
    let record: ExternalRecord = serde_json::from_slice(&record_response.payload).unwrap();
    assert_eq!(record.file_hashes.len(), 1);
    assert_eq!(record.file_hashes[0].relative_path, "known-file.txt");
    assert_eq!(
        record.file_hashes[0].content_digest,
        Digest::sha256(b"observed content")
    );

    let receipt_payload = serde_json::to_vec(&ObserveReceiptRequest {
        observed_at: sample_time(),
        observer_identity: Digest::sha256(b"observer"),
        provenance: ProvenanceBlock("spawn-and-request-test/1".into()),
        independence_attestation: Digest::sha256(b"attestation"),
    })
    .unwrap();
    let receipt_response = child
        .request(&request_msg(
            PortId::P24,
            SCHEMA_RECEIPT_REQUEST,
            receipt_payload,
        ))
        .expect("P24-Request muss beantwortet werden");
    assert_eq!(receipt_response.port_id, PortId::P24);
    let receipt: ExternalReceipt = serde_json::from_slice(&receipt_response.payload).unwrap();
    assert_eq!(
        receipt.observer_adapter,
        AdapterId("observer-local-fs".into())
    );

    child.shutdown().expect("Kindprozess muss sauber beenden");
    fs::remove_dir_all(&root).ok();
}
