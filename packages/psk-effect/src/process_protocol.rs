//! P24a: Nachrichtenformen fuer P22 (M15->M16, EffectToken) und P37
//! (M26->M16, TokenInvalidate) ueber eine echte Prozessgrenze, plus ein
//! wiederverwendbarer Dispatcher (`serve_request`), den sowohl der
//! `effect-local-fs`-Prozess (real, ueber stdin/stdout) als auch Tests
//! (in-process, ohne Prozessgrenze) gegen denselben `EffectAdapter`
//! aufrufen koennen.
//!
//! `EffectApplyRequest` ist keine eigene Wertedecke aus einem Kapitel-7-
//! Register (`EffectPlan` selbst ist laut psk-reconciliation-Modulkopf
//! kein registriertes Objekt) - sie buendelt nur `EffectAdapter::apply`s
//! zwei bestehende Parameter (`token`, `started_at`) fuer die Drahtform,
//! genau wie `IssueInputs`/`ObservationInputs` an anderer Stelle dieses
//! Werks bereits bestehende Parameterlisten buendeln.
//!
//! Fuer P37 (TokenInvalidate) existiert im Werk bisher keine reale
//! Semantik jenseits des leeren Markertyps (`architecture/port_registry.yaml`
//! nennt die Nutzlast, kein Register beschreibt ihr Verhalten am
//! Adapter) - `TokenLedger`s Zustandsfuehrung (psk-effect::consume) ist
//! die tatsaechlich zustaendige Stelle, nicht der Adapter selbst. Diese
//! Implementierung bestaetigt den Empfang echt (kein stiller Drop), ohne
//! eine Adapterreaktion zu erfinden, die nirgends spezifiziert ist.

use psk_types::objects::{EffectAttempt, EffectToken};
use psk_types::{
    Digest, DualTime, MessageType, ModuleId, Msg, PortId, RunId, SchemaId, TraceRef, Ulid,
};

use crate::EffectAdapter;

/// P22-Nutzlast: `EffectAdapter::apply`s beide Parameter, drahtfaehig
/// gebuendelt. "M16 fuehrt keine eigene Uhr" (siehe `boundary`-Modulkopf) -
/// `started_at` MUSS deshalb Teil der Anfrage sein, nicht am Adapterende
/// erzeugt werden.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EffectApplyRequest {
    pub token: EffectToken,
    pub started_at: DualTime,
}

pub const SCHEMA_APPLY_REQUEST: &str = "psk.effect-apply-request/1.0";
pub const SCHEMA_TOKEN_INVALIDATE: &str = "psk.token-invalidate/1.0";

fn wire_time() -> DualTime {
    DualTime {
        tau_i: 0,
        tau_e: "1970-01-01T00:00:00.000000000Z".into(),
        clock_ref: psk_types::ClockRef("psk-ipc".into()),
        uncertainty_ns: 0,
    }
}

/// Baut eine Antwort-Msg zu `request` - `msg_id` als `request.msg_id + 1`
/// ist ein bewusst einfacher, deterministischer Platzhalter: dieses Werk
/// hat noch keinen echten ULID-Generator (Uhr-Anbindung, Crockford-
/// Base32), siehe `psk_types::msg`-Modulkopf. Innerhalb EINES Request/
/// Response-Paars bleibt er kollisionsfrei; ein produktionsreifer
/// Generator ist eigenstaendige, hier nicht vorgezogene Arbeit.
fn respond(
    request: &Msg,
    port_id: PortId,
    r#type: MessageType,
    schema_id: &str,
    payload: Vec<u8>,
) -> Msg {
    Msg {
        msg_id: Ulid(request.msg_id.0.wrapping_add(1)),
        port_id,
        r#type,
        schema_id: SchemaId(schema_id.to_string()),
        producer: ModuleId::EffectBoundary,
        consumer: request.producer,
        run_id: RunId(request.run_id.0.clone()),
        seq: request.seq,
        input_digests: vec![request.payload_digest],
        created_at: wire_time(),
        trace_parent: TraceRef(request.payload_digest),
        payload_digest: Digest::sha256(&payload),
        payload,
        signature: None,
    }
}

fn fault(request: &Msg, reason: &str) -> Msg {
    respond(
        request,
        request.port_id,
        MessageType::Fault,
        "psk.fault/1.0",
        reason.as_bytes().to_vec(),
    )
}

/// Wertet eine einzelne Anfrage gegen `adapter` aus und baut die Antwort -
/// von `effect-local-fs::main` (reale Prozessgrenze) und von Tests
/// (in-process) gleichermassen aufrufbar.
pub fn serve_request(adapter: &impl EffectAdapter, request: &Msg) -> Msg {
    match request.port_id {
        PortId::P22 => match serde_json::from_slice::<EffectApplyRequest>(&request.payload) {
            Ok(apply_request) => {
                let attempt: EffectAttempt =
                    adapter.apply(&apply_request.token, apply_request.started_at);
                match serde_json::to_vec(&attempt) {
                    Ok(bytes) => respond(
                        request,
                        PortId::P23,
                        MessageType::Response,
                        "psk.effect-attempt/1.0",
                        bytes,
                    ),
                    Err(_) => fault(request, "EffectAttempt nicht serialisierbar"),
                }
            }
            Err(_) => fault(request, "EffectApplyRequest nicht lesbar"),
        },
        PortId::P37 => {
            // Siehe Modulkopf: echte Empfangsbestaetigung, keine erfundene
            // Adapterreaktion - P37 hat keine spezifizierte Adapterwirkung.
            respond(
                request,
                PortId::P37,
                MessageType::Response,
                SCHEMA_TOKEN_INVALIDATE,
                Vec::new(),
            )
        }
        _ => fault(request, "unbekannter Port fuer den Effektprozess"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        BudgetSpec, CapabilityId, EffectClassId, EffectTokenRollbackKind, PredicateExpr,
        ReceiptSpec, RollbackSpec, ScopeExpr, SortId,
    };
    use psk_types::ObjectId;

    struct NoopAdapter;
    impl EffectAdapter for NoopAdapter {
        fn id(&self) -> psk_types::objects::AdapterId {
            psk_types::objects::AdapterId("noop".into())
        }
        fn declared_effect_classes(&self) -> Vec<EffectClassId> {
            vec![]
        }
        fn required_capabilities(&self) -> Vec<CapabilityId> {
            vec![]
        }
        fn prestate(&self, _scope: &ScopeExpr) -> Digest {
            Digest::sha256(b"pre")
        }
        fn apply(&self, token: &EffectToken, started_at: DualTime) -> EffectAttempt {
            EffectAttempt {
                id: ObjectId::new(SortId::Effect, Digest::sha256(b"applied")),
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
            false
        }
    }

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_token() -> EffectToken {
        EffectToken {
            schema: "psk.effect-token/1.0".into(),
            id: ObjectId::new(SortId::Capability, Digest::sha256(b"tok")),
            subject: ModuleId::EffectBoundary,
            effect_class: EffectClassId("fs.write.sandbox".into()),
            plan_digest: Digest::sha256(b"plan"),
            scope: ScopeExpr("x.txt".into()),
            capabilities: vec![CapabilityId("fs.write.sandbox".into())],
            preconditions: vec![PredicateExpr("hi".into())],
            budget: BudgetSpec("1".into()),
            expires_at_tau_i: 1000,
            idempotency_key: "run-0/P22/x.txt".into(),
            nonce: [0u8; 32],
            issuer_digest: Digest::sha256(b"issuer"),
            expected_receipt: ReceiptSpec("r/1".into()),
            rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec("undo".into())),
            gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
        }
    }

    fn request_msg(port_id: PortId, schema_id: &str, payload: Vec<u8>) -> Msg {
        Msg {
            msg_id: Ulid(1),
            port_id,
            r#type: MessageType::Request,
            schema_id: SchemaId(schema_id.into()),
            producer: ModuleId::EffectTokenService,
            consumer: ModuleId::EffectBoundary,
            run_id: RunId("run-0".into()),
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
    fn p22_apply_request_produces_a_p23_response_with_a_real_attempt() {
        let req = EffectApplyRequest {
            token: sample_token(),
            started_at: sample_time(),
        };
        let payload = serde_json::to_vec(&req).unwrap();
        let msg = request_msg(PortId::P22, SCHEMA_APPLY_REQUEST, payload);

        let response = serve_request(&NoopAdapter, &msg);
        assert_eq!(response.port_id, PortId::P23);
        assert_eq!(response.r#type, MessageType::Response);
        let attempt: EffectAttempt = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(
            attempt.outcome,
            psk_types::objects::EffectAttemptOutcomeKind::Completed
        );
    }

    #[test]
    fn p37_invalidate_is_acknowledged_not_dropped() {
        let msg = request_msg(PortId::P37, SCHEMA_TOKEN_INVALIDATE, Vec::new());
        let response = serve_request(&NoopAdapter, &msg);
        assert_eq!(response.port_id, PortId::P37);
        assert_eq!(response.r#type, MessageType::Response);
    }

    #[test]
    fn a_malformed_apply_payload_yields_a_fault_not_a_panic() {
        let msg = request_msg(PortId::P22, SCHEMA_APPLY_REQUEST, b"not json".to_vec());
        let response = serve_request(&NoopAdapter, &msg);
        assert_eq!(response.r#type, MessageType::Fault);
    }
}
