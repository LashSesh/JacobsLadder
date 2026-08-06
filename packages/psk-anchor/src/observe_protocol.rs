//! P24a: Nachrichtenformen fuer P06 (M17->M05, ExternalRecord) und P24
//! (M17->M18, ExternalReceipt) ueber eine echte Prozessgrenze, plus ein
//! wiederverwendbarer Dispatcher (`serve_request`), den sowohl der
//! `observer-local-fs`-Prozess (real, ueber stdin/stdout) als auch Tests
//! (in-process) aufrufen koennen.
//!
//! `serve_request` nimmt die eigentliche Beobachtung als Closure entgegen
//! (`FnOnce(DualTime) -> Result<ExternalRecord, String>`), NICHT als
//! `ObserverAdapter`-Trait-Objekt: `ObserverAdapter` (Schnittstelle 20.5)
//! hat in diesem Werk noch keinen realen Implementor - die tatsaechlich
//! funktionierende, getestete Beobachtung ist `observer_local_fs::observe`,
//! eine freie Funktion mit ANDERER Signatur
//! (`Result<ExternalRecord, ObserveError>` gegen ein `ObserverConfig`,
//! nicht `ExternalReceipt` gegen ein `ScopeExpr`). psk-anchor haengt
//! bewusst nicht von `observer-local-fs` ab (Adapter haengen von M17 ab,
//! nicht umgekehrt) - die Closure ist die minimale Bruecke, ohne eine
//! Traitimplementierung vorzutaeuschen, die es nicht gibt.
//!
//! `port_registry.yaml` fuehrt fuer M17 nur die AUSGEHENDEN Ports (P06,
//! P24) - kein Port modelliert eine eingehende "bitte beobachten"-
//! Anforderung. Diese Implementierung liest das als: die Anforderung
//! selbst ist kein Kapitel-4-Portvertrag (sie traegt keine Kapitel-7-
//! Nutzlast, nur Beobachtungsparameter), sondern reine Auftragsvergabe
//! ueber denselben Msg-Rahmen; erst die ANTWORT (ExternalRecord oder
//! ExternalReceipt) realisiert den jeweiligen Port.

use psk_types::objects::ProvenanceBlock;
use psk_types::{
    Digest, DualTime, MessageType, ModuleId, Msg, PortId, RunId, SchemaId, TraceRef, Ulid,
};

use crate::receipt::{build_receipt, ObservationInputs};
use crate::ExternalRecord;
use psk_types::objects::AdapterId;

pub const SCHEMA_RECORD_REQUEST: &str = "psk.observe-record-request/1.0";
pub const SCHEMA_RECEIPT_REQUEST: &str = "psk.observe-receipt-request/1.0";

/// Anforderung fuer P06 (ExternalRecord).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObserveRecordRequest {
    pub observed_at: DualTime,
}

/// Anforderung fuer P24 (ExternalReceipt) - `ObservationInputs` minus
/// `record`/`observer_adapter` (die liefert `serve_request` selbst, aus
/// der Beobachtung bzw. `observer_id`).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ObserveReceiptRequest {
    pub observed_at: DualTime,
    pub observer_identity: Digest,
    pub provenance: ProvenanceBlock,
    pub independence_attestation: Digest,
}

fn wire_time() -> DualTime {
    DualTime {
        tau_i: 0,
        tau_e: "1970-01-01T00:00:00.000000000Z".into(),
        clock_ref: psk_types::ClockRef("psk-ipc".into()),
        uncertainty_ns: 0,
    }
}

/// Siehe `psk_effect::process_protocol::respond`s Modulkommentar zu
/// `msg_id`: derselbe einfache, dokumentierte Platzhalter, kein echter
/// ULID-Generator.
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
        producer: ModuleId::ExternalRecordIngress,
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

/// Wertet eine einzelne Beobachtungsanforderung aus. `observe` fuehrt die
/// tatsaechliche Dateisystembeobachtung durch (siehe Modulkopf);
/// `observer_id` ist die `AdapterId`, die beide Antwortformen tragen.
pub fn serve_request(
    observe: impl FnOnce(DualTime) -> Result<ExternalRecord, String>,
    observer_id: AdapterId,
    request: &Msg,
) -> Msg {
    match (request.port_id, request.schema_id.0.as_str()) {
        (PortId::P06, SCHEMA_RECORD_REQUEST) => {
            match serde_json::from_slice::<ObserveRecordRequest>(&request.payload) {
                Ok(parsed) => match observe(parsed.observed_at) {
                    Ok(record) => match serde_json::to_vec(&record) {
                        Ok(bytes) => respond(
                            request,
                            PortId::P06,
                            MessageType::Response,
                            "psk.external-record/1.0",
                            bytes,
                        ),
                        Err(_) => fault(request, "ExternalRecord nicht serialisierbar"),
                    },
                    Err(e) => fault(request, &e),
                },
                Err(_) => fault(request, "ObserveRecordRequest nicht lesbar"),
            }
        }
        (PortId::P24, SCHEMA_RECEIPT_REQUEST) => {
            match serde_json::from_slice::<ObserveReceiptRequest>(&request.payload) {
                Ok(parsed) => {
                    let record = match observe(parsed.observed_at.clone()) {
                        Ok(r) => r,
                        Err(e) => return fault(request, &e),
                    };
                    let record_bytes = match serde_json::to_vec(&record) {
                        Ok(b) => b,
                        Err(_) => return fault(request, "ExternalRecord nicht serialisierbar"),
                    };
                    let receipt = build_receipt(ObservationInputs {
                        observer_adapter: observer_id,
                        observer_identity: parsed.observer_identity,
                        observed_at: parsed.observed_at,
                        record: record_bytes,
                        provenance: parsed.provenance,
                        independence_attestation: parsed.independence_attestation,
                    });
                    match receipt.and_then(|r| {
                        serde_json::to_vec(&r)
                            .map_err(|_| psk_types::PskError::CanonicalizationFailed)
                    }) {
                        Ok(bytes) => respond(
                            request,
                            PortId::P24,
                            MessageType::Response,
                            "psk.external-receipt/1.0",
                            bytes,
                        ),
                        Err(_) => fault(request, "ExternalReceipt nicht erzeugbar"),
                    }
                }
                Err(_) => fault(request, "ObserveReceiptRequest nicht lesbar"),
            }
        }
        _ => fault(
            request,
            "unbekannter Port oder Schema fuer den Beobachterprozess",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::ExternalReceipt;

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_record() -> ExternalRecord {
        ExternalRecord {
            file_hashes: vec![],
            git_commit: None,
            observed_at: sample_time(),
            permissions: crate::ObservedPermissions { read_only: false },
            configuration_digest: Digest::sha256(b"cfg"),
            allowed_scope: "workspace".into(),
        }
    }

    fn request_msg(port_id: PortId, schema_id: &str, payload: Vec<u8>) -> Msg {
        Msg {
            msg_id: Ulid(7),
            port_id,
            r#type: MessageType::Request,
            schema_id: SchemaId(schema_id.into()),
            producer: ModuleId::AnchorRegistry,
            consumer: ModuleId::ExternalRecordIngress,
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
    fn p06_record_request_returns_a_real_external_record() {
        let payload = serde_json::to_vec(&ObserveRecordRequest {
            observed_at: sample_time(),
        })
        .unwrap();
        let msg = request_msg(PortId::P06, SCHEMA_RECORD_REQUEST, payload);

        let response = serve_request(
            |_at| Ok(sample_record()),
            AdapterId("observer-local-fs".into()),
            &msg,
        );
        assert_eq!(response.port_id, PortId::P06);
        assert_eq!(response.r#type, MessageType::Response);
        let record: ExternalRecord = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(record, sample_record());
    }

    #[test]
    fn p24_receipt_request_returns_a_real_external_receipt() {
        let payload = serde_json::to_vec(&ObserveReceiptRequest {
            observed_at: sample_time(),
            observer_identity: Digest::sha256(b"observer"),
            provenance: ProvenanceBlock("prov/1".into()),
            independence_attestation: Digest::sha256(b"attest"),
        })
        .unwrap();
        let msg = request_msg(PortId::P24, SCHEMA_RECEIPT_REQUEST, payload);

        let response = serve_request(
            |_at| Ok(sample_record()),
            AdapterId("observer-local-fs".into()),
            &msg,
        );
        assert_eq!(response.port_id, PortId::P24);
        let receipt: ExternalReceipt = serde_json::from_slice(&response.payload).unwrap();
        assert_eq!(
            receipt.observer_adapter,
            AdapterId("observer-local-fs".into())
        );
    }

    #[test]
    fn an_observation_failure_yields_a_fault_not_a_panic() {
        let msg = request_msg(
            PortId::P06,
            SCHEMA_RECORD_REQUEST,
            serde_json::to_vec(&ObserveRecordRequest {
                observed_at: sample_time(),
            })
            .unwrap(),
        );
        let response = serve_request(
            |_at| Err("Wurzel nicht gefunden".to_string()),
            AdapterId("observer-local-fs".into()),
            &msg,
        );
        assert_eq!(response.r#type, MessageType::Fault);
    }

    #[test]
    fn an_unknown_schema_yields_a_fault() {
        let msg = request_msg(PortId::P06, "psk.unknown/1.0", Vec::new());
        let response = serve_request(
            |_at| Ok(sample_record()),
            AdapterId("observer-local-fs".into()),
            &msg,
        );
        assert_eq!(response.r#type, MessageType::Fault);
    }
}
