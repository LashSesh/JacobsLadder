//! M15 EffectTokenService (Kapitel 19).
//!
//! Invariante 20.4 (Kein Effekt ohne Token): "ExecuteEffect(e) = 1 =>
//! Gate(e) = PASS UND TokenBound(e) = 1." `issue` erzwingt die erste
//! Haelfte jetzt auf Substratebene statt per Konvention: es nimmt eine
//! `psk_gate::GateAuthorization` entgegen, nicht mehr den rohen
//! `GateReport`. `GateAuthorization` ist ausserhalb von `psk-gate` nicht
//! per Struct-Literal konstruierbar (privates Feld) - der einzige Weg zu
//! einem Wert ist `psk_gate::authorize()`, und das gelingt nur bei
//! `decision == PASS`. `issue` selbst prueft `decision` deshalb nicht
//! mehr: die blosse Existenz des Parameters ist der Beweis. Siehe
//! `psk_gate::authorization` fuer die vollstaendige Begruendung
//! (T-SEC-001/R-RA-009, CapabilityMatrix-Denial token.issue fuer M16).
//!
//! `idempotency_key: string` (Struktur 7.34 (EffectToken)) - Sie: "ueber die
//! Idempotenzschluessel [run_id, port_id, seq] aus dem Portvertrag."
//! `psk.port-registry/1.0` (Kapitel 4) fuehrt `idempotency_key: [run_id,
//! port_id, seq]` als SchluesselTUPEL fuer die Nachrichtenzustellung -
//! das Token uebernimmt dieselben drei Groessen fuer seine eigene
//! Einmaligkeit, nicht eine vierte, unabhaengige Kennung.

use psk_canon::{can, Media};
use psk_gate::GateAuthorization;
use psk_types::objects::{
    BudgetSpec, CapabilityId, EffectClassId, EffectToken, PredicateExpr, ReceiptSpec, ScopeExpr,
};
use psk_types::{Digest, ObjectId, PortId, PskError, RunId};

/// Eingaben fuer `issue`. `id`, `issuer_digest`, `nonce` und
/// `idempotency_key` fehlen: `id`/`issuer_digest` folgen aus dem Inhalt,
/// `nonce` wird vom Aufrufer als bereits gezogener Zufallswert uebergeben
/// (M15 selbst zieht keinen Zufall - Invariante 11.3 (Passdeterminismus), Passdeterminismus:
/// Zufall MUSS aus dem RunDescriptor/seed abgeleitet sein, nicht hier neu
/// gewuerfelt), `idempotency_key` wird aus `run_id`/`port_id`/`seq` gebaut.
///
/// `Clone`/`Serialize`: der deklarierte Patchplan eines Laufs liegt seit
/// der Taktumverdrahtung als Wert im Laufzustand Sigma (die Execute-
/// Phase liest ihn von dort) und geht damit in I_t ein.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IssueInputs {
    pub effect_class: EffectClassId,
    pub plan_digest: Digest,
    pub scope: ScopeExpr,
    pub capabilities: Vec<CapabilityId>,
    pub preconditions: Vec<PredicateExpr>,
    pub budget: BudgetSpec,
    pub expires_at_tau_i: u64,
    pub run_id: RunId,
    pub port_id: PortId,
    pub seq: u64,
    pub nonce: [u8; 32],
    pub expected_receipt: ReceiptSpec,
    pub rollback: psk_types::objects::EffectTokenRollbackKind,
}

/// "ueber die Idempotenzschluessel [run_id, port_id, seq] aus dem
/// Portvertrag" - eine feste, textuelle Zusammensetzung der drei
/// Groessen, damit zwei Aufrufe mit denselben dreien denselben Schluessel
/// ergeben.
fn build_idempotency_key(run_id: &RunId, port_id: PortId, seq: u64) -> String {
    format!("{}/{}/{}", run_id.0, port_id.id(), seq)
}

fn compute_identity(draft: &EffectToken) -> Result<(ObjectId, Digest), PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("id");
    obj.remove("issuer_digest");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, Media::Json)?;
    let id: ObjectId =
        psk_canon::object_id(psk_types::objects::SortId::Capability.id(), &projected)
            .parse()
            .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok((id, can(&bytes, Media::Json)?.digest()))
}

/// M15: stellt ein EffectToken aus. `auth` zu besitzen bezeugt bereits
/// `decision == PASS` (siehe Modulkopf) - kein weiterer Check hier noetig.
pub fn issue(auth: &GateAuthorization, inputs: IssueInputs) -> Result<EffectToken, PskError> {
    let idempotency_key = build_idempotency_key(&inputs.run_id, inputs.port_id, inputs.seq);
    let draft = EffectToken {
        schema: "psk.effect-token/1.0".to_string(),
        id: ObjectId::new(psk_types::objects::SortId::Capability, Digest::sha256(b"")), // Platzhalter
        subject: psk_types::ModuleId::EffectBoundary, // "ausschliesslich M16" (Struktur 7.34 (EffectToken))
        effect_class: inputs.effect_class,
        plan_digest: inputs.plan_digest,
        scope: inputs.scope,
        capabilities: inputs.capabilities,
        preconditions: inputs.preconditions,
        budget: inputs.budget,
        expires_at_tau_i: inputs.expires_at_tau_i,
        idempotency_key,
        nonce: inputs.nonce,
        issuer_digest: Digest::sha256(b""), // Platzhalter
        expected_receipt: inputs.expected_receipt,
        rollback: inputs.rollback,
        gate_report_ref: auth.gate_report_id,
    };
    let (id, issuer_digest) = compute_identity(&draft)?;
    Ok(EffectToken {
        id,
        issuer_digest,
        ..draft
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{EffectTokenRollbackKind, RollbackSpec};

    fn authorization() -> GateAuthorization {
        let report = psk_types::objects::GateReport {
            schema: "psk.gate-report/1.0".into(),
            id: ObjectId::new(psk_types::objects::SortId::Gate, Digest::sha256(b"gate")),
            gate_id: psk_types::objects::GateId::GEffect,
            order: 2,
            input_digests: vec![Digest::sha256(b"in")],
            decision: psk_types::objects::GateReportDecisionKind::Pass,
            reasons: vec![],
            evidence_refs: vec![],
            residue_refs: vec![],
            seam_report_refs: vec![ObjectId::new(
                psk_types::objects::SortId::Trace,
                Digest::sha256(b"seam"),
            )],
            replay_descriptor: psk_types::objects::ReplayDescriptor("replay/1".into()),
            decided_at: sample_time(),
            trace_ref: psk_types::TraceRef(Digest::sha256(b"trace")),
        };
        psk_gate::authorize(&report).unwrap()
    }

    fn sample_time() -> psk_types::DualTime {
        psk_types::DualTime {
            tau_i: 0,
            tau_e: "2026-08-04T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_inputs() -> IssueInputs {
        IssueInputs {
            effect_class: EffectClassId("fs.write".into()),
            plan_digest: Digest::sha256(b"plan"),
            scope: ScopeExpr("sandbox".into()),
            capabilities: vec![CapabilityId("fs.write.sandbox".into())],
            preconditions: vec![],
            budget: BudgetSpec("10 Einheiten".into()),
            expires_at_tau_i: 1000,
            run_id: RunId("run-0".into()),
            port_id: PortId::P22,
            seq: 3,
            nonce: [1u8; 32],
            expected_receipt: ReceiptSpec("receipt/1".into()),
            rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec("undo write".into())),
        }
    }

    #[test]
    fn issuing_with_a_genuine_authorization_succeeds() {
        let auth = authorization();
        let token = issue(&auth, sample_inputs()).unwrap();
        assert_eq!(token.gate_report_ref, auth.gate_report_id);
        assert_eq!(token.subject, psk_types::ModuleId::EffectBoundary);
    }

    #[test]
    fn idempotency_key_is_built_from_run_id_port_id_seq() {
        let token = issue(&authorization(), sample_inputs()).unwrap();
        assert_eq!(token.idempotency_key, "run-0/P22/3");
    }

    #[test]
    fn same_run_port_seq_yields_the_same_key() {
        let a = issue(&authorization(), sample_inputs()).unwrap();
        let b = issue(&authorization(), sample_inputs()).unwrap();
        assert_eq!(a.idempotency_key, b.idempotency_key);
    }

    #[test]
    fn different_seq_yields_a_different_key_and_identity() {
        let mut inputs_b = sample_inputs();
        inputs_b.seq = 4;
        let a = issue(&authorization(), sample_inputs()).unwrap();
        let b = issue(&authorization(), inputs_b).unwrap();
        assert_ne!(a.idempotency_key, b.idempotency_key);
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn rollback_carries_its_actual_content_not_just_a_tag() {
        // Codegen-Fund: "RollbackSpec | NO_ROLLBACK_JUSTIFIED" erzeugte vor
        // der Korrektur nur einen inhaltslosen Tag.
        let token = issue(&authorization(), sample_inputs()).unwrap();
        match token.rollback {
            EffectTokenRollbackKind::Rollbackspec(spec) => assert_eq!(spec.0, "undo write"),
            other => panic!("erwartet Rollbackspec mit Inhalt, bekam {other:?}"),
        }
    }

    #[test]
    fn no_rollback_justified_is_representable_without_a_spec() {
        let mut inputs = sample_inputs();
        inputs.rollback = EffectTokenRollbackKind::NoRollbackJustified;
        let token = issue(&authorization(), inputs).unwrap();
        assert_eq!(token.rollback, EffectTokenRollbackKind::NoRollbackJustified);
    }
}
