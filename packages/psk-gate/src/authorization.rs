//! M14 AuthorityConsequenceGate, Autorisierungstoken.
//!
//! Sie: "CapabilityMatrix verweigert M16 explizit token.issue (denials,
//! reason: separation_of_powers), und Vertrag 'Capability-Erzwingung'
//! verlangt Substratebene - 'Erzwingung allein durch Programmkonvention
//! ist nicht konform, erzeugt T-SEC-001-Fehlschlag.' API-Form ist damit
//! nicht ausreichend, kein offener Punkt."
//!
//! `GateReport` (Struktur 7.30) hat ausschliesslich `pub`-Felder - wie
//! jedes generierte Kapitel-7-Objekt in diesem Werk. Das heisst: JEDER
//! Code, der `psk_types::objects::GateReport` importiert, kann per
//! Struct-Literal einen GateReport mit `decision: PASS` BEHAUPTEN, ohne
//! `evaluate_gate` je durchlaufen zu haben. Der bisherige Aufbau von
//! `token::issue()` (Pruefung von `gate_report.decision == PASS` zur
//! Laufzeit) war deshalb nie mehr als Programmkonvention, unabhaengig
//! davon, ob M15 oder M16 der Aufrufer war.
//!
//! `GateAuthorization` behebt das mit `#[non_exhaustive]`: ein so
//! markierter Typ ist ausserhalb seines definierenden CRATES per
//! Struct-Literal NICHT konstruierbar, selbst wenn - wie hier - alle
//! Felder `pub` sind (die idiomatische Alternative zu einem versteckten
//! privaten Feld; clippy::manual_non_exhaustive verlangt sie ausdruecklich
//! anstelle eines solchen Felds). Das gilt fuer JEDEN Aufrufer in JEDEM
//! fremden Crate, nicht nur "innerhalb desselben Crates schwierig" wie
//! beim token/boundary-Geschwisterproblem in psk-effect - psk-gate und
//! psk-effect sind eigene Crates, also greift die Schranke voll. Der
//! einzige Weg zu einem Wert ist `authorize()`, und `authorize()` gibt
//! nur bei `decision == PASS` einen zurueck. `token::issue()`
//! (psk-effect) nimmt jetzt `&GateAuthorization` statt `&GateReport`
//! entgegen - der Laufzeit-Vergleich entfaellt dort vollstaendig, weil er
//! nichts mehr pruefen muesste: die Existenz des Wertes IST der Beweis.

use psk_types::objects::{GateId, GateReport, GateReportDecisionKind as Decision};
use psk_types::{ObjectId, PskError};

/// Unfaelschbarer Nachweis eines bestandenen Gates. Konstruierbar nur
/// innerhalb dieses Crates (`#[non_exhaustive]`) - siehe Modulkopf.
///
/// T-SEC-001 / R-RA-009 ("Capabilities are enforced at substrate level,
/// not by convention"): ein Aufrufer in einem fremden Crate - z.B. M16 in
/// psk-effect, selbst mit `psk-gate` als sichtbarer Abhaengigkeit - kann
/// diesen Typ nicht per Struct-Literal fabrizieren. Das MUSS ein
/// Kompilierfehler sein, keine Laufzeitpruefung:
///
/// ```compile_fail
/// let forged = psk_gate::GateAuthorization {
///     gate_report_id: todo!(),
///     gate_id: todo!(),
/// };
/// ```
///
/// Zweite, unabhaengige Schranke: `#[non_exhaustive]` blockiert NUR
/// Struct-Literal-Konstruktion. Deserialisierung ist kein Struct-Literal
/// und faellt nicht darunter - ein kuenftiges `#[derive(Deserialize)]`
/// wuerde diese ganze Sicherung unbemerkt aushebeln (jeder Aufrufer
/// koennte sich per JSON eine Autorisierung "ausdenken", ganz ohne
/// `authorize()`). `GateAuthorization` ist deshalb bewusst KEIN
/// Serialize/Deserialize und laeuft NICHT durch den generischen
/// Kapitel-7-Codegen (der serde fuer jedes kanonische Objekt automatisch
/// ableitet, siehe `tools/psk-codegen/src/objects.rs`) - es ist kein
/// Registerobjekt (object_registry.yaml fuehrt 28 Eintraege, keiner davon
/// GateAuthorization), sondern ein reiner In-Prozess-Marker. Passend zur
/// Regel "Einzelrechnerbetrieb": M14 und M15 teilen sich denselben
/// Kernprozess (M00-M15, M18-M27; nur M16 laeuft separat) -
/// GateAuthorization ueberquert also nie eine Prozessgrenze und muss es
/// nie tun. Diese negative Trait-Schranke haelt das sichtbar, statt es
/// nur zu behaupten - faellt sie um (z.B. weil jemand versehentlich
/// `#[derive(Deserialize)]` ergaenzt), schlaegt der naechste Testlauf
/// fehl, weil DANN kompiliert, was hier NICHT kompilieren soll:
///
/// ```compile_fail
/// fn require_deserialize<T: serde::de::DeserializeOwned>() {}
/// require_deserialize::<psk_gate::GateAuthorization>();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct GateAuthorization {
    pub gate_report_id: ObjectId,
    pub gate_id: GateId,
}

/// M14: die einzige Konstruktion einer `GateAuthorization`. Scheitert mit
/// PSK-E007 (gate_bypass), wenn `report.decision != PASS` - dieselbe
/// Fehlerursache, die `token::issue()` bis zu dieser Korrektur selbst
/// meldete, jetzt an der Quelle statt beim Verbraucher.
pub fn authorize(report: &GateReport) -> Result<GateAuthorization, PskError> {
    if report.decision != Decision::Pass {
        return Err(PskError::GateBypass);
    }
    Ok(GateAuthorization {
        gate_report_id: report.id,
        gate_id: report.gate_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(decision: Decision) -> GateReport {
        GateReport {
            schema: "psk.gate-report/1.0".into(),
            id: ObjectId::new(
                psk_types::objects::SortId::Gate,
                psk_types::Digest::sha256(b"gate"),
            ),
            gate_id: GateId::GEffect,
            order: 1,
            input_digests: vec![],
            decision,
            reasons: vec![],
            evidence_refs: vec![],
            residue_refs: vec![],
            seam_report_refs: vec![],
            replay_descriptor: psk_types::objects::ReplayDescriptor("replay/1".into()),
            decided_at: psk_types::DualTime {
                tau_i: 0,
                tau_e: "2026-08-04T00:00:00.000000000Z".into(),
                clock_ref: psk_types::ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            trace_ref: psk_types::TraceRef(psk_types::Digest::sha256(b"trace")),
        }
    }

    #[test]
    fn authorizing_a_passed_gate_succeeds() {
        let auth = authorize(&report(Decision::Pass)).unwrap();
        assert_eq!(auth.gate_id, GateId::GEffect);
    }

    #[test]
    fn authorizing_a_held_gate_fails() {
        assert_eq!(
            authorize(&report(Decision::Hold)),
            Err(PskError::GateBypass)
        );
    }

    #[test]
    fn authorizing_a_failed_gate_fails() {
        assert_eq!(
            authorize(&report(Decision::Fail)),
            Err(PskError::GateBypass)
        );
    }
}
