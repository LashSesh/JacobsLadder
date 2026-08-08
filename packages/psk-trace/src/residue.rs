//! M19 TraceReplayResidueStore, Residuenteil (Struktur 7.40, OBJ-RES).
//!
//! Axiom 7.41 (No Silent Loss), woertlich: "Jede Nichtclosure erzeugt
//! HOLD, FAIL, Quarantaene, Fork, Reanalyseauftrag oder ein sichtbares
//! Residuum. Stilles Verwerfen ist nicht konform. Ein ResidueRecord DARF
//! NICHT geloescht werden; er wird ausschliesslich in einen Folgezustand
//! ueberfuehrt."
//!
//! "Ueberfuehrt" (nicht: neu erzeugt) liest sich als Zustandsuebergang
//! DESSELBEN Residuums, nicht als neues Objekt mit neuer ObjectId -
//! anders als FieldIdentity.lifecycle (das ausdruecklich Teil von Can()
//! ist, siehe psk-fields::registry::advance). ResidueRecord.state ist
//! nicht in volatile_fields.yaml ausgeschlossen; die Identitaet wird hier
//! deshalb bei `open()` einmalig aus den inhaltlichen Feldern gebildet
//! (schema/type/origin_module/origin_object/scope/severity/
//! open_obligation/allowed_followups/opened_at - explizit ohne id, state,
//! closed_by), und `transition()` aendert `state`/`closed_by` am
//! bestehenden Eintrag, ohne die ID neu zu berechnen. Befund: das Werk
//! entscheidet diese Frage fuer ResidueRecord nicht ausdruecklich; diese
//! Implementierung liest "ueberfuehrt" als Identitaetskontinuitaet.
//!
//! Fuer die erlaubten Folgezustaende gibt es - anders als fuer
//! CandidateCapsule.phase (FSM-artig in Kapitel 12 beschrieben) oder die
//! sieben in constitution/state_machines.yaml gefuehrten Automaten - KEINE
//! deklarierte Zustandsmaschine ueber die sechs Werte OPEN | HELD |
//! QUARANTINED | RECANONICALIZED | CLOSED | EXCISED. Diese Implementierung
//! erfindet keine; sie erzwingt nur, was der Text ausdruecklich sagt: kein
//! Zurueck aus einem Endzustand (CLOSED, EXCISED - danach existiert kein
//! Operator, der weiterfuehrt), und `closed_by` ausschliesslich beim
//! Uebergang nach CLOSED, "nur durch expliziten Closure-Operator".

use psk_canon::{can, Media};
use psk_types::objects::{ObligationExpr, OperationId, ScopeExpr};
use psk_types::{DualTime, ModuleId, ObjectId, PskError};

use psk_types::objects::ResidueRecordStateKind as State;
pub use psk_types::objects::{ResidueRecord, ResidueRecordSeverityKind, ResidueRecordTypeKind};

/// Eingaben fuer `open`. `id`, `closed_by` und `state` fehlen: die ID folgt
/// aus dem Inhalt, `state` beginnt bei OPEN, `closed_by` bei `None`.
pub struct ResidueInputs {
    pub r#type: ResidueRecordTypeKind,
    pub origin_module: ModuleId,
    pub origin_object: ObjectId,
    pub scope: ScopeExpr,
    pub severity: ResidueRecordSeverityKind,
    pub open_obligation: ObligationExpr,
    pub allowed_followups: Vec<OperationId>,
    pub opened_at: DualTime,
}

fn compute_identity(draft: &ResidueInputs) -> Result<ObjectId, PskError> {
    // Nur die identitaetsbildenden Felder - state/closed_by/id sind
    // bewusst nicht Teil des Vorbilds (siehe Modulkopf).
    let preimage = serde_json::json!({
        "schema": "psk.residue/1.0",
        "type": draft.r#type,
        "origin_module": draft.origin_module,
        "origin_object": draft.origin_object,
        "scope": draft.scope,
        "severity": draft.severity,
        "open_obligation": draft.open_obligation,
        "allowed_followups": draft.allowed_followups,
        "opened_at": draft.opened_at,
    });
    let bytes = serde_json::to_vec(&preimage).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, Media::Json)?;
    psk_canon::object_id(psk_types::objects::SortId::Residue.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// Das Residuenledger eines Laufs. Es gibt bewusst keine `remove`-Methode:
/// Loeschung ist mit dieser API nicht ausdrueckbar (Axiom 7.41).
///
/// T-TRACE-001 (`drop_previous_residue -> FAIL`): die Zusicherung IST die
/// Abwesenheit der Methode, und die folgenden Doctests machen sie
/// mechanisch pruefbar statt bloss kommentiert - dasselbe Beweismuster
/// wie `GateAuthorization`s `compile_fail`-Doctests (psk-gate). Ein
/// Laufzeittest kann das nicht leisten: man kann nicht aufrufen, was
/// nicht existiert. Er wuerde nur zeigen, dass ein anderer Weg auch nicht
/// loescht - nie, dass es KEINEN gibt.
///
/// Kein `remove`:
/// ```compile_fail
/// let mut ledger = psk_trace::ResidueLedger::new();
/// let id = psk_types::ObjectId::new(
///     psk_types::objects::SortId::Residue,
///     psk_types::Digest::sha256(b"x"),
/// );
/// ledger.remove(id);
/// ```
///
/// Kein `clear`:
/// ```compile_fail
/// let mut ledger = psk_trace::ResidueLedger::new();
/// ledger.clear();
/// ```
///
/// Und kein Schreibzugriff auf die Sammlung selbst - `residues` ist
/// privat, `all()` gibt einen unveraenderlichen Ausschnitt:
/// ```compile_fail
/// let mut ledger = psk_trace::ResidueLedger::new();
/// ledger.all().clear();
/// ```
///
/// Positivkontrolle - ohne sie waeren die drei Doctests oben wertlos: ein
/// `compile_fail` besteht auch, wenn der Aufbau aus einem GANZ ANDEREN
/// Grund nicht uebersetzt (Tippfehler im Pfad, fehlender Import). Dieser
/// Test zeigt, dass genau derselbe Aufbau uebersetzt und laeuft - was
/// oben scheitert, scheitert also an der fehlenden Methode und an nichts
/// sonst:
/// ```
/// let mut ledger = psk_trace::ResidueLedger::new();
/// let id = psk_types::ObjectId::new(
///     psk_types::objects::SortId::Residue,
///     psk_types::Digest::sha256(b"x"),
/// );
/// assert!(ledger.get(id).is_none());
/// assert!(ledger.all().is_empty());
/// ```
///
/// `Serialize` (nicht `Deserialize`): das Ledger ist Teil von Sigma
/// (Definition 13.1, Position `Rt`) und geht damit in `I_t =
/// H(Can(Sigma_t))` ein - siehe `psk_scheduler::sigma_digest`. Die
/// Gegenrichtung fehlt bewusst: ein Residuum entsteht ueber `open` und
/// wandert ueber `transition`, nie durch Deserialisierung - sonst liesse
/// sich Axiom 7.41 (kein stilles Verwerfen) durch das Einspielen eines
/// gekuerzten Ledgers umgehen.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ResidueLedger {
    residues: Vec<ResidueRecord>,
}

impl ResidueLedger {
    pub fn new() -> Self {
        ResidueLedger {
            residues: Vec::new(),
        }
    }

    /// Oeffnet ein neues Residuum. Ein bereits vorhandenes Residuum mit
    /// identischem Inhalt (gleiche ID) wird nicht dupliziert, sondern
    /// zurueckgegeben - zwei gleichlautende Meldungen desselben Befunds
    /// sind dasselbe Residuum, kein zweites.
    pub fn open(&mut self, inputs: ResidueInputs) -> Result<ObjectId, PskError> {
        let id = compute_identity(&inputs)?;
        if self.residues.iter().any(|r| r.id == id) {
            return Ok(id);
        }
        self.residues.push(ResidueRecord {
            schema: "psk.residue/1.0".to_string(),
            id,
            r#type: inputs.r#type,
            origin_module: inputs.origin_module,
            origin_object: inputs.origin_object,
            scope: inputs.scope,
            severity: inputs.severity,
            open_obligation: inputs.open_obligation,
            allowed_followups: inputs.allowed_followups,
            opened_at: inputs.opened_at,
            closed_by: None,
            state: State::Open,
        });
        Ok(id)
    }

    pub fn get(&self, id: ObjectId) -> Option<&ResidueRecord> {
        self.residues.iter().find(|r| r.id == id)
    }

    pub fn all(&self) -> &[ResidueRecord] {
        &self.residues
    }

    /// Alle Residuen, die noch keinen Endzustand erreicht haben - fuer
    /// `M19.persist_open_obligations()` (Algorithmus 17.4).
    pub fn open_residues(&self) -> impl Iterator<Item = &ResidueRecord> {
        self.residues
            .iter()
            .filter(|r| !matches!(r.state, State::Closed | State::Excised))
    }

    /// Ueberfuehrt ein Residuum in `to`. CLOSED und EXCISED sind
    /// Endzustaende - kein Operator im Werk fuehrt aus ihnen heraus.
    /// `closed_by` MUSS genau dann gesetzt sein, wenn `to == Closed`
    /// ("nur durch expliziten Closure-Operator").
    pub fn transition(
        &mut self,
        id: ObjectId,
        to: State,
        closed_by: Option<ObjectId>,
    ) -> Result<(), PskError> {
        let record = self
            .residues
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(PskError::TraceOrResidueViolation)?;

        if matches!(record.state, State::Closed | State::Excised) {
            return Err(PskError::TraceOrResidueViolation);
        }
        let closing = to == State::Closed;
        if closing != closed_by.is_some() {
            return Err(PskError::TraceOrResidueViolation);
        }

        record.state = to;
        record.closed_by = closed_by;
        Ok(())
    }
}

/// H(Can(ResidueRecord)) fuer Referenzen von aussen (z.B. `residue_ref` in
/// ObstructionRecord, `residue_report_digest` in MachineCertificate).
pub fn residue_digest(record: &ResidueRecord) -> Result<psk_types::Digest, PskError> {
    let bytes = serde_json::to_vec(record).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(can(&bytes, Media::Json)?.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-04T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn inputs(scope: &str) -> ResidueInputs {
        ResidueInputs {
            r#type: ResidueRecordTypeKind::Budget,
            origin_module: ModuleId::Scheduler,
            origin_object: ObjectId::new(
                psk_types::objects::SortId::Dependency,
                psk_types::Digest::sha256(b"origin"),
            ),
            scope: ScopeExpr(scope.into()),
            severity: ResidueRecordSeverityKind::Blocking,
            open_obligation: ObligationExpr("Budget wieder aufladen".into()),
            allowed_followups: vec![],
            opened_at: sample_time(),
        }
    }

    #[test]
    fn opening_starts_in_open_state_with_no_closer() {
        let mut ledger = ResidueLedger::new();
        let id = ledger.open(inputs("s1")).unwrap();
        let record = ledger.get(id).unwrap();
        assert_eq!(record.state, State::Open);
        assert_eq!(record.closed_by, None);
    }

    #[test]
    fn identical_content_does_not_duplicate() {
        let mut ledger = ResidueLedger::new();
        let a = ledger.open(inputs("s1")).unwrap();
        let b = ledger.open(inputs("s1")).unwrap();
        assert_eq!(a, b);
        assert_eq!(ledger.all().len(), 1);
    }

    #[test]
    fn different_scope_yields_a_different_residue() {
        let mut ledger = ResidueLedger::new();
        let a = ledger.open(inputs("s1")).unwrap();
        let b = ledger.open(inputs("s2")).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn closing_requires_an_explicit_closer() {
        let mut ledger = ResidueLedger::new();
        let id = ledger.open(inputs("s1")).unwrap();
        assert_eq!(
            ledger.transition(id, State::Closed, None),
            Err(PskError::TraceOrResidueViolation),
            "closed_by MUSS gesetzt sein, wenn nach CLOSED uebergegangen wird"
        );
        let closer = ObjectId::new(
            psk_types::objects::SortId::Gate,
            psk_types::Digest::sha256(b"op"),
        );
        assert_eq!(ledger.transition(id, State::Closed, Some(closer)), Ok(()));
        assert_eq!(ledger.get(id).unwrap().closed_by, Some(closer));
    }

    #[test]
    fn non_closing_transitions_must_not_carry_a_closer() {
        let mut ledger = ResidueLedger::new();
        let id = ledger.open(inputs("s1")).unwrap();
        let closer = ObjectId::new(
            psk_types::objects::SortId::Gate,
            psk_types::Digest::sha256(b"op"),
        );
        assert_eq!(
            ledger.transition(id, State::Held, Some(closer)),
            Err(PskError::TraceOrResidueViolation)
        );
        assert_eq!(ledger.transition(id, State::Held, None), Ok(()));
    }

    #[test]
    fn closed_is_terminal() {
        let mut ledger = ResidueLedger::new();
        let id = ledger.open(inputs("s1")).unwrap();
        let closer = ObjectId::new(
            psk_types::objects::SortId::Gate,
            psk_types::Digest::sha256(b"op"),
        );
        ledger.transition(id, State::Closed, Some(closer)).unwrap();
        assert_eq!(
            ledger.transition(id, State::Held, None),
            Err(PskError::TraceOrResidueViolation),
            "aus CLOSED fuehrt kein Operator zurueck"
        );
    }

    #[test]
    fn excised_is_terminal() {
        let mut ledger = ResidueLedger::new();
        let id = ledger.open(inputs("s1")).unwrap();
        ledger.transition(id, State::Excised, None).unwrap();
        assert_eq!(
            ledger.transition(id, State::Quarantined, None),
            Err(PskError::TraceOrResidueViolation)
        );
    }

    #[test]
    fn there_is_no_way_to_remove_a_residue() {
        // Axiom 7.41: strukturelle Abwesenheit einer Loeschmethode ist der
        // Test hier selbst - er kompiliert nur, weil `remove` nicht existiert.
        let mut ledger = ResidueLedger::new();
        ledger.open(inputs("s1")).unwrap();
        ledger
            .transition(ledger.all()[0].id, State::Excised, None)
            .unwrap();
        assert_eq!(
            ledger.all().len(),
            1,
            "auch exzidiert bleibt der Eintrag sichtbar"
        );
    }

    #[test]
    fn open_residues_excludes_terminal_states() {
        let mut ledger = ResidueLedger::new();
        let a = ledger.open(inputs("s1")).unwrap();
        let b = ledger.open(inputs("s2")).unwrap();
        ledger.transition(a, State::Excised, None).unwrap();
        let remaining: Vec<_> = ledger.open_residues().map(|r| r.id).collect();
        assert_eq!(remaining, vec![b]);
    }

    #[test]
    fn transitioning_an_unknown_id_fails_closed() {
        let mut ledger = ResidueLedger::new();
        let unknown = ObjectId::new(
            psk_types::objects::SortId::Residue,
            psk_types::Digest::sha256(b"x"),
        );
        assert_eq!(
            ledger.transition(unknown, State::Held, None),
            Err(PskError::TraceOrResidueViolation)
        );
    }
}
