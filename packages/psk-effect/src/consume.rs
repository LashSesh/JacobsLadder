//! M15/M16, FSM-TOKEN-Verbrauch (Automat 13.x, "token").
//!
//! Sie: "Ein Token ist genau einmal konsumierbar, ueber die
//! Idempotenzschluessel [run_id, port_id, seq] aus dem Portvertrag."
//! Der generierte Automat (`psk_types::automata::token`) ist zustandslos -
//! `step(from, operator)` sagt nur, ob EIN Uebergang aus EINEM gegebenen
//! Zustand zulaessig waere. Welchen Zustand ein KONKRETES Token gerade
//! hat, muss etwas anderes festhalten - das ist `TokenLedger` hier: er
//! bindet jede `idempotency_key` an ihren aktuellen Zustand und macht die
//! Einmaligkeit dadurch wirksam, nicht nur die Kantenmenge des Automaten.
//! Ohne dieses Ledger koennte derselbe Aufruf `consume_once` zweimal aus
//! dem (jedes Mal neu behaupteten) Zustand ISSUED heraus "gueltig"
//! erscheinen.

use std::collections::BTreeMap;

use psk_types::automata::token as token_fsm;
use psk_types::automata::StepOutcome;
use psk_types::objects::EffectToken;
use psk_types::PskError;

pub use token_fsm::State as TokenState;

/// Bindet jede `idempotency_key` an ihren aktuellen FSM-TOKEN-Zustand.
#[derive(Debug, Clone, Default)]
pub struct TokenLedger {
    states: BTreeMap<String, TokenState>,
}

/// Von Hand geschrieben statt abgeleitet, aus einem inhaltlichen Grund:
/// das Ledger ist Teil von Sigma (Definition 13.1, Position `Qt`) und geht
/// damit in `I_t = H(Can(Sigma_t))` ein (siehe
/// `psk_scheduler::sigma_digest`). Der kanonische Zustandsname MUSS der im
/// Register deklarierte sein (`constitution/state_machines.yaml`: ISSUED,
/// CONSUMED, EXPIRED, INVALIDATED, REVOKED) - also `State::id()`, nicht
/// serdes aus dem Rust-Variantennamen abgeleitete Schreibweise. Ein
/// `#[derive(Serialize)]` haette "Issued" geschrieben und damit einen
/// Bezeichner in die Laufzeitidentitaet getragen, den kein Register fuehrt;
/// eine spaetere Umbenennung der Rust-Variante haette I_t still veraendert.
///
/// Kein `Deserialize`: ein Tokenzustand entsteht ueber `register`/`advance`
/// (FSM-TOKEN), nie durch Einspielen eines fremden Werts - sonst waere die
/// Einmaligkeitsgarantie umgehbar.
impl serde::Serialize for TokenLedger {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.states.len()))?;
        for (key, state) in &self.states {
            map.serialize_entry(key, state.id())?;
        }
        map.end()
    }
}

impl TokenLedger {
    pub fn new() -> Self {
        TokenLedger {
            states: BTreeMap::new(),
        }
    }

    /// Registriert ein frisch ausgestelltes Token (Zustand ISSUED). Ein
    /// bereits bekannter Schluessel bleibt unveraendert - erneutes
    /// Registrieren ist kein neuer Ausstellungsakt.
    pub fn register(&mut self, token: &EffectToken) {
        self.states
            .entry(token.idempotency_key.clone())
            .or_insert(token_fsm::INITIAL);
    }

    pub fn state_of(&self, idempotency_key: &str) -> Option<TokenState> {
        self.states.get(idempotency_key).copied()
    }

    /// Wendet `operator` auf das Token mit `idempotency_key` an. Ein
    /// unbekannter Schluessel, ein struktur widriger Uebergang oder ein
    /// bereits verbrauchtes Token (CONSUMED/EXPIRED/INVALIDATED/REVOKED -
    /// alle vier sind laut Register Endzustaende, `forbidden` verbietet
    /// jede Rueckkehr) scheitert gleichermassen mit PSK-E008
    /// (effect_without_token): ein Aufrufer, der auf ein bereits
    /// entwertetes Token baut, hat strukturell kein gueltiges Token mehr.
    pub fn advance(
        &mut self,
        idempotency_key: &str,
        operator: &str,
    ) -> Result<TokenState, PskError> {
        let current = self
            .states
            .get(idempotency_key)
            .copied()
            .ok_or(PskError::EffectWithoutToken)?;

        let to = match token_fsm::step(current, operator, &[]) {
            Ok(StepOutcome::Allowed { to }) => to,
            // FSM-TOKEN deklariert keine gegateten Kanten (alle vier
            // Transitionen `gate: null`) - dieser Zweig ist nach dem
            // Register unerreichbar, bleibt aber ein Fehler statt eines
            // Panics, falls sich das Register je aendert.
            Ok(StepOutcome::RequiresGate { .. }) => return Err(PskError::EffectWithoutToken),
            Err(_) => return Err(PskError::EffectWithoutToken),
        };
        self.states.insert(idempotency_key.to_string(), to);
        Ok(to)
    }

    /// "genau einmal konsumierbar" - die konkrete Anwendung von `advance`
    /// mit dem Operator `consume_once`.
    pub fn consume_once(&mut self, idempotency_key: &str) -> Result<(), PskError> {
        self.advance(idempotency_key, "consume_once").map(|_| ())
    }
}

/// Invariante 20.4, zweiter Teil ("nicht abgelaufen"): prueft
/// `expires_at_tau_i` gegen den aktuellen Kausalzaehler. Der Kausalzaehler
/// (DualTime.tau_i) kommt vom Aufrufer - M16 fuehrt keine eigene Uhr.
pub fn check_not_expired(token: &EffectToken, current_tau_i: u64) -> Result<(), PskError> {
    if current_tau_i > token.expires_at_tau_i {
        Err(PskError::EffectWithoutToken)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        BudgetSpec, CapabilityId, EffectClassId, EffectTokenRollbackKind, ReceiptSpec, ScopeExpr,
    };
    use psk_types::{Digest, ObjectId};

    fn sample_token(key: &str) -> EffectToken {
        EffectToken {
            schema: "psk.effect-token/1.0".into(),
            id: ObjectId::new(
                psk_types::objects::SortId::Capability,
                Digest::sha256(key.as_bytes()),
            ),
            subject: psk_types::ModuleId::EffectBoundary,
            effect_class: EffectClassId("fs.write".into()),
            plan_digest: Digest::sha256(b"plan"),
            scope: ScopeExpr("sandbox".into()),
            capabilities: vec![CapabilityId("fs.write.sandbox".into())],
            preconditions: vec![],
            budget: BudgetSpec("10".into()),
            expires_at_tau_i: 100,
            idempotency_key: key.to_string(),
            nonce: [0u8; 32],
            issuer_digest: Digest::sha256(b"issuer"),
            expected_receipt: ReceiptSpec("receipt/1".into()),
            rollback: EffectTokenRollbackKind::NoRollbackJustified,
            gate_report_ref: ObjectId::new(psk_types::objects::SortId::Gate, Digest::sha256(b"g")),
        }
    }

    #[test]
    fn a_registered_token_starts_issued() {
        let mut ledger = TokenLedger::new();
        let token = sample_token("k1");
        ledger.register(&token);
        assert_eq!(ledger.state_of("k1"), Some(TokenState::Issued));
    }

    #[test]
    fn consuming_once_succeeds() {
        let mut ledger = TokenLedger::new();
        ledger.register(&sample_token("k1"));
        assert_eq!(ledger.consume_once("k1"), Ok(()));
        assert_eq!(ledger.state_of("k1"), Some(TokenState::Consumed));
    }

    #[test]
    fn consuming_twice_fails_the_second_time() {
        let mut ledger = TokenLedger::new();
        ledger.register(&sample_token("k1"));
        ledger.consume_once("k1").unwrap();
        assert_eq!(ledger.consume_once("k1"), Err(PskError::EffectWithoutToken));
    }

    #[test]
    fn expiring_then_consuming_fails() {
        let mut ledger = TokenLedger::new();
        ledger.register(&sample_token("k1"));
        ledger.advance("k1", "expire").unwrap();
        assert_eq!(ledger.consume_once("k1"), Err(PskError::EffectWithoutToken));
    }

    #[test]
    fn revoking_then_consuming_fails() {
        let mut ledger = TokenLedger::new();
        ledger.register(&sample_token("k1"));
        ledger.advance("k1", "revoke").unwrap();
        assert_eq!(ledger.consume_once("k1"), Err(PskError::EffectWithoutToken));
    }

    #[test]
    fn an_unknown_key_cannot_be_consumed() {
        let mut ledger = TokenLedger::new();
        assert_eq!(
            ledger.consume_once("never-registered"),
            Err(PskError::EffectWithoutToken)
        );
    }

    #[test]
    fn registering_twice_does_not_reset_progress() {
        let mut ledger = TokenLedger::new();
        let token = sample_token("k1");
        ledger.register(&token);
        ledger.consume_once("k1").unwrap();
        ledger.register(&token); // erneut "ausgestellt" gemeldet
        assert_eq!(
            ledger.state_of("k1"),
            Some(TokenState::Consumed),
            "ein zweites register() darf ein verbrauchtes Token nicht auf ISSUED zuruecksetzen"
        );
    }

    #[test]
    fn not_expired_within_the_window() {
        let token = sample_token("k1");
        assert_eq!(check_not_expired(&token, 50), Ok(()));
        assert_eq!(check_not_expired(&token, 100), Ok(()));
    }

    #[test]
    fn expired_past_the_window() {
        let token = sample_token("k1");
        assert_eq!(
            check_not_expired(&token, 101),
            Err(PskError::EffectWithoutToken)
        );
    }
}
