//! M16 EffectBoundary (Kapitel 20).
//!
//! Definition 20.1 (Effektgrenze): "M16 ist die einzige Komponente mit
//! ausgehenden Substratrechten." Schnittstelle 20.5 (Adapter) - `trait
//! EffectAdapter` fuehrt absichtlich KEINE `observe()`/`read_result()`/
//! `confirm()`-Methoden (im Text ausdruecklich "VERBOTEN" markiert): sie
//! fehlen hier nicht aus Nachlaessigkeit, sondern weil ein Typ, der
//! `EffectAdapter` implementiert, mit diesem Trait strukturell keine
//! Beobachtungsfaehigkeit erhalten KANN - es gibt keine Methode, ueber die
//! er eine liefern koennte.
//!
//! Invariante 20.7 (Adaptertrennung): "Keine Codeeinheit DARF zugleich
//! EffectAdapter und ObserverAdapter implementieren. Die beiden Adapter
//! MUSS getrennte Prozesse, getrennte Capabilities und getrennte
//! Identitaeten besitzen." Die getrennten Prozesse sind bereits als
//! getrennte Cargo-Pakete gefuehrt (`adapters/effect-local-fs`,
//! `adapters/observer-local-fs`, seit WP00/WP05). `ObserverAdapter` selbst
//! ist hier NICHT definiert: sein Trait gehoert M17 (psk-anchor), und
//! `psk-effect` haengt nicht von `psk-anchor` ab - ein Typ in diesem Paket
//! kann `ObserverAdapter` deshalb gar nicht implementieren, ihm fehlt der
//! Trait. Dieselbe Abwesenheit der Abhaengigkeit macht "M16 erzeugt
//! keinen eigenen Receipt" (forbidden_edge [M16, M17],
//! architecture/module_map.yaml) zu einem Compilerfehler, nicht zu einer
//! Konvention: `ExternalReceipt` ist ein psk-anchor-Typ und in diesem
//! Paket nicht benennbar.
//!
//! Fuer die zweite verbotene Kante, [M16, M15] ("Effektor stellt kein
//! eigenes Token aus"), gilt das NICHT im selben Sinn: M15 und M16 liegen
//! laut Werk im selben Paket ("psk-effect/ # M15, M16: Token Service,
//! Effektgrenze", Anhang-Verzeichnisbaum). Rusts Sichtbarkeitsregeln
//! kennen keine Geschwistermodul-Ausgrenzung innerhalb eines Crates - ein
//! `pub fn` in `token` ist fuer JEDES Modul desselben Crates erreichbar,
//! auch fuer `boundary`, sobald es oeffentlich genug ist, um von aussen
//! (anderen Crates) ueberhaupt aufgerufen werden zu koennen. Diese
//! Implementierung erreicht deshalb nicht mehr als: `boundary` importiert
//! `token::issue` nirgends, und keine Funktion hier nimmt einen
//! `GateReport` entgegen (nur bereits ausgestellte, im Ledger registrierte
//! Token) - das ist API-Formdurchsetzung, kein Compilerfehler bei
//! Verletzung. Befund, nicht stillschweigend als "erledigt" behandelt.

use crate::consume::{check_not_expired, TokenLedger};
use psk_types::objects::{
    AdapterId, CapabilityId, EffectAttempt, EffectClassId, EffectToken, ScopeExpr,
};
use psk_types::{Digest, DualTime, PskError};

/// Schnittstelle 20.5 (Adapter), `interface EffectAdapter`. Absichtlich OHNE
/// `observe`/`read_result`/`confirm` - siehe Modulkopf.
///
/// `apply` nimmt `started_at` als Parameter statt es selbst zu bestimmen:
/// "M16 fuehrt keine eigene Uhr" (`consume::check_not_expired`s
/// Modulkommentar) gilt fuer Adapter genauso wie fuer die Grenze selbst -
/// `EffectAttempt.started_at` MUSS gesetzt sein (Struktur 7.36 (EffectAttempt / ExternalReceipt), kein
/// optionales Feld), aber woher der Zeitwert stammt, ist Sache des
/// Aufrufers von `execute_effect`, nicht des Adapters.
/// ## Warum `prestate` und `apply` `&mut self` nehmen
///
/// Regel 20.6 (Vorzustand und Versuch klammern den Effekt): beide
/// Aufrufe MUESSEN denselben Beobachtungskanal benutzen, und zwischen
/// ihnen darf am beobachteten Bereich nichts geschehen. Ueber eine
/// Prozessgrenze heisst das: DERSELBE Kindprozess bedient beide und
/// wird ueber beide hinweg gehalten.
///
/// Die Regel sagt ausdruecklich, dass die Signatur zu aendern ist, wenn
/// sie das Halten verhindert. Gewaehlt ist `&mut self` und nicht innere
/// Veraenderlichkeit: `&mut self` DRUECKT die Klammer im Typsystem aus -
/// wer klammert, haelt den Adapter exklusiv. Ein Mutex haette dieselbe
/// Leitung geschuetzt, aber zwei Aufrufern erlaubt, sich zwischen
/// Vorzustand und Versuch zu schieben; genau das Fenster, das die Regel
/// schliesst.
///
/// Die vier lesenden Methoden bleiben `&self` - sie beobachten den
/// Bereich nicht.
pub trait EffectAdapter {
    fn id(&self) -> AdapterId;
    fn declared_effect_classes(&self) -> Vec<EffectClassId>;
    fn required_capabilities(&self) -> Vec<CapabilityId>;
    /// Klammert mit `apply` (Regel 20.6 (Vorzustand und Versuch klammern den Effekt)) - siehe Traitkommentar.
    fn prestate(&mut self, scope: &ScopeExpr) -> Digest;
    /// Klammert mit `prestate` (Regel 20.6 (Vorzustand und Versuch klammern den Effekt)) - siehe Traitkommentar.
    fn apply(&mut self, token: &EffectToken, started_at: DualTime) -> EffectAttempt;
    fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt;
    fn is_reversible(&self, token: &EffectToken) -> bool;
}

/// Weiterreichende Instanz fuer den geboxten Adapter: `execute_effect`
/// unten verlangt `&impl EffectAdapter`, was den impliziten `Sized`-Bund
/// des generischen Parameters auf `dyn EffectAdapter` (unsized) nicht
/// zulaesst. Ein zur Laufzeit gewaehlter Adapter (z.B. M25/`dispatch()`,
/// das Execute-Phase-Elemente typisiert entgegennimmt, ohne selbst
/// generisch ueber jeden moeglichen Adaptertyp zu sein) braucht deshalb
/// diese Bruecke - Standardmuster fuer Trait-Objekte, keine Erweiterung
/// des Traits selbst.
impl EffectAdapter for Box<dyn EffectAdapter + Send> {
    fn id(&self) -> AdapterId {
        self.as_ref().id()
    }
    fn declared_effect_classes(&self) -> Vec<EffectClassId> {
        self.as_ref().declared_effect_classes()
    }
    fn required_capabilities(&self) -> Vec<CapabilityId> {
        self.as_ref().required_capabilities()
    }
    fn prestate(&mut self, scope: &ScopeExpr) -> Digest {
        self.as_mut().prestate(scope)
    }
    fn apply(&mut self, token: &EffectToken, started_at: DualTime) -> EffectAttempt {
        self.as_mut().apply(token, started_at)
    }
    fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt {
        self.as_ref().compensate(attempt)
    }
    fn is_reversible(&self, token: &EffectToken) -> bool {
        self.as_ref().is_reversible(token)
    }
}

/// Invariante 20.4 (Kein Effekt ohne Token): "ExecuteEffect(e) = 1 =>
/// Gate(e) = PASS UND TokenBound(e) = 1. Ein Adapteraufruf ohne
/// Die ANGESCHLOSSENEN Leitungen der Effektgrenze (M16), wie der
/// Taktzyklus sie sieht: je Effektklasse hoechstens eine exklusive,
/// bereits verbundene Leitung.
///
/// Warum ein eigener Typ und kein Wert in Sigma: eine Leitung ist kein
/// Zustand, sondern die Anwesenheit der Aussenwelt - sie laesst sich
/// weder kanonisieren noch digesten, und ein Laufzustand, der sie
/// enthielte, waere nicht mehr H(Can(Sigma_t))-faehig. Die BINDUNG der
/// Adapter steht als Wert im RuntimeManifest (`adapter_versions`); das
/// lebende Gegenstueck reicht der Aufrufer der Taktschleife hier herein -
/// dasselbe Muster wie `ExclusiveLine` fuer den Kindprozess: der Kern
/// nimmt typisiert entgegen, was andere besitzen (das Spawnen gehoert
/// M26, `proc.control` liegt laut module_map.yaml nicht bei M25).
///
/// `&mut` in `line`: wer die Leitung bekommt, haelt sie exklusiv -
/// dieselbe Klammer-Begruendung wie bei `prestate`/`apply` oben. Kein
/// `Send`-Bund: `ExecuteRun` ist nicht nebenlaeufigkeitsfaehig
/// (gemeinsamer Schreibzustand, Regel 14.8 (Nebenläufigkeitsmodell)), die Leitung wechselt also
/// nie den Thread - ein Bund ohne Nutzer waere eine Anforderung, die
/// echte Kindprozess-Handles grundlos ausschloesse.
pub trait EffectLines {
    fn line(&mut self, class: &EffectClassId) -> Option<&mut dyn EffectAdapter>;
}

/// Keine Leitung angeschlossen: fuer Laeufe ohne Aussenwirkung (Shadow/
/// Readonly-Profile, reine Rechenlaeufe) und fuer Tests, die die
/// Execute-Phase nicht betreten. Ein ExecuteRun-Element ueber dieser
/// Grenze scheitert typisiert statt still zu simulieren.
pub struct NoEffectLines;

impl EffectLines for NoEffectLines {
    fn line(&mut self, _class: &EffectClassId) -> Option<&mut dyn EffectAdapter> {
        None
    }
}

/// gueltiges, nicht konsumiertes, nicht abgelaufenes Token erzeugt
/// PSK-E008, fuehrt keinen Effekt aus und schreibt ein ResidueRecord."
///
/// Diese Funktion ist die Schwelle: sie ruft `adapter.apply()` NUR auf,
/// wenn `idempotency_key` im Ledger als ISSUED steht und die
/// Ablaufzeit nicht ueberschritten ist, und markiert das Token danach als
/// verbraucht (`consume_once`) - der Adapter selbst sieht nie ein Token,
/// das nicht schon durch diese Pruefung ist.
pub fn execute_effect<A: EffectAdapter + ?Sized>(
    ledger: &mut TokenLedger,
    token: &EffectToken,
    current_tau_i: u64,
    started_at: DualTime,
    adapter: &mut A,
) -> Result<EffectAttempt, PskError> {
    check_not_expired(token, current_tau_i)?;
    ledger.consume_once(&token.idempotency_key)?;
    Ok(adapter.apply(token, started_at))
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        BudgetSpec, EffectAttemptOutcomeKind, EffectTokenRollbackKind, PredicateExpr, ReceiptSpec,
        SortId,
    };
    use psk_types::ObjectId;

    struct NullAdapter;

    impl EffectAdapter for NullAdapter {
        fn id(&self) -> AdapterId {
            AdapterId("null/1".into())
        }
        fn declared_effect_classes(&self) -> Vec<EffectClassId> {
            vec![EffectClassId("fs.write".into())]
        }
        fn required_capabilities(&self) -> Vec<CapabilityId> {
            vec![CapabilityId("fs.write.sandbox".into())]
        }
        fn prestate(&mut self, _scope: &ScopeExpr) -> Digest {
            Digest::sha256(b"prestate")
        }
        fn apply(&mut self, token: &EffectToken, started_at: psk_types::DualTime) -> EffectAttempt {
            EffectAttempt {
                id: ObjectId::new(SortId::Effect, Digest::sha256(b"attempt")),
                token_ref: token.id,
                adapter: self.id(),
                prestate_digest: self.prestate(&token.scope),
                plan_digest: token.plan_digest,
                started_at,
                ended_at: Some(sample_time()),
                outcome: EffectAttemptOutcomeKind::Completed,
                error: None,
                compensation_ref: None,
            }
        }
        fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt {
            EffectAttempt {
                id: ObjectId::new(SortId::Effect, Digest::sha256(b"compensation")),
                compensation_ref: Some(attempt.id),
                ..attempt.clone()
            }
        }
        fn is_reversible(&self, _token: &EffectToken) -> bool {
            true
        }
    }

    fn sample_time() -> psk_types::DualTime {
        psk_types::DualTime {
            tau_i: 0,
            tau_e: "2026-08-04T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_token(key: &str, expires: u64) -> EffectToken {
        EffectToken {
            schema: "psk.effect-token/1.0".into(),
            id: ObjectId::new(SortId::Capability, Digest::sha256(key.as_bytes())),
            subject: psk_types::ModuleId::EffectBoundary,
            effect_class: EffectClassId("fs.write".into()),
            plan_digest: Digest::sha256(b"plan"),
            scope: ScopeExpr("sandbox".into()),
            capabilities: vec![CapabilityId("fs.write.sandbox".into())],
            preconditions: Vec::<PredicateExpr>::new(),
            budget: BudgetSpec("10".into()),
            expires_at_tau_i: expires,
            idempotency_key: key.to_string(),
            nonce: [0u8; 32],
            issuer_digest: Digest::sha256(b"issuer"),
            expected_receipt: ReceiptSpec("receipt/1".into()),
            rollback: EffectTokenRollbackKind::NoRollbackJustified,
            gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
        }
    }

    #[test]
    fn executing_with_a_valid_token_succeeds_and_consumes_it() {
        let mut ledger = TokenLedger::new();
        let token = sample_token("k1", 100);
        ledger.register(&token);
        let attempt =
            execute_effect(&mut ledger, &token, 10, sample_time(), &mut NullAdapter).unwrap();
        assert_eq!(attempt.token_ref, token.id);
        assert_eq!(
            ledger.state_of("k1"),
            Some(crate::consume::TokenState::Consumed)
        );
    }

    #[test]
    fn executing_twice_with_the_same_token_fails_the_second_time() {
        let mut ledger = TokenLedger::new();
        let token = sample_token("k1", 100);
        ledger.register(&token);
        execute_effect(&mut ledger, &token, 10, sample_time(), &mut NullAdapter).unwrap();
        assert_eq!(
            execute_effect(&mut ledger, &token, 10, sample_time(), &mut NullAdapter),
            Err(PskError::EffectWithoutToken)
        );
    }

    #[test]
    fn executing_with_an_expired_token_fails_and_does_not_consume() {
        let mut ledger = TokenLedger::new();
        let token = sample_token("k1", 5);
        ledger.register(&token);
        assert_eq!(
            execute_effect(&mut ledger, &token, 10, sample_time(), &mut NullAdapter),
            Err(PskError::EffectWithoutToken)
        );
        // Nicht konsumiert - ein spaeter noch rechtzeitig eintreffender
        // Versuch (falls die Uhr falsch lag) findet das Token unveraendert.
        assert_eq!(
            ledger.state_of("k1"),
            Some(crate::consume::TokenState::Issued)
        );
    }

    #[test]
    fn executing_an_unregistered_token_fails() {
        let mut ledger = TokenLedger::new();
        let token = sample_token("never-registered", 100);
        assert_eq!(
            execute_effect(&mut ledger, &token, 10, sample_time(), &mut NullAdapter),
            Err(PskError::EffectWithoutToken)
        );
    }
}
