//! M18 ReconciliationEngine (Kapitel 20.2).
//!
//! Algorithmus 20.7 (Reconciliation), woertlich:
//! ```text
//! function reconcile(plan, attempt, receipts, anchor_post) -> ReconciliationReport:
//!     require attempt.token_ref.plan_digest == H(Can(plan)) else FAIL(PSK-E008)
//!     require |receipts| >= 1 else FAIL(PSK-E009)
//!     for r in receipts:
//!         require r.observer_adapter != attempt.adapter else FAIL(PSK-E009)
//!     expected = project_expected_state(plan, attempt.prestate_digest)
//!     observed = merge_records(receipts, anchor_post)
//!     diff = structural_diff(expected, observed)
//!     match diff:
//!         empty                       -> verdict = CLOSED
//!         within_declared_tolerance   -> verdict = CLOSED
//!         nonempty and explicable     -> verdict = OPEN; residualize(diff)
//!         contradictory               -> verdict = DIVERGENT; residualize(diff); FAIL
//!         receipts_insufficient       -> verdict = UNKNOWN; quarantine(attempt)
//!     promotion = (verdict == CLOSED) ? ACTUALIZED
//!               : (receipts_valid ? OBSERVED : NONE)
//!     return ReconciliationReport{ verdict, diff, finality, promotion, ... }
//! ```
//!
//! `project_expected_state`, `merge_records` und `structural_diff` setzen
//! die Struktur eines EffectPlan voraus - und EffectPlan ist in keinem der
//! 28 Kapitel-7-Objekte registriert (nur `plan_digest: Digest` referenziert
//! es, nie sein Inhalt). Ohne diese Struktur ist `structural_diff` hier
//! ebenso wenig berechenbar wie `RankEff` in psk-dependency oder die
//! Linsenaufloesung in psk-fields - domaenenspezifische Auswertung, keine
//! aus dem Register ableitbare. `reconcile` nimmt das Ergebnis deshalb als
//! `DiffOutcome` entgegen (eine der fuenf im Text benannten Klassen) und
//! realisiert die Verdict-/Promotion-/Residualisierungslogik, die der Text
//! VOLLSTAENDIG festlegt - dasselbe Muster wie M14::evaluate_gate
//! (ConditionOutcome von aussen) und M09::route_lens (Aufloesung von
//! aussen).
//!
//! Das spaete "FAIL" im `contradictory`-Zweig faellt anders als die
//! fruehen `require ... else FAIL(...)` NICHT vor der Berichterstellung -
//! `verdict` ist zu diesem Zeitpunkt schon DIVERGENT und `residualize`
//! bereits aufgerufen. Gelesen als dasselbe Muster wie GateReport
//! (Invariante 18.7: "jede Auswertung liefert genau einen Bericht", auch
//! bei FAIL) - `verdict: DIVERGENT` TRAEGT die Fehlschlagsmeldung, statt
//! den Bericht durch einen Err() zu ersetzen. Nur die drei fruehen
//! `require`-Zeilen (Planbindung, Mindestempfangszahl, Beobachter-
//! unabhaengigkeit) scheitern die Funktion selbst - sie liegen VOR jeder
//! Berichtskonstruktion, es gibt nichts zu berichten.
//!
//! Befund gegen die eigene v1.0.10-Implementierung (gefunden beim
//! Nachpruefen von Invariante 7.34 auf Anfrage): "Beobachterunabhaengigkeit"
//! ist im Text KEIN einzelner Vergleich, sondern zwei UND-verknuepfte:
//! "ExternalReceipt.observer_adapter != EffectAttempt.adapter UND
//! observer_identity != issuer_digest. Verletzung erzeugt PSK-E009." Die
//! erste Haelfte (Adapterlabel) war hier von Anfang an geprueft; die
//! zweite (Beobachter-Identitaetsdigest gegen den Digest der M15-Instanz,
//! die das Token ausgestellt hat - `EffectToken.issuer_digest`, "I_M von
//! M15") fehlte. Nachgetragen ueber `psk_anchor::check_observer_separation`,
//! derselben Funktion, die WP05 fuer die Provenance-Beobachtertrennung
//! baute und deren Dokumentation bereits vermerkte, dass sie erst mit M16
//! (WP12) wirksam pruefbar wuerde. Ein Adapterlabel allein waere die
//! schwaechere Schranke gewesen, denn zwei verschiedene
//! Adapterinstallationen koennten sich denselben AdapterId-Bezeichner
//! teilen, waehrend ihre Identitaetsdigests das nicht koennen.

use psk_canon::{can, Media};
use psk_trace::{ResidueInputs, ResidueLedger, ResidueRecordTypeKind};
use psk_types::objects::{
    DiffTree, EffectAttempt, ExternalReceipt, ReconciliationReport,
    ReconciliationReportFactPromotionKind as Promotion,
    ReconciliationReportFinalityKind as Finality, ReconciliationReportVerdictKind as Verdict,
    ScopeExpr,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId, PskError};

/// Eine der fuenf im Text benannten Diff-Klassen. `structural_diff`s
/// Ergebnis - von aussen bestimmt, siehe Modulkopf.
pub enum DiffOutcome {
    Empty,
    WithinDeclaredTolerance(DiffTree),
    Explicable(DiffTree),
    Contradictory(DiffTree),
    ReceiptsInsufficient,
}

/// Eingaben fuer `reconcile`. `token_plan_digest` ist
/// `attempt.token_ref.plan_digest` bereits aufgeloest - `EffectAttempt`
/// selbst traegt nur `token_ref: ObjectId` (einen Verweis), nicht das
/// Token; das Nachschlagen ist Sache des Aufrufers (M15 haelt die
/// ausgestellten Token, nicht M18).
pub struct ReconcileInputs {
    pub plan_ref: ObjectId,
    /// H(Can(plan)) - vom Aufrufer berechnet (siehe Modulkopf: EffectPlan
    /// ist kein registriertes Kapitel-7-Objekt, M18 kennt seine Struktur
    /// nicht).
    pub plan_digest: Digest,
    pub attempt: EffectAttempt,
    pub token_plan_digest: Digest,
    /// `EffectToken.issuer_digest` ("I_M von M15") des Tokens, unter dem
    /// `attempt` lief - zweite Haelfte von Invariante 7.34, siehe Modulkopf.
    pub token_issuer_digest: Digest,
    pub receipts: Vec<ExternalReceipt>,
    pub anchor_ref: ObjectId,
    pub diff: DiffOutcome,
    /// Struktur 7.35 fuehrt `finality` ohne Berechnungsvorschrift - der
    /// Text setzt es nur als Ergebnisfeld, leitet es nirgends her (anders
    /// als `promotion`, das Algorithmus 20.7 vollstaendig festlegt).
    /// Befund: von aussen entgegengenommen, nicht erfunden.
    pub finality: Finality,
    /// "ActualizationWitness bei ACTUALIZED" - kein Kapitel-7-Objekt
    /// dieses Namens registriert. Das Feld ist in Struktur 7.35 nicht
    /// optional; ausserhalb von ACTUALIZED bleibt sein Inhalt hier dem
    /// Aufrufer ueberlassen.
    pub witness_ref: ObjectId,
    pub opened_at: DualTime,
}

fn reconciliation_sort() -> psk_types::objects::SortId {
    psk_types::objects::SortId::Reconciliation
}

fn compute_identity(draft: &ReconciliationReport) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, Media::Json)?;
    psk_canon::object_id(reconciliation_sort().id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// M18: Algorithmus 20.7. `residues` ist das laufende Residuenledger
/// (Regel 8.2 / Axiom 7.41 ueber P28, `from: "*"` - M18 ist keine
/// Ausnahme); `residualize(diff)` (Explicable/Contradictory) oeffnet dort
/// ein Residuum des Typs `reconciliation`.
pub fn reconcile(
    inputs: ReconcileInputs,
    residues: &mut ResidueLedger,
) -> Result<ReconciliationReport, PskError> {
    // require attempt.token_ref.plan_digest == H(Can(plan)) else FAIL(PSK-E008)
    if inputs.token_plan_digest != inputs.plan_digest {
        return Err(PskError::EffectWithoutToken);
    }
    // require |receipts| >= 1 else FAIL(PSK-E009)
    if inputs.receipts.is_empty() {
        return Err(PskError::ActualizationWithoutReconciliation);
    }
    // for r in receipts: require r.observer_adapter != attempt.adapter else FAIL(PSK-E009)
    if inputs
        .receipts
        .iter()
        .any(|r| r.observer_adapter == inputs.attempt.adapter)
    {
        return Err(PskError::ActualizationWithoutReconciliation);
    }
    // Invariante 7.34, zweite Haelfte: observer_identity != issuer_digest.
    // Wiederverwendet aus WP05 statt neu geschrieben - derselbe Vergleich,
    // dieselbe Fehlerursache (siehe Modulkopf).
    for r in &inputs.receipts {
        psk_anchor::check_observer_separation(
            r.observer_identity,
            Some(inputs.token_issuer_digest),
        )?;
    }

    let receipt_refs: Vec<ObjectId> = inputs.receipts.iter().map(|r| r.id).collect();

    let (verdict, difference, needs_residue) = match inputs.diff {
        DiffOutcome::Empty => (Verdict::Closed, DiffTree(String::new()), false),
        DiffOutcome::WithinDeclaredTolerance(d) => (Verdict::Closed, d, false),
        DiffOutcome::Explicable(d) => (Verdict::Open, d, true),
        DiffOutcome::Contradictory(d) => (Verdict::Divergent, d, true),
        DiffOutcome::ReceiptsInsufficient => (Verdict::Unknown, DiffTree(String::new()), false),
    };

    // "promotion = (verdict == CLOSED) ? ACTUALIZED : (receipts_valid ?
    // OBSERVED : NONE)" - receipts_valid ist hier "eine Klassifikation
    // wurde ueberhaupt erreicht", also alles ausser ReceiptsInsufficient
    // (das den Empfaengen selbst die Zulaenglichkeit abspricht).
    let fact_promotion = match verdict {
        Verdict::Closed => Promotion::Actualized,
        Verdict::Unknown => Promotion::None,
        Verdict::Open | Verdict::Divergent => Promotion::Observed,
    };

    let mut residue_refs = Vec::new();
    if needs_residue {
        let id = residues.open(ResidueInputs {
            r#type: ResidueRecordTypeKind::Reconciliation,
            origin_module: ModuleId::ReconciliationEngine,
            origin_object: inputs.attempt.id,
            scope: ScopeExpr(format!("plan:{}", inputs.plan_ref)),
            severity: match verdict {
                Verdict::Divergent => psk_types::objects::ResidueRecordSeverityKind::Blocking,
                _ => psk_types::objects::ResidueRecordSeverityKind::NonBlocking,
            },
            open_obligation: psk_types::objects::ObligationExpr(format!(
                "Plan-Ist-Differenz klaeren: {difference:?}"
            )),
            allowed_followups: Vec::new(),
            opened_at: inputs.opened_at,
        })?;
        residue_refs.push(id);
    }
    // "receipts_insufficient -> ... quarantine(attempt)" - Quarantaene ist
    // ein Zustandsuebergang des Attempts selbst (FSM-EFFECT kennt keinen
    // eigenen QUARANTINE-Zustand fuer `effect`; das naechstliegende ist
    // UNKNOWN_EFFECT, das FSM-EFFECT bereits fuehrt). Der Uebergang selbst
    // ist Sache des Aufrufers, der den Attempt-Datensatz haelt - M18
    // meldet hier nur die Tatsache ueber `verdict: UNKNOWN`.

    let draft = ReconciliationReport {
        schema: "psk.reconciliation/1.0".to_string(),
        id: ObjectId::new(reconciliation_sort(), Digest::sha256(b"")), // Platzhalter
        plan_ref: inputs.plan_ref,
        attempt_ref: inputs.attempt.id,
        receipt_refs,
        anchor_ref: inputs.anchor_ref,
        difference,
        verdict,
        finality: inputs.finality,
        fact_promotion,
        residue_refs,
        witness_ref: inputs.witness_ref,
    };
    let id = compute_identity(&draft)?;
    Ok(ReconciliationReport { id, ..draft })
}

/// H(Can(bytes)) - Hilfsfunktion fuer Aufrufer, die `plan_digest` aus
/// einem seriellisierten EffectPlan bilden muessen.
pub fn plan_digest_of(bytes: &[u8], media: Media) -> Result<Digest, PskError> {
    Ok(can(bytes, media)?.digest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{AdapterId, EffectAttemptOutcomeKind, ProvenanceBlock, SortId};

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-04T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_attempt(adapter: &str) -> EffectAttempt {
        EffectAttempt {
            id: ObjectId::new(SortId::Effect, Digest::sha256(b"attempt")),
            token_ref: ObjectId::new(SortId::Capability, Digest::sha256(b"token")),
            adapter: AdapterId(adapter.into()),
            prestate_digest: Digest::sha256(b"pre"),
            plan_digest: Digest::sha256(b"plan"),
            started_at: sample_time(),
            ended_at: Some(sample_time()),
            outcome: EffectAttemptOutcomeKind::Completed,
            error: None,
            compensation_ref: None,
        }
    }

    fn sample_receipt(id_seed: &str, observer: &str) -> ExternalReceipt {
        ExternalReceipt {
            id: ObjectId::new(SortId::Receipt, Digest::sha256(id_seed.as_bytes())),
            observer_adapter: AdapterId(observer.into()),
            observer_identity: Digest::sha256(observer.as_bytes()),
            observed_at: sample_time(),
            record: vec![1, 2, 3],
            provenance: ProvenanceBlock("provenance/1".into()),
            result_digest: Digest::sha256(b"result"),
            independence_attestation: Digest::sha256(b"attestation"),
        }
    }

    fn base_inputs(diff: DiffOutcome) -> ReconcileInputs {
        let plan_digest = Digest::sha256(b"plan");
        ReconcileInputs {
            plan_ref: ObjectId::new(SortId::Effect, Digest::sha256(b"plan-obj")),
            plan_digest,
            attempt: sample_attempt("effect-local-fs"),
            token_plan_digest: plan_digest,
            token_issuer_digest: Digest::sha256(b"m15-instance"),
            receipts: vec![sample_receipt("r1", "observer-local-fs")],
            anchor_ref: ObjectId::new(SortId::Anchor, Digest::sha256(b"anchor")),
            diff,
            finality: Finality::Final,
            witness_ref: ObjectId::new(SortId::Witness, Digest::sha256(b"witness")),
            opened_at: sample_time(),
        }
    }

    #[test]
    fn plan_digest_mismatch_fails_before_any_report() {
        let mut inputs = base_inputs(DiffOutcome::Empty);
        inputs.token_plan_digest = Digest::sha256(b"other-plan");
        let mut ledger = ResidueLedger::new();
        assert_eq!(
            reconcile(inputs, &mut ledger),
            Err(PskError::EffectWithoutToken)
        );
    }

    #[test]
    fn zero_receipts_fails() {
        let mut inputs = base_inputs(DiffOutcome::Empty);
        inputs.receipts.clear();
        let mut ledger = ResidueLedger::new();
        assert_eq!(
            reconcile(inputs, &mut ledger),
            Err(PskError::ActualizationWithoutReconciliation)
        );
    }

    #[test]
    fn a_receipt_from_the_effect_adapter_itself_fails() {
        // Beobachterunabhaengigkeit, erste Haelfte von Invariante 7.34:
        // derselbe Adapterbezeichner darf nicht sein eigener Zeuge sein.
        let mut inputs = base_inputs(DiffOutcome::Empty);
        inputs.receipts = vec![sample_receipt("r1", "effect-local-fs")];
        let mut ledger = ResidueLedger::new();
        assert_eq!(
            reconcile(inputs, &mut ledger),
            Err(PskError::ActualizationWithoutReconciliation)
        );
    }

    #[test]
    fn a_receipt_sharing_the_issuers_identity_digest_fails() {
        // Beobachterunabhaengigkeit, zweite Haelfte von Invariante 7.34:
        // "observer_identity != issuer_digest" - unabhaengig vom
        // Adapterbezeichner. Das ist die staerkere Schranke: zwei
        // verschiedene AdapterId-Bezeichner koennten sich denselben
        // Identitaetsdigest teilen (z.B. dieselbe Prozessinstanz unter
        // zwei Namen angesprochen), und genau das faengt dieser Test.
        let mut inputs = base_inputs(DiffOutcome::Empty);
        let colliding_digest = Digest::sha256(b"shared-identity");
        inputs.token_issuer_digest = colliding_digest;
        inputs.receipts = vec![ExternalReceipt {
            observer_identity: colliding_digest,
            ..sample_receipt("r1", "observer-local-fs")
        }];
        let mut ledger = ResidueLedger::new();
        assert_eq!(
            reconcile(inputs, &mut ledger),
            Err(PskError::ActualizationWithoutReconciliation)
        );
    }

    #[test]
    fn empty_diff_closes_and_actualizes() {
        let mut ledger = ResidueLedger::new();
        let report = reconcile(base_inputs(DiffOutcome::Empty), &mut ledger).unwrap();
        assert_eq!(report.verdict, Verdict::Closed);
        assert_eq!(report.fact_promotion, Promotion::Actualized);
        assert!(report.residue_refs.is_empty());
    }

    #[test]
    fn tolerance_closes_just_like_empty() {
        let mut ledger = ResidueLedger::new();
        let report = reconcile(
            base_inputs(DiffOutcome::WithinDeclaredTolerance(DiffTree(
                "minor rounding".into(),
            ))),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Closed);
        assert_eq!(report.fact_promotion, Promotion::Actualized);
    }

    #[test]
    fn explicable_diff_opens_and_residualizes_non_blocking() {
        let mut ledger = ResidueLedger::new();
        let report = reconcile(
            base_inputs(DiffOutcome::Explicable(DiffTree("late write".into()))),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Open);
        assert_eq!(report.fact_promotion, Promotion::Observed);
        assert_eq!(report.residue_refs.len(), 1);
        assert_eq!(
            ledger.get(report.residue_refs[0]).unwrap().severity,
            psk_types::objects::ResidueRecordSeverityKind::NonBlocking
        );
    }

    #[test]
    fn contradictory_diff_diverges_and_residualizes_blocking() {
        // "contradictory -> verdict = DIVERGENT; residualize(diff); FAIL" -
        // FAIL ist hier verdict:DIVERGENT selbst, kein Err() (siehe Modulkopf).
        let mut ledger = ResidueLedger::new();
        let report = reconcile(
            base_inputs(DiffOutcome::Contradictory(DiffTree(
                "conflicting state".into(),
            ))),
            &mut ledger,
        )
        .unwrap();
        assert_eq!(report.verdict, Verdict::Divergent);
        assert_eq!(report.fact_promotion, Promotion::Observed);
        assert_eq!(
            ledger.get(report.residue_refs[0]).unwrap().severity,
            psk_types::objects::ResidueRecordSeverityKind::Blocking
        );
    }

    #[test]
    fn insufficient_receipts_yields_unknown_and_no_promotion() {
        let mut ledger = ResidueLedger::new();
        let report =
            reconcile(base_inputs(DiffOutcome::ReceiptsInsufficient), &mut ledger).unwrap();
        assert_eq!(report.verdict, Verdict::Unknown);
        assert_eq!(report.fact_promotion, Promotion::None);
        assert!(report.residue_refs.is_empty());
    }

    #[test]
    fn reconciliation_is_deterministic() {
        let mut ledger_a = ResidueLedger::new();
        let mut ledger_b = ResidueLedger::new();
        let a = reconcile(base_inputs(DiffOutcome::Empty), &mut ledger_a).unwrap();
        let b = reconcile(base_inputs(DiffOutcome::Empty), &mut ledger_b).unwrap();
        assert_eq!(a.id, b.id);
    }
}
