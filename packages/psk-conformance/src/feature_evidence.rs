//! Die Messseite von `feature_coverage`: reale Laufartefakte einsammeln.
//!
//! `psk_certify::derive_feature_coverage` traegt die Ableitungsregel, misst
//! aber selbst nichts (M21: "Kein Feld wird hier gemessen"). Diese Datei
//! misst - aus den Artefakten, die ein Zertifikatsaussteller tatsaechlich
//! in der Hand haelt: dem Bootbericht, den zwei Golden Runs samt
//! Replaypruefung und, wenn gelaufen, dem Baselinevergleich.
//!
//! ## Was hier als Beleg zaehlt und was nicht
//!
//! Zaehlbar ist, was ein Lauf HERVORBRINGT. Nicht zaehlbar ist, was ein
//! Test ZEIGT. Die Unterscheidung ist nicht kosmetisch: ein Test belegt
//! eine Eigenschaft des Codes, ein Laufartefakt belegt, dass die
//! Eigenschaft im zertifizierten Betrieb auch zur Anwendung kam. Das
//! Zertifikat behauptet Zweiteres. Seit v1.0.24 faellt die Unterscheidung
//! nur noch bei FC3 ins Gewicht - FC2 hat mit dem realen
//! IRBundle-Kandidaten ein Laufartefakt bekommen. Der Messpunkt vermerkt
//! es unten selbst, damit die kuerzere Antwort ihren Grund mitbringt.
//!
//! Diese Datei erfindet keine Zaehlung, die der Lauf nicht liefert. Wo ein
//! Feld 0 oder `None` bleibt, ist das der Messwert, nicht eine Luecke im
//! Messen.

use psk_certify::{FeatureEvidence, ReplayEvidence};
use psk_types::objects::{
    CandidateCapsulePhaseKind, RealityStatus, ReconciliationReportFactPromotionKind,
    ReconciliationReportVerdictKind,
};
use psk_types::Digest;

use crate::baselines::BaselineComparison;
use crate::golden_run::{GoldenRunCertification, GoldenRunReport};

/// Digest des Bundles vor und nach `ir_decode(ir_encode(..))`.
/// `None` heisst: der Codec selbst scheiterte - dann ist nichts gemessen,
/// und FC2 bekommt keinen halben Beleg.
pub(crate) fn ir_round_trip(bundle: &psk_types::objects::IRBundle) -> Option<(Digest, Digest)> {
    let encoded = psk_ir::ir_encode(bundle).ok()?;
    let decoded = psk_ir::ir_decode(&encoded).ok()?;
    let reencoded = psk_ir::ir_encode(&decoded).ok()?;
    Some((Digest::sha256(&encoded), Digest::sha256(&reencoded)))
}

/// Der deklarierte und der nachgerechnete Wert, sofern beides vorliegt.
fn identity_pair(stored: Option<&str>, computed: Digest) -> Option<(Digest, Digest)> {
    // Ein unversiegeltes Bundle liefert kein Paar - das ist "kein
    // Artefakt", nicht "Abweichung". Ein gesetzter, aber unparsbarer Wert
    // ist dagegen sehr wohl eine Abweichung und wird als solche
    // weitergereicht (ein Digest, der nicht Definition 6.4 (Digest) entspricht, ist
    // kein Treffer).
    let stored = stored?;
    match Digest::from_hex(stored) {
        Ok(declared) => Some((declared, computed)),
        Err(_) => Some((Digest::sha256(b"unparsable-declared-identity"), computed)),
    }
}

/// FC4s Lineage-Zaehlung: nichtleer nach demselben Massstab wie M08s
/// `lineage_declared` (trim, dann nicht leer). Eigene Funktion, damit das
/// Kriterium testbar ist, ohne einen ganzen Golden Run zu brauchen.
fn count_nonempty_lineages(fields: &[psk_types::objects::FieldIdentity]) -> usize {
    fields
        .iter()
        .filter(|f| !f.lineage.0.trim().is_empty())
        .count()
}

/// Sammelt die Messwerte eines einzelnen Laufs ein.
fn measure_run(run: &GoldenRunReport, evidence: &mut FeatureEvidence) {
    // ---- FC1: die lokale Seam-Closure. `section` ist `Some` nur bei
    // eindeutiger globaler Sektion (Invariante 11.14 (Eindeutigkeit der Verklebung)) - genau die
    // Bedingung, die FC1 verlangt.
    if run.glue.section.is_some() {
        evidence.local_seam_section = run.glue.section;
    }

    // ---- FC3: die Typisierung selbst ist belegt, sobald eine
    // Klassifikation entstand.
    evidence.reality_classifications += 1;

    // FC3, zweite Haelfte ("ohne Promotionsbypass"): die real ausgeuebte
    // Sperre wird aus der ARTEFAKTMENGE gemessen, nicht aus dem Bericht
    // allein. Der Bericht traegt das Subjekt nicht, und check_promotion
    // liefert fuer die UNKNOWN-Klausel denselben Fehler wie fuer
    // Invariante 5.10 (Keine implizite Promotion) - aus dem Bericht allein ist also "dass gesperrt
    // wurde" erkennbar, aber nicht "warum". Erst das Paar aus (a) einem
    // Subjekt, dessen Klassifikation UNKNOWN ist, und (b) einem Bericht
    // mit verdict != UNKNOWN und fact_promotion == NONE belegt die
    // UNKNOWN-Sperre: dieses Paar ist ohne sie unerreichbar (durch
    // Aufzaehlung bewiesen in psk-reconciliation::
    // a_barred_promotion_is_distinguishable_from_nothing_to_promote).
    //
    // Seit die zwei Erfindungen des Laufs entfernt sind (Phantom-Plugin,
    // hartkodiertes Subjektpaar), entsteht dieses Artefaktpaar im
    // Referenzlauf natuerlich: kein Klassifikationsplugin existiert, also
    // ist die Klassifikation UNKNOWN (Vertrag 27.2 (Domänengelieferte opake Eingaben) Pflicht 3), also
    // faellt die von CLOSED beabsichtigte Promotion auf NONE.
    let subject_unknown = run.reality.reality_status == RealityStatus::Unknown;
    let report_shows_barred = run.reconciliation.verdict
        != ReconciliationReportVerdictKind::Unknown
        && run.reconciliation.fact_promotion == ReconciliationReportFactPromotionKind::None;
    if subject_unknown && report_shows_barred {
        *evidence.promotions_barred_on_unknown.get_or_insert(0) += 1;
    }

    // ---- FC4.
    evidence.field_projections += run.field_projections.len();
    if !run.dependency_profile.quotient_classes.is_empty() {
        evidence.dependency_profiles += 1;
    }

    // FC4, Lineage: `Lin_lambda` sitzt auf `FieldIdentity`, und der Lauf
    // gibt seine sechs Identitaeten seit dem FC2-Bau heraus. Gezaehlt
    // wird NICHTLEER, nicht vorhanden - eine Lineage, die da ist, aber
    // nichts sagt, belegt keine Herkunft. Das Kriterium ist nicht hier
    // erfunden: es ist woertlich M08s eigene Aktivierungsbedingung
    // (`lineage_declared` in psk-fields::registry::
    // check_activation_requirements, "die jeweilige Zeichenkette ist
    // nicht leer").
    evidence.field_lineages += count_nonempty_lineages(&run.field_identities);

    // ---- FC5: seit dem Challenge-Schritt durchlaeuft der Lauf M24 real.
    // Drei der vier Nachweise entstehen dabei: die Kapseln (eine je
    // Quotientenklasse, publiziert im Bericht - seit v1.0.46 wirklich
    // mehrere statt nur der ersten), der Ratchet-Schritt (aufgeloest im
    // Kapselfixpunkt, nicht Budget-RESIDUAL - siehe `reached_fixpoint`)
    // und die Supportentscheidung (Phase SUPPORTED oder RESIDUAL, beides
    // ist eine Entscheidung).
    //
    // Gezaehlt wird JE KAPSEL, nicht je Lauf: mit mehreren Kapseln ist
    // "die Phase" kein Singular mehr, und eine Kapsel, deren Ratchet
    // anders ausging als die einer anderen, ist ein eigener Nachweis,
    // kein Duplikat.
    evidence.candidate_capsules += run.capsule_outcomes.len();
    for outcome in &run.capsule_outcomes {
        if outcome.reached_fixpoint || outcome.capsule.phase == CandidateCapsulePhaseKind::Residual
        {
            evidence.ratcheted_capsules += 1;
        }
        if matches!(
            outcome.capsule.phase,
            CandidateCapsulePhaseKind::Supported | CandidateCapsulePhaseKind::Residual
        ) {
            evidence.support_decisions += 1;
        }

        // Vierter Nachweis - Residuenfluss. `residue_flow_next` gibt die
        // zulaessige Folgephase; sie existiert nur ab RESIDUAL. Gezaehlt
        // wird ein Uebergang nur, wenn DIESE Kapsel tatsaechlich dort
        // steht UND das Werk von dort aus einen Weg fuehrt. Steht eine
        // Kapsel auf SUPPORTED, fliesst fuer sie nichts - das ist dann
        // ihr Messwert, kein Mangel der Messung.
        if psk_adversarial::residue_flow_next(outcome.capsule.phase).is_some() {
            evidence.residue_flow_transitions += 1;
        }
    }

    // ---- FC6.
    evidence.gate_reports += 2; // boot_gate und patch_gate
    evidence.effect_tokens += 1; // token_authorization -> EffectToken
    evidence.external_receipts += 1;
    evidence.reconciliation_reports += 1;

    // ---- FC7: G-SELF-COMPILE wird in keinem Lauf ausgewertet; M24s
    // Selbstverhaertung laeuft nicht mit. `self_compile_gate_passed`
    // bleibt `None`.
}

/// Misst den Deckungsvektor an dem, was zwei Golden Runs und der Boot
/// tatsaechlich hervorgebracht haben.
/// Die Teile eines Zertifizierungslaufs, aus denen der Deckungsvektor
/// folgt - OHNE das Zertifikat selbst.
///
/// Warum diese Form: Regel 7.55 (Plattformgebundene Verpflichtungsauflösung im Zertifikat)
/// verlangt `feature_coverage` als ABGELEITETEN Wert, also muss die
/// Ableitung VOR der Ausstellung laufen. `GoldenRunCertification` enthaelt
/// aber das Zertifikat - die alte Signatur war zirkulaer und konnte
/// deshalb nur nach der Ausstellung aufgerufen werden, was genau der
/// Grund war, aus dem der Vektor stattdessen behauptet wurde. Die Teile
/// aufzuzaehlen loest den Zirkel auf, ohne die Ableitung zu aendern.
pub struct CoverageParts<'a> {
    pub first: &'a GoldenRunReport,
    pub second: &'a GoldenRunReport,
    pub replay_check: &'a psk_trace::ReplayCheck,
    pub self_compile_gate: &'a psk_types::objects::GateReport,
}

/// Wie `collect_feature_evidence`, aber ohne das Zertifikat als Eingabe.
pub fn collect_feature_evidence_from_parts(
    parts: CoverageParts<'_>,
    baseline: Option<&BaselineComparison>,
) -> FeatureEvidence {
    let certification = &parts;
    let boot = &certification.first.boot_report;
    let mut evidence = FeatureEvidence {
        // ---- FC0: I_C und I_A, deklariert gegen nachgerechnet.
        constitution_id: identity_pair(
            boot.constitution_check.stored_constitution_id.as_deref(),
            boot.constitution_check.computed_constitution_id,
        ),
        architecture_id: identity_pair(
            boot.architecture_check.stored_architecture_id.as_deref(),
            boot.architecture_check.computed_architecture_id,
        ),

        // ---- FC1: die Kardinalitaeten aus M13 selbst, nicht aus einer
        // Konstanten hier.
        m13_nodes: psk_topology::nodes().len(),
        m13_edges: psk_topology::edges().len(),
        m13_cells: psk_topology::cells().len(),

        // ---- FC2, zweite Haelfte: M19s eigenes Replayurteil, unveraendert
        // uebernommen.
        replay: Some(ReplayEvidence {
            attempted: certification.replay_check.replay_attempted,
            canonical_digest_match: certification.replay_check.canonical_digest_match,
            gate_sequence_match: certification.replay_check.gate_sequence_match,
        }),

        // FC2, erste Haelfte: seit v1.0.24 bringt der Lauf einen echten
        // IRBundle-Kandidaten hervor (Definition 14.2 (Phasen-Modul-Bindung), Compile). Der
        // Round-Trip wird an DIESEM Artefakt gemessen, nicht an einem
        // Fixture - T-IR-001 belegt den Codec, dieser Messpunkt belegt das
        // System.
        ir_bundle_round_trip: ir_round_trip(&certification.first.ir_bundle),
        ..Default::default()
    };

    measure_run(certification.first, &mut evidence);
    measure_run(certification.second, &mut evidence);

    // ---- FC7: seit dem CRA-Bau wird G-SELF-COMPILE real ausgewertet -
    // ueber einen echten RevisionProposal aus den Laufresiduen und
    // -obstruktionen. Der Messwert ist die Gatentscheidung selbst:
    // Some(true) nur bei PASS. Ein HOLD/FAIL ist Some(false) - die
    // Ableitung unterscheidet das von "nie ausgewertet" (None), und der
    // Grund steht in den reasons des Gatberichts.
    evidence.self_compile_gate_passed = Some(
        certification.self_compile_gate.decision
            == psk_types::objects::GateReportDecisionKind::Pass,
    );

    // ---- FC8.
    evidence.baseline_comparison_passed = baseline.map(|b| b.kern_passes());

    evidence
}

/// Die alte Form, jetzt eine Weiterleitung: nach der Ausstellung ist das
/// Zertifikat vorhanden, und Aufrufer, die es ohnehin haben, sollen
/// nicht umbauen muessen.
pub fn collect_feature_evidence(
    certification: &GoldenRunCertification,
    baseline: Option<&BaselineComparison>,
) -> FeatureEvidence {
    collect_feature_evidence_from_parts(
        CoverageParts {
            first: &certification.first,
            second: &certification.second,
            replay_check: &certification.replay_check,
            self_compile_gate: &certification.self_compile_gate,
        },
        baseline,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{FieldIdentity, Lineage};

    fn field_with_lineage(lineage: &str, salt: &str) -> FieldIdentity {
        FieldIdentity {
            schema: "psk.field-identity/1.0".into(),
            id: psk_types::ObjectId::new(
                psk_types::objects::SortId::FieldIdentity,
                Digest::sha256(salt.as_bytes()),
            ),
            domain: psk_types::objects::DomainExpr("d".into()),
            lens: psk_types::objects::LensSpec("l".into()),
            operators: vec![],
            questions: vec![],
            witness_rules: psk_types::objects::WitnessPolicy("w".into()),
            boundaries: psk_types::objects::BoundarySpec("b".into()),
            gates: vec![],
            time_window: psk_types::objects::TimeWindow("t".into()),
            lineage: Lineage(lineage.into()),
            lifecycle: psk_types::objects::FieldIdentityLifecycleKind::Active,
            dependency_profile_ref: psk_types::ObjectId::new(
                psk_types::objects::SortId::Dependency,
                Digest::sha256(b"dep"),
            ),
            budget: psk_types::objects::BudgetSpec("bu".into()),
            rollback: psk_types::objects::RollbackSpec("r".into()),
            archetype: psk_types::objects::ArchetypeId::Explorer,
            marginal_gain: psk_types::objects::Scaled {
                schema: "psk.scaled/1.0".into(),
                numerator: 0,
                scale: 1,
            },
        }
    }

    /// Die Vorgabe woertlich: "eine Lineage, die vorhanden, aber leer
    /// ist, ist kein Beleg." Leer und Nur-Whitespace zaehlen nicht;
    /// Inhalt zaehlt - die Positivseite, ohne die der Test auch mit
    /// einem Zaehler bestuende, der immer 0 liefert.
    #[test]
    fn an_empty_lineage_is_not_evidence() {
        let fields = vec![
            field_with_lineage("", "a"),
            field_with_lineage("   ", "b"),
            field_with_lineage("golden-run", "c"),
            field_with_lineage("golden-run", "d"),
        ];
        assert_eq!(count_nonempty_lineages(&fields), 2);
        assert_eq!(count_nonempty_lineages(&[]), 0);
    }
}
