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
    RealityStatus, ReconciliationReportFactPromotionKind, ReconciliationReportVerdictKind,
};
use psk_types::Digest;

use crate::baselines::BaselineComparison;
use crate::golden_run::{GoldenRunCertification, GoldenRunReport};

/// Digest des Bundles vor und nach `ir_decode(ir_encode(..))`.
/// `None` heisst: der Codec selbst scheiterte - dann ist nichts gemessen,
/// und FC2 bekommt keinen halben Beleg.
fn ir_round_trip(bundle: &psk_types::objects::IRBundle) -> Option<(Digest, Digest)> {
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
    // weitergereicht (ein Digest, der nicht Definition 6.4 entspricht, ist
    // kein Treffer).
    let stored = stored?;
    match Digest::from_hex(stored) {
        Ok(declared) => Some((declared, computed)),
        Err(_) => Some((Digest::sha256(b"unparsable-declared-identity"), computed)),
    }
}

/// Sammelt die Messwerte eines einzelnen Laufs ein.
fn measure_run(run: &GoldenRunReport, evidence: &mut FeatureEvidence) {
    // ---- FC1: die lokale Seam-Closure. `section` ist `Some` nur bei
    // eindeutiger globaler Sektion (Invariante 11.14) - genau die
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
    // Invariante 5.9 - aus dem Bericht allein ist also "dass gesperrt
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
    // ist die Klassifikation UNKNOWN (Vertrag 27.2 Pflicht 3), also
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

    // FC4, Lineage: `Lin_lambda` sitzt auf `FieldIdentity`, nicht auf der
    // Projektion. Der Lauf BAUT eine Feldidentitaet mit echter Lineage,
    // gibt sie aber nicht heraus - `FieldProjection.field_ref` ist eine
    // ObjectId, also ein Verweis auf das Lineage tragende Objekt, nicht
    // das Objekt. Damit ist die Lineage referenziert, nicht belegt, und
    // `field_lineages` bleibt 0.

    // ---- FC5: der Golden Run durchlaeuft M24 nicht. Es entstehen keine
    // CandidateCapsules, kein Ratchet, keine Supportentscheidung und kein
    // Residuenfluss zwischen Kapselzustaenden. Die vier Zaehler bleiben
    // deshalb 0. (`psk_closure::CapsuleRestriction` im Glue-Schritt ist
    // eine Nahtrestriktion, keine Kandidatenkapsel - gleicher Wortstamm,
    // anderes Objekt.)

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
pub fn collect_feature_evidence(
    certification: &GoldenRunCertification,
    baseline: Option<&BaselineComparison>,
) -> FeatureEvidence {
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
        // IRBundle-Kandidaten hervor (Definition 14.2, Compile). Der
        // Round-Trip wird an DIESEM Artefakt gemessen, nicht an einem
        // Fixture - T-IR-001 belegt den Codec, dieser Messpunkt belegt das
        // System.
        ir_bundle_round_trip: ir_round_trip(&certification.first.ir_bundle),
        ..Default::default()
    };

    measure_run(&certification.first, &mut evidence);
    measure_run(&certification.second, &mut evidence);

    // ---- FC8.
    evidence.baseline_comparison_passed = baseline.map(|b| b.kern_passes());

    evidence
}
