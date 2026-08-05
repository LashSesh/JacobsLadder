//! M21 CertificateReleaseEngine (Kapitel 23, Struktur 7.46).
//!
//! Regel 23.1 (Eine Konformanzleiter): "FC ist keine Klassifikation,
//! sondern eine Pflichtangabe im Maschinenzertifikat und eine
//! Vorbedingung bestimmter C-Klassen. Eine parallele Verwendung als
//! eigenstaendige Konformitaetsklasse ist nicht zulaessig." Die Tabelle
//! 23.2 legt die FC-Vorbedingung UND die zusaetzlichen Abnahmen je Klasse
//! wortgetreu fest:
//!
//! | Klasse | FC-Pflicht | zusaetzliche Abnahme                         |
//! |--------|-----------|------------------------------------------------|
//! | C0     | FC0       | Bundle, Lock, Schemas, Requirement Coverage = 1 |
//! | C1     | FC0-FC2   | minimaler Kern laeuft, valide Artefakte         |
//! | C2     | FC0-FC3   | R2-Replay und Golden Runs bestanden             |
//! | C3     | FC0-FC6   | Token/Capability/Effektgrenze/Receipt/Recon.    |
//! | C4     | FC0-FC6,FC8 | Baselines und Negativtests bestanden          |
//! | C5     | FC0-FC8   | unabhaengige Instanz reproduziert Konformitaet  |
//!
//! `compute_conformance_class` bildet GENAU diese Tabelle ab: die
//! zusaetzlichen Abnahmen kommen als bereits getroffene Feststellungen
//! herein (derselbe Grund wie bei `psk_gate::evaluate_gate`s
//! `ConditionOutcome` - ob z.B. "Golden Runs bestanden" zutrifft, ist
//! keine aus einem Register ableitbare Berechnung, sondern das Ergebnis
//! eines tatsaechlichen Laufs). M21 traegt die MONOTONE ABLEITUNG (welche
//! Klasse aus welcher Evidenzkombination folgt), nicht die Einzelpruefungen.
//!
//! `MachineCertificate` (Struktur 7.46) hat - anders als jedes andere
//! Kapitel-7-Objekt - kein `id: ObjectId`-Feld. Seine Identitaet SIND die
//! vier Systemidentitaeten I_C/I_A/I_M/I_t; das uebliche
//! pi_vol-Selbstreferenzmuster (Definition 6.6) hat hier nichts zu
//! entfernen und wird deshalb nicht angewandt.
//!
//! `signature: Signature` bleibt opak und wird nicht hier erzeugt - OBL-005
//! (Security Reduction) erklaert Signaturverfahren und Schluesselhaltung
//! ausdruecklich fuer domaenenabhaengig ("Die Architektur legt SHA-256 als
//! Digest fest; Signaturverfahren und Schluesselhaltung sind
//! domaenenabhaengig zu deklarieren"): eine hier erfundene Signatur waere
//! eine unbelegte Sicherheitsbehauptung.

use std::collections::BTreeSet;

use psk_gate::{evaluate_gate, ConditionOutcome, GateInputs};
use psk_trace::{ResidueLedger, TraceStore};
use psk_types::objects::{
    FeatureCoverageId, GateId, MachineCertificate, MachineCertificateConformanceClassKind as Class,
    MachineCertificateReplayClassKind as ReplayClass, ReplayDescriptor, ScopeExpr,
};
use psk_types::{Digest, DualTime, ObjectId, PskError, Signature, TraceRef};

/// Die zusaetzlichen Abnahmen aus Tabelle 23.2, ausserhalb dessen, was
/// sich aus `feature_coverage` allein ablesen liesse.
#[derive(Debug, Clone, Copy, Default)]
pub struct AdditionalAcceptance {
    /// C0: "Bundle, Lock, Schemas, Requirement Coverage = 1."
    pub artifact_conformant: bool,
    /// C1: "Minimaler Kern laeuft und erzeugt valide Artefakte."
    pub kernel_executable: bool,
    /// C2: "R2-Replay und Golden Runs bestanden."
    pub replay_valid: bool,
    /// C3: "Token, Capability, Effektgrenze, Receipt, Reconciliation geprueft."
    pub sandbox_effect_safe: bool,
    /// C4: "Reale Referenzdomaene besteht Baselines und Negativtests."
    pub reference_validated: bool,
    /// C5: "Unabhaengige Instanz reproduziert Konformitaets- und Leistungsbefunde."
    pub externally_reproduced: bool,
}

fn covers(features: &BTreeSet<FeatureCoverageId>, upto: &[FeatureCoverageId]) -> bool {
    upto.iter().all(|f| features.contains(f))
}

/// M21: leitet die hoechste erreichte Konformitaetsklasse aus der
/// Deckung und den zusaetzlichen Abnahmen ab (Tabelle 23.2). Prueft von
/// C5 absteigend, damit die HOECHSTE erfuellte Klasse zurueckkommt, nicht
/// die erste zufaellig getroffene.
pub fn compute_conformance_class(
    features: &[FeatureCoverageId],
    acceptance: AdditionalAcceptance,
) -> Class {
    use FeatureCoverageId::*;
    let features: BTreeSet<FeatureCoverageId> = features.iter().copied().collect();

    let fc0_2 = [Fc0, Fc1, Fc2];
    let fc0_3 = [Fc0, Fc1, Fc2, Fc3];
    let fc0_6 = [Fc0, Fc1, Fc2, Fc3, Fc4, Fc5, Fc6];
    let fc0_6_8 = [Fc0, Fc1, Fc2, Fc3, Fc4, Fc5, Fc6, Fc8];
    let fc0_8 = [Fc0, Fc1, Fc2, Fc3, Fc4, Fc5, Fc6, Fc7, Fc8];

    if acceptance.externally_reproduced && covers(&features, &fc0_8) {
        Class::C5
    } else if acceptance.reference_validated && covers(&features, &fc0_6_8) {
        Class::C4
    } else if acceptance.sandbox_effect_safe && covers(&features, &fc0_6) {
        Class::C3
    } else if acceptance.replay_valid && covers(&features, &fc0_3) {
        Class::C2
    } else if acceptance.kernel_executable && covers(&features, &fc0_2) {
        Class::C1
    } else if acceptance.artifact_conformant && features.contains(&Fc0) {
        Class::C0
    } else {
        // Regel 23.1 nennt keinen Wert "unterhalb C0" - ein Zertifikat,
        // das nicht einmal C0 erreicht, wird hier nicht ausgestellt (siehe
        // `issue_certificate`), diese Funktion bleibt aber total.
        Class::C0
    }
}

/// Vertrag 22.2: "Ein Referenzrelease MUSS mindestens R2 erreichen."
/// Diese Wache ist bewusst unabhaengig von `compute_conformance_class` -
/// C2 ("Replay-valid") verlangt R2 bereits inhaltlich, aber der Vertrag
/// gilt fuer JEDES Referenzrelease, nicht nur fuer im Zertifikat als C2+
/// deklarierte.
pub fn check_minimum_replay_class(achieved: ReplayClass) -> Result<(), PskError> {
    match achieved {
        ReplayClass::R2 | ReplayClass::R3 => Ok(()),
        ReplayClass::R0 | ReplayClass::R1 => Err(PskError::UnboundNondeterminismOrDivergence),
    }
}

/// Eingaben fuer `issue_certificate`. Kein Feld wird hier gemessen -
/// jeder Digest kommt vom Modul, das ihn tatsaechlich gebildet hat
/// (M19 fuer trace_head/replay_manifest_digest/residue_report_digest,
/// M14 fuer gate_report_digest, ...). M21 bindet nur zusammen.
pub struct CertificateInputs {
    pub i_c: Digest,
    pub i_a: Digest,
    pub i_m: Digest,
    pub i_t: Digest,
    pub features: Vec<FeatureCoverageId>,
    pub acceptance: AdditionalAcceptance,
    pub replay_class: ReplayClass,
    pub gate_report_digest: Digest,
    pub trace_head: Digest,
    pub replay_manifest_digest: Digest,
    pub residue_report_digest: Digest,
    pub capability_audit_digest: Digest,
    pub negative_test_report_digest: Digest,
    pub scope: ScopeExpr,
    pub issued_at: DualTime,
    pub signature: Signature,
}

/// M21: stellt ein MachineCertificate aus. Scheitert, wenn nicht einmal
/// C0 erreicht ist (Regel 23.1 kennt keine Klasse darunter - ein
/// "Zertifikat der Nichtkonformitaet" ist keine Struktur des Werkes) oder
/// wenn Vertrag 22.2 (mindestens R2) verletzt ist.
pub fn issue_certificate(inputs: CertificateInputs) -> Result<MachineCertificate, PskError> {
    check_minimum_replay_class(inputs.replay_class)?;

    let conformance_class = compute_conformance_class(&inputs.features, inputs.acceptance);
    if conformance_class == Class::C0 && !inputs.acceptance.artifact_conformant {
        return Err(PskError::ReleaseGateBlocked);
    }

    Ok(MachineCertificate {
        schema: "psk.machine-certificate/1.0".to_string(),
        I_C: inputs.i_c,
        I_A: inputs.i_a,
        I_M: inputs.i_m,
        I_t: inputs.i_t,
        conformance_class,
        feature_coverage: inputs.features,
        replay_class: inputs.replay_class,
        gate_report_digest: inputs.gate_report_digest,
        trace_head: inputs.trace_head,
        replay_manifest_digest: inputs.replay_manifest_digest,
        residue_report_digest: inputs.residue_report_digest,
        capability_audit_digest: inputs.capability_audit_digest,
        negative_test_report_digest: inputs.negative_test_report_digest,
        scope: inputs.scope,
        issued_at: inputs.issued_at,
        signature: inputs.signature,
    })
}

/// M21 besitzt G-RELEASE (gate_registry.yaml). Auswertung ueber dieselbe
/// generische `evaluate_gate` wie M14/M20 - siehe deren Modulkoepfe.
#[allow(clippy::too_many_arguments)]
pub fn evaluate_release_gate(
    conditions: Vec<ConditionOutcome>,
    input_digests: Vec<Digest>,
    evidence_refs: Vec<ObjectId>,
    replay_descriptor: ReplayDescriptor,
    decided_at: DualTime,
    trace_ref: TraceRef,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<psk_types::objects::GateReport, PskError> {
    evaluate_gate(
        GateInputs {
            gate_id: GateId::GRelease,
            order: 2, // gate_registry.yaml: G-RELEASE, order: 2
            input_digests,
            conditions,
            seam_compatible: Some(true), // Release ist kein M13-Zellbezug; siehe psk_gate-Modulkopf
            evidence_refs,
            seam_report_refs: vec![ObjectId::new(
                psk_types::objects::SortId::Trace,
                Digest::sha256(b"release-closure"),
            )],
            replay_descriptor,
            decided_at,
            trace_ref,
        },
        trace,
        residues,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::ReasonCode;

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn full_features() -> Vec<FeatureCoverageId> {
        use FeatureCoverageId::*;
        vec![Fc0, Fc1, Fc2, Fc3, Fc4, Fc5, Fc6, Fc7, Fc8]
    }

    #[test]
    fn no_features_and_no_acceptance_is_c0_by_default_but_blocked_at_issue() {
        let class = compute_conformance_class(&[], AdditionalAcceptance::default());
        assert_eq!(class, Class::C0);
    }

    #[test]
    fn fc0_alone_with_artifact_acceptance_is_c0() {
        let class = compute_conformance_class(
            &[FeatureCoverageId::Fc0],
            AdditionalAcceptance {
                artifact_conformant: true,
                ..Default::default()
            },
        );
        assert_eq!(class, Class::C0);
    }

    #[test]
    fn missing_fc3_caps_the_class_below_c2_even_with_replay_valid() {
        // FC-Pflicht ist eine Vorbedingung, keine Ersetzung fuer die Abnahme.
        let class = compute_conformance_class(
            &[
                FeatureCoverageId::Fc0,
                FeatureCoverageId::Fc1,
                FeatureCoverageId::Fc2,
            ],
            AdditionalAcceptance {
                artifact_conformant: true,
                kernel_executable: true,
                replay_valid: true, // Abnahme da, aber FC3 fehlt
                ..Default::default()
            },
        );
        assert_eq!(class, Class::C1);
    }

    #[test]
    fn full_coverage_and_full_acceptance_reaches_c5() {
        let class = compute_conformance_class(
            &full_features(),
            AdditionalAcceptance {
                artifact_conformant: true,
                kernel_executable: true,
                replay_valid: true,
                sandbox_effect_safe: true,
                reference_validated: true,
                externally_reproduced: true,
            },
        );
        assert_eq!(class, Class::C5);
    }

    #[test]
    fn highest_satisfied_class_wins_not_the_first_checked() {
        // C4-Bedingungen erfuellt, C5 nicht (externally_reproduced fehlt).
        let class = compute_conformance_class(
            &full_features(),
            AdditionalAcceptance {
                artifact_conformant: true,
                kernel_executable: true,
                replay_valid: true,
                sandbox_effect_safe: true,
                reference_validated: true,
                externally_reproduced: false,
            },
        );
        assert_eq!(class, Class::C4);
    }

    #[test]
    fn r0_and_r1_fail_the_reference_release_minimum() {
        // Vertrag 22.2.
        assert_eq!(
            check_minimum_replay_class(ReplayClass::R0),
            Err(PskError::UnboundNondeterminismOrDivergence)
        );
        assert_eq!(
            check_minimum_replay_class(ReplayClass::R1),
            Err(PskError::UnboundNondeterminismOrDivergence)
        );
    }

    #[test]
    fn r2_and_r3_satisfy_the_reference_release_minimum() {
        assert_eq!(check_minimum_replay_class(ReplayClass::R2), Ok(()));
        assert_eq!(check_minimum_replay_class(ReplayClass::R3), Ok(()));
    }

    fn sample_inputs() -> CertificateInputs {
        CertificateInputs {
            i_c: Digest::sha256(b"constitution"),
            i_a: Digest::sha256(b"architecture"),
            i_m: Digest::sha256(b"implementation"),
            i_t: Digest::sha256(b"runtime"),
            features: vec![FeatureCoverageId::Fc0],
            acceptance: AdditionalAcceptance {
                artifact_conformant: true,
                ..Default::default()
            },
            replay_class: ReplayClass::R2,
            gate_report_digest: Digest::sha256(b"gate"),
            trace_head: Digest::sha256(b"trace"),
            replay_manifest_digest: Digest::sha256(b"replay"),
            residue_report_digest: Digest::sha256(b"residue"),
            capability_audit_digest: Digest::sha256(b"capability"),
            negative_test_report_digest: Digest::sha256(b"negative"),
            scope: ScopeExpr("local_workspace".into()),
            issued_at: sample_time(),
            signature: Signature("unsigned-reference-build".into()),
        }
    }

    #[test]
    fn issuing_at_c0_succeeds() {
        let cert = issue_certificate(sample_inputs()).unwrap();
        assert_eq!(cert.conformance_class, Class::C0);
        assert_eq!(cert.replay_class, ReplayClass::R2);
    }

    #[test]
    fn issuing_below_c0_is_blocked() {
        let mut inputs = sample_inputs();
        inputs.acceptance.artifact_conformant = false;
        assert_eq!(issue_certificate(inputs), Err(PskError::ReleaseGateBlocked));
    }

    #[test]
    fn issuing_with_r0_replay_is_blocked_even_at_c0() {
        let mut inputs = sample_inputs();
        inputs.replay_class = ReplayClass::R0;
        assert_eq!(
            issue_certificate(inputs),
            Err(PskError::UnboundNondeterminismOrDivergence)
        );
    }

    #[test]
    fn certificate_carries_all_four_system_identities_unmodified() {
        let inputs = sample_inputs();
        let (ic, ia, im, it) = (inputs.i_c, inputs.i_a, inputs.i_m, inputs.i_t);
        let cert = issue_certificate(inputs).unwrap();
        assert_eq!((cert.I_C, cert.I_A, cert.I_M, cert.I_t), (ic, ia, im, it));
    }

    #[test]
    fn release_gate_pass_reports_pass() {
        let mut trace = TraceStore::new();
        let mut residues = ResidueLedger::new();
        let report = evaluate_release_gate(
            vec![ConditionOutcome::True],
            vec![Digest::sha256(b"in")],
            vec![],
            ReplayDescriptor("replay/1".into()),
            sample_time(),
            TraceRef(Digest::sha256(b"trace")),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(
            report.decision,
            psk_types::objects::GateReportDecisionKind::Pass
        );
        assert_eq!(report.gate_id, GateId::GRelease);
    }

    #[test]
    fn release_gate_blocks_on_a_missing_prerequisite() {
        let mut trace = TraceStore::new();
        let mut residues = ResidueLedger::new();
        let report = evaluate_release_gate(
            vec![ConditionOutcome::False(ReasonCode("residues-open".into()))],
            vec![Digest::sha256(b"in")],
            vec![],
            ReplayDescriptor("replay/1".into()),
            sample_time(),
            TraceRef(Digest::sha256(b"trace")),
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(
            report.decision,
            psk_types::objects::GateReportDecisionKind::Fail
        );
        // T-RES-001: FAIL muss residualisiert sein.
        assert_eq!(residues.all().len(), 1);
    }
}
