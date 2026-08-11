//! M21: `feature_coverage` ABLEITEN, nicht entgegennehmen.
//!
//! Kapitel 23: "Die Merkmalsstufen der Gesamtspezifikation werden als
//! abgeleiteter Deckungsvektor FC = (FC0, ..., FC8) gefuehrt. FC ist keine
//! Klassifikation, sondern eine Pflichtangabe im Maschinenzertifikat und
//! eine Vorbedingung bestimmter C-Klassen." Struktur 7.50 (MachineCertificate) fuehrt das Feld
//! woertlich als `feature_coverage: [FC0..FC8] # abgeleiteter
//! Deckungsvektor`.
//!
//! "Abgeleitet" ist kein Stilwort: solange der Vektor beansprucht statt
//! abgeleitet wird, ist die Konformanzklasse selbst beansprucht - und die
//! Klasse ist die eine Behauptung, die das Zertifikat nach aussen traegt.
//!
//! ## Was hier Beleg heisst
//!
//! `FeatureEvidence` traegt MESSWERTE aus realen Artefakten (Zahlen,
//! Digests, bereits von ihrem zustaendigen Modul gebildete Urteile), nicht
//! Meinungen. Wo ein Feld ein blosses `bool` ist, stammt es von dem Modul,
//! das die Frage tatsaechlich beantworten kann (z.B.
//! `psk_trace::ReplayCheck`s eigene Felder, die M19 aus dem Vergleich
//! zweier Laeufe bildet), nicht vom Aufrufer als Behauptung.
//!
//! Wo fuer eine Stufe KEIN Artefakt existiert, erscheint sie nicht im
//! Vektor - auch dann nicht, wenn sie faktisch erfuellt sein mag. Ein
//! ehrlich kuerzerer Vektor ist mehr wert als ein vollstaendiger ohne
//! Beleg; genau diese Unterscheidung ist der Grund, warum das Feld
//! "abgeleitet" heisst.
//!
//! M21 misst dabei selbst nichts (siehe `CertificateInputs`: "Kein Feld
//! wird hier gemessen") - diese Datei wendet nur die Ableitungsregel auf
//! bereits anderswo gemessene Werte an.

use psk_types::objects::FeatureCoverageId;
use psk_types::Digest;

/// Messwerte aus realen Artefakten, je Merkmalsstufe gruppiert.
///
/// `Option` heisst durchgaengig: "dieses Artefakt existiert nicht" -
/// unterschieden von einem vorhandenen Artefakt mit negativem Befund.
/// Beides fuehrt zur selben Folge (Stufe nicht gedeckt), aber nur das
/// erste ist eine Luecke; die Begruendungstexte unten halten das
/// auseinander.
#[derive(Debug, Clone, Default)]
pub struct FeatureEvidence {
    // ---- FC0: Grammatiktypen, kanonische Serialisierung, Spezifikations-ID.
    /// Der im Bundle deklarierte und der selbst nachgerechnete I_C.
    pub constitution_id: Option<(Digest, Digest)>,
    /// Dasselbe fuer I_A.
    pub architecture_id: Option<(Digest, Digest)>,

    // ---- FC1: M13-Graph, 30 Kanten, 18 Zellen, lokale Seam-Closure.
    pub m13_nodes: usize,
    pub m13_edges: usize,
    pub m13_cells: usize,
    /// `GlueOutcome.section` - `Some` nur bei eindeutiger globaler Sektion
    /// (Invariante 11.14).
    pub local_seam_section: Option<Digest>,

    // ---- FC2: PSK-IR, Round-Trip, Replay.
    /// Digest eines IRBundle vor und nach `ir_decode(ir_encode(..))`.
    /// `None`: in keinem Lauf entstand ein IRBundle.
    pub ir_bundle_round_trip: Option<(Digest, Digest)>,
    /// Aus `psk_trace::ReplayCheck`, von M19 aus zwei Laeufen gebildet.
    pub replay: Option<ReplayEvidence>,

    // ---- FC3: Reality-/Faktizitaetstypisierung ohne Promotionsbypass.
    pub reality_classifications: usize,
    /// Wurde die Promotionssperre in einem realen Lauf tatsaechlich
    /// ausgeuebt (Vertrag 7.13)? `None`: nie zur Anwendung gekommen.
    pub promotions_barred_on_unknown: Option<usize>,

    // ---- FC4: Feldprojektionen, Lineage, Abhaengigkeitsquotient.
    pub field_projections: usize,
    pub dependency_profiles: usize,
    /// Zaehlt NICHTLEERE Lineages (Massstab: M08s `lineage_declared`,
    /// trim + nicht leer). Eine vorhandene, aber leere Lineage ist kein
    /// Herkunftsbeleg - dieselbe Linie wie beim Deckungsvektor selbst.
    pub field_lineages: usize,

    // ---- FC5: Kandidatenkapseln, adversariales Ratchet, Support, Residuenfluss.
    pub candidate_capsules: usize,
    pub ratcheted_capsules: usize,
    pub support_decisions: usize,
    pub residue_flow_transitions: usize,

    // ---- FC6: Gate, Effekttoken, Receipt, Reconciliation.
    pub gate_reports: usize,
    pub effect_tokens: usize,
    pub external_receipts: usize,
    pub reconciliation_reports: usize,

    // ---- FC7: Kontrollierte Selbstkompilation und unabhaengige Aktivierung.
    /// G-SELF-COMPILE bestanden (Invariante 12.15). `None`: nie ausgewertet.
    pub self_compile_gate_passed: Option<bool>,

    // ---- FC8: Validierte Referenzdomaene mit Baselinevergleich.
    /// `BaselineComparison::kern_passes()`. `None`: kein Vergleich gelaufen.
    pub baseline_comparison_passed: Option<bool>,
}

/// M19s eigenes Replayurteil (Definition 22.1), nicht neu gebildet.
#[derive(Debug, Clone, Copy)]
pub struct ReplayEvidence {
    pub attempted: bool,
    pub canonical_digest_match: bool,
    pub gate_sequence_match: bool,
}

/// Warum eine Stufe gedeckt ist oder nicht - fuer den Bericht, damit ein
/// kuerzerer Vektor seinen Grund mitbringt statt nur seine Kuerze.
#[derive(Debug, Clone)]
pub struct CoverageFinding {
    pub feature: FeatureCoverageId,
    pub covered: bool,
    pub reason: String,
}

/// Das Ergebnis der Ableitung.
#[derive(Debug, Clone)]
pub struct CoverageDerivation {
    pub covered: Vec<FeatureCoverageId>,
    pub findings: Vec<CoverageFinding>,
}

fn finding(
    feature: FeatureCoverageId,
    covered: bool,
    reason: impl Into<String>,
) -> CoverageFinding {
    CoverageFinding {
        feature,
        covered,
        reason: reason.into(),
    }
}

/// Leitet den Deckungsvektor aus den Messwerten ab (Kapitel 23).
///
/// Jede Stufe verlangt ALLE in ihrer Zeile genannten Nachweise - die
/// Tabelle zaehlt sie mit Komma auf, nicht mit "oder".
pub fn derive_feature_coverage(evidence: &FeatureEvidence) -> CoverageDerivation {
    use FeatureCoverageId::*;
    let mut findings = Vec::new();

    // FC0: "Grammatiktypen, kanonische Serialisierung, Spezifikations-ID."
    // Die Spezifikations-ID ist nachgerechnet und stimmt - damit sind
    // Grammatik und kanonische Serialisierung mitbelegt: I_C/I_A ENTSTEHEN
    // durch Can() ueber die getypten Register, ein Treffer ist ohne beides
    // nicht erreichbar.
    findings.push(match (evidence.constitution_id, evidence.architecture_id) {
        (Some((c_declared, c_actual)), Some((a_declared, a_actual))) => {
            if c_declared == c_actual && a_declared == a_actual {
                finding(Fc0, true, "I_C und I_A nachgerechnet und deckungsgleich")
            } else {
                finding(
                    Fc0,
                    false,
                    "Spezifikations-ID weicht ab: Bundle nicht versiegelt oder veraendert",
                )
            }
        }
        _ => finding(
            Fc0,
            false,
            "kein Artefakt: I_C/I_A wurden nicht nachgerechnet",
        ),
    });

    // FC1: "M13-Graph, 30 Kanten, 18 Zellen, lokale Seam-Closure."
    let topology_ok =
        evidence.m13_nodes == 13 && evidence.m13_edges == 30 && evidence.m13_cells == 18;
    findings.push(match (topology_ok, evidence.local_seam_section) {
        (true, Some(_)) => finding(
            Fc1,
            true,
            "13/30/18 belegt und eine eindeutige globale Sektion vorhanden",
        ),
        (true, None) => finding(
            Fc1,
            false,
            "Topologie belegt, aber kein Artefakt fuer lokale Seam-Closure (keine globale Sektion)",
        ),
        (false, _) => finding(
            Fc1,
            false,
            format!(
                "Kardinalitaet verfehlt: {}/{}/{} statt 13/30/18",
                evidence.m13_nodes, evidence.m13_edges, evidence.m13_cells
            ),
        ),
    });

    // FC2: "PSK-IR, Round-Trip, Replay." Drei Nachweise, alle noetig.
    let replay_ok = evidence
        .replay
        .is_some_and(|r| r.attempted && r.canonical_digest_match && r.gate_sequence_match);
    findings.push(match (evidence.ir_bundle_round_trip, replay_ok) {
        (Some((before, after)), true) if before == after => finding(
            Fc2,
            true,
            "IR-Round-Trip verlustfrei und Replay deckungsgleich",
        ),
        (Some((_, _)), true) => finding(Fc2, false, "IR-Round-Trip nicht verlustfrei"),
        (Some(_), false) => finding(
            Fc2,
            false,
            "Replay nicht deckungsgleich oder nicht versucht",
        ),
        (None, _) => finding(
            Fc2,
            false,
            "kein Artefakt: in keinem Lauf entsteht ein IRBundle, also ist kein Round-Trip messbar",
        ),
    });

    // FC3: "Reality- und Faktizitaetstypisierung ohne Promotionsbypass."
    findings.push(
        if evidence.reality_classifications > 0 && evidence.promotions_barred_on_unknown.is_some() {
            finding(
                Fc3,
                true,
                format!(
                    "{} Realitaetsklassifikation(en) und die Promotionssperre real ausgeuebt",
                    evidence.reality_classifications
                ),
            )
        } else if evidence.reality_classifications > 0 {
            finding(
                Fc3,
                false,
                "Typisierung belegt, aber kein Artefakt dafuer, dass die Promotionssperre je griff",
            )
        } else {
            finding(
                Fc3,
                false,
                "kein Artefakt: keine Realitaetsklassifikation erzeugt",
            )
        },
    );

    // FC4: "Feldprojektionen, Lineage, Abhaengigkeitsquotient."
    findings.push(
        if evidence.field_projections > 0
            && evidence.field_lineages > 0
            && evidence.dependency_profiles > 0
        {
            finding(
                Fc4,
                true,
                format!(
                    "{} Projektion(en), {} Lineage(s), {} Abhaengigkeitsprofil(e)",
                    evidence.field_projections,
                    evidence.field_lineages,
                    evidence.dependency_profiles
                ),
            )
        } else {
            finding(
                Fc4,
                false,
                format!(
                    "unvollstaendig: Projektionen={}, Lineages={}, Abhaengigkeitsprofile={}",
                    evidence.field_projections,
                    evidence.field_lineages,
                    evidence.dependency_profiles
                ),
            )
        },
    );

    // FC5: "Kandidatenkapseln, adversariales Ratchet, Support, Residuenfluss."
    findings.push(
        if evidence.candidate_capsules > 0
            && evidence.ratcheted_capsules > 0
            && evidence.support_decisions > 0
            && evidence.residue_flow_transitions > 0
        {
            finding(
                Fc5,
                true,
                "Kapseln, Ratchet, Support und Residuenfluss belegt",
            )
        } else {
            finding(
                Fc5,
                false,
                format!(
                    "unvollstaendig: Kapseln={}, Ratchet={}, Support={}, Residuenfluss={}",
                    evidence.candidate_capsules,
                    evidence.ratcheted_capsules,
                    evidence.support_decisions,
                    evidence.residue_flow_transitions
                ),
            )
        },
    );

    // FC6: "Gate, Effekttoken, Receipt, Reconciliation."
    findings.push(
        if evidence.gate_reports > 0
            && evidence.effect_tokens > 0
            && evidence.external_receipts > 0
            && evidence.reconciliation_reports > 0
        {
            finding(
                Fc6,
                true,
                format!(
                    "{} Gate(s), {} Token, {} Receipt(s), {} Reconciliation(en)",
                    evidence.gate_reports,
                    evidence.effect_tokens,
                    evidence.external_receipts,
                    evidence.reconciliation_reports
                ),
            )
        } else {
            finding(
                Fc6,
                false,
                format!(
                    "unvollstaendig: Gates={}, Token={}, Receipts={}, Reconciliations={}",
                    evidence.gate_reports,
                    evidence.effect_tokens,
                    evidence.external_receipts,
                    evidence.reconciliation_reports
                ),
            )
        },
    );

    // FC7: "Kontrollierte Selbstkompilation und unabhaengige Aktivierung."
    findings.push(match evidence.self_compile_gate_passed {
        Some(true) => finding(Fc7, true, "G-SELF-COMPILE bestanden"),
        Some(false) => finding(Fc7, false, "G-SELF-COMPILE nicht bestanden"),
        None => finding(Fc7, false, "kein Artefakt: G-SELF-COMPILE nie ausgewertet"),
    });

    // FC8: "Validierte Referenzdomaene mit Baselinevergleich."
    findings.push(match evidence.baseline_comparison_passed {
        Some(true) => finding(Fc8, true, "Baselinevergleich bestanden (kern_passes)"),
        Some(false) => finding(Fc8, false, "Baselinevergleich nicht bestanden"),
        None => finding(Fc8, false, "kein Artefakt: kein Baselinevergleich gelaufen"),
    });

    let covered = findings
        .iter()
        .filter(|f| f.covered)
        .map(|f| f.feature)
        .collect();
    CoverageDerivation { covered, findings }
}

#[cfg(test)]
mod tests {
    use super::*;
    use FeatureCoverageId::*;

    fn matching(seed: &[u8]) -> Option<(Digest, Digest)> {
        let d = Digest::sha256(seed);
        Some((d, d))
    }

    #[test]
    fn empty_evidence_derives_an_empty_vector() {
        // Der Kernpunkt: ohne Artefakt keine Stufe. Ein Vorgabewert waere
        // genau die Behauptung, die "abgeleitet" ausschliesst.
        let d = derive_feature_coverage(&FeatureEvidence::default());
        assert!(d.covered.is_empty(), "{:?}", d.covered);
        assert_eq!(d.findings.len(), 9, "jede Stufe MUSS begruendet sein");
        assert!(d.findings.iter().all(|f| !f.covered));
    }

    #[test]
    fn fc0_needs_both_identities_to_match() {
        let mut e = FeatureEvidence {
            constitution_id: matching(b"c"),
            architecture_id: matching(b"a"),
            ..Default::default()
        };
        assert!(derive_feature_coverage(&e).covered.contains(&Fc0));

        e.architecture_id = Some((Digest::sha256(b"a"), Digest::sha256(b"anders")));
        assert!(!derive_feature_coverage(&e).covered.contains(&Fc0));
    }

    #[test]
    fn a_missing_artefact_and_a_negative_finding_are_reported_differently() {
        // Beide fuehren zu "nicht gedeckt", aber nur das erste ist eine
        // Luecke - der Bericht muss das auseinanderhalten.
        let missing = derive_feature_coverage(&FeatureEvidence::default());
        let missing_fc8 = missing.findings.iter().find(|f| f.feature == Fc8).unwrap();
        assert!(missing_fc8.reason.contains("kein Artefakt"));

        let negative = derive_feature_coverage(&FeatureEvidence {
            baseline_comparison_passed: Some(false),
            ..Default::default()
        });
        let negative_fc8 = negative.findings.iter().find(|f| f.feature == Fc8).unwrap();
        assert!(!negative_fc8.reason.contains("kein Artefakt"));
        assert!(negative_fc8.reason.contains("nicht bestanden"));
    }

    #[test]
    fn fc1_requires_the_seam_section_not_only_the_cardinality() {
        let e = FeatureEvidence {
            m13_nodes: 13,
            m13_edges: 30,
            m13_cells: 18,
            local_seam_section: None,
            ..Default::default()
        };
        let d = derive_feature_coverage(&e);
        assert!(!d.covered.contains(&Fc1));
        let f = d.findings.iter().find(|f| f.feature == Fc1).unwrap();
        assert!(f.reason.contains("Seam-Closure"), "{}", f.reason);
    }

    #[test]
    fn every_named_sub_proof_of_a_level_is_required() {
        // Die Tabelle zaehlt mit Komma auf, nicht mit "oder": ein
        // fehlender Teilnachweis genuegt, um die Stufe zu verhindern.
        let full = FeatureEvidence {
            gate_reports: 1,
            effect_tokens: 1,
            external_receipts: 1,
            reconciliation_reports: 1,
            ..Default::default()
        };
        assert!(derive_feature_coverage(&full).covered.contains(&Fc6));

        let mut missing_receipt = full.clone();
        missing_receipt.external_receipts = 0;
        assert!(!derive_feature_coverage(&missing_receipt)
            .covered
            .contains(&Fc6));
    }
}
