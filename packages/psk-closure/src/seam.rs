//! M11 ClosureGlueEngine, Pass C9 (Closure and Gluing), Seamteil.
//!
//! Algorithmus 11.13 (Verklebung), der hier realisierte Ausschnitt:
//! ```text
//! for (a,b) in pairs(capsules):
//!     if overlap(a,b) != empty:
//!         s = compare_restrictions(a, b)     // s_a|U = s_b|U ?
//!         seams.append(s)
//!         if not s.compatible:
//!             emit ObstructionRecord{kind:seam, located_at:s.cell_refs,
//!                                    severity: blocking}
//! ```
//!
//! Vertrag 7.3 (Identitätsclosure)1 (Kein halluziniertes Gluing) und Invariante 11.14 (Eindeutigkeit der Verklebung)
//! (Eindeutigkeit der Verklebung): "Der Compiler DARF NICHT zwischen
//! mehreren globalen Sektionen waehlen; Mehrdeutigkeit ist ein Defekt und
//! erzeugt PSK-E011." Deshalb gibt `unique_global_section` keinen "besten"
//! Kandidaten zurueck, sondern scheitert bei Mehrdeutigkeit.
//!
//! Die Gate-Entscheidung zweiter Ordnung (`g2 = M14.second_order_gate`)
//! gehoert NICHT hierher: M14 entsteht erst mit WP11 (Phase I6), und der
//! Weg dorthin fuehrt ueber M11 -> P18 -> M12 -> P19 -> M13 -> P20 -> M14
//! (Algorithmus 11.19 (Normativer Compilerlauf), v1.0.5). `glue` liefert deshalb einen Bericht, der
//! die lokale Vorbedingung feststellt, und nie eine Gate-Entscheidung.

use std::collections::BTreeSet;

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    CandidateCapsule, M13Address, ObstructionRecord, ObstructionRecordKindKind,
    ObstructionRecordSeverityKind, RecoveryPathId, SeamReport, SeamReportToleranceClassKind,
    SortId,
};
use psk_types::{Digest, ObjectId, PskError};

/// Der Ueberlappungsbereich zweier Kapseln: die gemeinsamen Zellen und die
/// dort geltenden Restriktionen.
///
/// `overlap(a,b)` und `compare_restrictions(a,b)` sind in Algorithmus 11.13 (Verklebung)
/// benannt, aber nicht ausgeschrieben - Struktur 7.2 (IdentityBinding)3 (CandidateCapsule)
/// fuehrt weder Zellen noch Restriktionen als Felder. Die Zuordnung
/// Kapsel -> (Zellen, Restriktionsdigest) ist damit eine Angabe von aussen,
/// nicht aus der Kapsel ableitbar; sie wird hier als `CapsuleRestriction`
/// entgegengenommen statt erfunden. Befund gemeldet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapsuleRestriction {
    pub capsule: ObjectId,
    /// Die M13-Zellen, auf denen diese Kapsel eine lokale Sektion traegt.
    pub cells: Vec<M13Address>,
    /// H(Can(lokale Sektion)) je Zelle, in derselben Reihenfolge wie `cells`.
    pub restriction_digests: Vec<Digest>,
}

impl CapsuleRestriction {
    fn digest_at(&self, cell: &M13Address) -> Option<Digest> {
        self.cells
            .iter()
            .position(|c| c == cell)
            .and_then(|i| self.restriction_digests.get(i).copied())
    }

    fn cell_set(&self) -> BTreeSet<&M13Address> {
        self.cells.iter().collect()
    }
}

fn seam_id(a: &ObjectId, b: &ObjectId, cells: &[M13Address]) -> Result<ObjectId, PskError> {
    let preimage = serde_json::json!({
        "overlap": [a, b],
        "cell_refs": cells,
    });
    let bytes = serde_json::to_vec(&preimage).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    object_id(SortId::Trace.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// `overlap(a,b)`: die gemeinsamen Zellen, in stabiler Ordnung.
pub fn overlap(a: &CapsuleRestriction, b: &CapsuleRestriction) -> Vec<M13Address> {
    let sb = b.cell_set();
    let mut common: Vec<M13Address> = a
        .cells
        .iter()
        .filter(|c| sb.contains(*c))
        .cloned()
        .collect();
    common.sort();
    common.dedup();
    common
}

/// `compare_restrictions(a, b)`: prueft `s_a|U = s_b|U` auf dem
/// Ueberlappungsbereich U und erzeugt den SeamReport (Struktur 7.30 (SeamReport / ObstructionRecord)).
///
/// `tolerance_class` ist hier immer `exact`: eine `declared_equivalence`
/// setzt eine deklarierte Aequivalenzrelation voraus, die es ohne
/// DomainProfile nicht gibt. Eine hier angenommene Toleranz waere genau
/// das halluzinierte Gluing, das Vertrag 7.31 (Kein halluziniertes Gluing) verbietet.
pub fn compare_restrictions(
    a: &CapsuleRestriction,
    b: &CapsuleRestriction,
) -> Result<Option<SeamReport>, PskError> {
    let cells = overlap(a, b);
    if cells.is_empty() {
        // "if overlap(a,b) != empty" - ohne Ueberlappung entsteht keine Naht.
        return Ok(None);
    }

    let mut compatible = true;
    for cell in &cells {
        match (a.digest_at(cell), b.digest_at(cell)) {
            (Some(da), Some(db)) if da == db => {}
            _ => {
                // Ungleiche ODER fehlende Restriktion auf einer gemeinsamen
                // Zelle. Beides ist inkompatibel: eine fehlende Restriktion
                // ist kein stillschweigendes Einverstaendnis.
                compatible = false;
            }
        }
    }

    // Der Digest, den der Bericht traegt, ist der ueber die Restriktionen
    // auf U - nicht der ueber alle Zellen der Kapsel.
    let da = restriction_digest_over(a, &cells)?;
    let db = restriction_digest_over(b, &cells)?;

    Ok(Some(SeamReport {
        id: seam_id(&a.capsule, &b.capsule, &cells)?,
        overlap: [a.capsule, b.capsule],
        restriction_digest_a: da,
        restriction_digest_b: db,
        compatible,
        tolerance_class: SeamReportToleranceClassKind::Exact,
        cell_refs: cells,
    }))
}

fn restriction_digest_over(
    r: &CapsuleRestriction,
    cells: &[M13Address],
) -> Result<Digest, PskError> {
    let per_cell: Vec<Option<Digest>> = cells.iter().map(|c| r.digest_at(c)).collect();
    let bytes = serde_json::to_vec(&per_cell).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(psk_canon::can(&bytes, Media::Json)?.digest())
}

/// Der ObstructionRecord, den eine inkompatible Naht erzeugt:
/// `kind:seam, located_at:s.cell_refs, severity: blocking` (Algorithmus
/// 11.13, woertlich).
///
/// `residue_ref` verweist auf das Residuum, das M19 dazu fuehrt. M19 ist
/// WP04 (Phase I5) und existiert noch nicht; das Feld ist in Struktur 7.30 (SeamReport / ObstructionRecord)
/// nicht optional. Der Aufrufer reicht die Referenz herein - erfunden wird
/// sie hier nicht.
pub fn obstruction_for(
    seam: &SeamReport,
    residue_ref: ObjectId,
) -> Result<ObstructionRecord, PskError> {
    let draft = ObstructionRecord {
        id: ObjectId::new(SortId::Residue, Digest::sha256(b"")), // Platzhalter
        kind: ObstructionRecordKindKind::Seam,
        located_at: seam.cell_refs.clone(),
        involved: seam.overlap.to_vec(),
        severity: ObstructionRecordSeverityKind::Blocking,
        residue_ref,
        // Kapitel 17 beschreibt Recoverypfade in Prosa, ohne IDs. Eine hier
        // erfundene Kennung waere eine Behauptung ueber verfuegbare
        // Erholung; die Liste bleibt leer, bis das Werk sie benennt.
        allowed_recovery: Vec::<RecoveryPathId>::new(),
    };
    let mut value = serde_json::to_value(&draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    let id: ObjectId = object_id(SortId::Residue.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(ObstructionRecord { id, ..draft })
}

/// Ergebnis des Seamdurchlaufs ueber alle Kapselpaare.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SeamScan {
    /// Alle Nahtberichte, in Paarreihenfolge.
    pub seams: Vec<SeamReport>,
    /// Die Nahtberichte, die nicht kompatibel sind - eine je erzeugtem
    /// ObstructionRecord.
    pub incompatible: Vec<SeamReport>,
}

impl SeamScan {
    /// "if any(seam not compatible) [...] return ClosureReport{global:false}"
    pub fn all_compatible(&self) -> bool {
        self.incompatible.is_empty()
    }
}

/// `for (a,b) in pairs(capsules)`: jedes ungeordnete Paar genau einmal, in
/// stabiler Reihenfolge.
///
/// OBL-003 (Gluing-Komplexitaet): "Die Architektur schreibt paarweise Tests
/// plus ein Gate zweiter Ordnung als Untergrenze vor." Paarweise ist damit
/// das Minimum, nicht das Optimum - und das Gate zweiter Ordnung liegt bei
/// M14 (WP11).
pub fn scan_seams(restrictions: &[CapsuleRestriction]) -> Result<SeamScan, PskError> {
    let mut seams = Vec::new();
    let mut incompatible = Vec::new();
    for i in 0..restrictions.len() {
        for j in (i + 1)..restrictions.len() {
            if let Some(seam) = compare_restrictions(&restrictions[i], &restrictions[j])? {
                if !seam.compatible {
                    incompatible.push(seam.clone());
                }
                seams.push(seam);
            }
        }
    }
    Ok(SeamScan {
        seams,
        incompatible,
    })
}

/// Invariante 11.14 (Eindeutigkeit der Verklebung): "Sind lokale Sektionen
/// kompatibel und erfuellt die Vertragspraegarbe Separiertheit und Gluing,
/// existiert hoechstens eine globale kanonische Sektion mit diesen
/// Restriktionen. Der Compiler DARF NICHT zwischen mehreren globalen
/// Sektionen waehlen; Mehrdeutigkeit ist ein Defekt und erzeugt PSK-E011."
///
/// Die globale Sektion ist hier der Digest ueber die Restriktionen aller
/// Kapseln je Zelle. Traegt eine Zelle zwei verschiedene Restriktionen, ist
/// die Sektion nicht eindeutig - und das ist der Defektfall, nicht ein
/// Auswahlproblem.
pub fn unique_global_section(restrictions: &[CapsuleRestriction]) -> Result<Digest, PskError> {
    let mut per_cell: std::collections::BTreeMap<&M13Address, Digest> =
        std::collections::BTreeMap::new();
    for r in restrictions {
        for (cell, digest) in r.cells.iter().zip(r.restriction_digests.iter()) {
            match per_cell.get(cell) {
                Some(existing) if existing != digest => {
                    return Err(PskError::NonclosingM13Seam);
                }
                _ => {
                    per_cell.insert(cell, *digest);
                }
            }
        }
    }
    let flat: Vec<(&M13Address, Digest)> = per_cell.into_iter().collect();
    let bytes = serde_json::to_vec(&flat).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(psk_canon::can(&bytes, Media::Json)?.digest())
}

/// Ergebnis von C9, soweit es ohne M14 feststellbar ist.
///
/// `global` ist ausdruecklich NICHT dasselbe wie "Gate bestanden": es sagt
/// nur, dass die lokalen Vorbedingungen erfuellt sind. Das Gate zweiter
/// Ordnung entscheidet M14 (WP11), erreicht ueber P18/P19/P20.
// `Serialize`: das Verklebungsergebnis liegt seit der Taktumverdrahtung
// als Phasenprodukt im Laufzustand Sigma und geht damit in I_t ein.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct GlueOutcome {
    pub seams: SeamScan,
    /// Some(section) nur, wenn alle Nahtberichte kompatibel sind UND die
    /// globale Sektion eindeutig ist.
    pub section: Option<Digest>,
    /// Die Begruendung, wenn keine Sektion entstand - fuer den
    /// HOLD-Grund, den Regel 32.2 (Phasenabhängigkeit der Passfolge) Punkt 2 verlangt ("HOLD mit benannter
    /// Ursache").
    pub hold_reason: Option<&'static str>,
}

/// M11, Pass C9: der lokale Teil von Algorithmus 11.13 (Verklebung).
///
/// `cells_closed` ist das Ergebnis von `M22.close_all_18(graph)`, das laut
/// Algorithmus 11.19 (Normativer Compilerlauf) vor C9 laeuft und dessen Modul (M22) seit WP03
/// existiert. Es wird hier nur gelesen, nicht neu berechnet.
pub fn glue(
    restrictions: &[CapsuleRestriction],
    cells_closed: bool,
) -> Result<GlueOutcome, PskError> {
    let seams = scan_seams(restrictions)?;

    if !seams.all_compatible() {
        return Ok(GlueOutcome {
            seams,
            section: None,
            hold_reason: Some("inkompatible Naht (PSK-E011)"),
        });
    }
    if !cells_closed {
        return Ok(GlueOutcome {
            seams,
            section: None,
            hold_reason: Some("offene Zellnaht aus close_all_18 (PSK-E011)"),
        });
    }

    match unique_global_section(restrictions) {
        Ok(section) => Ok(GlueOutcome {
            seams,
            section: Some(section),
            hold_reason: None,
        }),
        Err(_) => Ok(GlueOutcome {
            seams,
            section: None,
            hold_reason: Some("mehrdeutige globale Sektion (Invariante 11.14 (Eindeutigkeit der Verklebung), PSK-E011)"),
        }),
    }
}

/// Invariante 11.15 (Kein Bypass durch Einzelpass): "Mehrere lokal
/// bestandene Gates ergeben keinen globalen Commit, solange ihre
/// Kopplungen, Zeitbezuege, Identitaeten, Tracekoepfe und Effektannahmen
/// nicht gemeinsam schliessen."
///
/// Die Wache macht genau das pruefbar: eine Menge lokal bestandener Gates
/// allein reicht nie. Sie nimmt die fuenf im Text genannten Bedingungen als
/// getrennte Feststellungen entgegen, damit keine davon in einer anderen
/// aufgeht.
pub fn check_no_single_pass_bypass(
    all_local_gates_passed: bool,
    couplings_close: bool,
    time_references_close: bool,
    identities_close: bool,
    trace_heads_close: bool,
    effect_assumptions_close: bool,
) -> Result<(), PskError> {
    let jointly = couplings_close
        && time_references_close
        && identities_close
        && trace_heads_close
        && effect_assumptions_close;
    if all_local_gates_passed && jointly {
        Ok(())
    } else {
        Err(PskError::NonclosingM13Seam)
    }
}

/// Der Kapselbezug einer Restriktion, damit `glue` mit den Kapseln
/// verwendet werden kann, die M24 (WP10) liefert.
pub fn restriction_of(
    capsule: &CandidateCapsule,
    cells: Vec<M13Address>,
    digests: Vec<Digest>,
) -> CapsuleRestriction {
    CapsuleRestriction {
        capsule: capsule.id,
        cells,
        restriction_digests: digests,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::{format_m13_address, parse_m13_address};

    fn cell(s: &str) -> M13Address {
        // Ueber den echten Parser, damit die Testadressen der Grammatik aus
        // Definition 9.12 (M13Address) genuegen und nicht nur Zeichenketten sind.
        let parsed = parse_m13_address(s).expect("Testadresse muss wohlgeformt sein");
        M13Address(format_m13_address(&parsed))
    }

    fn restriction(id: &str, entries: &[(&str, &[u8])]) -> CapsuleRestriction {
        CapsuleRestriction {
            capsule: ObjectId::new(SortId::Branch, Digest::sha256(id.as_bytes())),
            cells: entries.iter().map(|(c, _)| cell(c)).collect(),
            restriction_digests: entries.iter().map(|(_, d)| Digest::sha256(d)).collect(),
        }
    }

    #[test]
    fn no_overlap_produces_no_seam() {
        let a = restriction("a", &[("m13:0/c0", b"x")]);
        let b = restriction("b", &[("m13:0/c1", b"y")]);
        assert!(overlap(&a, &b).is_empty());
        assert_eq!(compare_restrictions(&a, &b).unwrap(), None);
    }

    #[test]
    fn equal_restrictions_on_overlap_are_compatible() {
        let a = restriction("a", &[("m13:0/c0", b"gleich"), ("m13:0/c1", b"nur-a")]);
        let b = restriction("b", &[("m13:0/c0", b"gleich"), ("m13:0/c2", b"nur-b")]);
        let seam = compare_restrictions(&a, &b).unwrap().unwrap();
        assert!(seam.compatible);
        assert_eq!(seam.cell_refs, vec![cell("m13:0/c0")]);
        assert_eq!(seam.restriction_digest_a, seam.restriction_digest_b);
    }

    #[test]
    fn differing_restrictions_on_overlap_are_incompatible() {
        let a = restriction("a", &[("m13:0/c0", b"version-a")]);
        let b = restriction("b", &[("m13:0/c0", b"version-b")]);
        let seam = compare_restrictions(&a, &b).unwrap().unwrap();
        assert!(!seam.compatible);
        assert_ne!(seam.restriction_digest_a, seam.restriction_digest_b);
    }

    #[test]
    fn incompatible_seam_yields_a_blocking_seam_obstruction() {
        // Algorithmus 11.13 (Verklebung) woertlich: kind:seam, severity: blocking.
        let a = restriction("a", &[("m13:0/c0", b"a")]);
        let b = restriction("b", &[("m13:0/c0", b"b")]);
        let seam = compare_restrictions(&a, &b).unwrap().unwrap();
        let residue = ObjectId::new(SortId::Residue, Digest::sha256(b"res"));
        let obs = obstruction_for(&seam, residue).unwrap();
        assert_eq!(obs.kind, ObstructionRecordKindKind::Seam);
        assert_eq!(obs.severity, ObstructionRecordSeverityKind::Blocking);
        assert_eq!(obs.located_at, seam.cell_refs);
        assert_eq!(obs.involved, seam.overlap);
    }

    #[test]
    fn tolerance_class_is_never_silently_declared_equivalent() {
        // Vertrag 7.3 (Identitätsclosure)1 (Kein halluziniertes Gluing): ohne deklarierte
        // Aequivalenz gilt exakt.
        let a = restriction("a", &[("m13:0/c0", b"x")]);
        let b = restriction("b", &[("m13:0/c0", b"x")]);
        let seam = compare_restrictions(&a, &b).unwrap().unwrap();
        assert_eq!(
            seam.tolerance_class,
            SeamReportToleranceClassKind::Exact,
            "eine Toleranz DARF NICHT angenommen werden"
        );
    }

    #[test]
    fn missing_restriction_on_a_shared_cell_is_not_tacit_agreement() {
        let a = restriction("a", &[("m13:0/c0", b"x")]);
        let mut b = restriction("b", &[("m13:0/c0", b"x")]);
        b.restriction_digests.clear(); // Zelle gefuehrt, Restriktion fehlt
        let seam = compare_restrictions(&a, &b).unwrap().unwrap();
        assert!(!seam.compatible);
    }

    #[test]
    fn scan_visits_each_unordered_pair_once() {
        let rs = vec![
            restriction("a", &[("m13:0/c0", b"x")]),
            restriction("b", &[("m13:0/c0", b"x")]),
            restriction("c", &[("m13:0/c0", b"x")]),
        ];
        let scan = scan_seams(&rs).unwrap();
        assert_eq!(scan.seams.len(), 3); // ab, ac, bc
        assert!(scan.all_compatible());
    }

    #[test]
    fn glue_yields_a_section_only_when_everything_closes() {
        let rs = vec![
            restriction("a", &[("m13:0/c0", b"x")]),
            restriction("b", &[("m13:0/c0", b"x")]),
        ];
        let out = glue(&rs, true).unwrap();
        assert!(out.section.is_some());
        assert_eq!(out.hold_reason, None);
    }

    #[test]
    fn glue_holds_with_a_named_cause_on_incompatible_seam() {
        // Regel 32.2 (Phasenabhängigkeit der Passfolge) Punkt 2: HOLD MUSS eine benannte Ursache tragen.
        let rs = vec![
            restriction("a", &[("m13:0/c0", b"x")]),
            restriction("b", &[("m13:0/c0", b"y")]),
        ];
        let out = glue(&rs, true).unwrap();
        assert_eq!(out.section, None);
        assert!(out.hold_reason.unwrap().contains("Naht"));
    }

    #[test]
    fn glue_holds_when_cells_are_not_closed() {
        let rs = vec![restriction("a", &[("m13:0/c0", b"x")])];
        let out = glue(&rs, false).unwrap();
        assert_eq!(out.section, None);
        assert!(out.hold_reason.unwrap().contains("Zellnaht"));
    }

    #[test]
    fn ambiguous_global_section_is_a_defect_not_a_choice() {
        // Invariante 11.14 (Eindeutigkeit der Verklebung): der Compiler DARF NICHT waehlen.
        let rs = vec![
            restriction("a", &[("m13:0/c0", b"eins")]),
            restriction("b", &[("m13:0/c0", b"zwei")]),
        ];
        assert_eq!(unique_global_section(&rs), Err(PskError::NonclosingM13Seam));
    }

    #[test]
    fn global_section_is_deterministic() {
        let rs = vec![
            restriction("a", &[("m13:0/c1", b"y"), ("m13:0/c0", b"x")]),
            restriction("b", &[("m13:0/c0", b"x")]),
        ];
        let rs2 = vec![
            restriction("b", &[("m13:0/c0", b"x")]),
            restriction("a", &[("m13:0/c0", b"x"), ("m13:0/c1", b"y")]),
        ];
        assert_eq!(
            unique_global_section(&rs).unwrap(),
            unique_global_section(&rs2).unwrap()
        );
    }

    #[test]
    fn local_gates_alone_never_commit() {
        // Invariante 11.15 (Kein Bypass durch Einzelpass).
        assert_eq!(
            check_no_single_pass_bypass(true, true, true, true, true, false),
            Err(PskError::NonclosingM13Seam)
        );
        assert_eq!(
            check_no_single_pass_bypass(false, true, true, true, true, true),
            Err(PskError::NonclosingM13Seam)
        );
        assert_eq!(
            check_no_single_pass_bypass(true, true, true, true, true, true),
            Ok(())
        );
    }
}
