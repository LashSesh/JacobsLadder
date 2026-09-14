//! M10 DependencyAnalyzer, Pass C6 (Dependency Quotient).
//!
//! Algorithmus 11.9 (Abhaengigkeitsquotient), woertlich:
//! ```text
//! S       = collect_sources(projections)
//! D       = build_dependency_matrix(projections, S)
//! W       = build_witness_matrix(projections)
//! classes = partition_by_shared_source(projections, D)   // F / ~_D
//! r_eff   = RankEff(W, D)                                // OBL-001
//! require r_eff <= count(classes)
//! ```
//!
//! Invariante 11.10 (Anti-Echokammer): "Mehrere Facetten, die dieselbe
//! Daten-, Modell-, Prompt-, Sonden- oder Kalibrierungsquelle teilen,
//! bilden keine unabhaengigen Witnesses. [...] Das Klonen desselben
//! Modells in n Facetten DARF NICHT r_eff = n erzeugen." Genau das erzwingt
//! die Quotientenbildung hier: geteilte Quelle => selbe Klasse.
//!
//! Struktur 7.27 (Matrix und Scaled), v1.0.8: Matrix ist "intern berechnet,
//! nicht domaenengeliefert" und quadratisch ueber EINER Achse
//! (`axis: [SourceRef]`, Zeilen- und Spaltenachse identisch) - anders als
//! die vorherige Kodierung dieses Moduls (Projektion x Knoten fuer W,
//! Projektion x Quelle fuer D), die mit der neuen Grammatik nicht mehr
//! ausdrueckbar ist. `dependency_matrix` und `witness_matrix` sind deshalb
//! hier als Quelle-x-Quelle-Relationen neu gefasst: D[i][j] = 1, wenn i und
//! j gemeinsam in mindestens einer Projektion auftreten (Kodependenz);
//! W[i][j] = 1, wenn i und j zusaetzlich gemeinsam in einer Projektion mit
//! nichtleerem `visible` auftreten (bezeugte Kodependenz). Diese
//! Zellsemantik ist eine Implementierungsentscheidung im verbleibenden
//! Raum (das Werk legt nur die FORM fest, Regel 7.28, nicht die Zellen);
//! `partition_by_shared_source` arbeitet weiterhin direkt auf den
//! Quellmengen je Projektion, nicht ueber D - D ist damit ein
//! Berichtsartefakt, kein Berechnungsweg.
//!
//! Regel 7.28 (Kanonische Achsenordnung): "axis MUSS aufsteigend nach der
//! kanonischen Form von SourceRef sortiert sein. Zeilen- und Spaltenachse
//! sind identisch; eine Matrix mit abweichenden Achsen ist unzulaessig.
//! [...] Verstoss erzeugt PSK-E102." SourceRef hat keine weitere Struktur
//! als seine Zeichenkette; "kanonische Form" wird deshalb als deren
//! Standardordnung gelesen (dieselbe Ableitung wie bei der ObjectId-
//! Tie-Break-Ordnung in psk-witness::planner).

use std::collections::{BTreeMap, BTreeSet};

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    DependencyProfile, DependencyProfileConsensusScopeKind, FieldProjection, Matrix, RankMethodId,
    Scaled, SortId, SourceRef,
};
use psk_types::{Digest, ObjectId, PskError};

/// Regel 7.28: prueft, dass `axis` aufsteigend und ohne Wiederholung
/// sortiert ist und dass `values` quadratisch genau darueber liegt.
/// Verstoss erzeugt PSK-E102 (`CanonicalizationFailed`).
pub fn check_canonical_axis_order(m: &Matrix) -> Result<(), PskError> {
    let sorted = m.axis.windows(2).all(|w| w[0] < w[1]); // aufsteigend, keine Wiederholung
    let square =
        m.values.len() == m.axis.len() && m.values.iter().all(|row| row.len() == m.axis.len());
    if sorted && square {
        Ok(())
    } else {
        Err(PskError::CanonicalizationFailed)
    }
}

/// Baut eine Matrix ueber `axis` (wird hier sortiert, nicht vom Aufrufer
/// entgegengenommen - Regel 7.28 ist damit strukturell erfuellt, nicht nur
/// geprueft) und einer symmetrischen Zellrelation.
fn build_square_matrix(
    axis_set: BTreeSet<SourceRef>,
    scale: i64,
    mut cell: impl FnMut(&SourceRef, &SourceRef) -> i64,
) -> Matrix {
    let axis: Vec<SourceRef> = axis_set.into_iter().collect(); // BTreeSet: bereits aufsteigend
    let values: Vec<Vec<i64>> = axis
        .iter()
        .map(|a| axis.iter().map(|b| cell(a, b)).collect())
        .collect();
    Matrix {
        schema: "psk.matrix/1.0".to_string(),
        axis,
        scale,
        values,
    }
}

/// Die Methode, mit der `r_eff` geschaetzt wird.
///
/// OBL-001 (Unabhaengigkeitsrang): "Die Norm verlangt die Eigenschaft
/// RankEff(W, D) <= |F / ~_D| und Monotonie unter Hinzufuegen korrelierter
/// Facetten; sie schreibt keinen universell optimalen Algorithmus vor. Die
/// gewaehlte Methode ist als MethodPlugin zu deklarieren und ueber T-DEP-001
/// zu testen."
///
/// Es gibt hier bewusst KEINEN Default: welche Methode gilt, ist eine
/// deklarierte Wahl, keine stillschweigende.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RankMethod {
    /// r_eff = |F / ~_D|, die Zahl der Quotientenklassen.
    ///
    /// Beide von OBL-001 verlangten Eigenschaften sind hier beweisbar, nicht
    /// nur plausibel: die Ungleichung gilt mit Gleichheit, und das
    /// Hinzufuegen einer Facette, die eine bestehende Quelle teilt,
    /// vergroessert die Klassenzahl nicht (sie faellt mit der bestehenden
    /// Klasse zusammen), kann r_eff also nicht erhoehen.
    ///
    /// Bewusst konservativ: die Methode erkennt keine Korrelation zwischen
    /// Facetten VERSCHIEDENER Quellklassen. Sie ueberschaetzt damit nie die
    /// Unabhaengigkeit unter dem deklarierten Quellenmodell, aber sie
    /// entdeckt auch nichts darueber hinaus. Eine Domaene mit besserem
    /// Wissen deklariert eine eigene Methode.
    QuotientClassCount,
}

impl RankMethod {
    pub const fn id(self) -> &'static str {
        match self {
            RankMethod::QuotientClassCount => "quotient_class_count",
        }
    }

    fn rank(self, _witness: &Matrix, _dependency: &Matrix, class_count: usize) -> usize {
        match self {
            RankMethod::QuotientClassCount => class_count,
        }
    }
}

/// Eingaben von M09 ueber P13, plus die Angaben, die das Profil verlangt
/// und die nicht aus den Projektionen folgen.
pub struct QuotientInputs<'a> {
    pub projections: &'a [FieldProjection],
    pub method: RankMethod,
    /// Vertrag 21.2 (Scopegebundener Konsens): "Ein Konsensobjekt MUSS
    /// seinen Scope als local, cluster, system oder external tragen."
    pub consensus_scope: DependencyProfileConsensusScopeKind,
}

/// `collect_sources`: die Vereinigung aller Quellen ueber alle Projektionen,
/// in stabiler Ordnung (BTreeSet), damit D und W reproduzierbar sind.
fn collect_sources(projections: &[FieldProjection]) -> BTreeSet<SourceRef> {
    projections
        .iter()
        .flat_map(|p| p.source_provenance.iter().cloned())
        .collect()
}

/// `build_dependency_matrix`: D[i][j] = 1, wenn die Quellen i und j
/// gemeinsam in mindestens einer Projektion auftreten (i == j zaehlt als
/// "tritt ueberhaupt auf").
fn build_dependency_matrix(
    projections: &[FieldProjection],
    sources: BTreeSet<SourceRef>,
) -> Matrix {
    build_square_matrix(sources, 0, |a, b| {
        let co_occurs = projections
            .iter()
            .any(|p| p.source_provenance.contains(a) && p.source_provenance.contains(b));
        i64::from(co_occurs)
    })
}

/// `build_witness_matrix`: W[i][j] = 1, wenn i und j zusaetzlich zur
/// Kodependenz gemeinsam in einer Projektion mit nichtleerem `visible`
/// auftreten - was eine Linse nachweislich nicht aufloest (`occluded`,
/// Regel 7.18), ist ein bezeugter Nichtbefund und traegt keine
/// Zeugenschaft, deshalb zaehlt hier nur `visible`.
fn build_witness_matrix(projections: &[FieldProjection], sources: BTreeSet<SourceRef>) -> Matrix {
    build_square_matrix(sources, 0, |a, b| {
        let jointly_witnessed = projections.iter().any(|p| {
            !p.visible.is_empty()
                && p.source_provenance.contains(a)
                && p.source_provenance.contains(b)
        });
        i64::from(jointly_witnessed)
    })
}

/// `partition_by_shared_source`: F / ~_D. Zwei Projektionen liegen in
/// derselben Klasse, wenn sie mindestens eine Quelle teilen - transitiv
/// fortgesetzt (Union-Find), weil ~_D eine Aequivalenzrelation ist.
///
/// Arbeitet direkt auf den Quellmengen je Projektion, nicht ueber die
/// (jetzt Quelle-x-Quelle-foermige) D-Matrix - siehe Modulkopf.
///
/// Genau hier greift Invariante 11.10: n Klone desselben Modells teilen ihre
/// Quelle, fallen in eine Klasse und ergeben eine Klasse, nicht n.
fn partition_by_shared_source(projections: &[FieldProjection]) -> Vec<Vec<ObjectId>> {
    let n = projections.len();
    let mut parent: Vec<usize> = (0..n).collect();

    fn find(parent: &mut [usize], mut x: usize) -> usize {
        while parent[x] != x {
            parent[x] = parent[parent[x]];
            x = parent[x];
        }
        x
    }

    let mut by_source: BTreeMap<&String, usize> = BTreeMap::new();
    for (i, p) in projections.iter().enumerate() {
        for s in &p.source_provenance {
            match by_source.get(&s.0) {
                None => {
                    by_source.insert(&s.0, i);
                }
                Some(&first) => {
                    let (a, b) = (find(&mut parent, first), find(&mut parent, i));
                    if a != b {
                        parent[a] = b;
                    }
                }
            }
        }
    }

    // Klassen in stabiler Ordnung: nach der kleinsten enthaltenen
    // Projektionsposition, damit zwei Laeufe dieselbe Reihenfolge liefern.
    let mut groups: BTreeMap<usize, Vec<ObjectId>> = BTreeMap::new();
    for (i, p) in projections.iter().enumerate() {
        let root = find(&mut parent, i);
        groups.entry(root).or_default().push(p.id);
    }
    let mut classes: Vec<(usize, Vec<ObjectId>)> = groups.into_iter().collect();
    classes.sort_by_key(|(root, _)| *root);
    classes.into_iter().map(|(_, members)| members).collect()
}

const PROFILE_SORT: SortId = SortId::Dependency;

fn compute_identity(draft: &DependencyProfile) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    object_id(PROFILE_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// M10, Pass C6: Algorithmus 11.9 in der Reihenfolge des Werkes.
///
/// `require r_eff <= count(classes)` ist als harte Wache implementiert:
/// eine Methode, die mehr Unabhaengigkeit behauptet, als der Quotient
/// hergibt, wird abgelehnt (PSK-E006, correlated_witness_overcount).
pub fn dependency_quotient(inputs: QuotientInputs<'_>) -> Result<DependencyProfile, PskError> {
    let sources = collect_sources(inputs.projections);
    let d = build_dependency_matrix(inputs.projections, sources.clone());
    let w = build_witness_matrix(inputs.projections, sources.clone());
    let classes = partition_by_shared_source(inputs.projections);

    // Strukturell garantiert durch build_square_matrix (Achse kommt aus
    // einem BTreeSet), hier zusaetzlich als expliziter Fail-Closed-Schritt
    // geprueft - derselbe Schutz, den ein von aussen ankommendes Matrix-
    // Objekt beim Deserialisieren durchlaufen muesste.
    check_canonical_axis_order(&d)?;
    check_canonical_axis_order(&w)?;

    let r_eff = inputs.method.rank(&w, &d, classes.len());
    if r_eff > classes.len() {
        return Err(PskError::CorrelatedWitnessOvercount);
    }

    let draft = DependencyProfile {
        schema: "psk.dependency-profile/1.0".to_string(),
        id: ObjectId::new(PROFILE_SORT, Digest::sha256(b"")), // Platzhalter
        sources: sources.into_iter().collect(),
        witness_matrix: w,
        dependency_matrix: d,
        effective_rank: Scaled {
            schema: "psk.scaled/1.0".to_string(),
            numerator: r_eff as i64,
            scale: 0,
        },
        method: RankMethodId(inputs.method.id().to_string()),
        quotient_classes: classes,
        consensus_scope: inputs.consensus_scope,
    };

    let id = compute_identity(&draft)?;
    Ok(DependencyProfile { id, ..draft })
}

/// Invariante 11.10, zweiter Satz: "Vor jeder Konsensbildung MUSS der
/// Abhaengigkeitsquotient berechnet sein." Diese Wache macht die Bedingung
/// pruefbar, statt sie nur zu behaupten: sie faellt fail-closed, wenn die
/// behauptete Zahl unabhaengiger Zeugen den effektiven Rang uebersteigt.
pub fn check_independent_witness_count(
    profile: &DependencyProfile,
    claimed_independent: i64,
) -> Result<(), PskError> {
    // effective_rank ist immer scale:0 (dependency_quotient setzt es so) -
    // ein Rang ist eine ganze Zahl. Ein Fremdobjekt mit scale != 0 waere
    // ein Formatverstoss, kein Vergleichsfall; fail-closed statt raten.
    if profile.effective_rank.scale != 0 {
        return Err(PskError::CanonicalizationFailed);
    }
    if claimed_independent > profile.effective_rank.numerator {
        Err(PskError::CorrelatedWitnessOvercount)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{IRNodeId, LensSpec, RealityStatus, ScopeSpec, TickId};

    fn projection(id: &str, sources: &[&str], visible: &[&str]) -> FieldProjection {
        FieldProjection {
            schema: "psk.field-projection/1.0".to_string(),
            id: ObjectId::new(SortId::Projection, Digest::sha256(id.as_bytes())),
            field_ref: ObjectId::new(SortId::FieldIdentity, Digest::sha256(b"field")),
            source_refs: vec![],
            lens_ref: LensSpec("lens/1".into()),
            scope: ScopeSpec("scan".into()),
            visible: visible.iter().map(|v| IRNodeId((*v).into())).collect(),
            occluded: vec![],
            distinctions: vec![],
            source_provenance: sources.iter().map(|s| SourceRef((*s).into())).collect(),
            reality_view: RealityStatus::Unknown,
            tick: TickId("t1".into()),
        }
    }

    fn run(projections: &[FieldProjection]) -> DependencyProfile {
        dependency_quotient(QuotientInputs {
            projections,
            method: RankMethod::QuotientClassCount,
            consensus_scope: DependencyProfileConsensusScopeKind::Local,
        })
        .unwrap()
    }

    #[test]
    fn cloning_one_model_into_n_facets_does_not_yield_rank_n() {
        // Invariante 11.10 woertlich: "Das Klonen desselben Modells in n
        // Facetten DARF NICHT r_eff = n erzeugen."
        let clones: Vec<_> = (0..5)
            .map(|i| projection(&format!("p{i}"), &["modell-A"], &["n1"]))
            .collect();
        let profile = run(&clones);
        assert_eq!(profile.quotient_classes.len(), 1);
        assert_eq!(profile.effective_rank.numerator, 1);
    }

    #[test]
    fn genuinely_separate_sources_stay_separate() {
        let ps = vec![
            projection("a", &["modell-A"], &["n1"]),
            projection("b", &["modell-B"], &["n2"]),
            projection("c", &["modell-C"], &["n3"]),
        ];
        let profile = run(&ps);
        assert_eq!(profile.quotient_classes.len(), 3);
        assert_eq!(profile.effective_rank.numerator, 3);
    }

    #[test]
    fn shared_source_merges_classes_transitively() {
        // a-b teilen "daten-1", b-c teilen "modell-X" => alle drei in einer
        // Klasse, weil ~_D transitiv ist.
        let ps = vec![
            projection("a", &["daten-1"], &["n1"]),
            projection("b", &["daten-1", "modell-X"], &["n2"]),
            projection("c", &["modell-X"], &["n3"]),
        ];
        let profile = run(&ps);
        assert_eq!(profile.quotient_classes.len(), 1);
        assert_eq!(profile.quotient_classes[0].len(), 3);
    }

    #[test]
    fn adding_a_correlated_facet_never_raises_the_rank() {
        // OBL-001, zweite verlangte Eigenschaft: Monotonie unter
        // Hinzufuegen korrelierter Facetten.
        let base = vec![
            projection("a", &["modell-A"], &["n1"]),
            projection("b", &["modell-B"], &["n2"]),
        ];
        let before = run(&base).effective_rank.numerator;

        let mut grown = base.clone();
        grown.push(projection("c", &["modell-A"], &["n3"])); // korreliert mit a
        let after = run(&grown).effective_rank.numerator;

        assert!(
            after <= before,
            "eine korrelierte Facette DARF den Rang nicht erhoehen ({before} -> {after})"
        );
    }

    #[test]
    fn rank_never_exceeds_class_count() {
        // OBL-001, erste verlangte Eigenschaft: RankEff(W,D) <= |F / ~_D|.
        let ps = vec![
            projection("a", &["s1"], &["n1"]),
            projection("b", &["s2"], &["n2"]),
            projection("c", &["s2"], &["n3"]),
        ];
        let profile = run(&ps);
        assert!(profile.effective_rank.numerator <= profile.quotient_classes.len() as i64);
    }

    #[test]
    fn claiming_more_independent_witnesses_than_r_eff_fails_closed() {
        let clones: Vec<_> = (0..4)
            .map(|i| projection(&format!("p{i}"), &["eine-quelle"], &["n1"]))
            .collect();
        let profile = run(&clones);
        assert_eq!(check_independent_witness_count(&profile, 1), Ok(()));
        assert_eq!(
            check_independent_witness_count(&profile, 4),
            Err(PskError::CorrelatedWitnessOvercount)
        );
    }

    #[test]
    fn occluded_nodes_do_not_witness() {
        // Regel 7.18: was eine Linse nicht aufloest, ist ein bezeugter
        // Nichtbefund - W zaehlt nur `visible`.
        let mut p = projection("a", &["s1"], &["n1"]);
        p.occluded = vec![IRNodeId("n2".into()), IRNodeId("n3".into())];
        let profile = run(&[p]);
        assert_eq!(profile.witness_matrix.values, vec![vec![1]]);

        let mut q = projection("b", &["s1"], &[]);
        q.occluded = vec![IRNodeId("n1".into())];
        let profile2 = run(&[q]);
        assert_eq!(
            profile2.witness_matrix.values,
            vec![vec![0]],
            "leeres visible darf nicht als Zeugenschaft zaehlen"
        );
    }

    #[test]
    fn matrices_use_the_canonical_ascending_axis_order() {
        // Regel 7.28: axis MUSS aufsteigend nach kanonischer Form von
        // SourceRef sortiert sein, unabhaengig von der Eingabereihenfolge.
        let a = run(&[projection("a", &["s2", "s1"], &["n2", "n1"])]);
        let b = run(&[projection("a", &["s1", "s2"], &["n1", "n2"])]);
        assert_eq!(a.dependency_matrix, b.dependency_matrix);
        assert_eq!(a.witness_matrix, b.witness_matrix);
        assert_eq!(a.id, b.id);
        assert_eq!(
            a.dependency_matrix.axis,
            vec![SourceRef("s1".into()), SourceRef("s2".into())]
        );
        check_canonical_axis_order(&a.dependency_matrix).unwrap();
        check_canonical_axis_order(&a.witness_matrix).unwrap();
    }

    #[test]
    fn a_matrix_with_unsorted_or_repeated_axis_is_rejected() {
        // Regel 7.28, woertlich: "eine Matrix mit abweichenden Achsen ist
        // unzulaessig [...] Verstoss erzeugt PSK-E102."
        let unsorted = Matrix {
            schema: "psk.matrix/1.0".into(),
            axis: vec![SourceRef("b".into()), SourceRef("a".into())],
            scale: 0,
            values: vec![vec![1, 0], vec![0, 1]],
        };
        assert_eq!(
            check_canonical_axis_order(&unsorted),
            Err(PskError::CanonicalizationFailed)
        );

        let non_square = Matrix {
            schema: "psk.matrix/1.0".into(),
            axis: vec![SourceRef("a".into()), SourceRef("b".into())],
            scale: 0,
            values: vec![vec![1, 0, 0], vec![0, 1, 0]],
        };
        assert_eq!(
            check_canonical_axis_order(&non_square),
            Err(PskError::CanonicalizationFailed)
        );
    }

    #[test]
    fn dependency_relates_co_occurring_sources_even_without_a_witness() {
        let p = projection("a", &["s1", "s2"], &[]); // nichts aufgeloest
        let profile = run(&[p]);
        assert_eq!(
            profile.dependency_matrix.values,
            vec![vec![1, 1], vec![1, 1]]
        );
        assert_eq!(
            profile.witness_matrix.values,
            vec![vec![0, 0], vec![0, 0]],
            "Kodependenz ohne Zeugenschaft darf W nicht setzen"
        );
    }

    #[test]
    fn empty_input_yields_empty_profile_not_a_panic() {
        let profile = run(&[]);
        assert!(profile.quotient_classes.is_empty());
        assert_eq!(profile.effective_rank.numerator, 0);
        assert!(profile.dependency_matrix.axis.is_empty());
        assert!(profile.dependency_matrix.values.is_empty());
    }

    #[test]
    fn declared_method_is_recorded_in_the_profile() {
        // OBL-001: "Die gewaehlte Methode ist als MethodPlugin zu
        // deklarieren." Das Profil traegt sie mit.
        let profile = run(&[projection("a", &["s1"], &["n1"])]);
        assert_eq!(profile.method.0, "quotient_class_count");
    }
}
