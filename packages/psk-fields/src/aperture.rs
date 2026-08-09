//! QPM-1, Aperturbuchfuehrung: QPM Axiom 3.1 (Kein stiller Ausschluss).
//!
//! ## Was das Werk sagt, woertlich
//!
//! "Jede von einer Apertur nicht durchgelassene Masse erscheint in GENAU
//! EINER der vier Klassen {sichtbarer Koerper, Schatten, Gegenhorizont,
//! Residuum}. Ein unbeobachteter Anteil DARF NICHT als abwesend gewertet
//! werden (`unobserved_is_absent = false`). Ein still fallengelassener
//! Ausschluss ist FAIL (`dropped-occlusion`)."
//!
//! "Genau eine" heisst Partition: vollstaendig UND disjunkt. Das ist
//! keine Auswahl unter vier Moeglichkeiten, sondern eine Buchfuehrung,
//! die aufgehen muss.
//!
//! ## Warum dieses Modul nur PRUEFT und nicht KLASSIFIZIERT
//!
//! Die Zuordnung selbst kann der Kern nicht leisten, und zwar aus einem
//! benennbaren Grund je Klasse:
//!
//! - `Schatten` setzt eine APERTUR voraus - "nicht durchgelassen" ist
//!   ohne Durchlassoperator bedeutungslos. QPM fuehrt dafuer
//!   `ApertureBank` ("versionierte Menge lokaler Durchlassoperatoren"),
//!   gibt ihr aber KEINE Struktur (nachgezaehlt: das Werk hat 33
//!   Struktur-Bloecke, keiner heisst ApertureBank).
//! - `Gegenhorizont` setzt `CounterHorizon` voraus (QPM-CTH, S-RES,
//!   Eigner M24) - ebenfalls ohne Struktur im Werk.
//!
//! Beides waere hier zu erfinden. Stattdessen kommt die Klassifikation
//! vom Aufrufer, und dieses Modul prueft, dass sie eine Partition IST -
//! dasselbe Muster wie Regel 10.9 bei den Kantenbedingungen: der Kern
//! berechnet die Praedikate nicht, er prueft ihre Form.
//!
//! ## Was `route_lens` beitraegt - und was nicht
//!
//! `route_lens` teilt die Kandidaten in `visible`/`occluded`. Das ist
//! EINE der vier Klassen plus ein Rest: `visible` ist der sichtbare
//! Koerper, `occluded` ist ein Klumpen, den QPM Axiom 3.1 gerade weiter
//! aufteilen will. Die Zweiteilung auf vier hochzureden waere die
//! Erfindung, vor der gewarnt wurde.
//!
//! `classify_absence` (M12) beantwortet eine ANDERE Frage: ob EIN
//! Ausbleiben Evidenz ist (Invariante 11.12, vier Tracebindungen). Seine
//! zwei Werte sind keine zwei der vier Klassen, sondern eine
//! orthogonale Achse - ein Schatten kann bezeugt oder unbezeugt sein,
//! und beides bleibt ein Schatten.

use std::collections::BTreeMap;

use psk_types::objects::IRNodeId;
use psk_types::PskError;

/// Die vier Klassen aus QPM Axiom 3.1, geschlossen. Kein `Other`: eine
/// fuenfte Klasse waere genau der stille Ausschluss, den das Axiom
/// verbietet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MassClass {
    /// Durchgelassen und beobachtet.
    VisibleBody,
    /// Von der Apertur nicht durchgelassen, aber als Fehlen bekannt.
    Shadow,
    /// Abgewiesene Deutung, Nullmodell, Pathologie (QPM-CTH).
    CounterHorizon,
    /// Als ResidueRecord gefuehrt.
    Residue,
}

impl MassClass {
    /// Alle vier - fuer erschoepfende Berichte und Tests.
    pub const ALL: [MassClass; 4] = [
        MassClass::VisibleBody,
        MassClass::Shadow,
        MassClass::CounterHorizon,
        MassClass::Residue,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            MassClass::VisibleBody => "sichtbarer Koerper",
            MassClass::Shadow => "Schatten",
            MassClass::CounterHorizon => "Gegenhorizont",
            MassClass::Residue => "Residuum",
        }
    }
}

/// Woran eine Aperturbuchfuehrung scheitert. Jede Variante ist ein
/// eigener Verstoss gegen QPM Axiom 3.1, nicht eine Abstufung derselben
/// Sache - deshalb tragen sie die betroffenen Kandidaten mit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountingFailure {
    /// Unvollstaendig: Masse ging ein, erscheint aber in keiner Klasse.
    /// Genau das ist "dropped-occlusion".
    Dropped(Vec<IRNodeId>),
    /// Nicht disjunkt: derselbe Kandidat in mehr als einer Klasse.
    /// "Genau eine" ist verletzt, auch wenn nichts fehlt.
    DoubleCounted(Vec<IRNodeId>),
    /// Erfunden: klassifiziert wurde, was gar nicht einging. Die
    /// Buchfuehrung geht sonst formal auf und behauptet doch mehr, als
    /// beobachtet wurde.
    Unaccounted(Vec<IRNodeId>),
}

/// Das Ergebnis einer aufgegangenen Buchfuehrung: die Klasse je
/// Kandidat plus die Zaehlung je Klasse.
///
/// Die Zaehlung wird ABGELEITET, nicht mitgegeben - dieselbe Doktrin wie
/// beim Deckungsvektor und bei den vakuum geschlossenen Zellen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApertureAccount {
    by_node: BTreeMap<IRNodeId, MassClass>,
}

impl ApertureAccount {
    pub fn class_of(&self, node: &IRNodeId) -> Option<MassClass> {
        self.by_node.get(node).copied()
    }

    /// Zaehlung je Klasse, alle vier immer genannt - eine Klasse mit
    /// Null ist eine Aussage, kein Weglassen.
    pub fn census(&self) -> BTreeMap<MassClass, usize> {
        let mut out: BTreeMap<MassClass, usize> = MassClass::ALL.iter().map(|c| (*c, 0)).collect();
        for c in self.by_node.values() {
            *out.get_mut(c).expect("MassClass ist geschlossen") += 1;
        }
        out
    }

    /// `unobserved_is_absent = false`: was nicht sichtbarer Koerper ist,
    /// ist NICHT abwesend, sondern anderswo verbucht. Diese Zahl ist die
    /// Masse, die ein naiver Leser fuer "nicht da" halten wuerde.
    pub fn not_passed(&self) -> usize {
        self.by_node
            .values()
            .filter(|c| **c != MassClass::VisibleBody)
            .count()
    }

    pub fn total(&self) -> usize {
        self.by_node.len()
    }
}

/// QPM Axiom 3.1: prueft, dass `classification` ueber `incoming` eine
/// Partition in die vier Klassen ist.
///
/// `incoming` ist die eingegangene Masse (bei `route_lens`: die
/// Kandidatenmenge). `classification` ist die vom Aufrufer gelieferte
/// Zuordnung - der Kern erfindet sie nicht, siehe Modulkopf.
///
/// Doppelnennungen faengt schon die Eingabeform ab (eine Abbildung
/// Knoten -> Klasse kann nicht zwei Klassen tragen); geprueft wird
/// deshalb, was eine Abbildung offenlaesst: fehlende und ueberzaehlige
/// Eintraege. Wer die Klassifikation als Liste von (Knoten, Klasse)
/// baut, findet den Disjunktheitsbruch in `account_from_pairs`.
pub fn account_apertures(
    incoming: &[IRNodeId],
    classification: &BTreeMap<IRNodeId, MassClass>,
) -> Result<ApertureAccount, AccountingFailure> {
    let dropped: Vec<IRNodeId> = incoming
        .iter()
        .filter(|n| !classification.contains_key(*n))
        .cloned()
        .collect();
    if !dropped.is_empty() {
        return Err(AccountingFailure::Dropped(dropped));
    }
    let unaccounted: Vec<IRNodeId> = classification
        .keys()
        .filter(|n| !incoming.contains(*n))
        .cloned()
        .collect();
    if !unaccounted.is_empty() {
        return Err(AccountingFailure::Unaccounted(unaccounted));
    }
    Ok(ApertureAccount {
        by_node: classification.clone(),
    })
}

/// Wie `account_apertures`, aber ueber einer LISTE von Paaren - die
/// Form, in der eine Domaene ihre Klassifikation natuerlich liefert.
/// Hier ist Disjunktheit eine echte Pruefung, keine Typeigenschaft.
pub fn account_from_pairs(
    incoming: &[IRNodeId],
    pairs: &[(IRNodeId, MassClass)],
) -> Result<ApertureAccount, AccountingFailure> {
    let mut map: BTreeMap<IRNodeId, MassClass> = BTreeMap::new();
    let mut doubled = Vec::new();
    for (node, class) in pairs {
        match map.get(node) {
            Some(existing) if existing != class => doubled.push(node.clone()),
            Some(_) => doubled.push(node.clone()),
            None => {
                map.insert(node.clone(), *class);
            }
        }
    }
    if !doubled.is_empty() {
        doubled.sort();
        doubled.dedup();
        return Err(AccountingFailure::DoubleCounted(doubled));
    }
    account_apertures(incoming, &map)
}

/// Der blockierende Negativtest `dropped-occlusion` als Fehlerwert des
/// Kerns. PSK-E013 ist die Feldfehlerdomaene (M08/M09).
pub fn as_psk_error(failure: &AccountingFailure) -> PskError {
    match failure {
        AccountingFailure::Dropped(_)
        | AccountingFailure::DoubleCounted(_)
        | AccountingFailure::Unaccounted(_) => PskError::FieldProjectionUndefined,
    }
}

/// Was `route_lens` zur Buchfuehrung BEITRAEGT: seine `visible`-Liste
/// ist der sichtbare Koerper, belegt durch die Aufloesung selbst.
///
/// Mehr kann es nicht beitragen, und das ist keine Luecke dieses Codes,
/// sondern der Stand des Werks: `occluded` weiter aufzuteilen verlangt
/// die Apertur (Schatten) und den Gegenhorizont, und beide fuehrt QPM
/// ohne Struktur. Wer diese Teilzuordnung allein an
/// `account_apertures` gibt, bekommt folgerichtig `Dropped` - der
/// blockierende Negativtest `dropped-occlusion` feuert, statt dass eine
/// Zweiteilung als Vierteilung durchginge.
pub fn visible_bodies(
    projection: &psk_types::objects::FieldProjection,
) -> Vec<(IRNodeId, MassClass)> {
    projection
        .visible
        .iter()
        .map(|n| (n.clone(), MassClass::VisibleBody))
        .collect()
}

/// Die eingegangene Masse einer Projektion: sichtbar plus verdeckt.
/// Beide Listen zusammen sind die Kandidatenmenge, ueber der QPM Axiom 3.1
/// aufgehen muss.
pub fn incoming_mass(projection: &psk_types::objects::FieldProjection) -> Vec<IRNodeId> {
    projection
        .visible
        .iter()
        .chain(projection.occluded.iter())
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> IRNodeId {
        IRNodeId(s.to_string())
    }

    fn incoming() -> Vec<IRNodeId> {
        vec![n("a"), n("b"), n("c"), n("d")]
    }

    #[test]
    fn a_complete_partition_accounts_and_the_census_names_all_four_classes() {
        let account = account_from_pairs(
            &incoming(),
            &[
                (n("a"), MassClass::VisibleBody),
                (n("b"), MassClass::Shadow),
                (n("c"), MassClass::CounterHorizon),
                (n("d"), MassClass::Residue),
            ],
        )
        .expect("Partition geht auf");
        assert_eq!(account.total(), 4);
        // unobserved_is_absent = false: drei sind nicht durchgelassen -
        // und keine davon ist deshalb abwesend.
        assert_eq!(account.not_passed(), 3);
        let census = account.census();
        assert_eq!(census.len(), 4, "alle vier Klassen werden genannt");
        assert!(census.values().all(|v| *v == 1));
    }

    #[test]
    fn an_empty_class_is_reported_as_zero_not_omitted() {
        let account = account_from_pairs(
            &[n("a"), n("b")],
            &[
                (n("a"), MassClass::VisibleBody),
                (n("b"), MassClass::Shadow),
            ],
        )
        .expect("Partition geht auf");
        let census = account.census();
        assert_eq!(census[&MassClass::CounterHorizon], 0);
        assert_eq!(census[&MassClass::Residue], 0);
        assert_eq!(census.len(), 4);
    }

    #[test]
    fn a_silently_dropped_exclusion_fails() {
        // "d" ging ein, erscheint in keiner Klasse - genau
        // "dropped-occlusion", blockierender Negativtest.
        let err = account_from_pairs(
            &incoming(),
            &[
                (n("a"), MassClass::VisibleBody),
                (n("b"), MassClass::Shadow),
                (n("c"), MassClass::Residue),
            ],
        )
        .expect_err("unvollstaendige Buchfuehrung MUSS scheitern");
        assert_eq!(err, AccountingFailure::Dropped(vec![n("d")]));
    }

    #[test]
    fn double_counting_breaks_the_partition_even_when_nothing_is_missing() {
        // "genau eine" ist verletzt, obwohl die Masse vollstaendig ist.
        let err = account_from_pairs(
            &[n("a"), n("b")],
            &[
                (n("a"), MassClass::VisibleBody),
                (n("a"), MassClass::Shadow),
                (n("b"), MassClass::Residue),
            ],
        )
        .expect_err("Doppelzaehlung MUSS scheitern");
        assert_eq!(err, AccountingFailure::DoubleCounted(vec![n("a")]));
    }

    #[test]
    fn classifying_mass_that_never_entered_fails() {
        let err = account_from_pairs(
            &[n("a")],
            &[
                (n("a"), MassClass::VisibleBody),
                (n("z"), MassClass::CounterHorizon),
            ],
        )
        .expect_err("erfundene Masse MUSS scheitern");
        assert_eq!(err, AccountingFailure::Unaccounted(vec![n("z")]));
    }

    /// Der Befund als Test: was `route_lens` liefert, ist EINE Klasse,
    /// und QPM Axiom 3.1 sagt das auch - der blockierende Negativtest
    /// `dropped-occlusion` feuert, statt die Zweiteilung als
    /// Vierteilung durchzuwinken.
    #[test]
    fn route_lens_alone_cannot_satisfy_axiom_3_1() {
        use psk_types::objects::{FieldProjection, RealityStatus, ScopeSpec, SourceRef, TickId};
        use psk_types::{Digest, ObjectId};
        let projection = FieldProjection {
            schema: "psk.field-projection/1.0".to_string(),
            id: ObjectId::new(psk_types::objects::SortId::Projection, Digest::sha256(b"p")),
            field_ref: ObjectId::new(
                psk_types::objects::SortId::FieldIdentity,
                Digest::sha256(b"f"),
            ),
            source_refs: vec![],
            lens_ref: psk_types::objects::LensSpec("lens".into()),
            scope: ScopeSpec("s".into()),
            visible: vec![n("a")],
            occluded: vec![n("b"), n("c")],
            distinctions: vec![],
            source_provenance: vec![SourceRef("src".into())],
            reality_view: RealityStatus::Coherent,
            tick: TickId("t0".into()),
        };

        let mass = incoming_mass(&projection);
        assert_eq!(mass.len(), 3, "sichtbar plus verdeckt ist die Masse");

        // Nur der sichtbare Koerper laesst sich aus der Projektion
        // belegen - die beiden verdeckten fallen durch.
        let err = account_from_pairs(&mass, &visible_bodies(&projection))
            .expect_err("die Zweiteilung erfuellt QPM Axiom 3.1 NICHT");
        assert_eq!(err, AccountingFailure::Dropped(vec![n("b"), n("c")]));

        // Erst mit der domaenengelieferten Zuordnung der beiden geht
        // die Buchfuehrung auf.
        let mut full = visible_bodies(&projection);
        full.push((n("b"), MassClass::Shadow));
        full.push((n("c"), MassClass::CounterHorizon));
        let account = account_from_pairs(&mass, &full).expect("jetzt vollstaendig");
        assert_eq!(account.not_passed(), 2);
    }

    #[test]
    fn the_class_set_is_closed_at_four() {
        assert_eq!(MassClass::ALL.len(), 4);
        let ids: Vec<&str> = MassClass::ALL.iter().map(|c| c.id()).collect();
        assert_eq!(
            ids,
            [
                "sichtbarer Koerper",
                "Schatten",
                "Gegenhorizont",
                "Residuum"
            ]
        );
    }
}
