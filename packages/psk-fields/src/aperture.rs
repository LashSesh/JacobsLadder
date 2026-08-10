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
//! ## Jede Klasse hat genau einen Erzeuger
//!
//! QPM Regel 3.8 (Die vier Massenklassen und ihre Erzeuger) macht die
//! Zuordnung ableitbar - bis v1.0.2 musste sie noch vom Aufrufer
//! kommen, weil ApertureBank und CounterHorizon keine Struktur hatten:
//!
//! | Klasse            | Erzeuger      | Beleg                        |
//! |-------------------|---------------|------------------------------|
//! | sichtbarer Koerper| M09           | Linsenroutung, `visible`     |
//! | Schatten          | ApertureBank  | Apertur plus pass_predicate  |
//! | Gegenhorizont     | CounterHorizon| Nullmodell/begr. Ausschluss  |
//! | Residuum          | M19           | ResidueRecord                |
//!
//! Die Klasse wird deshalb ABGELEITET: `account_mass` fragt die vier
//! Erzeuger, statt eine Zuordnung entgegenzunehmen. Was kein Erzeuger
//! hervorbringt, ist `dropped-occlusion` - und ein Schatten ohne
//! benannte Apertur laesst sich gar nicht erst bauen (QPM Regel 3.5:
//! "Ein Schatten ohne benannte Apertur ist ein stiller Ausschluss"),
//! weil `ShadowRecord` die Apertur als Feld verlangt.
//!
//! `account_from_pairs` bleibt als untere Schicht: sie prueft die
//! Partitionseigenschaft selbst und kennt keine Erzeuger.
//!
//! ## Was `route_lens` beitraegt
//!
//! `route_lens` teilt die Kandidaten in `visible`/`occluded`. `visible`
//! IST der sichtbare Koerper - eine der vier Klassen, mit M09 als
//! Erzeuger. `occluded` ist kein Erzeugnis, sondern die Frage: welche
//! der drei uebrigen Klassen jeden dieser Kandidaten traegt, sagen erst
//! ApertureBank, CounterHorizon und der Residuenledger.
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

/// Ein Schatten mit seinem Erzeuger (QPM Regel 3.5): "mit Verweis auf
/// die Apertur, die es zurueckhielt, und auf ihr pass_predicate".
///
/// Beide Verweise sind PFLICHTFELDER, nicht Optionen - "ein Schatten
/// ohne benannte Apertur ist ein stiller Ausschluss". Was die Regel
/// verbietet, laesst sich hier nicht bauen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShadowRecord {
    pub node: IRNodeId,
    /// Die Apertur, die zurueckhielt.
    pub aperture: crate::ApertureId,
    /// Ihr pass_predicate - domaenengeliefert, mit Herkunftspflicht.
    pub pass_predicate: psk_types::objects::PredicateExpr,
}

/// Die vier Erzeuger aus QPM Regel 3.8, als Daten.
///
/// Bewusst keine Modulverweise: M08 (dieses Paket) und M24
/// (psk-adversarial) liegen beide auf L4, und eine Paketkante zwischen
/// ihnen waere eine Abhaengigkeit, die kein Port deckt. Der Aufrufer
/// reicht herein, was die Erzeuger hervorgebracht haben - dasselbe
/// Muster wie `ClosureContext` bei der Zellclosure.
#[derive(Debug, Clone)]
pub struct MassProducers<'a> {
    /// M09: `FieldProjection.visible` aus der Linsenroutung.
    pub visible: &'a [IRNodeId],
    /// ApertureBank: je zurueckgehaltenem Knoten seine Apertur.
    pub shadows: &'a [ShadowRecord],
    /// CounterHorizon (M24): die getragene Masse
    /// (`CounterHorizon::carried()`, auf Knotenkennungen aufgeloest -
    /// der Gegenhorizont fuehrt ObjectIds, die Masse einer Projektion
    /// IRNodeIds, und diese Aufloesung ist Sache des Aufrufers).
    pub counter_horizon: &'a [IRNodeId],
    /// M19: was als ResidueRecord gefuehrt wird.
    pub residues: &'a [IRNodeId],
}

impl MassProducers<'_> {
    /// Die von den Erzeugern abgeleitete Zuordnung, als Paarliste - die
    /// Form, in der `account_from_pairs` die Partition prueft.
    fn classification(&self) -> Vec<(IRNodeId, MassClass)> {
        let mut pairs = Vec::new();
        pairs.extend(
            self.visible
                .iter()
                .map(|n| (n.clone(), MassClass::VisibleBody)),
        );
        pairs.extend(
            self.shadows
                .iter()
                .map(|s| (s.node.clone(), MassClass::Shadow)),
        );
        pairs.extend(
            self.counter_horizon
                .iter()
                .map(|n| (n.clone(), MassClass::CounterHorizon)),
        );
        pairs.extend(
            self.residues
                .iter()
                .map(|n| (n.clone(), MassClass::Residue)),
        );
        pairs
    }

    /// Welche Apertur einen Knoten zurueckhielt - der Beleg, den QPM
    /// QPM Regel 3.5 fuer jeden Schatten verlangt.
    pub fn shadow_of(&self, node: &IRNodeId) -> Option<&ShadowRecord> {
        self.shadows.iter().find(|s| s.node == *node)
    }
}

/// QPM Axiom 3.1 gegen die vier Erzeuger aus QPM Regel 3.8.
///
/// Die Klasse wird ABGELEITET, nicht entgegengenommen. Was kein
/// Erzeuger hervorbringt, faellt als `Dropped` auf - der blockierende
/// Negativtest `dropped-occlusion`. Was zwei Erzeuger beanspruchen,
/// faellt als `DoubleCounted` auf: "ist sie zweien zugeordnet, so ist
/// die Buchfuehrung verletzt. Beides ist blockierend."
pub fn account_mass(
    incoming: &[IRNodeId],
    producers: &MassProducers,
) -> Result<ApertureAccount, AccountingFailure> {
    account_from_pairs(incoming, &producers.classification())
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

    /// Die angekuendigte Probe: mit einer REALEN ApertureBank muss der
    /// Dropped-Befund kippen - nicht weil der Test weicher wuerde,
    /// sondern weil der Schatten jetzt einen benannten Erzeuger hat.
    ///
    /// Derselbe Aufbau wie `route_lens_alone_cannot_satisfy_axiom_3_1`,
    /// EIN Unterschied: die Apertur existiert.
    #[test]
    fn a_real_aperture_bank_turns_the_dropped_finding_into_shadows() {
        use crate::{Aperture, ApertureBank, ApertureId, ChannelId, CoverageSpec};
        use psk_types::objects::{PredicateExpr, SemVer, SortId};
        use psk_types::{Digest, ObjectId, TraceRef};

        let bank = ApertureBank {
            schema: "psk.qpm.aperture-bank/1.0".to_string(),
            id: ObjectId::new(SortId::FieldIdentity, Digest::sha256(b"bank")),
            version: SemVer("1.0.0".into()),
            apertures: vec![Aperture {
                id: ApertureId("AP-topology".into()),
                channel_ref: ChannelId("topology".into()),
                // Aussondernd - eine Apertur, die alles durchlaesst,
                // ist keine (QPM Regel 3.5).
                pass_predicate: PredicateExpr("knoten liegt in m13:0".into()),
                declared_coverage: CoverageSpec("m13:0".into()),
            }],
            trace_ref: TraceRef(Digest::sha256(b"t")),
        };
        bank.check_predicates().expect("Praedikat sondert aus");
        let ap = &bank.apertures[0];

        let mass = vec![n("a"), n("b"), n("c")];
        // M09 laesst "a" durch; die Apertur haelt "b" und "c" zurueck.
        let shadows = vec![
            ShadowRecord {
                node: n("b"),
                aperture: ap.id.clone(),
                pass_predicate: ap.pass_predicate.clone(),
            },
            ShadowRecord {
                node: n("c"),
                aperture: ap.id.clone(),
                pass_predicate: ap.pass_predicate.clone(),
            },
        ];
        let producers = MassProducers {
            visible: &[n("a")],
            shadows: &shadows,
            counter_horizon: &[],
            residues: &[],
        };

        // GEKIPPT: die Buchfuehrung geht auf.
        let account = account_mass(&mass, &producers).expect("mit realer Apertur geht sie auf");
        assert_eq!(account.class_of(&n("b")), Some(MassClass::Shadow));
        assert_eq!(account.class_of(&n("c")), Some(MassClass::Shadow));
        assert_eq!(account.not_passed(), 2);
        // Und der von QPM Regel 3.5 verlangte Beleg steht bereit.
        let s = producers.shadow_of(&n("b")).expect("Schatten hat Erzeuger");
        assert_eq!(s.aperture, ap.id);
        assert_eq!(s.pass_predicate, ap.pass_predicate);

        // Gegenprobe, damit das Kippen nicht Nachgeben ist: nimmt man
        // der Bank EINEN Schatten weg, faellt genau dieser Knoten
        // wieder als dropped-occlusion auf.
        let thin = MassProducers {
            shadows: &shadows[..1],
            ..producers.clone()
        };
        assert_eq!(
            account_mass(&mass, &thin).expect_err("ohne Erzeuger kein Durchwinken"),
            AccountingFailure::Dropped(vec![n("c")])
        );
    }

    /// Zwei Erzeuger, ein Knoten: die Buchfuehrung ist verletzt, auch
    /// wenn nichts fehlt ("ist sie zweien zugeordnet ... blockierend").
    #[test]
    fn two_producers_claiming_the_same_mass_break_the_books() {
        use psk_types::objects::PredicateExpr;
        let shadows = vec![ShadowRecord {
            node: n("a"),
            aperture: crate::ApertureId("AP".into()),
            pass_predicate: PredicateExpr("p".into()),
        }];
        let producers = MassProducers {
            visible: &[n("a")], // M09 sagt sichtbar ...
            shadows: &shadows,  // ... die Apertur sagt Schatten
            counter_horizon: &[],
            residues: &[],
        };
        assert_eq!(
            account_mass(&[n("a")], &producers).expect_err("Doppelanspruch faellt auf"),
            AccountingFailure::DoubleCounted(vec![n("a")])
        );
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
