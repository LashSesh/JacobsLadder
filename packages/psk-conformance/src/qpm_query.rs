//! QPM-6, Schicht 2: die Katalogabfrage in ihrer spezifizierten
//! Leerform und die Entscheidung der Ergebnisordnung darueber.
//!
//! QPM Offene Implementierungsverpflichtung 8.7 (QPM-OBL-002: Komponentenwörterbuch der Chromatographie):
//! "Ohne registriertes Wörterbuch bleibt QueryVersionedTemplateCatalog
//! strukturell leer und jeder Lauf endet in UNKNOWN, nicht in FAIL."
//! Die Leerform ist damit woertlich spezifiziert und woertlich baubar.
//! Der Zweck dieses Moduls: die UNKNOWN-Deckelung wird am
//! ABFRAGEERGEBNIS gemessen statt an der Scope-Politik vorweggenommen -
//! vorher stand das Verdikt fest, bevor die Pipelinestufe existierte,
//! die es begruendet.
//!
//! QPM Regel 3.17 (Zwei Weisen, UNKNOWN zu sein) unterscheidet die
//! beiden Lagen, die hier als Varianten getrennt sind und nicht
//! zusammenfallen duerfen:
//!
//! 1. Katalogfremd: "die Messung war gültig, der Katalog wurde
//!    abgefragt, und kein Eintrag passte." Erzeugt einen UnknownRecord,
//!    dessen catalog_digest den Stand nennt.
//! 2. Ohne Katalog: "es ist kein Wörterbuch registriert, also fand
//!    keine Abfrage statt." Erzeugt KEINEN UnknownRecord, sondern eine
//!    Scope-Deckelung. "Ein UnknownRecord ohne registrierten Katalog
//!    ist ein Konformitätsdefekt — er behauptete eine Abfrage, die
//!    nicht stattfand."
//!
//! Deshalb gibt es hier weiterhin KEINEN UnknownRecord-Typ: der
//! Referenzlauf steht in Lage 2, und die Struktur, die Lage 1
//! dokumentiert, ist mitsamt ihrem Pflichtfeld catalog_digest
//! kataloggebunden. Sie zu bauen, ohne dass eine Abfrage stattfinden
//! kann, hiesse das Artefakt vor seiner Bedingung zu erfinden.

use psk_fields::PanopticScope;
use psk_types::objects::Scaled;
use psk_types::Digest;

use crate::qpm_run::IdentityVerdict;

/// Klassenkennung eines Katalogeintrags - die Form, in der
/// QPM Struktur 3.16 (UnknownRecord) und QPM Struktur 3.15 (TemplateClass)
/// Klassen nennen (`class: ClassId`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassId(pub String);

/// Ein Eintrag der Rangfolge, Form aus QPM Struktur 3.16 (UnknownRecord),
/// `nearest_candidates: [{class: ClassId, distance: Scaled}]` -
/// "Rangfolge, NICHT Zuordnung". Die Distanz ist `Scaled`, nicht
/// Fliesskomma, aus demselben Grund wie im Atlas.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    pub class: ClassId,
    pub distance: Scaled,
}

/// Das Ergebnis der Pipelinestufe QueryVersionedTemplateCatalog
/// (QPM Algorithmus 7.1 (Normative Pipeline)) - die beiden Lagen aus
/// QPM Regel 3.17 (Zwei Weisen, UNKNOWN zu sein) als getrennte
/// Varianten, damit sie der Typ auseinanderhaelt und nicht die Disziplin.
#[derive(Debug, Clone, PartialEq)]
pub enum CatalogQuery {
    /// Lage 2: kein Woerterbuch registriert - keine Abfrage fand statt.
    /// Der Grund benennt den Weg dorthin (fehlender Verweis oder
    /// Verweis ohne Registrierung).
    NotQueried { reason: String },
    /// Lage 1: die Abfrage fand statt, gegen einen benannten Stand.
    /// Heute konstruiert nichts diese Variante - sie zu erreichen
    /// setzt ein registriertes, domaenengeliefertes Woerterbuch voraus
    /// (QPM-OBL-002). Sie steht hier, weil die Ergebnisordnung sie
    /// nennt, mit demselben Stand wie KNOWN und AMBIGUOUS: definiert,
    /// kataloggebunden, ohne Erzeuger.
    Queried {
        /// "gegen welchen Katalogstand" - das Pflichtfeld, das den
        /// UnknownRecord der Lage 1 tragfaehig macht.
        catalog_digest: Digest,
        /// Rangfolge, nicht Zuordnung.
        candidates: Vec<Candidate>,
    },
}

/// QueryVersionedTemplateCatalog in der Leerform.
///
/// QPM-OBL-002 macht das Woerterbuch domaenengeliefert; registriert ist
/// keines - das Domaenenprofil erklaert das ausdruecklich
/// (`catalog_ref: null`, "nicht aus Nachlaessigkeit"). Beide Wege in
/// die Leerform sind benannt, denn sie sind verschieden: ein Scope ohne
/// Verweis und ein Verweis, hinter dem keine Registrierung steht.
pub fn query_versioned_template_catalog(scope: &PanopticScope) -> CatalogQuery {
    match &scope.policies.catalog_ref {
        None => CatalogQuery::NotQueried {
            reason: "kein catalog_ref im Scope - keine Abfrage fand statt; \
                     QPM-OBL-002 deckelt jeden Lauf auf UNKNOWN, nicht FAIL"
                .to_string(),
        },
        Some(r) => CatalogQuery::NotQueried {
            reason: format!(
                "catalog_ref '{}' verweist, aber ein registriertes \
                 Woerterbuch gibt es nicht (QPM-OBL-002) - keine Abfrage \
                 fand statt",
                r.0
            ),
        },
    }
}

/// ExecuteOpenSetGate-Seite der Ergebnisordnung (QPM Struktur 4.2 (Ergebnisordnung)),
/// ueber dem Abfrageergebnis entschieden - nicht ueber der Scope-Politik.
///
/// Gibt (Verdikt, Grund) und NICHTS zur Gate-Achse zurueck:
/// QPM Invariante 4.4 (Score vor Gate ist verboten) trennt die Achsen, und
/// die Trennung steht hier in der Signatur. Ein Score kann dieses
/// Ergebnis ordnen, aber keinen Uebergang erlauben.
pub fn open_set_decide(query: &CatalogQuery) -> (IdentityVerdict, String) {
    match query {
        // Lage 2: nichts wurde geprueft. Die Deckelung ist damit
        // GEMESSEN - am Ergebnis der Stufe, die nicht abfragen konnte.
        CatalogQuery::NotQueried { reason } => (
            IdentityVerdict::Unknown,
            format!("Scope-Deckelung, keine Abfrage: {reason}"),
        ),
        // Lage 1: geprueft und nicht gefunden. KNOWN verlangte einen
        // "eindeutigen kalibrierten Katalogtreffer" - kalibriert heisst
        // eine acceptance_region nach QPM Struktur 3.15 (TemplateClass),
        // und die ist kataloggebunden und nicht gebaut. Eine Rangfolge
        // allein ist keine Zuordnung; sie zur Zuordnung zu machen waere
        // forced-nearest-known (QPM Regel 4.3 (Zwei orthogonale Statusachsen)).
        CatalogQuery::Queried {
            catalog_digest,
            candidates,
        } => (
            IdentityVerdict::Unknown,
            format!(
                "katalogfremd: gegen Stand {} geprueft, {} Kandidaten als \
                 Rangfolge, keine kalibrierte Akzeptanzregion laesst einen \
                 Treffer zu",
                catalog_digest,
                candidates.len()
            ),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact(n: i64) -> Scaled {
        Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: n,
            scale: 0,
        }
    }

    /// QPM Invariante 4.4 (Score vor Gate ist verboten): "Für alle x,y
    /// gilt Score(x) > Score(y) nicht-impliziert Gate(x) = PASS." Hier das
    /// konkrete x,y: zwei Kandidaten, einer naeher. Die Entscheidung
    /// darf daraus weder KNOWN noch irgendeine Gate-Aussage machen.
    #[test]
    fn a_better_score_neither_assigns_nor_gates() {
        let near = Candidate {
            class: ClassId("K-A".into()),
            distance: exact(1),
        };
        let far = Candidate {
            class: ClassId("K-B".into()),
            distance: exact(7),
        };
        let query = CatalogQuery::Queried {
            catalog_digest: Digest::sha256(b"test-stand"),
            candidates: vec![near.clone(), far.clone()],
        };
        let (verdict, reason) = open_set_decide(&query);
        assert_ne!(verdict, IdentityVerdict::Known, "forced-nearest-known");
        assert_ne!(verdict, IdentityVerdict::Ambiguous);
        assert_eq!(verdict, IdentityVerdict::Unknown);
        assert!(reason.contains("katalogfremd"));

        // Ordnungsinvarianz: die Reihenfolge der Rangfolge - und damit
        // jede Score-Ordnung - aendert am Verdikt nichts.
        let swapped = CatalogQuery::Queried {
            catalog_digest: Digest::sha256(b"test-stand"),
            candidates: vec![far, near],
        };
        assert_eq!(open_set_decide(&swapped).0, verdict);
    }

    /// QPM Regel 3.17 (Zwei Weisen, UNKNOWN zu sein): die Lagen fallen
    /// nicht zusammen - gleiches Verdikt, verschiedener, jeweils
    /// benannter Grund.
    #[test]
    fn the_two_ways_to_be_unknown_do_not_collapse() {
        let lage2 = open_set_decide(&CatalogQuery::NotQueried {
            reason: "kein catalog_ref im Scope".into(),
        });
        let lage1 = open_set_decide(&CatalogQuery::Queried {
            catalog_digest: Digest::sha256(b"test-stand"),
            candidates: vec![],
        });
        assert_eq!(lage2.0, IdentityVerdict::Unknown);
        assert_eq!(lage1.0, IdentityVerdict::Unknown);
        assert!(lage2.1.contains("keine Abfrage"));
        assert!(lage1.1.contains("katalogfremd"));
        assert_ne!(lage2.1, lage1.1);
    }
}
