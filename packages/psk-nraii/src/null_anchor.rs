//! L0: der Nullanker, als Struktur statt als Laufzeitpruefung.
//!
//! QPM Definition 10.5 (Nullanker): "N_0 ist ein zustandsloses Element
//! der Ordnungs- und Synchronisationssprache: Payload(N_0) = leer."
//!
//! QPM Vertrag 10.6 (Nichttraversal): "Kein zulaessiger Operator
//! realisiert einen Pfad durch N_0. Scheinbare Verbindung entsteht durch
//! Identifikation, Spiegelung, Quotientierung oder Synchronisation
//! relativ zu N_0."
//!
//! QPM Invariante 9.10 (Nullanker-Statelessness) nennt drei Verbote;
//! jedes hat hier eine eigene Traegerform, keine Zusicherung:
//!
//! | "kein Speicher"            | `NullAnchor` hat keine Felder - es gibt nichts, worin etwas stehen koennte |
//! | "kein Vertex mit Nutzdaten"| kein Payload, kein Digest, keine Kennung - der Typ traegt sie nicht        |
//! | "kein durchlaufener Zustand"| `NullAnchor` implementiert `Traversable` nicht                            |
//!
//! ## Warum das der GateAuthorization-Klasse angehoert
//!
//! Der Unterschied zu einer Pruefung: eine Pruefung kann uebersprungen
//! werden, ein Typ nicht. `GateAuthorization` macht Autoritaet
//! unfaelschbar, indem es nur EINEN Konstruktionsweg gibt und eine
//! negative Traitschranke den Rest ausschliesst. Hier tragen zwei
//! voneinander unabhaengige Sprachmittel:
//!
//! 1. Die **Traitschranke**: `Step` verlangt `Traversable` an beiden
//!    Enden, `NullAnchor` erfuellt es nicht.
//! 2. Die **Orphan Rule**: kein fremdes Paket kann `Traversable` fuer
//!    `NullAnchor` nachtraeglich implementieren - beide Namen gehoeren
//!    diesem Paket, also ist der Impl ausserhalb verboten.
//!
//! Das zweite Mittel ist das staerkere: es schliesst nicht nur den
//! direkten Verstoss aus, sondern auch den Weg, ihn zu erlauben. Beide
//! sind als `compile_fail`-Doctests festgehalten, und Doctests
//! kompilieren gegen dieses Paket als FREMDES - sie pruefen also genau
//! die Aussensicht, um die es geht.
//!
//! Blockierender Negativtest `traversal-through-null-anchor`
//! (QPM Regel 18.2 (Negative Tests, Auszug)): er faellt hier nicht zur
//! Laufzeit, sondern beim Bauen.

/// Ein Element, das Endpunkt eines Pfadschritts sein darf.
///
/// Markertrait ohne Methoden: die Aussage steckt darin, WER ihn
/// implementiert und wer nicht. L1 haengt ihn an die kanonischen
/// Zustaende; `NullAnchor` bekommt ihn nie.
///
/// Ausserhalb dieses Pakets ist er fuer `NullAnchor` nicht
/// implementierbar - Traitname und Typname gehoeren beide hierher, und
/// die Orphan Rule verbietet den Impl im fremden Paket:
///
/// ```compile_fail,E0117
/// impl psk_nraii::Traversable for psk_nraii::NullAnchor {}
/// ```
pub trait Traversable {}

/// N_0, QPM Definition 10.5 (Nullanker).
///
/// Ohne Felder: `Payload(N_0) = leer` ist damit keine Bedingung, die
/// jemand pruefen muesste, sondern eine Eigenschaft des Typs. Der
/// Nachweis misst sie (`size_of == 0`) statt sie zu behaupten.
///
/// `#[non_exhaustive]` haelt die Konstruktion im Paket: es gibt genau
/// einen Nullanker, [`N0`], und keinen Weg, einen zweiten zu bilden.
/// Eine Ordnungsreferenz, von der es Kopien mit eigener Herkunft gaebe,
/// waere keine.
///
/// Ein Pfad DURCH ihn ist ein Kompilierfehler, kein Laufzeitbefund.
///
/// ## Was der Fehlercode leistet - und was nicht
///
/// Ein `compile_fail` ohne Code ist schon gruen, wenn IRGENDETWAS nicht
/// kompiliert; ein Tippfehler im Beispiel bewiese dann nichts. Der Code
/// daneben sagt, WELCHER Fehler gemeint ist.
///
/// **Gemessen (L3-Runde): rustdoc ERZWINGT ihn nicht.** Ein Doctest mit
/// `compile_fail,E0451`, dessen tatsaechlicher Fehler E0308 war, lief
/// gruen durch, ohne Warnung. Der Code ist damit ein MESSPROTOKOLL -
/// er haelt fest, was beim Schreiben an einem echten Pruefpaket
/// gemessen wurde -, aber keine fortlaufende Wache: ein spaeterer
/// Umbau, der einen anderen Fehler ausloest, faellt hier nicht auf.
///
/// Die Wache ist deshalb zweiteilig: der Doctest haelt fest, DASS es
/// nicht kompiliert (das prueft rustdoc wirklich), und die Messung
/// gegen ein Pruefpaket haelt fest, WARUM. Wer eine dieser Schranken
/// umbaut, misst neu.
///
/// Hier gemessen: E0277 ist die unerfuellte Traitschranke.
///
/// ```compile_fail,E0277
/// struct Zustand;
/// impl psk_nraii::Traversable for Zustand {}
/// // Der Nullanker als Ziel eines Schritts - `Traversable` fehlt ihm.
/// let _ = psk_nraii::Step::new(Zustand, psk_nraii::N0);
/// ```
///
/// ```compile_fail,E0277
/// struct Zustand;
/// impl psk_nraii::Traversable for Zustand {}
/// // Und als Ausgangspunkt ebenso.
/// let _ = psk_nraii::Step::new(psk_nraii::N0, Zustand);
/// ```
///
/// Ein ZWEITER Nullanker ist ebenso wenig bildbar - `#[non_exhaustive]`
/// haelt den Wert im Paket (E0603):
///
/// ```compile_fail,E0603
/// let _zweiter = psk_nraii::NullAnchor;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NullAnchor;

/// Der eine Nullanker. Eine Konstante, kein Konstruktor: N_0 wird nicht
/// erzeugt, er wird bezogen.
pub const N0: NullAnchor = NullAnchor;

/// Ein Pfadschritt zwischen zwei traversierbaren Elementen.
///
/// Die Komposition [`Step::then`] ist die Stelle, an der
/// QPM Vertrag 10.6 (Nichttraversal) wirksam wird: der Mittelpunkt B
/// zweier verketteter Schritte ist genau das, was "durchlaufen" heisst.
/// Weil B `Traversable` sein muss, kann dort kein Nullanker stehen -
/// und weil schon der einzelne Schritt es verlangt, faellt der Versuch
/// eine Stufe frueher, beim Bilden des Schritts selbst.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step<A: Traversable, B: Traversable> {
    pub from: A,
    pub to: B,
}

impl<A: Traversable, B: Traversable> Step<A, B> {
    pub fn new(from: A, to: B) -> Self {
        Step { from, to }
    }

    /// Verkettet zwei Schritte ueber ihren gemeinsamen Mittelpunkt.
    ///
    /// `B` verschwindet aus dem Ergebnis - es ist der durchlaufene
    /// Zustand. Genau diese Position verbietet
    /// QPM Invariante 9.10 (Nullanker-Statelessness) dem Nullanker.
    pub fn then<C: Traversable>(self, next: Step<B, C>) -> Step<A, C> {
        Step {
            from: self.from,
            to: next.to,
        }
    }
}

/// Die vier Weisen, auf die nach QPM Vertrag 10.6 (Nichttraversal) eine
/// scheinbare Verbindung entstehen darf - geschlossenes Vokabular,
/// woertlich aus dem Vertragssatz.
///
/// Geschlossen und nicht erweiterbar: eine fuenfte Weise waere ein
/// Traversal unter anderem Namen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnchoredRelation {
    /// "Identifikation"
    Identification,
    /// "Spiegelung"
    Mirroring,
    /// "Quotientierung"
    Quotienting,
    /// "Synchronisation"
    Synchronization,
}

/// Eine scheinbare Verbindung: zwei Seiten, die relativ zu N_0 in
/// Beziehung stehen, OHNE dass ein Pfad zwischen ihnen liefe.
///
/// Bewusst kein [`Step`] und ohne `then`: sie ist nicht verkettbar, und
/// das ist der ganze Unterschied. Wer aus ihr einen Pfad machen wollte,
/// muesste einen `Step` bilden - und dafuer braeuchte er den Nullanker
/// als Endpunkt.
///
/// Der Anker steht als Feld darin, weil "relativ zu N_0" eine Aussage
/// UEBER die Verbindung ist. Kosten: keine - der Nachweis
/// `the_anchor_adds_no_bytes_to_what_references_it` misst, dass das Feld
/// die Struktur nicht vergroessert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApparentConnection<A, B> {
    pub left: A,
    pub right: B,
    pub relation: AnchoredRelation,
    pub anchor: NullAnchor,
}

/// Bildet eine scheinbare Verbindung relativ zum Nullanker.
///
/// Nimmt ihn als Referenz - die positive Haelfte von
/// QPM Vertrag 10.6 (Nichttraversal): N_0 erscheint als Bezugspunkt,
/// nie als Station. Die Signatur sagt es: `&NullAnchor` steht neben den
/// Seiten, nicht zwischen ihnen.
pub fn apparent_connection<A, B>(
    left: A,
    relation: AnchoredRelation,
    right: B,
    _anchor: &NullAnchor,
) -> ApparentConnection<A, B> {
    ApparentConnection {
        left,
        right,
        relation,
        anchor: N0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zwei Zustaende, an denen sich die Gegenprobe fuehren laesst: ohne
    /// sie waere jeder Nachweis unten gruen, auch wenn NICHTS
    /// traversierbar waere - dieselbe Ueberlegung wie bei den vakuum
    /// geschlossenen Zellen auf der PSK-RA-Seite.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct Zustand(u8);
    impl Traversable for Zustand {}

    /// QPM Definition 10.5 (Nullanker), gemessen: `Payload(N_0)` ist
    /// leer, und zwar bis auf das letzte Byte.
    #[test]
    fn the_null_anchor_carries_no_payload() {
        assert_eq!(std::mem::size_of::<NullAnchor>(), 0);
        // Gegenprobe: ein Traeger MIT Nutzdaten ist nicht null gross -
        // sonst maesse die Zeile darueber nur eine Eigenschaft von
        // `size_of`, nicht eine des Nullankers.
        assert!(std::mem::size_of::<Zustand>() > 0);
    }

    /// Es gibt genau einen Nullanker. Gleichheit ist hier keine
    /// Wertgleichheit unter mehreren, sondern die Feststellung, dass es
    /// nichts gibt, worin zwei sich unterscheiden koennten.
    #[test]
    fn there_is_exactly_one_null_anchor() {
        assert_eq!(N0, N0);
        let borrowed = &N0;
        assert_eq!(*borrowed, N0);
    }

    /// QPM Vertrag 10.6 (Nichttraversal), positive Haelfte: die vier
    /// erlaubten Weisen sind bildbar, und die Verbindung traegt ihren
    /// Anker als Bezug.
    #[test]
    fn all_four_apparent_connections_are_formable() {
        let vier = [
            AnchoredRelation::Identification,
            AnchoredRelation::Mirroring,
            AnchoredRelation::Quotienting,
            AnchoredRelation::Synchronization,
        ];
        for relation in vier {
            let c = apparent_connection(Zustand(1), relation, Zustand(2), &N0);
            assert_eq!(c.relation, relation);
            assert_eq!(c.anchor, N0);
            assert_eq!((c.left, c.right), (Zustand(1), Zustand(2)));
        }
        // Geschlossen: vier, nicht "mindestens vier".
        assert_eq!(vier.len(), 4);
    }

    /// QPM Invariante 9.10 (Nullanker-Statelessness), erste Haelfte
    /// ("kein Speicher"): der Anker vergroessert das, was ihn fuehrt,
    /// um kein einziges Byte. Eine Ordnungsreferenz, die Platz
    /// beanspruchte, waere Datenhaltung.
    #[test]
    fn the_anchor_adds_no_bytes_to_what_references_it() {
        struct OhneAnker {
            _left: Zustand,
            _right: Zustand,
            _relation: AnchoredRelation,
        }
        assert_eq!(
            std::mem::size_of::<ApparentConnection<Zustand, Zustand>>(),
            std::mem::size_of::<OhneAnker>()
        );
    }

    /// Die Gegenprobe zum `compile_fail`-Nachweis: zwischen
    /// traversierbaren Elementen sind Schritte bildbar UND verkettbar.
    /// Ohne diesen Test hiesse "der Nullanker kann nicht traversiert
    /// werden" womoeglich nur, dass ueberhaupt niemand traversieren kann.
    #[test]
    fn traversal_between_traversable_elements_composes() {
        let a = Step::new(Zustand(1), Zustand(2));
        let b = Step::new(Zustand(2), Zustand(3));
        let ac = a.then(b);
        assert_eq!(ac.from, Zustand(1));
        assert_eq!(ac.to, Zustand(3));
    }

    /// Der Mittelpunkt IST der durchlaufene Zustand: er faellt aus dem
    /// Ergebnis heraus. Das ist die Stelle, an der ein Nullanker stehen
    /// muesste, damit ein Pfad DURCH ihn liefe - und die der Typ ihm
    /// verschliesst.
    #[test]
    fn the_midpoint_of_a_composition_is_what_gets_traversed() {
        let durchlaufen = Zustand(2);
        let komponiert =
            Step::new(Zustand(1), durchlaufen).then(Step::new(durchlaufen, Zustand(3)));
        assert_eq!(komponiert.from, Zustand(1));
        assert_eq!(komponiert.to, Zustand(3));
        // Der Mittelpunkt kommt im Ergebnistyp nicht mehr vor.
        assert_eq!(
            std::any::type_name::<Step<Zustand, Zustand>>(),
            std::any::type_name_of_val(&komponiert)
        );
    }
}
