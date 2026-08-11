//! L1, zweiter Teil: die Signaturabbildung und die Diamant-Aequivalenz -
//! das genuin Neue an dieser Schicht.
//!
//! QPM Definition 10.9 (Diamant-Äquivalenz): "Fuer Signatur
//! sigma: X -> S: x ~diamant y genau dann, wenn sigma(x) = sigma(y).
//! Operator T ist quotientenvertraeglich, wenn x ~diamant y => T(x)
//! ~diamant T(y); nur dann ist T_diamant([x]) = [T(x)] wohldefiniert."
//!
//! ## Warum das NRAII gehoert und nicht geteilt ist
//!
//! Der Pruefstein aus QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen):
//! "was eine Entscheidung trifft, gehoert NRAII und ist eigenstaendig.
//! Was eine Form festlegt, ist geteilt." WELCHE Merkmale die Klasse
//! bilden, ist eine Entscheidung - PSK-RA hat dafuer kein Gegenstueck
//! (der dortige `Signature`-Typ ist der kryptografische, eine andere
//! Sache). Die Serialisierung und Digestbildung darunter bleiben
//! geteilt; sie liegen in [`crate::CanonicalState`].
//!
//! ## Die zwei Quotienten, die nicht zusammenfallen duerfen
//!
//! NRAII fuehrt ZWEI verschiedene Quotienten, und sie messen
//! Verschiedenes:
//!
//! - Die **Diamant-Aequivalenz** (hier) quotientiert ueber der
//!   SIGNATUR: gleich, wenn die klassenbildenden Merkmale gleich sind.
//! - Der **Abhaengigkeitsquotient** (QPM Definition 11.5 (Abhängigkeitsquotient, zweite Instanz))
//!   quotientiert ueber geteilten QUELLEN: "Zwei Perspektiven werden
//!   nicht doppelt gezaehlt, wenn sie Quelle, Kalibrierung, Heuristik
//!   oder Vorverarbeitung teilen." Er ist ausdruecklich "dieselbe
//!   Konstruktion wie PSK-RAs DependencyProfile" und damit Bindung, kein
//!   Neubau - er wird hier NICHT gebaut, sondern kommt mit L5 aus
//!   PSK-RAs `DependencyProfile`.
//!
//! Sie zusammenfallen zu lassen waere ein Fehler mit Folgen: zwei
//! Zustaende mit gleicher Signatur koennen aus unabhaengigen Quellen
//! stammen (dann traegt ihre Uebereinstimmung Evidenz), oder aus
//! derselben (dann traegt sie keine). Der Nachweis
//! `the_two_quotients_are_independent_in_both_directions` misst, dass
//! keine der beiden Relationen die andere impliziert.

/// sigma: X -> S. Welche Merkmale die Klasse bilden - die Entscheidung,
/// die diese Schicht trifft.
///
/// Der Signaturraum `S` ist ein zugeordneter Typ und keine feste Form:
/// verschiedene Zustandsraeume signieren verschieden. Verlangt wird nur,
/// was QPM Definition 10.9 (Diamant-Äquivalenz) braucht - Gleichheit.
pub trait Signed {
    /// S, der Signaturraum.
    type Sig: PartialEq;

    /// sigma(x).
    fn signature(&self) -> Self::Sig;
}

/// x ~diamant y, woertlich: gleich genau dann, wenn die Signaturen
/// gleich sind.
pub fn diamond_equivalent<X: Signed>(x: &X, y: &X) -> bool {
    x.signature() == y.signature()
}

/// [x], die Diamant-Klasse eines Zustands.
///
/// Traegt einen Vertreter. Zwei Klassen sind gleich, wenn ihre
/// Vertreter aequivalent sind - nicht, wenn die Vertreter gleich sind.
#[derive(Debug, Clone)]
pub struct DiamondClass<X: Signed> {
    representative: X,
}

impl<X: Signed> DiamondClass<X> {
    /// [x] aus einem Vertreter.
    pub fn of(representative: X) -> Self {
        DiamondClass { representative }
    }

    pub fn representative(&self) -> &X {
        &self.representative
    }
}

impl<X: Signed> PartialEq for DiamondClass<X> {
    fn eq(&self, other: &Self) -> bool {
        diamond_equivalent(&self.representative, &other.representative)
    }
}

/// Warum ein vorgelegtes Zeugenpaar den Verträglichkeitsnachweis nicht
/// traegt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompatibilityBreach {
    /// Ein aequivalentes Paar wurde auf ein nicht aequivalentes
    /// abgebildet - der Operator ist nicht quotientenvertraeglich, und
    /// `T_diamant([x])` waere nicht wohldefiniert.
    NotCompatible { witness_index: usize },
    /// Kein einziges der vorgelegten Paare war aequivalent. Damit hat
    /// die Pruefung NICHTS geprueft: die Implikation "x ~ y => T(x) ~
    /// T(y)" ist ueber einer leeren Praemissenmenge vakuum wahr.
    ///
    /// Dieselbe Haltung wie Regel 9.11 (Vakuum ist kein Beleg) auf der
    /// PSK-RA-Seite: eine vakuum bestandene Pruefung ist keine
    /// bestandene Pruefung.
    VacuousWitnessSet { pairs_offered: usize },
}

/// Ein Operator, dessen Quotientenvertraeglichkeit GEPRUEFT ist.
///
/// Es gibt keinen anderen Weg zu diesem Typ als [`lift`] - dasselbe
/// Muster wie `GateAuthorization`, aus demselben Grund: die
/// Wohldefiniertheit von `T_diamant([x]) = [T(x)]` ist eine
/// Voraussetzung, keine Hoffnung. Wer auf Klassen wirken will, braucht
/// den Nachweis; wer ihn nicht hat, kann nur auf Vertretern wirken.
pub struct QuotientOperator<X: Signed, F: Fn(&X) -> X> {
    operator: F,
    checked_pairs: usize,
    _marker: std::marker::PhantomData<X>,
}

/// Zeigt, WORAN geprueft wurde - nicht den Operator selbst. Ein
/// gehobener Operator ist genau so viel wert wie seine Zeugenmenge, und
/// das ist die Zahl, die hier steht.
impl<X: Signed, F: Fn(&X) -> X> std::fmt::Debug for QuotientOperator<X, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuotientOperator")
            .field("checked_pairs", &self.checked_pairs)
            .finish_non_exhaustive()
    }
}

impl<X: Signed, F: Fn(&X) -> X> QuotientOperator<X, F> {
    /// T_diamant([x]) = [T(x)] - erst hier wohldefiniert.
    pub fn apply_to_class(&self, class: &DiamondClass<X>) -> DiamondClass<X> {
        DiamondClass::of((self.operator)(class.representative()))
    }

    /// An wie vielen wirklich aequivalenten Paaren die Vertraeglichkeit
    /// geprueft wurde. Null kann es nicht sein - [`lift`] weist eine
    /// vakuoese Zeugenmenge zurueck.
    pub fn checked_pairs(&self) -> usize {
        self.checked_pairs
    }
}

/// Hebt einen Operator auf die Klassen - wenn er es traegt.
///
/// Prueft QPM Definition 10.9 (Diamant-Äquivalenz) an den vorgelegten
/// Paaren: fuer jedes Paar mit `x ~diamant y` muss `T(x) ~diamant T(y)`
/// gelten. Paare, die selbst nicht aequivalent sind, sind keine Zeugen -
/// sie werden uebergangen, und wenn KEIN Paar aequivalent war, faellt
/// die Pruefung als vakuum aus.
///
/// Das Gate N-QUOTIENT ("Signatur und Quotientenvertraeglichkeit
/// geprueft") sitzt genau hier.
pub fn lift<X: Signed, F: Fn(&X) -> X>(
    operator: F,
    witnesses: &[(X, X)],
) -> Result<QuotientOperator<X, F>, CompatibilityBreach> {
    let mut checked = 0usize;
    for (i, (x, y)) in witnesses.iter().enumerate() {
        if !diamond_equivalent(x, y) {
            continue;
        }
        checked += 1;
        if !diamond_equivalent(&operator(x), &operator(y)) {
            return Err(CompatibilityBreach::NotCompatible { witness_index: i });
        }
    }
    if checked == 0 {
        return Err(CompatibilityBreach::VacuousWitnessSet {
            pairs_offered: witnesses.len(),
        });
    }
    Ok(QuotientOperator {
        operator,
        checked_pairs: checked,
        _marker: std::marker::PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ein Beispielzustand mit zwei unabhaengigen Merkmalen: dem
    /// klassenbildenden (`kind`) und der Quelle (`source`). Die Trennung
    /// der beiden ist genau das, was die zwei Quotienten unterscheidet.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Zustand {
        kind: &'static str,
        source: &'static str,
        /// Nicht klassenbildend - sigma sieht es nicht.
        note: u32,
    }

    impl Signed for Zustand {
        type Sig = &'static str;
        fn signature(&self) -> &'static str {
            self.kind
        }
    }

    fn z(kind: &'static str, source: &'static str, note: u32) -> Zustand {
        Zustand { kind, source, note }
    }

    /// QPM Definition 10.9 (Diamant-Äquivalenz), erster Satz: die
    /// Aequivalenz haengt an sigma, nicht an der Gleichheit der
    /// Zustaende.
    #[test]
    fn equivalence_follows_the_signature_not_the_state() {
        let a = z("A", "q1", 1);
        let b = z("A", "q2", 99);
        assert_ne!(a, b, "die Zustaende sind verschieden");
        assert!(diamond_equivalent(&a, &b), "ihre Signaturen sind gleich");
        assert!(!diamond_equivalent(&a, &z("B", "q1", 1)));
        // Und die Klassen folgen mit.
        assert_eq!(DiamondClass::of(a.clone()), DiamondClass::of(b));
        assert_ne!(DiamondClass::of(a), DiamondClass::of(z("B", "q1", 1)));
    }

    /// Die beiden Quotienten sind unabhaengig - in BEIDEN Richtungen
    /// gemessen, weil eine Richtung allein die Verwechslung nicht
    /// ausschliesst.
    ///
    /// Der Abhaengigkeitsquotient selbst wird hier nicht gebaut (er ist
    /// Bindung an PSK-RAs `DependencyProfile`, siehe Modulkopf); geprueft
    /// wird, dass die Diamant-Aequivalenz ihn weder impliziert noch aus
    /// ihm folgt.
    #[test]
    fn the_two_quotients_are_independent_in_both_directions() {
        // Gleiche Signatur, verschiedene Quellen: diamant-aequivalent,
        // abhaengigkeits-VERSCHIEDEN. Ihre Uebereinstimmung traegt
        // Evidenz, weil sie unabhaengig zustande kam.
        let a = z("A", "q1", 0);
        let b = z("A", "q2", 0);
        assert!(diamond_equivalent(&a, &b));
        assert_ne!(a.source, b.source);

        // Verschiedene Signatur, gleiche Quelle: diamant-VERSCHIEDEN,
        // abhaengigkeits-gleich. Zwei Sichten derselben Quelle, die
        // nicht in dieselbe Klasse fallen.
        let c = z("A", "q1", 0);
        let d = z("B", "q1", 0);
        assert!(!diamond_equivalent(&c, &d));
        assert_eq!(c.source, d.source);
    }

    /// Ein vertraeglicher Operator laesst sich heben, und die Hebung
    /// rechnet auf Klassen.
    #[test]
    fn a_compatible_operator_lifts_and_acts_on_classes() {
        // Wirkt nur auf das nicht klassenbildende Merkmal - also
        // vertraeglich.
        let op = |x: &Zustand| Zustand {
            note: x.note + 1,
            ..x.clone()
        };
        let witnesses = [(z("A", "q1", 1), z("A", "q2", 7))];
        let lifted = lift(op, &witnesses).expect("vertraeglich");
        assert_eq!(lifted.checked_pairs(), 1);

        // T_diamant([x]) = [T(x)]: das Ergebnis haengt nicht vom
        // Vertreter ab - hier an zwei verschiedenen Vertretern derselben
        // Klasse gemessen.
        let aus_a = lifted.apply_to_class(&DiamondClass::of(z("A", "q1", 1)));
        let aus_b = lifted.apply_to_class(&DiamondClass::of(z("A", "q2", 7)));
        assert_eq!(aus_a, aus_b);
    }

    /// Die Gegenprobe: ein Operator, der die Klasse zerreisst, wird
    /// NICHT gehoben - und der Befund nennt das Paar, an dem es brach.
    #[test]
    fn an_incompatible_operator_is_refused_and_the_witness_is_named() {
        // Wirkt auf das klassenbildende Merkmal, und zwar abhaengig von
        // der Quelle: zwei aequivalente Zustaende fallen auseinander.
        let op = |x: &Zustand| Zustand {
            kind: if x.source == "q1" { "A" } else { "B" },
            ..x.clone()
        };
        let witnesses = [(z("A", "q1", 0), z("A", "q2", 0))];
        let breach = lift(op, &witnesses).expect_err("darf nicht heben");
        assert_eq!(
            breach,
            CompatibilityBreach::NotCompatible { witness_index: 0 }
        );
    }

    /// Eine Zeugenmenge ohne ein einziges aequivalentes Paar prueft
    /// nichts - und wird deshalb zurueckgewiesen, statt vakuum zu
    /// bestehen.
    ///
    /// Ohne diese Schranke waere `lift` mit einer beliebigen Menge
    /// nicht aequivalenter Paare aufrufbar und liefe durch: die
    /// Implikation ist ueber leerer Praemissenmenge wahr. Genau der
    /// Fall, den derselbe Operator wie im Test darueber sichtbar macht -
    /// er ist unvertraeglich und kaeme trotzdem durch.
    #[test]
    fn a_vacuous_witness_set_is_refused_not_passed() {
        let op = |x: &Zustand| Zustand {
            kind: if x.source == "q1" { "A" } else { "B" },
            ..x.clone()
        };
        // Kein Paar ist aequivalent.
        let witnesses = [(z("A", "q1", 0), z("B", "q2", 0))];
        assert!(!diamond_equivalent(&witnesses[0].0, &witnesses[0].1));
        let breach = lift(op, &witnesses).expect_err("vakuum ist kein Beleg");
        assert_eq!(
            breach,
            CompatibilityBreach::VacuousWitnessSet { pairs_offered: 1 }
        );

        // Und die leere Menge erst recht.
        let leer: [(Zustand, Zustand); 0] = [];
        assert_eq!(
            lift(op, &leer).expect_err("leer prueft nichts"),
            CompatibilityBreach::VacuousWitnessSet { pairs_offered: 0 }
        );
    }
}
