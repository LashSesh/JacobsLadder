//! L5: das duale Wunsch- und Inversionskalkuel.
//!
//! ## Die Fuenfermenge - gemessen, nicht angenommen
//!
//! QPM Struktur 11.6 (Rekonstruktive Wish-Klasse) nennt fuenf
//! zulaessige Ergebnisse, und QPM Struktur 4.2 (Ergebnisordnung) auf
//! der QPM-Seite ebenfalls fuenf. Die Frage, ob das DIESELBE Menge ist
//! oder nur gleich aussieht, ist gemessen worden:
//!
//! | | QPM Struktur 4.2 (Ergebnisordnung) | hier |
//! |---|---|---|
//! | Gegenstand | `ID(x)`, eine Identifikation | `W^-`, eine Hypothesenklasse |
//! | erster Wert | KNOWN = "eindeutiger kalibrierter KATALOGTREFFER" | "eindeutige Klasse" = Klasse mit einem Element |
//! | dritter Wert | UNKNOWN = "in-scope, gemessen, KATALOGFREMD" | "offene Unknown-Klasse" = schrumpft nicht auf eins |
//! | Grundlage | der Katalog (ohne ihn deckelt QPM-OBL-002 alles) | die Kardinalitaet, kein Katalog beteiligt |
//!
//! Befund: gleiche Kardinalitaet, zwei namensgleiche Randfaelle
//! (OutOfScope, Invalid), aber VERSCHIEDENE Entscheidungsgrundlage. Es
//! ist nicht dieselbe Menge, sondern dieselbe FORM ueber verschiedenen
//! Gegenstaenden.
//!
//! Deshalb ist [`WishOutcome`] ein eigenes Vokabular und keine Bindung
//! an `IdentityVerdict`: eine Bindung importierte die Katalogsemantik
//! von KNOWN in eine Schicht, in der kein Katalog vorkommt. Und nach
//! QPM Regel 9.3 (Was NRAII feststellt, ordnet der Eigner ein) ist das
//! auch nicht noetig - wer ein NRAII-Ergebnis in QPMs Ordnung
//! einordnen will, bekommt es als Wert; NRAII ordnet nicht ein.
//!
//! ## Distanz ist kein Gate
//!
//! QPM Vertrag 11.2 (Distanz ist kein Gate): "Eine geringe
//! Wish-Distanz ist ein Ranking- und Diagnosewert. Sie erzeugt keine
//! Berechtigung zur Closure oder Materialisierung - dieselbe Trennung
//! wie Gate vor Score."
//!
//! "Dieselbe Trennung" ist woertlich zu nehmen: dies ist BINDUNG an das
//! Muster, das QPM Invariante 4.4 (Score vor Gate ist verboten) traegt
//! und das auf der QPM-Seite bereits gebaut ist - kein zweiter
//! Mechanismus. Die Signaturtrennung, die dort getragen hat, traegt
//! auch hier: [`WishDistance`] hat keine Methode, die eine Berechtigung
//! zurueckgibt, und [`Materialization`] entsteht nur ueber ein Gate.
//! Die Funktion KANN zur Gate-Achse nichts sagen.
//!
//! ## Der Kreis schliesst bei der Reobservation
//!
//! QPM Regel 11.3 (Regelkreis) endet mit `Materialize -> Z_{t+1}`, aber
//! der Satz danach zieht die Grenze: "Closure wird aus Reobservation
//! geschlossen, nicht aus Absicht." Der Kreis schliesst also NICHT bei
//! `Z_{t+1}`, sondern erst beim naechsten `Obs`.
//!
//! Gebaut ist das als Zustandsfolge, die den Weg erzwingt: aus einer
//! [`Materialization`] fuehrt kein Weg zu einer [`LoopClosure`] ausser
//! ueber [`reobserve`]. Ein Durchlauf ohne Reobservation kann keine
//! Closure behaupten, weil es den Typ dafuer nicht gibt.
//!
//! ## Was NRAII-5 verlangt - gemessen
//!
//! Die Stufe heisst "Quotientenstabiler Forward/Inverse-Channel mit
//! Reobservation". Gemessen, woran sie haengt:
//!
//! - **Forward/Inverse-Channel**: die beiden Wish-Richtungen dieses
//!   Kapitels - deklarativ (QPM Struktur 11.1 (Deklarativer Wish)) und
//!   rekonstruktiv (QPM Struktur 11.6 (Rekonstruktive Wish-Klasse)) -
//!   verbunden durch den Regelkreis.
//!
//!   **Befund, und wie er normativ wurde.** Bis v1.0.15 hatte das Wort
//!   "Channel" im NRAII-Teil KEINEN eigenen Block; es erschien dort nur
//!   in der Stufenliste selbst. Als Befund gemeldet und aus den
//!   Nachbarbloecken abgeleitet, nicht erfunden - dieselbe Lage wie
//!   beim Zykluswitness vor v1.0.14.
//!   QPM Struktur 11.4 (Forward/Inverse-Channel) hat die Lesart in
//!   v1.0.16 festgeschrieben, und sie deckt sich mit der hier gebauten:
//!   "Der Channel ist das Paar, verbunden durch die Reobservation -
//!   ohne sie ist er offen, nicht geschlossen", und
//!   quotientenstabil heisst quotientenvertraeglich im Sinne der
//!   Diamant-Aequivalenz, "es gibt dafuer keinen eigenen Mechanismus".
//!   QPM Regel 11.5 (Zwei Kanäle, ein Wort) trennt dazu die beiden
//!   Bedeutungen: QPMs `ChannelId` wird deklariert und abgetastet, der
//!   Forward/Inverse-Channel durchlaufen und geschlossen; eine Bindung
//!   des einen an den anderen ist ein Konformitaetsdefekt.
//! - **mit Reobservation**: [`reobserve`], gebaut.
//! - **quotientenstabil**: der Channel MUSS die Klassen erhalten, also
//!   quotientenvertraeglich sein. Das Werkzeug dafuer steht seit L1
//!   (`crate::lift`); [`lift_channel`] wendet es auf den Channel an.
//!
//! Und der lose Faden aus L1: QPM Definition 11.7 (Abhängigkeitsquotient, zweite Instanz)
//! gehoert zu diesem Kapitel und war im ersten Zug nicht gebaut. Er ist
//! unten nachgetragen - als BEFUND nach
//! QPM Regel 9.3 (Was NRAII feststellt, ordnet der Eigner ein), weil die
//! Quotientenbildung selbst M10 gehoert.

use psk_types::objects::Scaled;

/// Eine Facette `f = (id, p, w, e, g)` aus
/// QPM Struktur 11.1 (Deklarativer Wish).
///
/// `p` ist das Praedikat, das an einer Beobachtung gemessen wird; sein
/// Wert liegt zwischen 0 und 1 und steht als `Scaled` da, nicht als
/// Fliesskomma - dieselbe Vorgabe wie im Signaturatlas.
#[derive(Debug, Clone, PartialEq)]
pub struct Facet {
    pub id: String,
    /// `w_i > 0` - die Struktur verlangt es ausdruecklich.
    pub weight: u32,
    /// Was die Facette misst, im Klartext (`e`).
    pub evidence: String,
    /// An welches Gate sie gebunden ist (`g`).
    pub gate: String,
}

/// Warum ein vorgelegter Wish nicht deklarierbar ist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WishBreach {
    /// `w_i > 0` verletzt.
    NonPositiveWeight { facet: String },
    /// Ein Wish ohne Facetten deklariert keinen Zielattraktor.
    NoFacets,
}

/// `W^+ = {(f_i, w_i)}` - der deklarative Wish.
///
/// "Ein Wish ist kein Prompt: er deklariert einen Zielattraktor und
/// einen Messvertrag, keine sprachliche Antwort." Deshalb traegt der
/// Typ Facetten mit Gewichten und Gates, keinen Text.
#[derive(Debug, Clone, PartialEq)]
pub struct Wish {
    facets: Vec<Facet>,
}

impl Wish {
    /// Der einzige Weg zu einem Wish - `w_i > 0` wird geprueft, nicht
    /// vorausgesetzt.
    pub fn declare(facets: Vec<Facet>) -> Result<Self, WishBreach> {
        if facets.is_empty() {
            return Err(WishBreach::NoFacets);
        }
        if let Some(f) = facets.iter().find(|f| f.weight == 0) {
            return Err(WishBreach::NonPositiveWeight {
                facet: f.id.clone(),
            });
        }
        Ok(Wish { facets })
    }

    pub fn facets(&self) -> &[Facet] {
        &self.facets
    }
}

/// `d(W^+, O_t)` als exakter Bruch.
///
/// Die Formel `sum w_i [1 - p_i(O_t)] / sum w_i` ist eine Division, und
/// eine Dezimalzahl waere hier eine Rundung ohne Not. Der Wert steht
/// deshalb als Zaehler und Nenner da; Vergleiche laufen ueber
/// Kreuzmultiplikation und sind damit exakt.
///
/// **Was dieser Typ NICHT hat**: eine Methode, die eine Berechtigung
/// zurueckgibt. Es gibt kein `allows_closure`, kein `passes`, kein
/// `is_good_enough`. Das ist die Signaturtrennung aus
/// QPM Vertrag 11.2 (Distanz ist kein Gate) - die Funktion kann zur
/// Gate-Achse nichts sagen, weil sie dafuer keinen Rueckgabewert hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WishDistance {
    numerator: i64,
    denominator: i64,
}

impl WishDistance {
    /// `d(W^+, O_t) = sum w_i [1 - p_i(O_t)] / sum w_i`.
    ///
    /// `predicates` gibt je Facette `p_i(O_t)` als `Scaled`; `1 - p_i`
    /// wird auf derselben Skala gerechnet.
    pub fn measure(wish: &Wish, predicates: &[(String, Scaled)]) -> Option<Self> {
        let mut num: i64 = 0;
        let mut den: i64 = 0;
        for f in wish.facets() {
            let p = predicates.iter().find(|(id, _)| id == &f.id)?;
            let scale = 10i64.checked_pow(p.1.scale as u32)?;
            // w_i * (1 - p_i), auf der Skala von p_i gerechnet.
            num += (f.weight as i64) * (scale - p.1.numerator);
            den += (f.weight as i64) * scale;
        }
        if den == 0 {
            return None;
        }
        Some(WishDistance {
            numerator: num,
            denominator: den,
        })
    }

    /// Ordnet zwei Distanzen - exakt, ueber Kreuzmultiplikation.
    ///
    /// Ein RANKINGwert, wie der Vertrag sagt. Dass er ordnet, heisst
    /// nicht, dass er berechtigt.
    pub fn is_closer_than(&self, other: &WishDistance) -> bool {
        self.numerator * other.denominator < other.numerator * self.denominator
    }

    pub fn as_fraction(&self) -> (i64, i64) {
        (self.numerator, self.denominator)
    }
}

/// Die Stufen des Regelkreises aus QPM Regel 11.3 (Regelkreis),
/// geschlossen und in der Reihenfolge des Werks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LoopStage {
    Observe,
    Assess,
    Plan,
    GateValidate,
    Materialize,
    /// Die Stufe, die das Werk nicht in die Kette schreibt, aber im
    /// Satz danach verlangt: "Closure wird aus Reobservation
    /// geschlossen, nicht aus Absicht."
    Reobserve,
}

impl LoopStage {
    pub fn all() -> [LoopStage; 6] {
        use LoopStage::*;
        [Observe, Assess, Plan, GateValidate, Materialize, Reobserve]
    }
}

/// `Z_{t+1}` - das Ergebnis von `Materialize`.
///
/// Ein materialisierter Zustand, und NICHT mehr: aus ihm fuehrt kein
/// Weg zu einer [`LoopClosure`] ausser ueber [`reobserve`]. Das ist der
/// Punkt, an dem "nicht aus Absicht" typseitig wird.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Materialization {
    /// Die Stufen, die dieser Durchlauf tatsaechlich durchlaufen hat.
    stages: Vec<LoopStage>,
}

impl Materialization {
    /// Bildet einen Durchlauf bis `Z_{t+1}`.
    pub fn after_full_pass() -> Self {
        Materialization {
            stages: vec![
                LoopStage::Observe,
                LoopStage::Assess,
                LoopStage::Plan,
                LoopStage::GateValidate,
                LoopStage::Materialize,
            ],
        }
    }

    pub fn stages(&self) -> &[LoopStage] {
        &self.stages
    }

    /// Ob dieser Durchlauf geschlossen ist. IMMER falsch: eine
    /// Materialisierung ist keine Closure. Die Funktion steht hier,
    /// damit die Frage einen Ort hat, an dem sie verneint wird.
    pub fn is_closed(&self) -> bool {
        false
    }
}

/// Die geschlossene Runde - erreichbar NUR ueber [`reobserve`].
///
/// Es gibt keinen oeffentlichen Konstruktor und kein oeffentliches
/// Feld. Wer eine `LoopClosure` haelt, haelt eine, der eine
/// Reobservation vorausging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoopClosure {
    stages: Vec<LoopStage>,
    /// Was die Reobservation ergab - der Beleg, aus dem geschlossen
    /// wurde.
    observation: String,
}

impl LoopClosure {
    pub fn stages(&self) -> &[LoopStage] {
        &self.stages
    }

    pub fn observation(&self) -> &str {
        &self.observation
    }

    /// Ob die Reobservation wirklich stattfand - gemessen an der
    /// Stufenfolge, nicht behauptet.
    pub fn was_reobserved(&self) -> bool {
        self.stages.last() == Some(&LoopStage::Reobserve)
    }
}

/// Warum aus einer Materialisierung keine Closure wird.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosureBreach {
    /// Die Reobservation hat nichts ergeben. Ein leerer Beleg schliesst
    /// nichts - dieselbe Haltung wie bei der Begruendungspflicht des
    /// dritten Kontraktionsausgangs.
    EmptyObservation,
}

/// Der einzige Weg von `Z_{t+1}` zu einer geschlossenen Runde.
///
/// QPM Regel 11.3 (Regelkreis), Satz danach: "Closure wird aus
/// Reobservation geschlossen, nicht aus Absicht."
pub fn reobserve(
    materialized: Materialization,
    observation: &str,
) -> Result<LoopClosure, ClosureBreach> {
    if observation.trim().is_empty() {
        return Err(ClosureBreach::EmptyObservation);
    }
    let mut stages = materialized.stages;
    stages.push(LoopStage::Reobserve);
    Ok(LoopClosure {
        stages,
        observation: observation.to_string(),
    })
}

/// Die fuenf zulaessigen Ergebnisse aus
/// QPM Struktur 11.6 (Rekonstruktive Wish-Klasse) - geschlossen und
/// woertlich.
///
/// Eigenes Vokabular, KEINE Bindung an `IdentityVerdict`: siehe die
/// Messung im Modulkopf. Die Grundlage ist hier die Kardinalitaet der
/// Klasse, dort der Katalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WishOutcome {
    /// "eindeutige Klasse" - genau eine Hypothese ueberlebt.
    Unique { hypothesis: String },
    /// "endliche Mehrdeutigkeit" - mehrere ueberleben, endlich viele.
    FinitelyAmbiguous { hypotheses: Vec<String> },
    /// "offene Unknown-Klasse" - die Klasse schrumpft nicht auf eine
    /// endliche Auswahl.
    OpenUnknown { reason: String },
    /// "OutOfScope"
    OutOfScope { reason: String },
    /// "Invalid"
    Invalid { reason: String },
}

/// Schraenkt die Hypothesenklasse ein und benennt das Ergebnis.
///
/// `W^-_{n+1} = {w in W^-_n | d(Obs(w), O_ext) <= eps_n, Gate_n(w) = PASS}`.
///
/// Das Ergebnis folgt der KARDINALITAET der ueberlebenden Menge - und
/// nie einer Erzwingung: "Erzwungene Eindeutigkeit ist ein Fehler."
/// Deshalb gibt es keinen Parameter, der eine Eindeutigkeit verlangt,
/// und keinen Weg, aus zwei Ueberlebenden eine `Unique` zu machen.
pub fn narrow_class(
    surviving: Vec<String>,
    within_epsilon: bool,
    all_gates_pass: bool,
) -> WishOutcome {
    if !all_gates_pass {
        return WishOutcome::Invalid {
            reason: "mindestens ein Gate steht nicht auf PASS".to_string(),
        };
    }
    if !within_epsilon {
        return WishOutcome::OutOfScope {
            reason: "keine Hypothese liegt innerhalb von epsilon_n".to_string(),
        };
    }
    match surviving.len() {
        0 => WishOutcome::OpenUnknown {
            reason: "keine Hypothese ueberlebt die Einschraenkung - die Klasse ist offen"
                .to_string(),
        },
        1 => WishOutcome::Unique {
            hypothesis: surviving.into_iter().next().expect("genau eine"),
        },
        _ => WishOutcome::FinitelyAmbiguous {
            hypotheses: surviving,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facette(id: &str, weight: u32) -> Facet {
        Facet {
            id: id.to_string(),
            weight,
            evidence: format!("{id}-evidenz"),
            gate: "N-WISH".to_string(),
        }
    }

    fn scaled(numerator: i64, scale: i64) -> Scaled {
        Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator,
            scale,
        }
    }

    /// QPM Struktur 11.1 (Deklarativer Wish): `w_i > 0`, geprueft.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: ein Gewicht null wird
    /// zurueckgewiesen UND die Facette benannt; eine leere Facettenliste
    /// ebenso. Ohne den zweiten Fall bliebe offen, ob ein Wish ohne
    /// jeden Zielattraktor durchginge.
    #[test]
    fn a_wish_needs_positive_weights_and_at_least_one_facet() {
        assert!(Wish::declare(vec![facette("a", 3), facette("b", 1)]).is_ok());
        assert_eq!(
            Wish::declare(vec![facette("a", 3), facette("null", 0)]).expect_err("w_i > 0"),
            WishBreach::NonPositiveWeight {
                facet: "null".to_string()
            }
        );
        assert_eq!(
            Wish::declare(vec![]).expect_err("leer"),
            WishBreach::NoFacets
        );
    }

    /// Die Distanz ist exakt und ordnet - aber sie berechtigt nicht.
    ///
    /// ERWARTUNG: zwei Beobachtungen ergeben verschiedene Distanzen, die
    /// sich exakt ordnen lassen. Und: an `WishDistance` gibt es KEINE
    /// Methode, die eine Berechtigung zurueckgibt - das ist eine
    /// Aussage ueber die Signatur, die der naechste Test typseitig
    /// haelt.
    #[test]
    fn the_distance_ranks_exactly_without_granting_anything() {
        let wish = Wish::declare(vec![facette("a", 1), facette("b", 3)]).expect("deklarierbar");

        // Beobachtung 1: beide Praedikate voll erfuellt -> Distanz 0.
        let nah = WishDistance::measure(
            &wish,
            &[
                ("a".to_string(), scaled(100, 2)),
                ("b".to_string(), scaled(100, 2)),
            ],
        )
        .expect("messbar");
        assert_eq!(nah.as_fraction().0, 0);

        // Beobachtung 2: das schwerer gewichtete Praedikat verfehlt.
        let fern = WishDistance::measure(
            &wish,
            &[
                ("a".to_string(), scaled(100, 2)),
                ("b".to_string(), scaled(0, 2)),
            ],
        )
        .expect("messbar");
        assert!(nah.is_closer_than(&fern));
        assert!(!fern.is_closer_than(&nah));

        // Exakt, nicht gerundet: 3/4 als Bruch, nicht als 0.75.
        assert_eq!(fern.as_fraction(), (300, 400));
    }

    /// QPM Regel 11.3 (Regelkreis): der Kreis schliesst erst bei der
    /// Reobservation.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: eine Materialisierung
    /// ist NICHT geschlossen, und aus ihr entsteht eine Closure NUR
    /// ueber `reobserve`. Ohne die erste Haelfte pruefte der Test nur,
    /// dass `reobserve` etwas zurueckgibt.
    #[test]
    fn closure_comes_from_reobservation_not_from_intent() {
        let materialisiert = Materialization::after_full_pass();
        assert!(
            !materialisiert.is_closed(),
            "Z_{{t+1}} ist kein Abschluss - der Kreis ist offen"
        );
        assert_eq!(materialisiert.stages().len(), 5);
        assert_eq!(
            materialisiert.stages().last(),
            Some(&LoopStage::Materialize)
        );

        let geschlossen = reobserve(materialisiert, "die Zielfacette ist erneut gemessen worden")
            .expect("Reobservation liegt vor");
        assert!(geschlossen.was_reobserved());
        assert_eq!(geschlossen.stages().len(), 6);
        assert_eq!(geschlossen.stages().last(), Some(&LoopStage::Reobserve));

        // Eine leere Reobservation schliesst nichts.
        assert_eq!(
            reobserve(Materialization::after_full_pass(), "   ").expect_err("leer"),
            ClosureBreach::EmptyObservation
        );
    }

    /// QPM Struktur 11.6 (Rekonstruktive Wish-Klasse): fuenf Ergebnisse,
    /// und "erzwungene Eindeutigkeit ist ein Fehler".
    ///
    /// ERWARTUNG: zwei Ueberlebende ergeben `FinitelyAmbiguous` und
    /// NIEMALS `Unique` - es gibt keinen Parameter, der das aendern
    /// koennte. Ohne diesen Fall bliebe offen, ob die Funktion bei
    /// Mehrdeutigkeit den ersten Treffer nimmt.
    #[test]
    fn ambiguity_is_never_forced_into_uniqueness() {
        let zwei = narrow_class(vec!["h1".into(), "h2".into()], true, true);
        match &zwei {
            WishOutcome::FinitelyAmbiguous { hypotheses } => assert_eq!(hypotheses.len(), 2),
            other => panic!("erzwungene Eindeutigkeit: {other:?}"),
        }

        let eine = narrow_class(vec!["h1".into()], true, true);
        assert!(matches!(eine, WishOutcome::Unique { .. }));

        let keine = narrow_class(vec![], true, true);
        assert!(matches!(keine, WishOutcome::OpenUnknown { .. }));

        let ausserhalb = narrow_class(vec!["h1".into()], false, true);
        assert!(matches!(ausserhalb, WishOutcome::OutOfScope { .. }));

        let ungueltig = narrow_class(vec!["h1".into()], true, false);
        assert!(matches!(ungueltig, WishOutcome::Invalid { .. }));
    }

    /// Der gemessene Unterschied zu QPMs Ergebnisordnung, als Test statt
    /// als Prosa.
    ///
    /// ERWARTUNG: eine `Unique` entsteht hier OHNE jeden Katalog - allein
    /// aus der Kardinalitaet. Auf der QPM-Seite ist KNOWN per Definition
    /// ein Katalogtreffer und ohne registrierten Katalog unerreichbar.
    /// Damit sind die beiden ersten Werte verschiedene Dinge, und die
    /// Mengen decken sich nicht.
    #[test]
    fn a_unique_class_here_needs_no_catalog_unlike_qpms_known() {
        // Kein Katalog, kein Woerterbuch, keine Akzeptanzregion - nur
        // eine ueberlebende Hypothese.
        let ergebnis = narrow_class(vec!["die einzige".into()], true, true);
        assert!(matches!(ergebnis, WishOutcome::Unique { .. }));

        // Und die Gegenprobe zur Namensgleichheit: die beiden
        // Randfaelle heissen gleich, tragen hier aber ihren eigenen
        // Grund.
        let ausserhalb = narrow_class(vec!["h".into()], false, true);
        match ausserhalb {
            WishOutcome::OutOfScope { reason } => assert!(reason.contains("epsilon")),
            other => panic!("{other:?}"),
        }
    }
}

// ---------------------------------------------------------------------
// Nachtrag: der Abhaengigkeitsquotient und die Quotientenstabilitaet des
// Forward/Inverse-Channels. Beides gehoert zu L5 und fehlte im ersten
// Zug - siehe den Abschnitt "Was NRAII-5 verlangt" im Modulkopf.
// ---------------------------------------------------------------------

/// Eine Perspektive im Sinne von
/// QPM Definition 11.7 (Abhängigkeitsquotient, zweite Instanz), mit den
/// vier Merkmalen, die sie abhaengig machen: "Quelle, Kalibrierung,
/// Heuristik oder Vorverarbeitung".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WishPerspective {
    pub hypothesis: String,
    pub source: String,
    pub calibration: String,
    pub heuristic: String,
    pub preprocessing: String,
}

/// Warum zwei Perspektiven nicht doppelt zaehlen - benannt, nicht als
/// blosses `true`.
///
/// Der BEFUND, den NRAII liefert. Die Einordnung in ein
/// `DependencyProfile` gehoert M10 (`psk-dependency`), und nach
/// QPM Regel 9.3 (Was NRAII feststellt, ordnet der Eigner ein) wird sie
/// hier nicht getroffen: eine Abhaengigkeit auf ein Modulpaket waere die
/// Architekturbindung, die QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)
/// ausschliesst, ein eigener Quotient die Parallelstruktur, die
/// QPM Definition 11.7 (Abhängigkeitsquotient, zweite Instanz)
/// ausschliesst ("dieselbe Konstruktion wie PSK-RAs
/// DependencyProfile").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SharedDependency {
    Source,
    Calibration,
    Heuristic,
    Preprocessing,
}

impl SharedDependency {
    pub fn label(&self) -> &'static str {
        match self {
            SharedDependency::Source => "Quelle",
            SharedDependency::Calibration => "Kalibrierung",
            SharedDependency::Heuristic => "Heuristik",
            SharedDependency::Preprocessing => "Vorverarbeitung",
        }
    }
}

/// Stellt fest, WAS zwei Perspektiven teilen - leer heisst unabhaengig.
///
/// Der Befund ist eine Liste, kein Wahrheitswert: wer die effektive
/// Evidenz zaehlt, muss wissen, WORAN die Abhaengigkeit haengt. Ein
/// blosses `true` liesse offen, ob eine Kalibrierung oder eine ganze
/// Quelle geteilt wird.
pub fn shared_dependencies(a: &WishPerspective, b: &WishPerspective) -> Vec<SharedDependency> {
    let mut out = Vec::new();
    if a.source == b.source {
        out.push(SharedDependency::Source);
    }
    if a.calibration == b.calibration {
        out.push(SharedDependency::Calibration);
    }
    if a.heuristic == b.heuristic {
        out.push(SharedDependency::Heuristic);
    }
    if a.preprocessing == b.preprocessing {
        out.push(SharedDependency::Preprocessing);
    }
    out
}

/// Die Perspektivenpaare, die nach QPM Definition 11.7 (Abhängigkeitsquotient, zweite Instanz)
/// NICHT doppelt zaehlen duerfen - als Befund fuer den Eigner.
///
/// Gibt Indexpaare mit dem geteilten Merkmal zurueck. Was daraus an
/// effektiver Evidenz folgt, rechnet M10.
pub fn dependent_pairs(
    perspectives: &[WishPerspective],
) -> Vec<(usize, usize, Vec<SharedDependency>)> {
    let mut out = Vec::new();
    for i in 0..perspectives.len() {
        for j in (i + 1)..perspectives.len() {
            let shared = shared_dependencies(&perspectives[i], &perspectives[j]);
            if !shared.is_empty() {
                out.push((i, j, shared));
            }
        }
    }
    out
}

/// Hebt den Forward/Inverse-Channel auf die Diamant-Klassen - die
/// "Quotientenstabilitaet" aus NRAII-5.
///
/// BINDUNG an das Werkzeug aus L1, kein zweiter Mechanismus:
/// [`crate::lift`] prueft `x ~diamant y => T(x) ~diamant T(y)` an
/// vorgelegten Zeugen und weist eine vakuoese Zeugenmenge zurueck. Ein
/// Channel, der die Klassen zerreisst, wird nicht gehoben - und ohne
/// Hebung gibt es keine Wirkung auf Klassen.
///
/// Der Name sagt, was geprueft wird, nicht was gehofft wird: stabil
/// heisst hier gemessen.
pub fn lift_channel<X, F>(
    channel: F,
    witnesses: &[(X, X)],
) -> Result<crate::QuotientOperator<X, F>, crate::CompatibilityBreach>
where
    X: crate::Signed,
    F: Fn(&X) -> X,
{
    crate::lift(channel, witnesses)
}

#[cfg(test)]
mod nachtrag_tests {
    use super::*;

    fn perspektive(h: &str, quelle: &str, kal: &str) -> WishPerspective {
        WishPerspective {
            hypothesis: h.to_string(),
            source: quelle.to_string(),
            calibration: kal.to_string(),
            heuristic: "h-std".to_string(),
            preprocessing: "p-std".to_string(),
        }
    }

    /// QPM Definition 11.7 (Abhängigkeitsquotient, zweite Instanz): der
    /// Befund nennt das geteilte Merkmal, nicht nur die Tatsache.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: zwei Perspektiven mit
    /// derselben Quelle teilen mindestens `Quelle`, und der Befund sagt
    /// welches Merkmal. Zwei mit verschiedenen Quellen UND verschiedener
    /// Kalibrierung teilen nur noch die Standardwerte - ohne diesen
    /// zweiten Fall bliebe offen, ob die Funktion immer alles meldet.
    #[test]
    fn the_dependency_finding_names_what_is_shared() {
        let a = perspektive("h1", "q1", "k1");
        let b = perspektive("h2", "q1", "k2");
        let geteilt = shared_dependencies(&a, &b);
        assert!(geteilt.contains(&SharedDependency::Source));
        assert!(!geteilt.contains(&SharedDependency::Calibration));

        // Die Standardwerte fuer Heuristik und Vorverarbeitung sind
        // gleich - der Befund meldet auch sie, denn sie SIND geteilt.
        assert!(geteilt.contains(&SharedDependency::Heuristic));

        // Paare ueber einer Menge.
        let paare = dependent_pairs(&[a, b, perspektive("h3", "q9", "k9")]);
        assert_eq!(paare.len(), 3, "jedes Paar teilt mindestens die Standards");
        assert!(paare.iter().all(|(_, _, s)| !s.is_empty()));
    }

    /// Die zweite Haelfte des Nachweises nach
    /// QPM Regel 9.3 (Was NRAII feststellt, ordnet der Eigner ein): der
    /// Befund bleibt unter zwei verschiedenen Einordnungen derselbe.
    ///
    /// ERWARTUNG: dieselbe Perspektivenmenge, zweimal von verschiedenen
    /// Eignern eingeordnet, ergibt DENSELBEN Befund - weil NRAII gar
    /// nicht einordnet. Waere die Herkunft heimlich konstant, koennte
    /// dieser Test es nicht sehen; deshalb ordnen die beiden
    /// Einordnungen wirklich verschieden.
    #[test]
    fn the_finding_survives_two_different_classifications() {
        let menge = [perspektive("h1", "q1", "k1"), perspektive("h2", "q1", "k2")];
        let befund = dependent_pairs(&menge);

        // Einordnung A: der Eigner zaehlt geteilte Quellen als eine
        // Klasse.
        let klassen_a = if befund
            .iter()
            .any(|(_, _, s)| s.contains(&SharedDependency::Source))
        {
            1
        } else {
            2
        };
        // Einordnung B: der Eigner zaehlt nur geteilte KALIBRIERUNG.
        let klassen_b = if befund
            .iter()
            .any(|(_, _, s)| s.contains(&SharedDependency::Calibration))
        {
            1
        } else {
            2
        };

        assert_ne!(
            klassen_a, klassen_b,
            "die beiden Einordnungen sind wirklich verschieden"
        );
        // Und der BEFUND ist beide Male derselbe.
        assert_eq!(befund, dependent_pairs(&menge));
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Hypothese {
        klasse: &'static str,
        text: &'static str,
    }

    impl crate::Signed for Hypothese {
        type Sig = &'static str;
        fn signature(&self) -> &'static str {
            self.klasse
        }
    }

    /// Die Quotientenstabilitaet des Channels - GEPRUEFT, nicht
    /// behauptet.
    ///
    /// ERWARTUNG: ein Channel, der nur den Text aendert, ist stabil und
    /// laesst sich heben; einer, der die Klasse quellabhaengig aendert,
    /// wird zurueckgewiesen. Ohne den zweiten Fall sagte der erste nur,
    /// dass `lift_channel` etwas zurueckgibt.
    #[test]
    fn a_quotient_stable_channel_lifts_an_unstable_one_does_not() {
        let stabil = |h: &Hypothese| Hypothese {
            text: "rekonstruiert",
            ..h.clone()
        };
        let zeugen = [(
            Hypothese {
                klasse: "A",
                text: "eins",
            },
            Hypothese {
                klasse: "A",
                text: "zwei",
            },
        )];
        let gehoben = lift_channel(stabil, &zeugen).expect("quotientenstabil");
        assert_eq!(gehoben.checked_pairs(), 1);

        let instabil = |h: &Hypothese| Hypothese {
            klasse: if h.text == "eins" { "A" } else { "B" },
            ..h.clone()
        };
        assert!(
            lift_channel(instabil, &zeugen).is_err(),
            "ein Channel, der die Klasse zerreisst, wird nicht gehoben"
        );
    }
}
