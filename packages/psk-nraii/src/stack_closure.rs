//! L7: Attraktorstack, Fold und Proof-Horizon.
//!
//! QPM Struktur 9.1 (Normative Schichten L0–L9) gibt der Schicht die
//! Rolle "Einbettungszertifikate, Fold, Nullmodelle, Falsifikation";
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB)
//! verlangt fuer NRAII-7 vier Stuecke: "Attraktorstack, FoldBundle,
//! Proof-Horizon und Falsifikationsharness".
//!
//! ## Was die Vormessung ergeben hat
//!
//! Zwei der vier Stuecke tragen Namen, die L4 schon gebaut hatte. Die
//! Frage war, ob sie dieselbe Sache sind oder nur gleich heissen -
//! dieselbe Frage wie bei der Wish-Fuenfermenge. Gemessen, Stueck fuer
//! Stueck:
//!
//! **Proof-Horizon: dieselbe Sache, aber zu klein.**
//! [`crate::ProofHorizon`] setzt QPM Definition 13.5 (Proof-Horizon)
//! woertlich um - endlich, versioniert, und `is_closed` haelt stabil
//! von geschlossen getrennt. Nur macht
//! QPM Definition 16.3 (4-4-4-Closure) davon einen Gebrauch, den L4
//! nicht hergab: sie verlangt, dass offene Pflichten "erfuellt ODER
//! explizit als nichtclosurewirksam klassifiziert" sind. Dieser zweite
//! Weg war nicht ausdrueckbar. Nachgetragen in `diagnostic_field`
//! ([`crate::ObligationStanding`]) statt hier neu gebaut - ein zweiter
//! Proof-Horizon waere die Parallelstruktur, die wir sonst ueberall
//! vermeiden. **Bindung, plus eine fehlende Unterscheidung.**
//!
//! **Falsifikationsharness: nur der Name.**
//! QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness) sagt "Der
//! Harness PRUEFT mindestens: ..." - er prueft. L4 baute
//! [`crate::FalsificationCheck`], das geschlossene Vokabular der zehn
//! Pruefungen, und sonst nichts: gemessen wird der Typ an drei Stellen
//! benutzt, und alle drei zaehlen bis zehn oder lesen Bezeichnungen.
//! Der L4-Test heisst `the_harness_lists_all_ten_checks` - er listet.
//! **Das Vokabular des Harness ist nicht der Harness.** Neubau, hier.
//!
//! L7 ist damit nicht zur Haelfte Bindung, sondern zu einem Viertel.
//!
//! ## Zwei undefinierte Stufenbegriffe, und wie sie normativ wurden
//!
//! Bis v1.0.17 waren zwei der vier Namen im Werk nirgends definiert:
//! **Attraktorstack** kam genau einmal in einem normativen Block vor
//! (QPM Regel 17.6 (Irreduzibler Kern)) und dort nur als das, was
//! kondensiert wird; **FoldBundle** ausschliesslich in der
//! Stufenanforderung und ihrem Registerecho, ebenso "Fold" und
//! "Huelle".
//!
//! Als Befund gemeldet und abgeleitet aus dem einen Block, der sie
//! beschraenkt - nicht gewaehlt. Dasselbe Vorgehen wie beim
//! Zykluswitness vor v1.0.14 und beim Channel vor v1.0.16.
//!
//! **QPM Struktur 17.4 (Attraktorstack und FoldBundle) hat die Lesart
//! in v1.0.18 festgeschrieben**, und sie deckt sich in allen drei
//! Punkten mit dem hier Gebauten:
//!
//! - "Jeder Uebergang zwischen zwei Stufen MUSS zertifiziert sein, und
//!   eine Herkunftsklasse, die beim Verdichten ganz verschwindet, MUSS
//!   verbucht werden" - [`AttractorStack::embed`] und
//!   [`EmbeddingCertificate::issue`].
//! - "Ein Fixpunkt gilt genau dann als erreicht, wenn alle drei
//!   denselben K* reproduzieren" - [`reach_fixpoint`].
//! - "Was Fold und Huelle je Domaene konkret sind, ist domaenengeliefert
//!   wie das GateSet" - dieselbe Form wie in
//!   QPM Regel 14.5 (Woher das Gate des Zyklus kommt) und beim
//!   `origin_module`.
//!
//! ## Warum das nicht nur eine Fussnote ist
//!
//! QPM Regel 17.5 (Undefinierte Stufenbegriffe) macht das Verfahren zur
//! Regel: ein undefinierter Stufenbegriff ist "aus den Bloecken
//! abzuleiten, die ihn beschraenken, und DARF NICHT frei zu waehlen";
//! ergibt die Ableitung nichts, ist die Stufe nicht erfuellbar und das
//! zu MELDEN, "nicht durch eine plausible Erfindung zu schliessen".
//!
//! Und die zweite Haelfte bindet uns: "Eine so abgeleitete Lesart MUSS
//! beim naechsten Werksstand festgeschrieben werden." Daraus folgt eine
//! Pflicht an diesem Kommentar selbst - steht die Lesart erst einmal im
//! Werk, MUSS der Modulkopf das sagen, statt weiter zu behaupten, das
//! Werk gebe nichts her. Genau das war hier und in `wish` faellig.
//!
//! ## Wo L7 aufhoert
//!
//! [`StackFixpoint`] ist der Fixpunkt aus
//! QPM Regel 17.6 (Irreduzibler Kern), NICHT der "gate- und
//! replayzertifizierte" Kern K*. Die Zertifizierung ist NRAII-8
//! (`C444`, Gate, Replay, PathInv), und
//! QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis) ist genau die
//! Regel, die das Zusammenziehen verbietet. Ein Fixpunkt, der sich hier
//! schon Kern nennte, waere derselbe Fehler in klein.

use crate::{AttractorMap, CanonicalState, FalsificationCheck, ResponseOrigin};
use psk_types::Digest;
use std::collections::BTreeMap;

// ---------------------------------------------------------------- Harness

/// Wie eine der zehn Pruefungen ausgegangen ist.
///
/// Drei Werte, nicht zwei, und der dritte ist der Grund fuer diesen
/// Typ: eine Pruefung, die nicht lief, ist kein Freispruch. Genau das
/// ist die Fehlerform, gegen die ein Harness gebaut wird - ein Bericht
/// "keine Falsifikation gefunden" von einem Lauf, der nichts geprueft
/// hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckOutcome {
    /// Die Pruefung lief und schlug an: der Kandidat ist an dieser
    /// Stelle falsifiziert.
    Falsified { evidence: String },
    /// Die Pruefung lief und schlug nicht an.
    Held { evidence: String },
    /// Die Pruefung lief NICHT - mit benanntem Grund
    /// (Regel 7.51 (Erklärter Nullstand): die Leere traegt Bedingung
    /// und Sichtbarkeit, sie wird nicht ersatzgefuellt).
    NotProbed { reason: String },
}

/// Eine Sonde: was die Domaene fuer eine der zehn Pruefungen mitbringt.
///
/// Die zehn Pruefungen sind vom Werk vorgegeben und geschlossen
/// (QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness)); WIE man
/// in einer konkreten Domaene eine Signaturkollision feststellt, ist es
/// nicht. Die Nullmodellfamilie dazu ist ausdruecklich domaenengeliefert
/// (QPM Offene Implementierungsverpflichtung 18.5 (NRAII-OBL-002: Komponentendiktionär der Nullmodellfamilie)).
pub trait Probe {
    /// Welche der zehn Pruefungen diese Sonde bedient.
    fn check(&self) -> FalsificationCheck;

    fn run(&self, subject: &CanonicalState) -> CheckOutcome;
}

/// Das Ergebnis eines Harnesslaufs - immer ueber alle zehn Pruefungen.
///
/// Es gibt keinen Konstruktor ausser [`run_harness`]. Ein Bericht mit
/// neun Eintraegen ist damit nicht bloss unerwuenscht, sondern
/// unbildbar: das "mindestens" aus
/// QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness) ist die
/// Form des Typs.
///
/// ```compile_fail,E0451
/// let _ = psk_nraii::HarnessReport { outcomes: Default::default() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HarnessReport {
    outcomes: BTreeMap<FalsificationCheck, CheckOutcome>,
}

impl HarnessReport {
    pub fn outcome(&self, check: FalsificationCheck) -> &CheckOutcome {
        self.outcomes
            .get(&check)
            .expect("run_harness belegt alle zehn")
    }

    /// Welche Pruefungen angeschlagen haben.
    pub fn falsified(&self) -> Vec<FalsificationCheck> {
        self.select(|o| matches!(o, CheckOutcome::Falsified { .. }))
    }

    /// Welche Pruefungen NICHT liefen. Getrennt von [`Self::falsified`]
    /// gefuehrt, weil die beiden verschiedene Dinge bedeuten und ein
    /// gemeinsamer Zaehler sie zusammenzoege.
    pub fn unprobed(&self) -> Vec<FalsificationCheck> {
        self.select(|o| matches!(o, CheckOutcome::NotProbed { .. }))
    }

    /// Nur wahr, wenn alle zehn Pruefungen liefen UND keine anschlug.
    ///
    /// Eine ungelaufene Pruefung macht den Bericht nicht sauber. Das
    /// ist die ganze Aussage dieses Typs.
    pub fn is_clean(&self) -> bool {
        self.outcomes
            .values()
            .all(|o| matches!(o, CheckOutcome::Held { .. }))
    }

    fn select(&self, f: impl Fn(&CheckOutcome) -> bool) -> Vec<FalsificationCheck> {
        self.outcomes
            .iter()
            .filter(|(_, o)| f(o))
            .map(|(c, _)| *c)
            .collect()
    }
}

/// Der Falsifikationsharness: laeuft ueber alle zehn Pruefungen aus
/// QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness).
///
/// Zwei Eigenschaften, die ihn von einer Liste unterscheiden:
///
/// 1. **Der Boden von zehn steht.** Jede Pruefung ohne Sonde erscheint
///    als [`CheckOutcome::NotProbed`] mit Grund, nicht als Leerstelle
///    und nicht als bestanden.
/// 2. **Falsifikation ist absorbierend.** Mehrere Sonden fuer dieselbe
///    Pruefung koennen sich nicht gegenseitig aufheben: schlaegt eine
///    an, ist die Pruefung falsifiziert - unabhaengig von der
///    Reihenfolge. Ein "eine andere Sonde sagte, es sei in Ordnung"
///    hebt einen Gegenbefund nicht auf.
pub fn run_harness(subject: &CanonicalState, probes: &[&dyn Probe]) -> HarnessReport {
    let mut outcomes: BTreeMap<FalsificationCheck, CheckOutcome> = FalsificationCheck::all()
        .into_iter()
        .map(|c| {
            (
                c,
                CheckOutcome::NotProbed {
                    reason: format!("keine Sonde fuer '{}' gestellt", c.label()),
                },
            )
        })
        .collect();

    for probe in probes {
        let check = probe.check();
        let neu = probe.run(subject);
        let bisher = outcomes.get(&check).expect("alle zehn vorbelegt");
        // Ein bestehender Gegenbefund bleibt stehen.
        if matches!(bisher, CheckOutcome::Falsified { .. }) {
            continue;
        }
        outcomes.insert(check, neu);
    }

    HarnessReport { outcomes }
}

// ------------------------------------------------------------------ Stack

/// Warum ein Stack nicht steht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StackBreach {
    /// Zwischen zwei Ebenen ist eine Herkunftsklasse ganz verschwunden,
    /// ohne dass die Einbettung sie verbucht - genau der Fall, den
    /// QPM Invariante 14.6 (Kein Assimilationssprung) ausschliesst:
    /// "Abgetrennte Fremdmasse erscheint als Residuum, nicht als
    /// Verlust."
    OriginVanished {
        lower: String,
        upper: String,
        origin: &'static str,
    },
    /// Ein Stack aus weniger als zwei Ebenen hat keine Einbettung -
    /// und damit nichts, worueber ein Zertifikat etwas aussagte.
    NothingToEmbed,
}

/// Eine Ebene des Attraktorstacks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackLevel {
    pub id: String,
    pub map: AttractorMap,
}

/// Ein Einbettungszertifikat zwischen zwei benachbarten Ebenen.
///
/// Der Wortlaut von QPM Struktur 17.4 (Attraktorstack und FoldBundle):
/// "Jeder Uebergang zwischen zwei Stufen MUSS zertifiziert sein, und
/// eine Herkunftsklasse, die beim Verdichten ganz verschwindet, MUSS
/// verbucht werden - derselbe Defekt wie Boundary-Absorption ohne
/// Residuum, eine Etage hoeher."
///
/// Geprueft wird deshalb genau das und nichts Erfundenes: der Stack
/// VERDICHTET (QPM Regel 17.6 (Irreduzibler Kern) laesst ihn
/// kondensieren), also duerfen Zahlen fallen - aber eine
/// Herkunftsklasse, die ganz verschwindet, MUSS verbucht sein. Ein
/// Nullmodell, das zwischen zwei Ebenen lautlos aufhoert zu existieren,
/// waere der Defekt, den der Satz benennt.
///
/// Was eine Einbettung darueber hinaus in einer Domaene bedeutet, kommt
/// als `accounted` herein.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingCertificate {
    lower: String,
    upper: String,
    /// Welche Herkunftsklassen beim Aufstieg endeten, je mit dem Grund.
    accounted: Vec<(&'static str, String)>,
}

impl EmbeddingCertificate {
    /// Der einzige Weg zu einem Zertifikat.
    pub fn issue(
        lower: &StackLevel,
        upper: &StackLevel,
        accounted: &[(ResponseOrigin, String)],
    ) -> Result<Self, StackBreach> {
        let unten = lower.map.by_origin();
        let oben = upper.map.by_origin();
        let mut verbucht = Vec::new();
        for origin in ResponseOrigin::all() {
            if unten[&origin] == 0 || oben[&origin] > 0 {
                continue;
            }
            let grund = accounted
                .iter()
                .find(|(o, g)| *o == origin && !g.trim().is_empty())
                .map(|(_, g)| g.clone());
            match grund {
                Some(g) => verbucht.push((origin.label(), g)),
                None => {
                    return Err(StackBreach::OriginVanished {
                        lower: lower.id.clone(),
                        upper: upper.id.clone(),
                        origin: origin.label(),
                    })
                }
            }
        }
        Ok(EmbeddingCertificate {
            lower: lower.id.clone(),
            upper: upper.id.clone(),
            accounted: verbucht,
        })
    }

    pub fn lower(&self) -> &str {
        &self.lower
    }

    pub fn upper(&self) -> &str {
        &self.upper
    }

    /// Was beim Aufstieg endete - als Befund, nicht als Loch.
    pub fn accounted(&self) -> &[(&'static str, String)] {
        &self.accounted
    }
}

/// Der Attraktorstack: geordnete Ebenen mit einem Zertifikat je
/// Uebergang.
///
/// Es gibt keinen Weg zu einem Stack ohne die Zertifikate: [`embed`]
/// stellt sie aus oder scheitert. Ein Stack, dessen Ebenen nur
/// nebeneinanderlaegen, waere die Buchfuehrung, die er ersetzen soll.
///
/// [`embed`]: AttractorStack::embed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttractorStack {
    levels: Vec<StackLevel>,
    certificates: Vec<EmbeddingCertificate>,
}

impl AttractorStack {
    /// Baut den Stack von unten nach oben und zertifiziert jeden
    /// Uebergang.
    pub fn embed(
        levels: Vec<StackLevel>,
        accounted: &[(ResponseOrigin, String)],
    ) -> Result<Self, StackBreach> {
        if levels.len() < 2 {
            return Err(StackBreach::NothingToEmbed);
        }
        let mut certificates = Vec::new();
        for paar in levels.windows(2) {
            certificates.push(EmbeddingCertificate::issue(&paar[0], &paar[1], accounted)?);
        }
        Ok(AttractorStack {
            levels,
            certificates,
        })
    }

    pub fn levels(&self) -> &[StackLevel] {
        &self.levels
    }

    pub fn certificates(&self) -> &[EmbeddingCertificate] {
        &self.certificates
    }

    /// Die oberste Ebene - das, was kondensiert wird
    /// (QPM Regel 17.6 (Irreduzibler Kern)).
    pub fn top(&self) -> &StackLevel {
        self.levels.last().expect("embed verlangt zwei Ebenen")
    }
}

// ------------------------------------------------------------------- Fold

/// Die drei Wege, die nach QPM Regel 17.6 (Irreduzibler Kern)
/// gemeinsam denselben `K*` reproduzieren muessen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reproducer {
    /// "Fold" - im Werk benannt, nicht definiert; domaenengeliefert.
    Fold,
    /// "Huelle" - ebenso.
    Hull,
    /// "quasi-singulaere Kondensation" - als einzige der drei im Werk
    /// definiert (QPM Definition 14.3 (QSNA)) und in L6 als
    /// [`crate::Qsna`] gebaut.
    Condensation,
}

impl Reproducer {
    pub fn all() -> [Reproducer; 3] {
        [Reproducer::Fold, Reproducer::Hull, Reproducer::Condensation]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Reproducer::Fold => "Fold",
            Reproducer::Hull => "Huelle",
            Reproducer::Condensation => "quasi-singulaere Kondensation",
        }
    }
}

/// Warum kein Fixpunkt zustande kommt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FixpointBreach {
    /// Zwei der drei Wege kommen auf verschiedene Ergebnisse. Der
    /// Befund nennt BEIDE - "kein Fixpunkt" allein sagte nicht, wo man
    /// nachzusehen hat.
    Disagreement { left: Reproducer, right: Reproducer },
}

/// Das FoldBundle: die drei Reproduzenten aus
/// QPM Regel 17.6 (Irreduzibler Kern), zusammen vorgelegt.
///
/// QPM Struktur 17.4 (Attraktorstack und FoldBundle) sagt es seit
/// v1.0.18 als eigenen Satz: "Das FoldBundle ist das Buendel der drei
/// Reproduzenten: Fold, Huelle und quasi-singulaere Kondensation. Ein
/// Fixpunkt gilt genau dann als erreicht, wenn alle drei denselben K*
/// reproduzieren." Bis dahin war das aus
/// QPM Regel 17.6 (Irreduzibler Kern) abgeleitet - dem einzigen Block,
/// der ueber Fold ueberhaupt etwas sagt.
///
/// Jeder der drei Wege legt sein Ergebnis als kanonischen Zustand vor.
/// Verglichen werden Digests der GETEILTEN Kanonisierung - drei Wege,
/// die dasselbe meinen, es aber verschieden schreiben, sind ein
/// Fixpunkt und kein Widerspruch. Dieselbe Ueberlegung wie bei `chi`,
/// wo derselbe Fehler einmal drinsteckte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoldBundle {
    results: BTreeMap<Reproducer, CanonicalState>,
}

impl FoldBundle {
    pub fn bundle(
        fold: CanonicalState,
        hull: CanonicalState,
        condensation: CanonicalState,
    ) -> Self {
        FoldBundle {
            results: BTreeMap::from([
                (Reproducer::Fold, fold),
                (Reproducer::Hull, hull),
                (Reproducer::Condensation, condensation),
            ]),
        }
    }

    pub fn result(&self, r: Reproducer) -> &CanonicalState {
        self.results.get(&r).expect("alle drei gebuendelt")
    }
}

/// Der Fixpunkt aus QPM Regel 17.6 (Irreduzibler Kern) - und
/// ausdruecklich noch nicht `K*`.
///
/// "Ein Fixpunkt gilt als erreicht, wenn Fold, Huelle und
/// quasi-singulaere Kondensation gemeinsam denselben K* reproduzieren."
/// Der gate- und replayzertifizierte Kern ist NRAII-8; dieser Typ
/// traegt den Fixpunkt und sagt mit seinem Namen, dass er die
/// Zertifizierung nicht enthaelt
/// (QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis)).
///
/// Von aussen unkonstruierbar - der Weg fuehrt nur ueber
/// [`reach_fixpoint`], und der vergleicht drei Wege:
///
/// ```compile_fail,E0451
/// let _ = psk_nraii::StackFixpoint { digest: todo!(), condensed_from: String::new() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFixpoint {
    digest: Digest,
    condensed_from: String,
}

impl StackFixpoint {
    /// `H(Can(K*))` - der Digest, auf den alle drei Wege fielen.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Die Ebene des Stacks, aus der kondensiert wurde. Ohne sie waere
    /// der Fixpunkt eine Zahl ohne Herkunft.
    pub fn condensed_from(&self) -> &str {
        &self.condensed_from
    }
}

/// Kondensiert den Attraktorstack ueber das FoldBundle
/// (QPM Regel 17.6 (Irreduzibler Kern)).
///
/// Prueft ALLE drei Paare, nicht zwei: aus `Fold == Huelle` und
/// `Fold == Kondensation` folgte die dritte Gleichheit zwar
/// rechnerisch, aber der Befund soll das Paar nennen, das wirklich
/// auseinanderging.
pub fn reach_fixpoint(
    stack: &AttractorStack,
    bundle: &FoldBundle,
) -> Result<StackFixpoint, FixpointBreach> {
    let alle = Reproducer::all();
    for (i, left) in alle.iter().enumerate() {
        for right in alle.iter().skip(i + 1) {
            if bundle.result(*left).digest() != bundle.result(*right).digest() {
                return Err(FixpointBreach::Disagreement {
                    left: *left,
                    right: *right,
                });
            }
        }
    }
    Ok(StackFixpoint {
        digest: bundle.result(Reproducer::Fold).digest(),
        condensed_from: stack.top().id.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ObligationStanding, ProofHorizon, ProofObligation, Response};
    use psk_canon::Media;

    fn zustand(inhalt: &str) -> CanonicalState {
        CanonicalState::canonicalize(inhalt.as_bytes(), Media::Json).expect("kanonisierbar")
    }

    fn antwort(marker: &str, origin: ResponseOrigin) -> Response {
        Response {
            marker: marker.to_string(),
            value: format!("{marker}-wert"),
            origin,
        }
    }

    fn ebene(id: &str, origins: &[ResponseOrigin]) -> StackLevel {
        StackLevel {
            id: id.to_string(),
            map: AttractorMap::triangulate(
                origins
                    .iter()
                    .enumerate()
                    .map(|(i, o)| antwort(&format!("m{i}"), *o))
                    .collect(),
            ),
        }
    }

    struct FesteSonde(FalsificationCheck, CheckOutcome);

    impl Probe for FesteSonde {
        fn check(&self) -> FalsificationCheck {
            self.0
        }
        fn run(&self, _subject: &CanonicalState) -> CheckOutcome {
            self.1.clone()
        }
    }

    fn haelt(c: FalsificationCheck) -> FesteSonde {
        FesteSonde(
            c,
            CheckOutcome::Held {
                evidence: format!("{}-geprueft", c.label()),
            },
        )
    }

    /// QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness): der
    /// Harness PRUEFT - und zwar mindestens zehn Dinge.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: mit allen zehn Sonden
    /// ist der Bericht sauber; mit neun ist er es NICHT, und die
    /// fehlende erscheint als `NotProbed` mit Grund. Der zweite Fall
    /// traegt den Test - der erste allein sagte nur, dass `is_clean`
    /// manchmal wahr wird, und liesse offen, ob ein Harness, der nichts
    /// prueft, ebenfalls sauber meldet. Genau das ist die Fehlerform.
    #[test]
    fn a_harness_that_did_not_run_a_check_is_not_clean() {
        let subjekt = zustand(r#"{"k":1}"#);

        let alle: Vec<FesteSonde> = FalsificationCheck::all().into_iter().map(haelt).collect();
        let refs: Vec<&dyn Probe> = alle.iter().map(|s| s as &dyn Probe).collect();
        let voll = run_harness(&subjekt, &refs);
        assert!(
            voll.is_clean(),
            "zehn gelaufene Pruefungen, keine schlug an"
        );
        assert!(voll.unprobed().is_empty());

        // Und jetzt einzeln fuer JEDE der zehn: ohne ihre Sonde ist der
        // Bericht nicht sauber, und SIE ist die ungeprueft gebliebene.
        for fehlend in FalsificationCheck::all() {
            let rest: Vec<FesteSonde> = FalsificationCheck::all()
                .into_iter()
                .filter(|c| *c != fehlend)
                .map(haelt)
                .collect();
            let refs: Vec<&dyn Probe> = rest.iter().map(|s| s as &dyn Probe).collect();
            let bericht = run_harness(&subjekt, &refs);

            assert!(
                !bericht.is_clean(),
                "ohne Sonde fuer {} darf der Bericht nicht sauber sein",
                fehlend.label()
            );
            assert_eq!(bericht.unprobed(), vec![fehlend]);
            assert!(
                bericht.falsified().is_empty(),
                "ungeprueft ist NICHT falsifiziert - die beiden bleiben getrennt"
            );
            match bericht.outcome(fehlend) {
                CheckOutcome::NotProbed { reason } => {
                    assert!(reason.contains(fehlend.label()), "der Grund nennt sie")
                }
                andere => panic!("erwartet NotProbed, gefunden {andere:?}"),
            }
        }
    }

    /// Ein Gegenbefund laesst sich nicht ueberschreiben.
    ///
    /// ERWARTUNG: zwei Sonden fuer dieselbe Pruefung, eine falsifiziert,
    /// eine nicht - das Ergebnis ist Falsifikation, in BEIDEN
    /// Reihenfolgen. Ohne die zweite Reihenfolge pruefte der Test nur,
    /// dass die letzte Sonde nicht gewinnt, und nicht, dass die
    /// Reihenfolge egal ist.
    #[test]
    fn falsification_absorbs_and_does_not_depend_on_probe_order() {
        let subjekt = zustand(r#"{"k":1}"#);
        let ziel = FalsificationCheck::CircularEvidence;

        let schlaegt_an = FesteSonde(
            ziel,
            CheckOutcome::Falsified {
                evidence: "die Evidenz zeigt auf sich selbst".into(),
            },
        );
        let haelt_still = haelt(ziel);

        for reihenfolge in [
            vec![&schlaegt_an as &dyn Probe, &haelt_still as &dyn Probe],
            vec![&haelt_still as &dyn Probe, &schlaegt_an as &dyn Probe],
        ] {
            let bericht = run_harness(&subjekt, &reihenfolge);
            assert_eq!(
                bericht.falsified(),
                vec![ziel],
                "eine andere Sonde hebt den Gegenbefund nicht auf"
            );
            assert!(!bericht.is_clean());
        }
    }

    /// QPM Invariante 14.6 (Kein Assimilationssprung), eine Etage
    /// hoeher: eine Herkunftsklasse, die beim Aufstieg verschwindet,
    /// MUSS verbucht sein.
    ///
    /// ERWARTUNG: der Stack verdichtet - weniger Antworten oben sind in
    /// Ordnung. Aber eine Klasse, die von "vorhanden" auf "gar nicht"
    /// faellt, reisst die Einbettung, und der Befund nennt die Klasse.
    /// Die Gegenprobe daneben ist die tragende: mit Verbuchung geht
    /// derselbe Uebergang durch.
    #[test]
    fn an_origin_class_may_not_vanish_between_levels_unaccounted() {
        let unten = ebene(
            "L-unten",
            &[
                ResponseOrigin::Data,
                ResponseOrigin::Data,
                ResponseOrigin::NullModel,
            ],
        );
        // Verdichtung: zwei Datenantworten werden eine. Das ist erlaubt.
        let oben_ok = ebene("L-oben", &[ResponseOrigin::Data, ResponseOrigin::NullModel]);
        let zertifikat =
            EmbeddingCertificate::issue(&unten, &oben_ok, &[]).expect("Verdichtung ist erlaubt");
        assert_eq!(zertifikat.lower(), "L-unten");
        assert_eq!(zertifikat.upper(), "L-oben");
        assert!(zertifikat.accounted().is_empty());

        // Verschwinden: das Nullmodell hoert auf zu existieren.
        let oben_leer = ebene("L-oben", &[ResponseOrigin::Data]);
        assert_eq!(
            EmbeddingCertificate::issue(&unten, &oben_leer, &[]).expect_err("unverbucht"),
            StackBreach::OriginVanished {
                lower: "L-unten".into(),
                upper: "L-oben".into(),
                origin: "Nullmodell",
            }
        );

        // Verbucht geht derselbe Uebergang durch - und das Zertifikat
        // traegt den Grund weiter.
        let mit_grund = EmbeddingCertificate::issue(
            &unten,
            &oben_leer,
            &[(
                ResponseOrigin::NullModel,
                "in die Kondensation eingegangen, Residuum R-17".into(),
            )],
        )
        .expect("verbucht");
        assert_eq!(mit_grund.accounted().len(), 1);
        assert_eq!(mit_grund.accounted()[0].0, "Nullmodell");

        // Und Leerraum verbucht nicht.
        assert!(EmbeddingCertificate::issue(
            &unten,
            &oben_leer,
            &[(ResponseOrigin::NullModel, "  ".into())]
        )
        .is_err());
    }

    /// Der Stack zertifiziert JEDEN Uebergang, nicht nur den ersten.
    ///
    /// ERWARTUNG: bei drei Ebenen stehen zwei Zertifikate, und ein
    /// Bruch im ZWEITEN Uebergang reisst den Stack genauso. Ein Test
    /// nur ueber den ersten liesse offen, ob die Schleife nach dem
    /// ersten Paar weiterlaeuft.
    #[test]
    fn every_transition_of_the_stack_is_certified() {
        let a = ebene("a", &[ResponseOrigin::Data, ResponseOrigin::BlockedPath]);
        let b = ebene("b", &[ResponseOrigin::Data, ResponseOrigin::BlockedPath]);
        let c = ebene("c", &[ResponseOrigin::Data]);

        let stack = AttractorStack::embed(vec![a.clone(), b.clone()], &[]).expect("zwei Ebenen");
        assert_eq!(stack.certificates().len(), 1);
        assert_eq!(stack.levels().len(), 2);
        assert_eq!(stack.top().id, "b");

        // Der Bruch sitzt im zweiten Uebergang.
        assert_eq!(
            AttractorStack::embed(vec![a.clone(), b.clone(), c.clone()], &[])
                .expect_err("b -> c verliert den blockierten Pfad"),
            StackBreach::OriginVanished {
                lower: "b".into(),
                upper: "c".into(),
                origin: "blockierter Pfad",
            }
        );

        // Verbucht: drei Ebenen, zwei Zertifikate.
        let voll = AttractorStack::embed(
            vec![a, b, c],
            &[(
                ResponseOrigin::BlockedPath,
                "Pfad wurde in c aufgeloest, Residuum R-3".into(),
            )],
        )
        .expect("verbucht");
        assert_eq!(voll.certificates().len(), 2);
        assert_eq!(voll.top().id, "c");

        // Eine einzelne Ebene bettet nichts ein.
        assert_eq!(
            AttractorStack::embed(vec![ebene("allein", &[ResponseOrigin::Data])], &[])
                .expect_err("nichts einzubetten"),
            StackBreach::NothingToEmbed
        );
    }

    /// QPM Regel 17.6 (Irreduzibler Kern): der Fixpunkt gilt erst, wenn
    /// alle DREI Wege dasselbe reproduzieren.
    ///
    /// ERWARTUNG: einig ergibt einen Fixpunkt; und jeder der drei Wege
    /// einzeln verstellt laesst ihn fallen, mit dem Paar im Befund. Ein
    /// einziger Uneinigkeitsfall liesse offen, ob der dritte Weg
    /// ueberhaupt verglichen wird - derselbe Grund wie bei der
    /// komponentenweisen Vertragsprobe.
    #[test]
    fn the_fixpoint_needs_all_three_reproducers_to_agree() {
        let stack = AttractorStack::embed(
            vec![
                ebene("unten", &[ResponseOrigin::Data]),
                ebene("oben", &[ResponseOrigin::Data]),
            ],
            &[],
        )
        .expect("zwei Ebenen");

        let gleich = || zustand(r#"{"kern":"K"}"#);
        let einig = FoldBundle::bundle(gleich(), gleich(), gleich());
        let fix = reach_fixpoint(&stack, &einig).expect("drei Wege, ein Ergebnis");
        assert_eq!(fix.condensed_from(), "oben");
        assert_eq!(&fix.digest, &gleich().digest());

        // Verschiedene SCHREIBWEISEN desselben Inhalts sind einig -
        // verglichen wird ueber die geteilte Kanonisierung, nicht ueber
        // Rohbytes.
        let anders_geschrieben = FoldBundle::bundle(
            zustand(r#"{"a":1,"b":2}"#),
            zustand(r#"{"b":2,"a":1}"#),
            zustand(r#"{"a":1,  "b":2}"#),
        );
        assert!(reach_fixpoint(&stack, &anders_geschrieben).is_ok());

        // Und jeder Weg einzeln verstellt laesst den Fixpunkt fallen.
        for abweichler in Reproducer::all() {
            let mut teile: BTreeMap<Reproducer, CanonicalState> = Reproducer::all()
                .into_iter()
                .map(|r| (r, gleich()))
                .collect();
            teile.insert(abweichler, zustand(r#"{"kern":"ANDERS"}"#));
            let uneinig = FoldBundle::bundle(
                teile[&Reproducer::Fold].clone(),
                teile[&Reproducer::Hull].clone(),
                teile[&Reproducer::Condensation].clone(),
            );
            let breach = reach_fixpoint(&stack, &uneinig).expect_err("kein Fixpunkt");
            let FixpointBreach::Disagreement { left, right } = breach;
            assert!(
                left == abweichler || right == abweichler,
                "der Befund muss {} nennen, meldete aber {left:?}/{right:?}",
                abweichler.label()
            );
        }
    }

    /// Der Fixpunkt ist NICHT die Closure.
    ///
    /// QPM Definition 16.3 (4-4-4-Closure) nennt zwei Bedingungen, und
    /// dieser Test misst, dass die eine die andere nicht mitbringt: ein
    /// erreichter Fixpunkt neben einem Proof-Horizon mit blockierender
    /// Pflicht. Waere das zusammengezogen, waere es genau der Fehler
    /// aus QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis).
    #[test]
    fn a_reached_fixpoint_does_not_by_itself_admit_closure() {
        let stack = AttractorStack::embed(
            vec![
                ebene("unten", &[ResponseOrigin::Data]),
                ebene("oben", &[ResponseOrigin::Data]),
            ],
            &[],
        )
        .expect("zwei Ebenen");
        let gleich = || zustand(r#"{"kern":"K"}"#);
        assert!(reach_fixpoint(&stack, &FoldBundle::bundle(gleich(), gleich(), gleich())).is_ok());

        let horizont = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![
                ProofObligation::open("Kalibrierung steht aus"),
                ProofObligation {
                    text: "Nullmodellfamilie ist domaenengeliefert (NRAII-OBL-002)".into(),
                    standing: ObligationStanding::NotClosureEffective {
                        justification: "das Werk liefert sie nicht".into(),
                    },
                },
            ],
        };
        assert!(
            !horizont.closure_admissible(),
            "die unklassifizierte Pflicht blockiert - der Fixpunkt aendert daran nichts"
        );
        assert_eq!(horizont.blocking().len(), 1);
        assert_eq!(horizont.blocking()[0].text, "Kalibrierung steht aus");
    }
}
