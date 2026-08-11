//! L4: das diagnostische Feld und der Gegenhorizont.
//!
//! ## Warum L4 vor L5 kommt
//!
//! Nicht Praeferenz, sondern Abhaengigkeit: der Regelkreis des
//! Wunschkalkuels (QPM Regel 11.3 (Regelkreis)) beginnt mit `Obs`, und
//! die rekonstruktive Wish-Klasse (QPM Struktur 11.6 (Rekonstruktive Wish-Klasse))
//! misst `d(Obs(w), O_ext)`. `Obs` ist das Marker- und Response-Feld
//! dieser Schicht. L5 vor L4 hiesse, `Obs` zu stubben oder zweimal zu
//! bauen.
//!
//! Die Stufenleiter belohnt L5 also nur scheinbar zuerst: NRAII-4
//! haengt an L5, aber L5 haengt an L4.
//!
//! ## Was hier Bindung ist und was neu
//!
//! Der Gegenhorizont ist BINDUNG.
//! QPM Invariante 13.3 (Counter-Horizon-Pflicht) sagt es selbst: "Deckt
//! sich mit PSK-RAs CounterHorizon in QPM-RA (Teil A)."
//!
//! **Befund, und wie er aufgeloest ist.** Die dreiwertige Skala liegt in
//! `psk_adversarial::CounterHorizonStanding` - einem Paket, das M24
//! besitzt. Eine Abhaengigkeit darauf waere eine Bindung an ein
//! PSK-RA-Modul, und genau die schliesst
//! QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)
//! aus ("bindet an keine PSK-RA-Module"). Die Skala nachzubauen waere
//! die Parallelstruktur, die dieselbe Regel in der Gegenrichtung
//! ausschliesst, und
//! QPM Invariante 13.3 (Counter-Horizon-Pflicht) ausdruecklich auch.
//!
//! Aufloesung wie beim Residuenvertrag in L2: NRAII prueft die PFLICHT
//! und liefert den BEFUND ([`claim_is_complete`],
//! [`missing_counter_horizon_reason`]); die Einordnung in die
//! PSK-RA-Skala bleibt beim Aufrufer, der sie hat. Damit ist die
//! Pflicht erfuellt, ohne dass NRAII eine zweite Skala fuehrt oder ein
//! Modul bindet.
//!
//! Die Attraktorkarte ist NEU. QPM Struktur 13.1 (Marker und Response-Feld)
//! verlangt eine Triangulation, "die EXPLIZIT zwischen Daten,
//! Modellanteil, extrapolierter Region, blockiertem Pfad und Nullmodell
//! unterscheidet" - fuenf Herkunftsklassen, die PSK-RA so nicht fuehrt.

use std::collections::BTreeMap;

/// Ein Marker `m_i: X -> Y_i` (QPM Struktur 13.1 (Marker und Response-Feld)).
///
/// Der Wertebereich ist ein zugeordneter Typ: verschiedene Marker messen
/// Verschiedenes, und ein gemeinsamer Rueckgabetyp waere eine
/// Vereinheitlichung, die die Struktur nicht verlangt.
pub trait Marker {
    type Input;
    type Output;

    /// Die Kennung des Markers - sie geht in das Response-Feld ein und
    /// muss deshalb stabil sein.
    fn id(&self) -> &str;

    fn measure(&self, x: &Self::Input) -> Self::Output;
}

/// Die fuenf Herkunftsklassen, die die Attraktorkarte auseinanderhalten
/// MUSS (QPM Struktur 13.1 (Marker und Response-Feld)) - geschlossen und
/// woertlich.
///
/// Geschlossen, weil "explizit unterscheiden" eine sechste Klasse
/// ausschliesst, die sich in eine der fuenf einschliche.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseOrigin {
    /// "Daten" - gemessen.
    Data,
    /// "Modellanteil" - aus dem Modell erzeugt.
    ModelPart,
    /// "extrapolierte Region" - jenseits des Gemessenen fortgeschrieben.
    Extrapolated,
    /// "blockierter Pfad" - der Weg dorthin ist versperrt, der Wert
    /// steht nicht zur Verfuegung.
    BlockedPath,
    /// "Nullmodell" - aus einem Gegenmodell, nicht aus dem Kandidaten.
    NullModel,
}

impl ResponseOrigin {
    pub fn all() -> [ResponseOrigin; 5] {
        use ResponseOrigin::*;
        [Data, ModelPart, Extrapolated, BlockedPath, NullModel]
    }

    pub fn label(&self) -> &'static str {
        use ResponseOrigin::*;
        match self {
            Data => "Daten",
            ModelPart => "Modellanteil",
            Extrapolated => "extrapolierte Region",
            BlockedPath => "blockierter Pfad",
            NullModel => "Nullmodell",
        }
    }
}

/// Ein Eintrag des Response-Felds `R: S x M -> Y`.
///
/// Der Wert steht NIE ohne seine Herkunft: das Feld ist ein Paar, kein
/// Wert mit optionalem Vermerk. Ein extrapolierter Wert, der wie ein
/// gemessener aussieht, ist genau das, was die Struktur mit "explizit
/// unterscheidet" ausschliesst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub marker: String,
    pub value: String,
    pub origin: ResponseOrigin,
}

/// Das Response-Feld und die daraus triangulierte Attraktorkarte
/// (QPM Struktur 13.1 (Marker und Response-Feld)).
///
/// `A_map = Triang({R(s,m)})` ist hier die Aufschluesselung nach
/// Herkunft: welche Anteile der Karte woher kommen. Alle fuenf Klassen
/// erscheinen, auch die leeren - eine Null ist eine Aussage, dieselbe
/// Haltung wie bei der QPM-Massenbuchfuehrung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttractorMap {
    responses: Vec<Response>,
}

impl AttractorMap {
    pub fn triangulate(responses: Vec<Response>) -> Self {
        AttractorMap { responses }
    }

    pub fn responses(&self) -> &[Response] {
        &self.responses
    }

    /// Die Aufschluesselung nach Herkunft. ALLE fuenf Klassen sind
    /// enthalten, auch mit Zaehlerstand null.
    pub fn by_origin(&self) -> BTreeMap<ResponseOrigin, usize> {
        let mut out: BTreeMap<ResponseOrigin, usize> =
            ResponseOrigin::all().into_iter().map(|o| (o, 0)).collect();
        for r in &self.responses {
            *out.entry(r.origin).or_default() += 1;
        }
        out
    }

    /// Was NICHT aus Daten stammt. Der Anteil, den ein Leser einer
    /// Attraktorkarte kennen muss, um sie nicht fuer eine Messung zu
    /// halten.
    pub fn non_data_share(&self) -> usize {
        self.responses
            .iter()
            .filter(|r| r.origin != ResponseOrigin::Data)
            .count()
    }
}

/// `H+(x)` und `H-(x)` aus QPM Struktur 13.2 (Horizont und Gegenhorizont).
///
/// "H+(x) = beobachtet oder unter dem Modell erreichbar; H-(x) =
/// plausible Alternativen zu Bahnen in H+(x)."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HorizonPair {
    /// H+ - beobachtet oder erreichbar.
    pub forward: Vec<String>,
    /// H- - plausible Alternativen zu Bahnen in H+.
    pub counter: Vec<String>,
    /// Warum H- leer ist, falls er es ist. Ein leerer Gegenhorizont
    /// OHNE Begruendung ist nach
    /// QPM Invariante 13.3 (Counter-Horizon-Pflicht) unvollstaendig.
    pub emptiness_justification: Option<String>,
}

/// Ob ein diagnostischer Claim nach
/// QPM Invariante 13.3 (Counter-Horizon-Pflicht) vollstaendig ist.
///
/// "Kein diagnostischer Claim ist vollstaendig, solange relevante
/// Gegenbahnen, Gegenmodelle oder alternative Generatoren nicht
/// KONSTRUIERT ODER als ausserhalb des Scopes BEGRUENDET ausgewiesen
/// sind." Zwei Wege, nicht drei: unbegruendet leer ist keiner davon.
///
/// Gibt `bool` und keine Skalenstufe zurueck - siehe den Befund im
/// Modulkopf. Wer die dreiwertige PSK-RA-Einordnung braucht, bildet sie
/// aus diesem Befund und dem Paar; NRAII fuehrt sie nicht.
pub fn claim_is_complete(pair: &HorizonPair) -> bool {
    missing_counter_horizon_reason(pair).is_none()
}

/// Warum die Gegenhorizontpflicht NICHT erfuellt ist - benannt statt zu
/// erraten. `None` heisst erfuellt.
pub fn missing_counter_horizon_reason(pair: &HorizonPair) -> Option<&'static str> {
    if !pair.counter.is_empty() {
        return None;
    }
    match pair.emptiness_justification.as_deref() {
        Some(j) if !j.trim().is_empty() => None,
        Some(_) => Some("Gegenhorizont leer, Begruendung besteht nur aus Leerraum"),
        None => Some("Gegenhorizont leer und unbegruendet"),
    }
}

/// Die zehn Pruefungen, die der Harness MINDESTENS fuehrt
/// (QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness)) -
/// geschlossen und woertlich in der Reihenfolge des Werks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FalsificationCheck {
    /// "Signaturkollisionen und falsche Merges"
    SignatureCollisions,
    /// "nicht quotient-kompatible Operatoren"
    IncompatibleOperators,
    /// "Pfadabhaengigkeit"
    PathDependence,
    /// "zirkulaere Evidenz"
    CircularEvidence,
    /// "Markerablation und Source-Dependency"
    MarkerAblation,
    /// "Hollow Layers"
    HollowLayers,
    /// "Replaybruch"
    ReplayBreak,
    /// "Residuenverlust"
    ResidueLoss,
    /// "Gate-Leakage"
    GateLeakage,
    /// "Zielinjektion und Overfitting"
    TargetInjection,
}

impl FalsificationCheck {
    pub fn all() -> [FalsificationCheck; 10] {
        use FalsificationCheck::*;
        [
            SignatureCollisions,
            IncompatibleOperators,
            PathDependence,
            CircularEvidence,
            MarkerAblation,
            HollowLayers,
            ReplayBreak,
            ResidueLoss,
            GateLeakage,
            TargetInjection,
        ]
    }

    pub fn label(&self) -> &'static str {
        use FalsificationCheck::*;
        match self {
            SignatureCollisions => "Signaturkollisionen und falsche Merges",
            IncompatibleOperators => "nicht quotient-kompatible Operatoren",
            PathDependence => "Pfadabhaengigkeit",
            CircularEvidence => "zirkulaere Evidenz",
            MarkerAblation => "Markerablation und Source-Dependency",
            HollowLayers => "Hollow Layers",
            ReplayBreak => "Replaybruch",
            ResidueLoss => "Residuenverlust",
            GateLeakage => "Gate-Leakage",
            TargetInjection => "Zielinjektion und Overfitting",
        }
    }
}

/// Wie eine offene Pflicht zur Closure steht
/// (QPM Definition 16.3 (4-4-4-Closure)).
///
/// Die Closure verlangt, dass "alle offenen Pflichten des Proof-Horizon
/// erfuellt ODER explizit als nichtclosurewirksam klassifiziert sind" -
/// zwei Wege, und der zweite ist der Grund, warum diese Skala
/// existiert. Ohne ihn gaebe es nur "offen" und "weg", und der einzige
/// Weg zur Closure fuehrte ueber das Loeschen einer Pflicht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObligationStanding {
    /// Offen und unklassifiziert - blockiert die Closure.
    Open,
    /// Erfuellt, mit Nachweis. Der erste der beiden Wege.
    Fulfilled { evidence: String },
    /// Explizit als nichtclosurewirksam klassifiziert, mit Begruendung.
    /// Der zweite Weg - die Pflicht bleibt offen und SICHTBAR, sie
    /// blockiert nur nicht mehr.
    NotClosureEffective { justification: String },
}

/// Eine einzelne Pflicht des Proof-Horizon, mit ihrem Stand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofObligation {
    pub text: String,
    pub standing: ObligationStanding,
}

impl ProofObligation {
    /// Eine neue, unklassifizierte Pflicht.
    pub fn open(text: &str) -> Self {
        ProofObligation {
            text: text.to_string(),
            standing: ObligationStanding::Open,
        }
    }

    /// Ob diese Pflicht der Closure im Weg steht.
    ///
    /// Eine Begruendung aus Leerraum klassifiziert nicht - dieselbe
    /// Haltung wie beim Gegenhorizont und beim Domain-Vertrag. Sonst
    /// waere "explizit klassifiziert" mit einem Leerzeichen erreichbar.
    pub fn blocks_closure(&self) -> bool {
        match &self.standing {
            ObligationStanding::Open => true,
            ObligationStanding::Fulfilled { evidence } => evidence.trim().is_empty(),
            ObligationStanding::NotClosureEffective { justification } => {
                justification.trim().is_empty()
            }
        }
    }

    /// Ob die Pflicht noch als offene Schuld im Horizont steht -
    /// unabhaengig davon, ob sie die Closure blockiert. Eine
    /// klassifizierte Pflicht ist BEIDES: offen und nicht blockierend.
    pub fn is_open(&self) -> bool {
        !matches!(self.standing, ObligationStanding::Fulfilled { .. })
    }
}

/// `PH(K)` aus QPM Definition 13.5 (Proof-Horizon): "die endliche,
/// versionierte Menge offener Beweis-, Validierungs-, Kalibrierungs-
/// und Falsifikationspflichten."
///
/// Der tragende Satz steht dahinter: "Ein Kandidat kann STABIL und
/// dennoch NICHT GESCHLOSSEN sein, wenn PH(K) nicht leer ist." Deshalb
/// sind Stabilitaet und Geschlossenheit hier zwei Fragen und nicht eine:
/// [`ProofHorizon::is_closed`] beantwortet die zweite, und keine
/// Funktion dieses Moduls leitet sie aus der ersten ab.
///
/// ## Was die NRAII-7-Messung hier gefunden hat
///
/// L4 baute diesen Typ nach QPM Definition 13.5 (Proof-Horizon) und
/// damit vollstaendig - aber nicht ausreichend fuer den Gebrauch, den
/// QPM Definition 16.3 (4-4-4-Closure) davon macht. Die verlangt
/// naemlich MEHR als eine leere Menge: "alle offenen Pflichten des
/// Proof-Horizon erfuellt ODER explizit als nichtclosurewirksam
/// klassifiziert". Der zweite Disjunkt war in L4 nicht ausdrueckbar -
/// eine Pflicht war entweder da (dann nicht geschlossen) oder weg.
///
/// Das ist keine Namensfrage, sondern eine fehlende Unterscheidung, und
/// sie ist mit L7 nachgetragen: [`ProofHorizon::is_closed`] bleibt
/// QPM Definition 13.5 (Proof-Horizon) woertlich,
/// [`ProofHorizon::closure_admissible`] ist der Test von
/// QPM Definition 16.3 (4-4-4-Closure). Die beiden fallen NICHT
/// zusammen, und der Fall, in dem sie auseinandergehen, ist genau der,
/// den die Closure braucht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofHorizon {
    /// Die Version, unter der diese Pflichtenmenge steht - "versioniert"
    /// steht in der Definition.
    pub version: String,
    /// Die Pflichten, je mit ihrem Text und ihrem Stand.
    pub obligations: Vec<ProofObligation>,
}

impl ProofHorizon {
    /// `PH(K) = {}` nach QPM Definition 13.5 (Proof-Horizon).
    ///
    /// Zaehlt die noch offenen Pflichten - eine klassifizierte ist
    /// weiterhin offen. Ein Horizont mit klassifizierter Pflicht ist
    /// also NICHT geschlossen, auch wenn er die Closure zulaesst.
    pub fn is_closed(&self) -> bool {
        self.open_count() == 0
    }

    /// Wieviele Pflichten noch offenstehen - klassifizierte
    /// eingeschlossen. Regel 7.52 (Erklärter Nullstand) verlangt
    /// Sichtbarkeit im Artefakt: eine Klassifikation verschwindet
    /// nicht aus dieser Zahl.
    pub fn open_count(&self) -> usize {
        self.obligations.iter().filter(|o| o.is_open()).count()
    }

    /// Der Closure-Test aus QPM Definition 16.3 (4-4-4-Closure): jede
    /// offene Pflicht ist erfuellt oder explizit als
    /// nichtclosurewirksam klassifiziert.
    ///
    /// Der Name sagt "admissible" und nicht "closed": das hier ist EINE
    /// der beiden Bedingungen von QPM Definition 16.3 (4-4-4-Closure),
    /// die andere ist `C444 = 1`. Wer beides zusammenzieht, hat den
    /// lokalen Sieg zum Globalbeweis gemacht, den
    /// QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis) ausschliesst.
    pub fn closure_admissible(&self) -> bool {
        self.blocking().is_empty()
    }

    /// Welche Pflichten die Closure blockieren - benannt, nicht
    /// gezaehlt. Ein "nicht zulaessig" ohne die Liste sagte so wenig
    /// wie ein Gate ohne Grund.
    pub fn blocking(&self) -> Vec<&ProofObligation> {
        self.obligations
            .iter()
            .filter(|o| o.blocks_closure())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn antwort(marker: &str, origin: ResponseOrigin) -> Response {
        Response {
            marker: marker.to_string(),
            value: format!("{marker}-wert"),
            origin,
        }
    }

    /// QPM Struktur 13.1 (Marker und Response-Feld): die Attraktorkarte
    /// unterscheidet EXPLIZIT zwischen den fuenf Herkuenften.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: die Aufschluesselung
    /// nennt alle fuenf Klassen, auch die mit Zaehlerstand null - sonst
    /// waere eine fehlende Klasse von einer leeren nicht zu
    /// unterscheiden, und genau das verbietet "explizit".
    #[test]
    fn the_attractor_map_names_all_five_origins_including_the_empty_ones() {
        let karte = AttractorMap::triangulate(vec![
            antwort("m1", ResponseOrigin::Data),
            antwort("m2", ResponseOrigin::Data),
            antwort("m3", ResponseOrigin::Extrapolated),
        ]);
        let nach_herkunft = karte.by_origin();
        assert_eq!(nach_herkunft.len(), 5, "alle fuenf Klassen erscheinen");
        assert_eq!(nach_herkunft[&ResponseOrigin::Data], 2);
        assert_eq!(nach_herkunft[&ResponseOrigin::Extrapolated], 1);
        // Die leeren stehen mit null da, nicht gar nicht.
        assert_eq!(nach_herkunft[&ResponseOrigin::NullModel], 0);
        assert_eq!(nach_herkunft[&ResponseOrigin::BlockedPath], 0);
        assert_eq!(nach_herkunft[&ResponseOrigin::ModelPart], 0);

        // Und der Nichtdatenanteil ist ablesbar: ein Leser sieht, dass
        // ein Drittel der Karte nicht gemessen ist.
        assert_eq!(karte.non_data_share(), 1);
    }

    /// QPM Invariante 13.3 (Counter-Horizon-Pflicht): zwei Wege zur
    /// Vollstaendigkeit, und unbegruendet leer ist keiner davon.
    ///
    /// ERWARTUNG: konstruiert und begruendet leer sind vollstaendig,
    /// unbegruendet leer NICHT. Ohne den dritten Fall sagten die ersten
    /// beiden nur, dass `claim_is_complete` manchmal wahr ist.
    #[test]
    fn a_claim_is_complete_only_when_constructed_or_justified() {
        let konstruiert = HorizonPair {
            forward: vec!["bahn-a".into()],
            counter: vec!["gegenbahn-a".into()],
            emptiness_justification: None,
        };
        assert!(missing_counter_horizon_reason(&konstruiert).is_none());
        assert!(claim_is_complete(&konstruiert));

        let begruendet_leer = HorizonPair {
            forward: vec!["bahn-a".into()],
            counter: vec![],
            emptiness_justification: Some("die Domaene konstruiert keine Nullmodelle".into()),
        };
        assert!(missing_counter_horizon_reason(&begruendet_leer).is_none());
        assert!(claim_is_complete(&begruendet_leer));

        let unbegruendet = HorizonPair {
            forward: vec!["bahn-a".into()],
            counter: vec![],
            emptiness_justification: None,
        };
        assert_eq!(
            missing_counter_horizon_reason(&unbegruendet),
            Some("Gegenhorizont leer und unbegruendet")
        );
        assert!(
            !claim_is_complete(&unbegruendet),
            "ein leerer Gegenhorizont ohne Grund macht den Claim unvollstaendig"
        );

        // Leerraum begruendet nichts - dieselbe Haltung wie beim
        // Domain-Vertrag.
        let leerraum = HorizonPair {
            emptiness_justification: Some("   ".into()),
            ..unbegruendet.clone()
        };
        assert!(!claim_is_complete(&leerraum));
    }

    /// QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness): zehn
    /// Pruefungen, geschlossen, in der Reihenfolge des Werks.
    #[test]
    fn the_harness_lists_all_ten_checks() {
        assert_eq!(FalsificationCheck::all().len(), 10);
        let labels: Vec<&str> = FalsificationCheck::all()
            .iter()
            .map(|c| c.label())
            .collect();
        assert_eq!(labels[0], "Signaturkollisionen und falsche Merges");
        assert_eq!(labels[9], "Zielinjektion und Overfitting");
        // Jede Pruefung ist von jeder anderen verschieden.
        let mut sortiert = FalsificationCheck::all().to_vec();
        sortiert.sort();
        sortiert.dedup();
        assert_eq!(sortiert.len(), 10);
    }

    /// QPM Definition 13.5 (Proof-Horizon): stabil und geschlossen sind
    /// zwei Fragen.
    ///
    /// ERWARTUNG: ein Proof-Horizon mit offener Pflicht ist NICHT
    /// geschlossen, auch wenn sonst alles steht - "ein Kandidat kann
    /// stabil und dennoch nicht geschlossen sein". Der Test misst genau
    /// diesen Fall, weil er derjenige ist, den eine Vereinfachung
    /// verlieren wuerde.
    #[test]
    fn an_open_proof_horizon_keeps_a_stable_candidate_unclosed() {
        let offen = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![ProofObligation::open(
                "Kalibrierung der Akzeptanzregion steht aus",
            )],
        };
        assert!(!offen.is_closed());
        assert_eq!(offen.open_count(), 1);

        let geschlossen = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![],
        };
        assert!(geschlossen.is_closed());
    }

    /// QPM Definition 16.3 (4-4-4-Closure) gegen
    /// QPM Definition 13.5 (Proof-Horizon): die beiden Praedikate
    /// fallen NICHT zusammen.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: eine als
    /// nichtclosurewirksam klassifizierte Pflicht laesst
    /// `closure_admissible` wahr werden und `is_closed` FALSCH bleiben.
    /// Genau dieser Fall traegt die Unterscheidung - waeren beide
    /// gleich, haette die Klassifikation keine Wirkung, und waeren sie
    /// unabhaengig, sagte keiner etwas ueber den anderen.
    #[test]
    fn classification_admits_closure_without_emptying_the_horizon() {
        let klassifiziert = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![ProofObligation {
                text: "Kontraktionskonstante ist domaenenabhaengig (NRAII-OBL-001)".into(),
                standing: ObligationStanding::NotClosureEffective {
                    justification: "das Werk legt sie nicht universell fest".into(),
                },
            }],
        };
        assert!(
            klassifiziert.closure_admissible(),
            "klassifiziert blockiert nicht"
        );
        assert!(
            !klassifiziert.is_closed(),
            "und bleibt trotzdem eine offene Pflicht"
        );
        assert_eq!(
            klassifiziert.open_count(),
            1,
            "Regel 7.52 (Erklärter Nullstand): sichtbar im Artefakt, nicht verschwunden"
        );

        // Erfuellt ist der andere Weg - und der leert den Horizont.
        let erfuellt = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![ProofObligation {
                text: "Replay reproduziert".into(),
                standing: ObligationStanding::Fulfilled {
                    evidence: "trace-0001".into(),
                },
            }],
        };
        assert!(erfuellt.closure_admissible());
        assert!(erfuellt.is_closed());

        // Und unklassifiziert blockiert - der Befund NENNT die Pflicht.
        let offen = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![ProofObligation::open("noch niemand hat hingesehen")],
        };
        assert!(!offen.closure_admissible());
        assert_eq!(offen.blocking().len(), 1);
        assert_eq!(offen.blocking()[0].text, "noch niemand hat hingesehen");
    }

    /// Eine Klassifikation aus Leerraum klassifiziert nicht - sonst
    /// waere die Closure mit einem Leerzeichen je Pflicht erreichbar.
    ///
    /// Dieselbe Gegenprobe wie beim Gegenhorizont und beim
    /// Domain-Vertrag, und aus demselben Grund: "explizit" ist eine
    /// Anforderung an den Inhalt, nicht an das Feld.
    #[test]
    fn whitespace_neither_fulfils_nor_classifies() {
        for stand in [
            ObligationStanding::NotClosureEffective {
                justification: "   ".into(),
            },
            ObligationStanding::Fulfilled {
                evidence: "".into(),
            },
        ] {
            let ph = ProofHorizon {
                version: "1.0.0".into(),
                obligations: vec![ProofObligation {
                    text: "p".into(),
                    standing: stand.clone(),
                }],
            };
            assert!(
                !ph.closure_admissible(),
                "{stand:?} darf die Closure nicht zulassen"
            );
        }
    }
}
