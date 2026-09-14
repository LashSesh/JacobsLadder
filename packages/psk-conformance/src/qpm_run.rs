//! Der Referenzlauf als erster QPM-Messgegenstand: QPM-0 (Scope,
//! Ergebnisordnung) und QPM-1 (Aperturbuchfuehrung) ueber dem, was
//! `run_golden_run` real hervorbringt.
//!
//! ## Warum das kein Zirkelschluss ist - und wie das geprueft wird
//!
//! Zwei Eingaenge speisen PSK-RAs Klassenberechnung
//! (`compute_conformance_class`): der abgeleitete Deckungsvektor und
//! die sechs Abnahmeflaggen. Der Vektor kommt aus
//! `collect_feature_evidence`, und die Funktion liest AUSSCHLIESSLICH
//! `GoldenRunCertification` (also `GoldenRunReport`, `replay_check`,
//! `self_compile_gate`) und `BaselineComparison` - nachgezaehlt, nicht
//! vermutet.
//!
//! Ein Rueckflusspfad entstuende also GENAU DANN, wenn eine QPM-Ausgabe
//! in einem dieser Typen landete. Deshalb ist `QpmRunReport` ein
//! eigener Typ, der in KEINEM von ihnen als Feld vorkommt, und
//! `observe_golden_run` nimmt den Bericht als `&GoldenRunReport`
//! entgegen, statt ihn zu erweitern: read-only ist hier eine
//! Signatureigenschaft, keine Zusage. Der Test
//! `qpm_findings_cannot_reach_the_conformance_class` haelt es fest.
//!
//! ## Was beobachtet wird
//!
//! Die Masse sind die zwanzig IR-Knoten des Laufs. Die sechs
//! FieldProjections des Laufs kommen dafuer NICHT in Frage: ihre
//! `visible`-Listen fuehren eigene Kennungen (`golden-run-node-N`), die
//! mit den ObjectIds des IR-Graphen nichts gemein haben - nachgemessen.
//! Wer sie als sichtbaren Koerper der IR-Masse ausgaebe, wuerde zwei
//! Identitaetsraeume verwechseln.

use std::collections::BTreeMap;
use std::path::Path;

use psk_adversarial::CounterHorizonStanding;
use psk_fields::{
    account_mass, ApertureBank, ApertureId, ChannelId, MassClass, MassProducers, PanopticScope,
    ShadowRecord,
};
use psk_types::objects::IRNodeId;
use psk_types::PskError;

use crate::golden_run::GoldenRunReport;

/// QPM Struktur 4.2 (Ergebnisordnung): die fuenf Werte, geschlossen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum IdentityVerdict {
    Known,
    Ambiguous,
    Unknown,
    OutOfScope,
    Invalid,
}

/// QPM Regel 4.3 (Zwei orthogonale Statusachsen): RunGate und
/// IdentityVerdict sind unabhaengig. "Ein gueltig ausgefuehrter Lauf
/// DARF RunGate = PASS und zugleich IdentityVerdict = UNKNOWN tragen;
/// diese Kombination ist ausdruecklich erwuenscht, wenn die Messung
/// valide, der Katalog aber unvollstaendig ist."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunGate {
    Pass,
    Hold,
    Fail,
}

/// Das Ergebnis einer QPM-Beobachtung. Bewusst ein EIGENER Typ, der in
/// keinem PSK-RA-Berichtstyp als Feld vorkommt - siehe Modulkopf.
#[derive(Debug, Clone)]
pub struct QpmRunReport {
    /// QPM-0: der Scope, unter dem beobachtet wurde.
    pub scope: PanopticScope,
    /// QPM-1: die Bank, deren Aperturen die Schatten erzeugten.
    pub bank: ApertureBank,
    /// QPM-1: der Gegenhorizont und sein Stand (QPM Regel 3.7 (Gegenhorizont ist konstruiert oder begründet leer)).
    pub counter_horizon_standing: CounterHorizonStanding,
    /// QPM-1: die Buchfuehrung nach QPM Axiom 3.1 (Kein stiller Ausschluss), je Klasse gezaehlt.
    /// Alle vier Klassen erscheinen; eine Null ist eine Aussage.
    pub census: BTreeMap<MassClass, usize>,
    /// Die Gesamtmasse, ueber der die Buchfuehrung aufging.
    pub total_mass: usize,
    /// Je Schatten die Apertur, die ihn zurueckhielt (QPM Regel 3.5 (Eine Apertur erzeugt Schatten, keine Abwesenheit)).
    /// Enthaelt AUCH die Knoten, die die Praezedenz anderswo zaehlt -
    /// der Schattenbeleg bleibt bestehen.
    pub shadows: Vec<(IRNodeId, ApertureId)>,
    /// QPM Regel 3.9 (Präzedenz unter den Erzeugern): je Knoten die Klassen, in die er ebenfalls
    /// faellt, die aber der Praezedenz unterlagen. "Die Praezedenz
    /// entscheidet die Zaehlung, nicht die Aufzeichnung."
    pub displaced: Vec<(IRNodeId, Vec<MassClass>)>,
    /// Die Zaehlklasse je Knoten - das Ergebnis der Praezedenz.
    counted: BTreeMap<IRNodeId, MassClass>,
    /// QPM Regel 3.3 (Scope ist explizit, nie universell): vorhandene, nicht deklarierte Kanaele - jeder mit
    /// seiner Einordnung, keiner als Abwesenheit.
    pub undeclared_channels: Vec<(ChannelId, String)>,
    /// QPM Struktur 4.2 (Ergebnisordnung), abgeleitet.
    pub verdict: IdentityVerdict,
    /// QPM Regel 4.3 (Zwei orthogonale Statusachsen): die zweite, unabhaengige Achse.
    pub run_gate: RunGate,
    /// Warum das Verdikt so ausfiel - benannt, nicht zu erraten.
    pub verdict_reason: String,
    /// Das Ergebnis der Pipelinestufe QueryVersionedTemplateCatalog,
    /// im Artefakt sichtbar (Regel 7.53 (Erklärter Nullstand), dritte
    /// Pflicht): die Leerform steht HIER, nicht nur im Grundtext des
    /// Verdikts.
    pub catalog_query: crate::qpm_query::CatalogQuery,
}

/// Beobachtet einen abgeschlossenen Golden Run.
///
/// Nimmt den Bericht als geteilte Referenz und gibt einen eigenen
/// zurueck: die read-only-Eigenschaft steht in der Signatur.
pub fn observe_golden_run(
    run: &GoldenRunReport,
    workspace_root: &Path,
) -> Result<QpmRunReport, PskError> {
    let profile = crate::qpm_profile::load_qpm_profile(workspace_root)?;
    let scope = profile.scope();
    let bank = profile.bank();
    bank.check_predicates()?;

    // ---- QPM-1: die Masse sind die IR-Knoten des Laufs.
    let mass: Vec<IRNodeId> = run
        .ir_bundle
        .graph
        .nodes
        .iter()
        .map(|n| IRNodeId(n.id.to_string()))
        .collect();

    // Erzeuger 1 (M09) und 2 (ApertureBank): welche Sorte eine Apertur
    // durchlaesst, hat die Domaene deklariert. Ein Knoten, den KEINE
    // deklarierte Apertur durchlaesst, ist Schatten - mit genau der
    // Apertur, die ihn zurueckhielt.
    let mut visible = Vec::new();
    let mut shadows = Vec::new();
    for node in &run.ir_bundle.graph.nodes {
        let id = IRNodeId(node.id.to_string());
        match profile.first_aperture_passing(node.sort) {
            Some(_) => visible.push(id),
            None => {
                // QPM Regel 3.5 (Eine Apertur erzeugt Schatten, keine Abwesenheit): die zurueckhaltende Apertur MUSS
                // benannt sein. Der Kanal `topology` ist der, unter dem
                // ein IR-Knoten ueberhaupt Gegenstand ist.
                let (ap, pred) = profile.holding_aperture(&ChannelId("topology".into()))?;
                shadows.push(ShadowRecord {
                    node: id,
                    aperture: ap,
                    pass_predicate: pred,
                });
            }
        }
    }

    // Erzeuger 3 (CounterHorizon, M24) und 4 (Residuum, M19).
    let counter_horizon = profile.counter_horizon(run);
    // Der Gegenhorizont der Referenzdomaene traegt keine Masse; seine
    // Objekte waeren Nullmodelle, und die Domaene konstruiert keine.
    let ch_mass: Vec<IRNodeId> = Vec::new();
    // Erzeuger 4 (M19): ein Knoten, den der Ledger als Ursprung eines
    // ResidueRecord fuehrt. Seit v1.0.6 traegt `build_node` diesen
    // Rueckverweis - vorher stand er hart auf leer, und die Klasse
    // konnte nie von null verschieden werden, obwohl der Lauf ein
    // blockierendes Residuum auf den Anker oeffnet. Der Anker liegt
    // zugleich im Schatten; QPM Regel 3.9 (Präzedenz unter den Erzeugern) entscheidet die Zaehlung
    // (Residuum sticht) und erhaelt den Schattenbeleg als Querverweis.
    let residue_mass: Vec<IRNodeId> = run
        .ir_bundle
        .graph
        .nodes
        .iter()
        .filter(|n| !n.residue_refs.is_empty())
        .map(|n| IRNodeId(n.id.to_string()))
        .collect();

    let producers = MassProducers {
        visible: &visible,
        shadows: &shadows,
        counter_horizon: &ch_mass,
        residues: &residue_mass,
    };
    let account = account_mass(&mass, &producers).map_err(|f| psk_fields::as_psk_error(&f))?;

    // ---- QPM-6, Schicht 2: die Ergebnisordnung (QPM Struktur 4.2 (Ergebnisordnung)),
    // Bedingung fuer Bedingung GEMESSEN, von der staerksten Stoerung
    // abwaerts gelesen: erst ob das Beweismaterial traegt (INVALID),
    // dann ob der Scope-Vertrag erfuellt ist (OUT_OF_SCOPE), erst
    // dann die Katalogachse. KNOWN und AMBIGUOUS bleiben ohne
    // Erzeuger - beide sind per Definition Katalogtreffer, und ein
    // Katalog ist nicht registriert.
    let breaks = evidence_breaks(run);
    let scope_breaks = scope_contract_breaks(&scope, &profile.undeclared_channels());
    let (verdict, verdict_reason, catalog_query) = if !breaks.is_empty() {
        (
            IdentityVerdict::Invalid,
            format!("Beweismaterial gebrochen: {}", breaks.join("; ")),
            // Ohne tragfaehiges Beweismaterial findet keine Abfrage
            // statt - eine Identitaetsfrage ueber gebrochener Evidenz
            // waere selbst ein Defekt.
            crate::qpm_query::CatalogQuery::NotQueried {
                reason: "keine Abfrage ueber gebrochenem Beweismaterial".to_string(),
            },
        )
    } else if !scope_breaks.is_empty() {
        (
            IdentityVerdict::OutOfScope,
            format!("Scope-Vertrag nicht erfuellt: {}", scope_breaks.join("; ")),
            crate::qpm_query::CatalogQuery::NotQueried {
                reason: "keine Abfrage ausserhalb des Scope-Vertrags".to_string(),
            },
        )
    } else {
        // QPM Regel 3.3 (Scope ist explizit, nie universell) letzter Satz: "Fehlt catalog_ref, so
        // endet jeder Lauf in UNKNOWN, nicht in FAIL (QPM-OBL-002)." Die
        // Deckelung wird an der Abfragestufe selbst abgelesen, nicht an
        // der Scope-Politik vorweggenommen - `ScopeCeiling` bleibt die
        // Typaussage der Politik, das VERDIKT kommt aus der Stufe.
        let query = crate::qpm_query::query_versioned_template_catalog(&scope);
        let (verdict, reason) = crate::qpm_query::open_set_decide(&query);
        (verdict, reason, query)
    };

    // QPM Regel 4.3 (Zwei orthogonale Statusachsen): die Gate-Achse ist unabhaengig vom Verdikt. Der
    // beobachtete Lauf hat beide Gates auf PASS - das bleibt wahr,
    // waehrend das Verdikt UNKNOWN ist. Genau die Kombination, die die
    // Regel ausdruecklich erwuenscht nennt.
    let run_gate = if account.total() == mass.len() {
        RunGate::Pass
    } else {
        RunGate::Hold
    };

    Ok(QpmRunReport {
        scope,
        bank,
        counter_horizon_standing: counter_horizon.standing(),
        census: account.census(),
        total_mass: account.total(),
        displaced: account
            .displacements()
            .into_iter()
            .map(|(n, c)| (n.clone(), c.clone()))
            .collect(),
        counted: mass
            .iter()
            .filter_map(|n| account.class_of(n).map(|c| (n.clone(), c)))
            .collect(),
        shadows: shadows.into_iter().map(|s| (s.node, s.aperture)).collect(),
        undeclared_channels: profile.undeclared_channels(),
        verdict,
        run_gate,
        verdict_reason,
        catalog_query,
    })
}

/// Die neun Kanaele, die QPM Struktur 3.20 (SignatureAtlas) woertlich
/// nennt - die Menge, gegen die QPM Regel 3.3 (Scope ist explizit, nie universell)
/// Satz 1 die Vollstaendigkeit der Deklaration misst.
const ATLAS_CHANNELS: [&str; 9] = [
    "topology", "spectrum", "phase", "symmetry", "rank", "entropy", "seam", "trace", "residue",
];

/// OUT_OF_SCOPE-Erzeuger: "Scope-, Apertur- oder Domänenvertrag nicht
/// erfüllt" (QPM Struktur 4.2 (Ergebnisordnung)).
///
/// Gemessen wird die Pflicht aus QPM Regel 3.3 (Scope ist explizit, nie universell):
/// "declared_channels MUSS vollständig sein. Ein im Zustandsraum
/// vorhandener, aber nicht deklarierter Kanal ... erscheint als
/// OUT_OF_SCOPE oder als blockierendes Residuum — niemals als
/// Abwesenheit." Vollstaendig heisst: jeder der neun Atlas-Kanaele ist
/// entweder deklariert oder BENANNT UND BEGRUENDET ausgenommen. Ein
/// Kanal, der weder das eine noch das andere ist, ist eine Abwesenheit -
/// genau das, was die Regel verbietet.
pub fn scope_contract_breaks(
    scope: &PanopticScope,
    undeclared: &[(ChannelId, String)],
) -> Vec<String> {
    let mut breaks = Vec::new();
    for name in ATLAS_CHANNELS {
        let channel = ChannelId(name.to_string());
        if scope.declared_channels.contains(&channel) {
            continue;
        }
        match undeclared.iter().find(|(c, _)| *c == channel) {
            Some((_, reason)) if !reason.trim().is_empty() => {}
            Some(_) => breaks.push(format!(
                "Kanal {name} ist ausgenommen, aber ohne Begruendung - eine Ausnahme ohne Grund \
                 ist eine Abwesenheit"
            )),
            None => breaks.push(format!(
                "Kanal {name} ist weder deklariert noch begruendet ausgenommen - eine Abwesenheit"
            )),
        }
    }
    breaks
}

/// INVALID-Erzeuger: "Provenienz-, Gate-, Trace- oder Replaybruch"
/// (QPM Struktur 4.2 (Ergebnisordnung)). BINDUNG, kein Neubau - dieselbe
/// Linie wie beim Witnessrang: gemessen wird mit den Pruefungen, die
/// PSK-RA bereits hat.
///
/// - Trace-Bruch: die Segmentkette des Laufs, geprueft mit
///   `psk_trace::verify_chain_detailed` (Regel 7.42 (Zwei Digests je Segment),
///   Kettenfortschreibung) - und der Taktabgleich: so viele
///   `tick.closed`-Siegel wie Takte.
/// - Provenienz-Bruch: dieselbe Pruefung, zweite Haelfte - die
///   Aufzeichnungsintegritaet ueber `segment_record_digest` sichert die
///   Herkunft der gespeicherten Bytes.
/// - Gate-Bruch: ein FAIL in den Gate-Berichten des Beweismaterials
///   (G-BOOT, PATCH) - ein Lauf, dessen eigene Gates fielen, traegt
///   keine Identitaetsfrage.
/// - Replay-Bruch: HIER NICHT MESSBAR, benannt statt vorgetaeuscht -
///   Definition 22.1 (Replayklassen) macht Replay zur Eigenschaft eines
///   VERGLEICHS zweier Laeufe; das Material dafuer liegt in der
///   Zertifizierung (`replay_check`), nicht im Einzellaufbericht.
pub fn evidence_breaks(run: &GoldenRunReport) -> Vec<String> {
    let mut breaks = Vec::new();

    match psk_trace::verify_chain_detailed(&run.trace_segments) {
        Ok(()) => {}
        Err(psk_trace::ChainViolation::RecordDigestMismatch { at }) => breaks.push(format!(
            "Provenienz-Bruch: Aufzeichnungsintegritaet verletzt bei Segment {at}"
        )),
        Err(v) => breaks.push(format!("Trace-Bruch: Segmentkette verletzt ({v:?})")),
    }

    let closed_ticks = run
        .trace_segments
        .iter()
        .filter(|s| s.event_type.0 == "tick.closed")
        .count() as u64;
    if closed_ticks != run.ticks {
        breaks.push(format!(
            "Trace-Bruch: {closed_ticks} Taktsiegel gegen ticks={}",
            run.ticks
        ));
    }

    use psk_types::objects::GateReportDecisionKind as Decision;
    if run.boot_gate.decision == Decision::Fail {
        breaks.push("Gate-Bruch: G-BOOT steht auf FAIL im Beweismaterial".to_string());
    }
    if run.patch_gate.decision == Decision::Fail {
        breaks.push("Gate-Bruch: PATCH steht auf FAIL im Beweismaterial".to_string());
    }

    breaks
}

/// QPM-2, effektiver Witnessrang (QPM Regel 3.19 (Splitbild und Parallaxe)):
/// "Der effektive Witnessrang folgt PSK-RAs
/// Abhaengigkeitsquotient ... korrelierte Facetten (identisches
/// Modell, identische Quelle) erhoehen den Rang nicht kuenstlich."
///
/// Das ist BINDUNG, kein Neubau: `DependencyProfile.effective_rank`
/// rechnet PSK-RA bereits, und der Referenzlauf ist der Fall, an dem
/// sich der blockierende Negativtest
/// `correlated-views-counted-as-independent` MESSEN laesst statt nur
/// behaupten - sechs Sichten, eine Quotientenklasse, Rang eins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessRank {
    /// Wie viele gebundene Projektionen der Lauf hervorbrachte.
    pub views: usize,
    /// Wie viele davon nach dem Abhaengigkeitsquotienten unabhaengig
    /// sind (`DependencyProfile.quotient_classes`).
    pub independent_classes: usize,
    /// `DependencyProfile.effective_rank`, unveraendert uebernommen.
    /// Vorzeichenbehaftet, weil `Scaled.numerator` es ist - ein
    /// negativer Rang waere ein Defekt, aber ihn hier wegzukuerzen
    /// hiesse, ihn unsichtbar zu machen.
    pub effective_rank: i64,
    /// Die deklarierte Schaetzmethode - der Rang ohne sie waere eine
    /// Zahl ohne Herkunft.
    pub method: String,
    /// Wie viele Quellen die Sichten teilen. Eine gemeinsame Quelle ist
    /// genau die Korrelation, die den Rang nicht heben darf.
    pub sources: usize,
}

impl WitnessRank {
    /// Der blockierende Negativtest, als Praedikat statt als Prosa:
    /// haette der Lauf die Sichten als unabhaengig gezaehlt, waere der
    /// Rang gleich ihrer Anzahl.
    ///
    /// Wahr heisst BESTANDEN - der Rang folgt den Quotientenklassen,
    /// nicht der Sichtenzahl.
    pub fn correlated_views_not_counted_as_independent(&self) -> bool {
        // Der Rang folgt den Quotientenklassen ...
        let follows_quotient = self.effective_rank == self.independent_classes as i64;
        // ... und wo Sichten korreliert sind, liegt er UNTER ihrer Zahl.
        // Sind sie es nicht, ist Gleichheit richtig und kein Verstoss.
        let not_inflated = if self.views > self.independent_classes {
            self.effective_rank < self.views as i64
        } else {
            true
        };
        follows_quotient && not_inflated
    }

    /// Wie viele Sichten die Korrelation geschluckt hat - der Messwert,
    /// der den Test aussagekraeftig macht. Null hiesse: der Fall ist
    /// nicht geuebt.
    pub fn absorbed_by_correlation(&self) -> usize {
        self.views.saturating_sub(self.independent_classes)
    }

    /// Ob dieser Rang eine MESSUNG ist
    /// (Regel 7.52 (Ein Bodenwert ist keine Messung)).
    ///
    /// **Gemessen, und der Befund ist gegenlaeufig zur Vermutung:** die
    /// Zahl hier ist keine Bodenzahl. `psk_dependency::quotient` gibt
    /// ueber einer leeren Projektionsmenge `effective_rank = 0` und
    /// leere `quotient_classes` zurueck, nicht eins - der Boden, den
    /// Regel 7.52 (Ein Bodenwert ist keine Messung) benennt, sass in
    /// `psk_adversarial::effective_rank_of`
    /// und nicht hier. Der Referenzlauf misst wirklich: sechs Sichten,
    /// eine Quotientenklasse, Rang eins.
    ///
    /// Die Kennzeichnung steht trotzdem, weil der Bericht sie verlangt:
    /// "ein Bericht, der den Bodenwert neben gemessenen Werten fuehrt,
    /// ohne ihn zu kennzeichnen, behauptet eine Messung, die nicht
    /// stattfand". Ein Lauf ohne Projektionen faellt hier auf, statt
    /// eine Null als Rang auszugeben.
    pub fn is_measured(&self) -> bool {
        self.views > 0
    }

    /// Der Rang mit seiner Kennzeichnung - fuer jeden Bericht, der ihn
    /// neben anderen Zahlen fuehrt.
    pub fn labelled(&self) -> String {
        if self.is_measured() {
            format!(
                "{} (gemessen ueber {} Sichten, {})",
                self.effective_rank, self.views, self.method
            )
        } else {
            "nicht gemessen (keine Projektionen)".to_string()
        }
    }
}

/// Bindet den Rang an PSK-RAs Abhaengigkeitsquotienten.
pub fn witness_rank(run: &GoldenRunReport) -> WitnessRank {
    let d = &run.dependency_profile;
    WitnessRank {
        views: run.field_projections.len(),
        independent_classes: d.quotient_classes.len(),
        effective_rank: d.effective_rank.numerator,
        method: d.method.0.clone(),
        sources: d.sources.len(),
    }
}

impl QpmRunReport {
    /// Die Klasse, in der dieser Knoten GEZAEHLT wird - das Ergebnis
    /// der Praezedenz aus QPM Regel 3.9 (Präzedenz unter den Erzeugern).
    pub fn census_class_of(&self, node: &IRNodeId) -> Option<MassClass> {
        self.counted.get(node).copied()
    }
}

/// Nur fuer den Bericht: die Klassen in kanonischer Reihenfolge mit
/// ihren Zaehlungen, alle vier, auch die leeren.
pub fn census_lines(report: &QpmRunReport) -> Vec<String> {
    MassClass::ALL
        .iter()
        .map(|c| format!("{}: {}", c.id(), report.census.get(c).copied().unwrap_or(0)))
        .collect()
}

/// QPM Regel 3.7 (Gegenhorizont ist konstruiert oder begründet leer): ein Gegenhorizont, der seine Pflicht nicht erfuellt,
/// macht jeden darauf gestuetzten Befund unvollstaendig. Diese Funktion
/// benennt das, statt es im Bericht zu verstecken.
pub fn counter_horizon_note(standing: CounterHorizonStanding) -> &'static str {
    match standing {
        CounterHorizonStanding::Constructed => "Gegenhorizont konstruiert",
        CounterHorizonStanding::JustifiedEmpty => "Gegenhorizont begruendet leer",
        CounterHorizonStanding::Unjustified => {
            "Gegenhorizont leer OHNE Begruendung - jeder darauf gestuetzte Befund unvollstaendig"
        }
    }
}

/// Wird vom Profilmodul gebraucht, damit der Gegenhorizont auf den
/// beobachteten Lauf zeigt (`subject_ref`).
pub(crate) fn run_subject(run: &GoldenRunReport) -> psk_types::ObjectId {
    run.anchor.id
}

/// Ob dieser Bericht ueberhaupt einen Befund tragen darf.
pub fn findings_admissible(report: &QpmRunReport) -> bool {
    report.counter_horizon_standing != CounterHorizonStanding::Unjustified
}

/// Der Vollstaendigkeit halber exportiert: die Buchfuehrung ist
/// aufgegangen, wenn die Gesamtmasse verbucht wurde.
pub fn books_balanced(report: &QpmRunReport, expected_mass: usize) -> bool {
    report.total_mass == expected_mass && report.census.values().sum::<usize>() == expected_mass
}
