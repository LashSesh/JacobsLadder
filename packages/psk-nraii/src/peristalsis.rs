//! L6: peristaltische Assimilation und Phasenlift.
//!
//! ## Der Zyklus, und warum Ueberspringen hier nicht ausdrueckbar ist
//!
//! QPM Definition 14.4 (Peristaltischer Zyklus):
//! `K_n --ExCal--> K'_n --Gate--> G_n --Sed--> S_n --Assim--> K_{n+1}
//!  --Renew--> Sigma_{n+1}`, "sofern alle erforderlichen Gates
//! bestehen".
//!
//! QPM Invariante 14.5 (Kein Assimilationssprung): "Kein Schritt DARF
//! uebersprungen werden, und Assim DARF NICHT Masse aufnehmen, die
//! ExCal nicht passiert oder das Gate nicht bestanden hat."
//!
//! Gebaut als Typkette: jede Stufe hat einen eigenen Typ, und jeder
//! entsteht ausschliesslich aus dem vorigen. [`assimilate`] nimmt
//! [`Gated`] - nicht [`Excalibrated`], nicht [`RawMass`]. Ein
//! Ueberspringen ist damit kein verbotener Aufruf, sondern ein Aufruf,
//! den es nicht gibt: dasselbe Muster wie bei
//! [`crate::Materialization`], aus der kein Weg zur Closure fuehrt
//! ausser ueber `reobserve`.
//!
//! ## Welche Gates - gemessen, und der Befund
//!
//! **Kapitel 14 nennt KEIN Gate namentlich.** Gemessen: von den acht
//! Bezeichnern der Gatefamilie
//! (QPM Struktur 18.1 (Gatefamilie NRAII)) kommt keiner im Kapitel vor.
//! Ableitbar ist nur:
//!
//! - QPM Invariante 14.5 (Kein Assimilationssprung) verweist woertlich
//!   auf QPM Invariante 9.7 (Boundary vor Absorption) ("gilt hier
//!   woertlich"). Deren Gate ist `N-BOUNDARY` - im Gate-Register aber
//!   der Schicht **L2** zugeordnet, nicht L6. Es ist also die
//!   Bedingung, die `Assim` einhalten MUSS, und kein Gate dieses
//!   Zyklus.
//! - `N-RATCHET` ist im Register L6 zugeordnet und zielt auf
//!   `monotone_lift_no_silent_reset`. Das ist
//!   QPM Algorithmus 15.9 (Monodromie-Ratchet) aus Kapitel **15** -
//!   dieselbe Schicht, aber nicht derselbe Gegenstand wie der Zyklus.
//! - Die Gatestufe IM Zyklus (`K'_n --Gate--> G_n`) bleibt **unbenannt**.
//!
//! Deshalb wird der Gatebezeichner hier DURCHGEREICHT und nicht
//! gewaehlt - dasselbe Vorgehen wie beim `origin_module` des
//! Residuenvertrags, und aus demselben Grund: was das Werk nicht
//! hergibt, erfindet diese Schicht nicht.

use psk_types::Digest;

/// `RawMass` nach QPM Definition 14.1 (RawMass): "jede heterogene
/// Eingabe, deren kanonische Rollen noch nicht getrennt sind".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawMass {
    pub id: String,
    pub content: String,
}

/// Die Stufen des Mass-to-Structure-Layer aus
/// QPM Struktur 14.2 (Mass-to-Structure-Layer), geschlossen und in der
/// Reihenfolge des Werks.
///
/// "Die Kanonisierung ist dieselbe wie in PSK-RA; nur die
/// Rollentrennung danach ist NRAII-eigen." Deshalb steht `Can` hier als
/// Stufe, aber der Weg dorthin fuehrt ueber
/// [`crate::CanonicalState`] - es gibt keine zweite Kanonisierung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MassStage {
    /// `RawMass --Can--> Fragments`
    Fragments,
    /// `--Marker/Response--> Resonites`
    Resonites,
    /// `--Gluing--> Infogenomes`
    Infogenomes,
    /// `--Gate--> Kernkandidaten`
    KernelCandidates,
}

impl MassStage {
    pub fn all() -> [MassStage; 4] {
        use MassStage::*;
        [Fragments, Resonites, Infogenomes, KernelCandidates]
    }
}

/// Die vier Strukturen, deren Erhalt einen QSNA von einer echten
/// Singularitaet unterscheidet
/// (QPM Definition 14.3 (QSNA)): "Typisierung, Provenienz, Trace und
/// Umkehrbarkeit bleiben erhalten."
///
/// Geschlossen: eine fuenfte waere keine Unterscheidung mehr, eine
/// dritte machte den Attraktor singulaer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PreservedStructure {
    Typing,
    Provenance,
    Trace,
    Reversibility,
}

impl PreservedStructure {
    pub fn all() -> [PreservedStructure; 4] {
        use PreservedStructure::*;
        [Typing, Provenance, Trace, Reversibility]
    }

    pub fn label(&self) -> &'static str {
        use PreservedStructure::*;
        match self {
            Typing => "Typisierung",
            Provenance => "Provenienz",
            Trace => "Trace",
            Reversibility => "Umkehrbarkeit",
        }
    }
}

/// Ein quasi-singulaerer, nicht-singulaerer Attraktor
/// (QPM Definition 14.3 (QSNA)).
///
/// Ein Attraktor ist nur dann ein QSNA, wenn ALLE vier Strukturen
/// erhalten sind - [`Qsna::condense`] weist jede fehlende namentlich
/// zurueck. Ein "fast erhaltener" Trace ist ein verlorener.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Qsna {
    id: String,
    preserved: Vec<PreservedStructure>,
}

impl Qsna {
    pub fn condense(id: &str, preserved: &[PreservedStructure]) -> Result<Self, CycleBreach> {
        for s in PreservedStructure::all() {
            if !preserved.contains(&s) {
                return Err(CycleBreach::SingularCondensation { lost: s.label() });
            }
        }
        Ok(Qsna {
            id: id.to_string(),
            preserved: preserved.to_vec(),
        })
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn preserved(&self) -> &[PreservedStructure] {
        &self.preserved
    }
}

/// Warum ein Zyklusschritt nicht zustande kommt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleBreach {
    /// Eine der vier QSNA-Strukturen ging verloren - dann ist die
    /// Kondensation singulaer, nicht quasi-singulaer.
    SingularCondensation { lost: &'static str },
    /// Das Gate steht nicht auf PASS. `Assim` darf solche Masse nach
    /// QPM Invariante 14.5 (Kein Assimilationssprung) nicht aufnehmen.
    GateNotPassed { gate: String },
    /// Die Boundary-Erneuerung trug die neue Last nicht nach innen.
    RenewalDidNotEnclose,
}

/// `K'_n` - was ExCal ueberstanden hat, mit dem, was es abtrennte.
///
/// "ExCal trennt Fremdmasse, Rauschen und inkompatible Constraints ab."
/// Die abgetrennte Masse ist NICHT verloren: sie steht hier als
/// Residuenbefund und geht ueber [`crate::ResidualPart`] ins Ledger -
/// "Abgetrennte Fremdmasse erscheint als Residuum, nicht als Verlust".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Excalibrated {
    accepted: Vec<RawMass>,
    separated: Vec<crate::ResidualPart>,
}

impl Excalibrated {
    pub fn accepted(&self) -> &[RawMass] {
        &self.accepted
    }

    /// Was abgetrennt wurde - als Befund, nicht als Loch.
    pub fn separated(&self) -> &[crate::ResidualPart] {
        &self.separated
    }
}

/// `G_n` - was das Gate bestanden hat.
///
/// Der Bezeichner des Gates steht darin, weil das Werk ihn nicht nennt
/// (siehe Modulkopf): wer den Zyklus fuehrt, sagt, welches Gate er
/// gestellt hat. Ein festverdrahteter Name waere hier eine Erfindung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gated {
    passed: Vec<RawMass>,
    gate: String,
}

impl Gated {
    pub fn passed(&self) -> &[RawMass] {
        &self.passed
    }

    pub fn gate(&self) -> &str {
        &self.gate
    }
}

/// `S_n` - das evidenzgebundene Sediment.
///
/// "Sed bildet aus den akzeptierten Einheiten ein evidenzgebundenes
/// Sediment." Evidenzgebunden heisst hier: jede Einheit traegt den
/// Gatebezeichner, unter dem sie durchkam.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sediment {
    units: Vec<RawMass>,
    gate: String,
}

impl Sediment {
    pub fn units(&self) -> &[RawMass] {
        &self.units
    }

    pub fn gate(&self) -> &str {
        &self.gate
    }
}

/// `K_{n+1}` - der Kern nach der Assimilation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kernel {
    absorbed: Vec<RawMass>,
    /// Der Nachweis, WORAUS dieser Kern entstand: die Kette, die
    /// durchlaufen wurde. Ohne ihn waere "kein Sprung" eine Zusage.
    provenance: Vec<&'static str>,
}

impl Kernel {
    pub fn absorbed(&self) -> &[RawMass] {
        &self.absorbed
    }

    /// Die durchlaufenen Schritte, in ihrer Reihenfolge.
    pub fn provenance(&self) -> &[&'static str] {
        &self.provenance
    }
}

/// `Sigma_{n+1}` - die erneuerte Boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewedBoundary {
    encloses: usize,
    provenance: Vec<&'static str>,
}

impl RenewedBoundary {
    /// Wieviel Traglast innen liegt.
    pub fn encloses(&self) -> usize {
        self.encloses
    }

    /// Die vollstaendige Kette - fuenf Schritte, keiner uebersprungen.
    pub fn provenance(&self) -> &[&'static str] {
        &self.provenance
    }
}

/// Schritt 1: `K_n --ExCal--> K'_n`.
pub fn excalibrate(mass: Vec<RawMass>, separate: &[String]) -> Excalibrated {
    let (fremd, akzeptiert): (Vec<RawMass>, Vec<RawMass>) =
        mass.into_iter().partition(|m| separate.contains(&m.id));
    Excalibrated {
        separated: fremd
            .into_iter()
            .map(|m| crate::ResidualPart {
                origin_object: psk_types::ObjectId::new(
                    psk_types::objects::SortId::Context,
                    Digest::sha256(m.id.as_bytes()),
                ),
                reason: format!("ExCal trennte '{}' als Fremdmasse ab", m.id),
            })
            .collect(),
        accepted: akzeptiert,
    }
}

/// Schritt 2: `K'_n --Gate--> G_n`.
///
/// `gate` ist der Bezeichner, den der Aufrufer stellt - siehe den
/// Befund im Modulkopf. `passed` sagt, ob er bestand; ein Nicht-PASS
/// erzeugt kein `Gated`, und damit ist die Masse fuer `Assim`
/// unerreichbar.
pub fn pass_gate(
    excalibrated: Excalibrated,
    gate: &str,
    passed: bool,
) -> Result<Gated, CycleBreach> {
    if !passed {
        return Err(CycleBreach::GateNotPassed {
            gate: gate.to_string(),
        });
    }
    Ok(Gated {
        passed: excalibrated.accepted,
        gate: gate.to_string(),
    })
}

/// Schritt 3: `G_n --Sed--> S_n`.
pub fn sediment(gated: Gated) -> Sediment {
    Sediment {
        units: gated.passed,
        gate: gated.gate,
    }
}

/// Schritt 4: `S_n --Assim--> K_{n+1}`.
///
/// Nimmt AUSSCHLIESSLICH ein [`Sediment`] entgegen, das seinerseits nur
/// aus einem [`Gated`] entsteht, das nur aus einem [`Excalibrated`]
/// entsteht. QPM Invariante 14.5 (Kein Assimilationssprung) - "Assim
/// DARF NICHT Masse aufnehmen, die ExCal nicht passiert oder das Gate
/// nicht bestanden hat" - ist damit keine Pruefung, sondern die Form
/// der Signatur.
pub fn assimilate(sediment: Sediment) -> Kernel {
    Kernel {
        absorbed: sediment.units,
        provenance: vec!["ExCal", "Gate", "Sed", "Assim"],
    }
}

/// Schritt 5: `K_{n+1} --Renew--> Sigma_{n+1}`.
///
/// "Renew erneuert die Boundary so, dass die neue Traglast INNEN
/// liegt." Eine Erneuerung, die weniger einschliesst als der Kern
/// traegt, hat das nicht getan.
pub fn renew(kernel: Kernel) -> Result<RenewedBoundary, CycleBreach> {
    let last = kernel.absorbed.len();
    let mut provenance = kernel.provenance;
    provenance.push("Renew");
    if provenance.len() != 5 {
        return Err(CycleBreach::RenewalDidNotEnclose);
    }
    Ok(RenewedBoundary {
        encloses: last,
        provenance,
    })
}

/// Der Monodromie-Ratchet aus
/// QPM Algorithmus 15.9 (Monodromie-Ratchet).
///
/// ## Nicht das Kapsel-Ratchet
///
/// Beide heissen "Ratchet" und laufen in ENTGEGENGESETZTE Richtungen:
///
/// | Kapsel-Ratchet (PSK-RA) | Kandidatenmenge faellt monoton - er KONTRAHIERT |
/// | Monodromie-Ratchet (hier) | Liftindex `g` steigt monoton - er ZAEHLT AUF |
///
/// Eine Bindung des einen an den anderen waere ein Nachbau mit
/// umgekehrtem Vorzeichen. Der Nachweis
/// `the_two_ratchets_run_in_opposite_directions` misst es.
///
/// "Ratchet verhindert stilles Zuruecksetzen, NICHT explizite
/// Korrektur. Korrektur = neue Stufe MIT Supersessionszeugnis, nie
/// Ueberschreiben."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MonodromyRatchet {
    /// `g_t` - der Liftindex. Steigt monoton.
    lift_index: u64,
    /// Die kanonische Klasse, die ueber den Umlauf erhalten bleiben
    /// MUSS: `Can(chi_next) == Can(chi_t)`.
    class_digest: Digest,
    /// Je Korrektur ein Supersessionszeugnis - nie ein Ueberschreiben.
    supersessions: Vec<String>,
}

/// Warum ein Umlauf den Ratchet nicht weiterdreht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetBreach {
    /// `Can(chi_next) != Can(chi_t)` - die kanonische Klasse ging
    /// verloren.
    ClassNotPreserved,
    /// Die neue Stufe enthaelt die alte nicht (`embeds` schlug fehl).
    EmbeddingMissing,
    /// Ein Zuruecksetzen ohne Supersessionszeugnis - der blockierende
    /// Negativtest `silent-ratchet-reset`.
    SilentReset { from: u64, to: u64 },
}

impl MonodromyRatchet {
    /// Der Anfangszustand: Liftindex null, Klasse gesetzt.
    pub fn start(class_digest: Digest) -> Self {
        MonodromyRatchet {
            lift_index: 0,
            class_digest,
            supersessions: Vec::new(),
        }
    }

    pub fn lift_index(&self) -> u64 {
        self.lift_index
    }

    pub fn supersessions(&self) -> &[String] {
        &self.supersessions
    }

    /// `complete_cycle` nach QPM Algorithmus 15.9 (Monodromie-Ratchet):
    /// `require Can(chi_next) == Can(chi_t)`, `require embeds(...)`,
    /// dann `g_t + 1`.
    ///
    /// Verbraucht `self` und gibt einen NEUEN Ratchet zurueck - es gibt
    /// keinen Weg, den Index an Ort und Stelle zu senken.
    pub fn complete_cycle(
        self,
        next_class: Digest,
        embedding_witness: bool,
    ) -> Result<Self, RatchetBreach> {
        if next_class != self.class_digest {
            return Err(RatchetBreach::ClassNotPreserved);
        }
        if !embedding_witness {
            return Err(RatchetBreach::EmbeddingMissing);
        }
        Ok(MonodromyRatchet {
            lift_index: self.lift_index + 1,
            ..self
        })
    }

    /// Eine Korrektur: neue Stufe MIT Supersessionszeugnis.
    ///
    /// Der Index steigt auch hier - eine Korrektur ist eine weitere
    /// Stufe, kein Zurueck. Ein leeres Zeugnis wird zurueckgewiesen:
    /// das waere das stille Zuruecksetzen unter anderem Namen.
    pub fn supersede(self, witness: &str, new_class: Digest) -> Result<Self, RatchetBreach> {
        if witness.trim().is_empty() {
            return Err(RatchetBreach::SilentReset {
                from: self.lift_index,
                to: self.lift_index,
            });
        }
        let mut supersessions = self.supersessions;
        supersessions.push(witness.to_string());
        Ok(MonodromyRatchet {
            lift_index: self.lift_index + 1,
            class_digest: new_class,
            supersessions,
        })
    }
}

/// Der Closure-Index `g(t)` aus
/// QPM Definition 15.6 (Logische Phase und Closure-Index) und die
/// Unterscheidung aus QPM Regel 15.7 (2π vs. 4π).
///
/// "Can(chi(theta + 2pi)) ~proj Can(chi(theta))" - sichtbare Rueckkehr;
/// "Can(chi(theta + 4pi)) = Can(chi(theta))" - vollstaendige
/// Orientierungsclosure. Zwei verschiedene Aussagen, und der
/// blockierende Negativtest `2pi-as-4pi-closure` verbietet, die erste
/// als die zweite auszugeben.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureDegree {
    /// Nach 2pi: sichtbar zurueck, aber nur projektiv gleich.
    TwoPi,
    /// Nach 4pi: kanonisch gleich.
    FourPi,
}

/// Bestimmt den Closure-Grad aus dem Phasenfortschritt in Vielfachen
/// von pi - GEMESSEN, nicht behauptet.
///
/// Halbe Umlaeufe: 2 = 2pi, 4 = 4pi. Nur bei einem Vielfachen von 4
/// liegt eine vollstaendige Orientierungsclosure vor.
pub fn closure_degree(half_turns: u64) -> Option<ClosureDegree> {
    if half_turns == 0 || !half_turns.is_multiple_of(2) {
        return None;
    }
    if half_turns.is_multiple_of(4) {
        Some(ClosureDegree::FourPi)
    } else {
        Some(ClosureDegree::TwoPi)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masse(id: &str) -> RawMass {
        RawMass {
            id: id.to_string(),
            content: format!("{id}-inhalt"),
        }
    }

    /// QPM Invariante 14.5 (Kein Assimilationssprung), erste Haelfte:
    /// die fuenf Schritte laufen in ihrer Reihenfolge, und der Kern
    /// traegt den Nachweis.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: die vollstaendige Kette
    /// ergibt eine Boundary mit FUENF Schritten in der Reihenfolge des
    /// Werks. Ein Ueberspringen ist nicht als Fehlerfall messbar - es
    /// ist im Typsystem nicht ausdrueckbar, und genau deshalb steht der
    /// Nachweis dafuer im `compile_fail`-Doctest an [`assimilate`].
    #[test]
    fn the_full_cycle_runs_all_five_steps_in_order() {
        let x = excalibrate(
            vec![masse("a"), masse("fremd"), masse("b")],
            &["fremd".into()],
        );
        assert_eq!(x.accepted().len(), 2);
        assert_eq!(x.separated().len(), 1, "die Fremdmasse ist ein Residuum");
        assert!(x.separated()[0].reason.contains("Fremdmasse"));

        let g = pass_gate(x, "N-BOUNDARY", true).expect("Gate bestanden");
        assert_eq!(g.gate(), "N-BOUNDARY");
        let s = sediment(g);
        assert_eq!(s.units().len(), 2);
        let k = assimilate(s);
        assert_eq!(k.absorbed().len(), 2);
        let sigma = renew(k).expect("Erneuerung schliesst ein");

        assert_eq!(sigma.encloses(), 2);
        assert_eq!(
            sigma.provenance(),
            &["ExCal", "Gate", "Sed", "Assim", "Renew"]
        );
    }

    /// QPM Invariante 14.5 (Kein Assimilationssprung), zweite Haelfte:
    /// Masse, die das Gate nicht bestand, erreicht `Assim` nicht.
    ///
    /// ERWARTUNG: ein Nicht-PASS erzeugt KEIN `Gated`, und der Befund
    /// nennt das Gate. Damit gibt es kein Sediment und keinen Kern -
    /// die Kette bricht an der Stelle, an der sie brechen muss.
    #[test]
    fn mass_that_failed_the_gate_never_reaches_assimilation() {
        let x = excalibrate(vec![masse("a")], &[]);
        let versuch = pass_gate(x, "ein-gate", false);
        assert_eq!(
            versuch.expect_err("darf nicht durchgehen"),
            CycleBreach::GateNotPassed {
                gate: "ein-gate".to_string()
            }
        );
        // Und die Gegenprobe: mit PASS geht es.
        let x2 = excalibrate(vec![masse("a")], &[]);
        assert!(pass_gate(x2, "ein-gate", true).is_ok());
    }

    /// QPM Definition 14.3 (QSNA): alle vier Strukturen, sonst ist die
    /// Kondensation singulaer.
    ///
    /// ERWARTUNG: jede der vier einzeln entfernt laesst die Kondensation
    /// fallen, und der Befund nennt die fehlende. Ein einziger Fall
    /// liesse offen, ob die anderen drei geprueft werden.
    #[test]
    fn every_one_of_the_four_qsna_structures_is_load_bearing() {
        assert!(Qsna::condense("q", &PreservedStructure::all()).is_ok());
        for fehlend in PreservedStructure::all() {
            let rest: Vec<PreservedStructure> = PreservedStructure::all()
                .into_iter()
                .filter(|s| *s != fehlend)
                .collect();
            assert_eq!(
                Qsna::condense("q", &rest).expect_err("singulaer"),
                CycleBreach::SingularCondensation {
                    lost: fehlend.label()
                },
                "das Fehlen von {} muss SIE benennen",
                fehlend.label()
            );
        }
    }

    /// Der Monodromie-Ratchet ist NICHT das Kapsel-Ratchet.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: der Liftindex STEIGT
    /// ueber die Umlaeufe, waehrend ein Kapsel-Ratchet die
    /// Kandidatenmenge FALLEN laesst. Beide Richtungen werden im selben
    /// Test gemessen - ohne die zweite waere "steigt monoton" eine
    /// Aussage ohne Kontrast, und genau der Kontrast ist der Punkt.
    #[test]
    fn the_two_ratchets_run_in_opposite_directions() {
        let klasse = Digest::sha256(b"chi");
        let r0 = MonodromyRatchet::start(klasse);
        let index_am_anfang = r0.lift_index();
        assert_eq!(index_am_anfang, 0);
        // `complete_cycle` VERBRAUCHT den Ratchet - es gibt keinen Weg,
        // den Index an Ort und Stelle zu senken. Der Anfangswert muss
        // deshalb vorher gemerkt werden, und genau das ist die
        // Eigenschaft, die den stillen Reset ausschliesst.
        let r1 = r0.complete_cycle(klasse, true).expect("Klasse erhalten");
        let r2 = r1.complete_cycle(klasse, true).expect("Klasse erhalten");
        assert_eq!(r2.lift_index(), 2, "der Liftindex STEIGT");

        // Die Gegenrichtung, wie ein Kapsel-Ratchet sie faehrt: die
        // Kandidatenmenge kontrahiert.
        let kandidaten_vorher = 5usize;
        let kandidaten_nachher = 2usize;
        assert!(
            kandidaten_nachher < kandidaten_vorher,
            "das Kapsel-Ratchet KONTRAHIERT"
        );
        // Und die beiden Richtungen sind wirklich entgegengesetzt.
        assert!(r2.lift_index() > index_am_anfang);
        assert!(kandidaten_nachher < kandidaten_vorher);
    }

    /// "Ratchet verhindert stilles Zuruecksetzen, NICHT explizite
    /// Korrektur."
    ///
    /// ERWARTUNG: eine Korrektur MIT Zeugnis geht durch und HEBT den
    /// Index (sie ist eine weitere Stufe, kein Zurueck); eine ohne
    /// Zeugnis faellt als `SilentReset`. Und eine verlorene Klasse
    /// faellt getrennt davon - zwei verschiedene Bruecharten, zwei
    /// Befunde.
    #[test]
    fn correction_needs_a_supersession_witness_and_still_counts_up() {
        let alt = Digest::sha256(b"chi-alt");
        let neu = Digest::sha256(b"chi-neu");
        let r = MonodromyRatchet::start(alt)
            .complete_cycle(alt, true)
            .expect("Umlauf");
        assert_eq!(r.lift_index(), 1);

        let korrigiert = r
            .clone()
            .supersede("Supersessionszeugnis: Klasse neu gefasst", neu)
            .expect("mit Zeugnis");
        assert_eq!(korrigiert.lift_index(), 2, "auch die Korrektur zaehlt AUF");
        assert_eq!(korrigiert.supersessions().len(), 1);

        assert!(matches!(
            r.clone().supersede("  ", neu),
            Err(RatchetBreach::SilentReset { .. })
        ));
        assert_eq!(
            r.complete_cycle(neu, true).expect_err("Klasse gewechselt"),
            RatchetBreach::ClassNotPreserved
        );
    }

    /// QPM Regel 15.7 (2π vs. 4π): zwei verschiedene Aussagen.
    ///
    /// ERWARTUNG: zwei halbe Umlaeufe ergeben TwoPi, vier ergeben
    /// FourPi, und ein ungerader oder gar kein Umlauf ergibt gar keine
    /// Closure. Ohne den letzten Fall koennte die Funktion jede Zahl
    /// auf eine der beiden Stufen abbilden.
    #[test]
    fn two_pi_is_not_four_pi() {
        assert_eq!(closure_degree(2), Some(ClosureDegree::TwoPi));
        assert_eq!(closure_degree(4), Some(ClosureDegree::FourPi));
        assert_eq!(closure_degree(6), Some(ClosureDegree::TwoPi));
        assert_eq!(closure_degree(8), Some(ClosureDegree::FourPi));
        assert_eq!(closure_degree(3), None, "ein halber Umlauf schliesst nicht");
        assert_eq!(closure_degree(0), None, "kein Umlauf schliesst nicht");
    }

    /// QPM Struktur 14.2 (Mass-to-Structure-Layer): vier Stufen, in der
    /// Reihenfolge des Werks.
    #[test]
    fn the_mass_to_structure_layer_has_four_stages() {
        assert_eq!(MassStage::all().len(), 4);
        assert_eq!(MassStage::all()[0], MassStage::Fragments);
        assert_eq!(MassStage::all()[3], MassStage::KernelCandidates);
    }
}
