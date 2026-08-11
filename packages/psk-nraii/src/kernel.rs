//! L8: das 4-4-4-Schloss, der Projektionszwilling und der irreduzible
//! Kern.
//!
//! QPM Struktur 9.1 (Normative Schichten L0–L9) gibt der Schicht die
//! Rolle "Fix, dreifache Vierfachclosure, Replay, PathInv";
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB)
//! verlangt fuer NRAII-8 einen "4-4-4-, Gate-, Replay-, PathInv- und
//! Irreduzibilitaetszertifizierten Kern".
//!
//! ## Warum die drei Schloesser sich hier nicht implizieren KOENNEN
//!
//! QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis): "Aus C4^geo = 1
//! folgt weder C4^epi = 1 noch C4^op = 1. Eine visuell oder topologisch
//! geschlossene Oberflaeche reicht nicht fuer Evidenz- oder
//! Betriebsclosure."
//!
//! Als Kommentar waere das eine Zusage. Gebaut ist es als Form, auf
//! zwei Ebenen:
//!
//! 1. **Drei getrennte Komponententypen.** [`GeoComponent`],
//!    [`EpiComponent`] und [`OpComponent`] sind verschiedene Typen, und
//!    es gibt zwischen ihnen keine Umwandlung, kein gemeinsames Trait
//!    und keinen gemeinsamen Konstruktor. Eine geometrische Komponente
//!    laesst sich nicht dort einsetzen, wo eine epistemische verlangt
//!    ist - das ist ein Uebersetzungsfehler, keine Laufzeitpruefung.
//!    Der Nachweis dafuer steht als `compile_fail` an [`EpiLock`].
//! 2. **Drei getrennte Schlosstypen.** [`GeoLock`], [`EpiLock`] und
//!    [`OpLock`] tragen keinen gemeinsamen Typ, aus dem einer den
//!    anderen erzeugen koennte. [`C444::certify`] verlangt alle drei
//!    einzeln; es gibt keinen Weg, zweimal dasselbe Schloss
//!    einzureichen und dreifache Closure zu bekommen.
//!
//! Ein einziges `Lock::new(kind, components)` haette beides
//! aufgehoben: dann waere `Lock::new(Epi, geometrische_komponenten)`
//! ein gueltiger Aufruf gewesen, und
//! QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis) haette wieder
//! von der Sorgfalt des Aufrufers abgehangen.
//!
//! ## Was C4 ist und was nicht
//!
//! QPM Definition 16.1 (Lokales Vierfachprimitiv) schliesst mit einem
//! Satz, der leicht zu ueberlesen ist: "C4 ist ein lokaler
//! Schliessungszeuge, kein globaler Wahrheitsoperator." [`c4`] heisst
//! deshalb so und gibt einen [`LocalWitness`] zurueck, kein `bool`:
//! wer ihn weiterreicht, reicht einen benannten lokalen Zeugen weiter
//! und keine Wahrheit.
//!
//! ## Wo L8 aufhoert
//!
//! [`IrreducibleCore`] ist die Stelle, an der der [`crate::StackFixpoint`]
//! aus L7 zu `K*` wird - die Zertifizierung, die L7 ausdruecklich
//! zurueckgehalten hat. Sie besteht aus zwei Bedingungen, und
//! QPM Definition 16.3 (4-4-4-Closure) nennt beide: `C444 = 1` UND alle
//! offenen Pflichten des Proof-Horizon erfuellt oder explizit als
//! nichtclosurewirksam klassifiziert. Die zweite ist seit L7 als
//! [`crate::ProofHorizon::closure_admissible`] ausdrueckbar; hier wird
//! sie verlangt.

use crate::{CanonicalState, ContractComponent, DomainContract, ProofHorizon, StackFixpoint};
use psk_types::Digest;
use std::collections::BTreeSet;

// -------------------------------------------------- Lokales Vierfachprimitiv

/// Eine typisierte Closure-Zelle aus
/// QPM Definition 16.1 (Lokales Vierfachprimitiv).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureCell {
    pub id: String,
    /// Ob das Gate dieser Zelle auf PASS steht.
    pub gate_passed: bool,
}

/// Das Ergebnis von [`c4`] - ein LOKALER Schliessungszeuge.
///
/// QPM Definition 16.1 (Lokales Vierfachprimitiv), letzter Satz: "C4
/// ist ein lokaler Schliessungszeuge, kein globaler Wahrheitsoperator."
/// Deshalb ein eigener Typ und kein `bool`: ein `bool` haette sich mit
/// jedem anderen Wahrheitswert vermischen lassen, und genau diese
/// Vermischung ist der Fehler, den
/// QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis) benennt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWitness {
    cells: Vec<String>,
}

impl LocalWitness {
    /// Welche vier Zellen dieser Zeuge deckt - und mehr sagt er nicht.
    pub fn cells(&self) -> &[String] {
        &self.cells
    }
}

/// Warum ein lokales Vierfachprimitiv nicht schliesst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum C4Breach {
    /// Eine der vier Zellen steht nicht auf PASS.
    GateNotPassed { cell: String },
    /// Zwei benachbarte Zellen sind nicht kompatibel.
    Incompatible { left: String, right: String },
}

/// `C4(l) = 1` nach QPM Definition 16.1 (Lokales Vierfachprimitiv):
/// alle vier Gates auf PASS UND alle drei Nachbarschaften kompatibel.
///
/// Die Kompatibilitaet kommt als Praedikat herein - was zwei Zellen in
/// einer Domaene kompatibel macht, sagt das Werk nicht, und die
/// Erfindung waere hier so falsch wie beim GateSet.
pub fn c4(
    cells: &[ClosureCell; 4],
    compat: impl Fn(&ClosureCell, &ClosureCell) -> bool,
) -> Result<LocalWitness, C4Breach> {
    for cell in cells {
        if !cell.gate_passed {
            return Err(C4Breach::GateNotPassed {
                cell: cell.id.clone(),
            });
        }
    }
    for pair in cells.windows(2) {
        if !compat(&pair[0], &pair[1]) {
            return Err(C4Breach::Incompatible {
                left: pair[0].id.clone(),
                right: pair[1].id.clone(),
            });
        }
    }
    Ok(LocalWitness {
        cells: cells.iter().map(|c| c.id.clone()).collect(),
    })
}

// ------------------------------------------------- Drei Vierfachschloesser

/// Die vier Komponenten von `C4^geo`
/// (QPM Definition 16.2 (Drei Vierfachschlösser)).
///
/// Ein eigener Typ, nicht ein Fall eines gemeinsamen: siehe den
/// Modulkopf. Zwischen den drei Komponentenmengen gibt es keine
/// Umwandlung.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GeoComponent {
    Projection,
    Counterphase,
    Seam,
    Orientation,
}

/// Die vier Komponenten von `C4^epi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EpiComponent {
    Observation,
    CounterHorizon,
    NullModel,
    Residue,
}

/// Die vier Komponenten von `C4^op`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum OpComponent {
    Gate,
    Trace,
    Replay,
    PathInv,
}

impl GeoComponent {
    pub fn all() -> [GeoComponent; 4] {
        use GeoComponent::*;
        [Projection, Counterphase, Seam, Orientation]
    }

    pub fn label(&self) -> &'static str {
        use GeoComponent::*;
        match self {
            Projection => "C_projection",
            Counterphase => "C_counterphase",
            Seam => "C_seam",
            Orientation => "C_orientation",
        }
    }
}

impl EpiComponent {
    pub fn all() -> [EpiComponent; 4] {
        use EpiComponent::*;
        [Observation, CounterHorizon, NullModel, Residue]
    }

    pub fn label(&self) -> &'static str {
        use EpiComponent::*;
        match self {
            Observation => "C_observation",
            CounterHorizon => "C_counterhorizon",
            NullModel => "C_nullmodel",
            Residue => "C_residue",
        }
    }
}

impl OpComponent {
    pub fn all() -> [OpComponent; 4] {
        use OpComponent::*;
        [Gate, Trace, Replay, PathInv]
    }

    pub fn label(&self) -> &'static str {
        use OpComponent::*;
        match self {
            Gate => "C_gate",
            Trace => "C_trace",
            Replay => "C_replay",
            PathInv => "C_pathinv",
        }
    }
}

/// Warum ein Vierfachschloss oder die dreifache Closure nicht schliesst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificationBreach {
    /// Eine Komponente des Schlosses fehlt - benannt, nicht gezaehlt.
    MissingComponent {
        lock: &'static str,
        component: &'static str,
    },
    /// Der Proof-Horizon laesst die Closure nicht zu: eine offene
    /// Pflicht ist weder erfuellt noch klassifiziert
    /// (QPM Definition 16.3 (4-4-4-Closure)).
    ProofHorizonBlocks { obligation: String },
}

/// `C4^geo` - geschlossen, wenn alle vier geometrischen Komponenten
/// zeugen.
///
/// Es gibt keinen Weg von hier zu [`EpiLock`] oder [`OpLock`]: kein
/// `From`, kein gemeinsames Trait, kein Feldzugriff, aus dem sich einer
/// bauen liesse. QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis)
/// ist damit nicht zugesagt, sondern unumgehbar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoLock {
    witnessed: BTreeSet<&'static str>,
}

/// `C4^epi` - die epistemische Closure.
///
/// Die Komponenten sind [`EpiComponent`], und nur die. Eine
/// geometrische Komponente hier einzusetzen ist ein
/// Uebersetzungsfehler:
///
/// ```compile_fail,E0308
/// # use psk_nraii::{EpiLock, GeoComponent};
/// let _ = EpiLock::close(&[
///     GeoComponent::Projection,
///     GeoComponent::Counterphase,
///     GeoComponent::Seam,
///     GeoComponent::Orientation,
/// ]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpiLock {
    witnessed: BTreeSet<&'static str>,
}

/// `C4^op` - die Betriebsclosure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpLock {
    witnessed: BTreeSet<&'static str>,
}

impl GeoLock {
    /// Schliesst, wenn alle vier Komponenten bezeugt sind; sonst nennt
    /// der Befund die erste fehlende.
    pub fn close(witnessed: &[GeoComponent]) -> Result<Self, CertificationBreach> {
        let set: BTreeSet<&'static str> = witnessed.iter().map(|c| c.label()).collect();
        for c in GeoComponent::all() {
            if !set.contains(c.label()) {
                return Err(CertificationBreach::MissingComponent {
                    lock: "C4^geo",
                    component: c.label(),
                });
            }
        }
        Ok(GeoLock { witnessed: set })
    }

    pub fn witnessed(&self) -> impl Iterator<Item = &&'static str> {
        self.witnessed.iter()
    }
}

impl EpiLock {
    pub fn close(witnessed: &[EpiComponent]) -> Result<Self, CertificationBreach> {
        let set: BTreeSet<&'static str> = witnessed.iter().map(|c| c.label()).collect();
        for c in EpiComponent::all() {
            if !set.contains(c.label()) {
                return Err(CertificationBreach::MissingComponent {
                    lock: "C4^epi",
                    component: c.label(),
                });
            }
        }
        Ok(EpiLock { witnessed: set })
    }

    pub fn witnessed(&self) -> impl Iterator<Item = &&'static str> {
        self.witnessed.iter()
    }
}

impl OpLock {
    pub fn close(witnessed: &[OpComponent]) -> Result<Self, CertificationBreach> {
        let set: BTreeSet<&'static str> = witnessed.iter().map(|c| c.label()).collect();
        for c in OpComponent::all() {
            if !set.contains(c.label()) {
                return Err(CertificationBreach::MissingComponent {
                    lock: "C4^op",
                    component: c.label(),
                });
            }
        }
        Ok(OpLock { witnessed: set })
    }

    pub fn witnessed(&self) -> impl Iterator<Item = &&'static str> {
        self.witnessed.iter()
    }
}

/// `C444 = C4^geo ∧ C4^epi ∧ C4^op`
/// (QPM Definition 16.3 (4-4-4-Closure)).
///
/// Der einzige Konstruktor verlangt alle drei Schloesser einzeln. Weil
/// sie drei verschiedene Typen sind, laesst sich dasselbe Schloss nicht
/// dreimal einreichen - der Aufruf uebersetzt dann nicht.
///
/// Von aussen unkonstruierbar:
///
/// ```compile_fail,E0451
/// let _ = psk_nraii::C444 { geo: todo!(), epi: todo!(), op: todo!() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct C444 {
    geo: GeoLock,
    epi: EpiLock,
    op: OpLock,
}

impl C444 {
    /// Die dreifache Closure. Nimmt die drei Schloesser als Werte -
    /// wer sie hat, hat sie einzeln erworben.
    ///
    /// Dreimal dasselbe Schloss einzureichen ist kein Missbrauch,
    /// sondern ein Uebersetzungsfehler. Der Nachweis, gemessen:
    ///
    /// ```compile_fail,E0308
    /// # use psk_nraii::{C444, GeoComponent, GeoLock};
    /// let geo = GeoLock::close(&GeoComponent::all()).unwrap();
    /// let _ = C444::certify(geo.clone(), geo.clone(), geo);
    /// ```
    ///
    /// Genau das ist die Form, die
    /// QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis) verlangt:
    /// aus einer geschlossenen Geometrie folgt keine Evidenz- und
    /// keine Betriebsclosure, und hier ist der Schluss nicht bloss
    /// verboten, sondern unformulierbar.
    pub fn certify(geo: GeoLock, epi: EpiLock, op: OpLock) -> Self {
        C444 { geo, epi, op }
    }

    pub fn geo(&self) -> &GeoLock {
        &self.geo
    }

    pub fn epi(&self) -> &EpiLock {
        &self.epi
    }

    pub fn op(&self) -> &OpLock {
        &self.op
    }
}

// ------------------------------------------------------ Projektionszwilling

/// Warum der Projektionszwilling etwas zurueckweist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwinBreach {
    /// Die Observable steht nicht im Domain-Vertrag. Der Zwilling
    /// repraesentiert "ausschliesslich die im Domain-Vertrag
    /// enthaltenen Observablen"
    /// (QPM Vertrag 17.2 (Repräsentationsgrenze)).
    NotInContract { observable: String },
    /// Nach dieser Observable wurde gefragt, aber sie ist nicht
    /// beobachtet. Der Zwilling ist "keine Lizenz, nicht beobachtbare
    /// innere Zustaende als bekannt auszugeben" - also gibt es hier
    /// keinen Wert, sondern diesen Befund.
    NotObserved { observable: String },
}

/// Eine Hypothese ueber den Zwilling, die noch nicht revalidiert ist.
///
/// QPM Struktur 17.1 (Projektionstwin): "jede Hypothese wird gegen neue
/// beobachtbare Antworten des externen Systems revalidiert." Dieser Typ
/// traegt die unvalidierte Form, und aus ihm fuehrt genau ein Weg
/// heraus - [`revalidate`]. Dasselbe Muster wie bei
/// [`crate::Materialization`], aus der kein Weg zur Closure fuehrt
/// ausser ueber die Reobservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hypothesis {
    pub claim: String,
}

/// Eine Hypothese, die gegen eine NEUE beobachtbare Antwort gehalten
/// wurde.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revalidated {
    claim: String,
    against: String,
}

impl Revalidated {
    pub fn claim(&self) -> &str {
        &self.claim
    }

    /// Die Antwort, gegen die revalidiert wurde - ohne sie waere die
    /// Revalidierung eine Behauptung ueber sich selbst.
    pub fn against(&self) -> &str {
        &self.against
    }
}

/// Der Projektionszwilling `X_twin` aus
/// QPM Struktur 17.1 (Projektionstwin).
///
/// QPM Vertrag 17.2 (Repräsentationsgrenze) zieht zwei Grenzen, und
/// beide sind hier Form statt Zusage:
///
/// - Der Zwilling repraesentiert "ausschliesslich die im Domain-Vertrag
///   enthaltenen Observablen": [`ProjectionTwin::project`] weist jede
///   ab, die nicht in [`crate::ContractComponent::Obs`] steht.
/// - Er ist "keine Lizenz, nicht beobachtbare innere Zustaende als
///   bekannt auszugeben": [`ProjectionTwin::read`] gibt fuer eine nicht
///   beobachtete Observable KEINEN Wert, sondern
///   [`TwinBreach::NotObserved`]. Es gibt keinen Standardwert und
///   keinen `unwrap_or` - ein Ersatzwert waere genau die Lizenz, die
///   der Vertrag ausschliesst.
///
/// "Zulaessige Operatoren wirken ausschliesslich auf X_twin": alle
/// Methoden hier arbeiten auf dem Zwilling, und es gibt keinen Zugriff
/// auf ein externes System - dieses Paket kennt keines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionTwin {
    observed: Vec<(String, String)>,
}

impl ProjectionTwin {
    /// `P: X_ext -> X_twin`, unter der Repraesentationsgrenze.
    pub fn project(
        contract: &DomainContract,
        observed: &[(String, String)],
    ) -> Result<Self, TwinBreach> {
        let erlaubt = contract.component(ContractComponent::Obs);
        for (name, _) in observed {
            if !erlaubt.iter().any(|o| o == name) {
                return Err(TwinBreach::NotInContract {
                    observable: name.clone(),
                });
            }
        }
        Ok(ProjectionTwin {
            observed: observed.to_vec(),
        })
    }

    /// Was der Zwilling ueber eine Observable weiss - oder der Befund,
    /// dass er nichts weiss.
    pub fn read(&self, observable: &str) -> Result<&str, TwinBreach> {
        self.observed
            .iter()
            .find(|(n, _)| n == observable)
            .map(|(_, v)| v.as_str())
            .ok_or_else(|| TwinBreach::NotObserved {
                observable: observable.to_string(),
            })
    }

    pub fn observed(&self) -> &[(String, String)] {
        &self.observed
    }
}

/// Haelt eine Hypothese gegen eine neue beobachtbare Antwort.
///
/// `answer` MUSS aus dem Zwilling gelesen werden koennen - eine
/// Revalidierung gegen etwas Unbeobachtetes waere die Lizenz, die
/// QPM Vertrag 17.2 (Repräsentationsgrenze) ausschliesst.
pub fn revalidate(
    twin: &ProjectionTwin,
    hypothesis: Hypothesis,
    against: &str,
) -> Result<Revalidated, TwinBreach> {
    twin.read(against)?;
    Ok(Revalidated {
        claim: hypothesis.claim,
        against: against.to_string(),
    })
}

// --------------------------------------------------------- Abstraktes Schloss

/// Warum eine Operatorfolge das abstrakte Schloss nicht loest.
///
/// Nur EIN Grund, und das ist Absicht: die zweite Bedingung aus
/// QPM Struktur 17.3 (Abstraktes Schloss) - `C444(x*) = 1` - ist keine
/// Pruefung in [`AbstractLock::solve`], sondern seine Signatur. Wer
/// kein [`C444`] hat, ruft nicht auf; der Nachweis dafuer steht als
/// `compile_fail` dort. Dasselbe Muster wie bei
/// [`crate::pass_gate`] und dem [`crate::CycleGate`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockBreach {
    /// `[x*]_◇ != [x_target]_◇` - die Klassen stimmen nicht ueberein.
    ClassMismatch,
}

/// `L = (X, Omega, ≡◇, G, C444)` aus
/// QPM Struktur 17.3 (Abstraktes Schloss).
///
/// "Eine Operatorfolge loest das Schloss nur relativ zum
/// Domain-Vertrag, wenn `[x*]◇ = [x_target]◇` UND `C444(x*) = 1`."
///
/// ZWEI Bedingungen, und [`AbstractLock::solve`] verlangt beide. Die
/// eine ohne die andere loest nichts - dieselbe Trennung wie zwischen
/// Wish-Distanz und Berechtigung, und aus demselben Grund: eine
/// Uebereinstimmung ist noch keine Closure.
///
/// "Der Universalschluessel ist kein einzelner Schluessel, sondern ein
/// domaenenvertraglich gebundener Such-, Inversions-, Projektions- und
/// Closure-Apparat" - deshalb traegt das Schloss den Vertrag, gegen den
/// es gilt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbstractLock {
    target_class: Digest,
    contract_identity: String,
}

/// Der Beleg, dass eine Operatorfolge das Schloss geloest hat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockOpened {
    class: Digest,
    contract_identity: String,
    closure: C444,
}

impl LockOpened {
    pub fn class(&self) -> &Digest {
        &self.class
    }

    /// Gegen WELCHEN Vertrag geloest wurde. "Nur relativ zum
    /// Domain-Vertrag" steht in der Struktur; ohne diese Angabe waere
    /// der Beleg absolut gelesen worden.
    pub fn contract_identity(&self) -> &str {
        &self.contract_identity
    }

    /// Die dreifache Closure, mit der geoeffnet wurde.
    pub fn closure(&self) -> &C444 {
        &self.closure
    }
}

impl AbstractLock {
    pub fn with_target(contract: &DomainContract, target: &CanonicalState) -> Self {
        AbstractLock {
            target_class: target.digest(),
            contract_identity: contract.target_identity().to_string(),
        }
    }

    /// Loest das Schloss - nur mit beiden Bedingungen.
    ///
    /// Die zweite steht in der Signatur: [`C444`] wird als Wert
    /// verlangt, und den gibt es nur mit allen drei
    /// Vierfachschloessern. Ohne ihn ist der Aufruf nicht bildbar -
    /// nicht "erlaubt und geprueft", sondern nicht vorhanden:
    ///
    /// ```compile_fail,E0061
    /// # use psk_nraii::{AbstractLock, CanonicalState, DomainContract};
    /// # fn f(schloss: &AbstractLock, x: &CanonicalState) {
    /// let _ = schloss.solve(x);
    /// # }
    /// ```
    ///
    /// Der Beleg traegt die Closure weiter, gegen die geoeffnet wurde.
    /// Ein `LockOpened` ohne sie waere ein Beleg ohne Gegenstand.
    pub fn solve(&self, candidate: &CanonicalState, c444: &C444) -> Result<LockOpened, LockBreach> {
        if candidate.digest() != self.target_class {
            return Err(LockBreach::ClassMismatch);
        }
        Ok(LockOpened {
            class: self.target_class,
            contract_identity: self.contract_identity.clone(),
            closure: c444.clone(),
        })
    }
}

// ---------------------------------------------------------- Irreduzibler Kern

/// `K*` aus QPM Regel 17.6 (Irreduzibler Kern): "die quasi-singulaere,
/// gate- und replayzertifizierte Restklasse".
///
/// Das ist die Stelle, an der der [`crate::StackFixpoint`] aus L7 zum
/// Kern wird. L7 hat den Namen bewusst nicht vergeben, weil die
/// Zertifizierung dort fehlte; hier ist sie faellig und wird verlangt:
///
/// - der Fixpunkt selbst, VERBRAUCHT statt geliehen - ein Kern, dessen
///   Fixpunkt danach noch anderweitig zertifiziert werden koennte,
///   waere zwei Kerne;
/// - `C444` als Wert, also alle drei Vierfachschloesser;
/// - ein Proof-Horizon, der die Closure zulaesst
///   (QPM Definition 16.3 (4-4-4-Closure), zweite Bedingung).
///
/// Von aussen unkonstruierbar:
///
/// ```compile_fail,E0451
/// let _ = psk_nraii::IrreducibleCore {
///     digest: todo!(),
///     condensed_from: String::new(),
///     closure: todo!(),
///     horizon_version: String::new(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IrreducibleCore {
    digest: Digest,
    condensed_from: String,
    /// Die Closure, auf der dieser Kern ruht - "gate- und
    /// replayzertifiziert" steht in der Regel, also ist die
    /// Zertifizierung am Kern ABLESBAR und nicht bloss vorausgesetzt.
    closure: C444,
    /// Unter welcher Fassung des Proof-Horizon zertifiziert wurde. Der
    /// Horizont ist versioniert (QPM Definition 13.5 (Proof-Horizon));
    /// ein Kern, der nicht sagt gegen welchen Stand er geschlossen ist,
    /// waere morgen unbelegt.
    horizon_version: String,
}

impl IrreducibleCore {
    /// `H(Can(K*))`.
    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    /// Die Stackebene, aus der kondensiert wurde.
    pub fn condensed_from(&self) -> &str {
        &self.condensed_from
    }

    /// Die dreifache Closure, die diesen Kern zertifiziert.
    pub fn closure(&self) -> &C444 {
        &self.closure
    }

    pub fn horizon_version(&self) -> &str {
        &self.horizon_version
    }
}

/// Kondensiert einen Fixpunkt zum irreduziblen Kern
/// (QPM Regel 17.6 (Irreduzibler Kern)).
///
/// Der Fixpunkt geht als WERT hinein und ist danach verbraucht: ein
/// Fixpunkt, der nach der Kondensation noch ein zweites Mal
/// zertifiziert werden koennte, waere zwei Kerne aus einer Restklasse.
/// Dasselbe Muster wie bei [`crate::MonodromyRatchet::complete_cycle`].
pub fn certify_core(
    fixpoint: StackFixpoint,
    c444: &C444,
    horizon: &ProofHorizon,
) -> Result<IrreducibleCore, CertificationBreach> {
    if let Some(blocking) = horizon.blocking().first() {
        return Err(CertificationBreach::ProofHorizonBlocks {
            obligation: blocking.text.clone(),
        });
    }
    Ok(IrreducibleCore {
        digest: *fixpoint.digest(),
        condensed_from: fixpoint.condensed_from().to_string(),
        closure: c444.clone(),
        horizon_version: horizon.version.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        reach_fixpoint, AttractorMap, AttractorStack, ClaimStatus, FoldBundle, ObligationStanding,
        ProofObligation, Response, ResponseOrigin, StackLevel,
    };
    use psk_canon::Media;

    fn zustand(inhalt: &str) -> CanonicalState {
        CanonicalState::canonicalize(inhalt.as_bytes(), Media::Json).expect("kanonisierbar")
    }

    fn vertrag_mit_obs(obs: &[&str]) -> DomainContract {
        let entries: Vec<(ContractComponent, Vec<String>)> = ContractComponent::all()
            .into_iter()
            .map(|c| {
                if c == ContractComponent::Obs {
                    (c, obs.iter().map(|o| o.to_string()).collect())
                } else {
                    (c, vec![format!("{}-eintrag", c.label())])
                }
            })
            .collect();
        DomainContract::bind(&entries, ClaimStatus::N, "kern-domaene").expect("zehn Komponenten")
    }

    fn zelle(id: &str, passed: bool) -> ClosureCell {
        ClosureCell {
            id: id.to_string(),
            gate_passed: passed,
        }
    }

    fn c444_voll() -> C444 {
        C444::certify(
            GeoLock::close(&GeoComponent::all()).expect("vier geo"),
            EpiLock::close(&EpiComponent::all()).expect("vier epi"),
            OpLock::close(&OpComponent::all()).expect("vier op"),
        )
    }

    fn fixpunkt() -> StackFixpoint {
        let stack = AttractorStack::embed(
            vec![
                StackLevel {
                    id: "unten".into(),
                    map: AttractorMap::triangulate(vec![Response {
                        marker: "m".into(),
                        value: "v".into(),
                        origin: ResponseOrigin::Data,
                    }]),
                },
                StackLevel {
                    id: "oben".into(),
                    map: AttractorMap::triangulate(vec![Response {
                        marker: "m".into(),
                        value: "v".into(),
                        origin: ResponseOrigin::Data,
                    }]),
                },
            ],
            &[],
        )
        .expect("zwei Ebenen");
        let gleich = || zustand(r#"{"kern":"K"}"#);
        reach_fixpoint(&stack, &FoldBundle::bundle(gleich(), gleich(), gleich())).expect("Fixpunkt")
    }

    /// QPM Definition 16.1 (Lokales Vierfachprimitiv): beide Haelften
    /// der Konjunktion tragen, und der Zeuge ist LOKAL.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: alle vier Gates auf
    /// PASS und alle drei Nachbarschaften kompatibel ergeben einen
    /// Zeugen; ein einziges Nicht-PASS und eine einzige
    /// Unvertraeglichkeit lassen ihn je fuer sich fallen, mit der
    /// Stelle im Befund. Ohne BEIDE Gegenproben liesse der Test offen,
    /// ob eine der zwei Haelften ueberhaupt geprueft wird.
    #[test]
    fn the_local_quadruple_needs_both_halves_of_the_conjunction() {
        let zellen = [
            zelle("c1", true),
            zelle("c2", true),
            zelle("c3", true),
            zelle("c4", true),
        ];
        let zeuge = c4(&zellen, |_, _| true).expect("vier PASS, drei kompatibel");
        assert_eq!(zeuge.cells(), &["c1", "c2", "c3", "c4"]);

        // Erste Haelfte: jedes der vier Gates einzeln auf FAIL.
        for i in 0..4 {
            let mut kaputt = zellen.clone();
            kaputt[i].gate_passed = false;
            assert_eq!(
                c4(&kaputt, |_, _| true).expect_err("ein Gate nicht bestanden"),
                C4Breach::GateNotPassed {
                    cell: format!("c{}", i + 1)
                },
                "das Gate von c{} muss namentlich fallen",
                i + 1
            );
        }

        // Zweite Haelfte: die Nachbarschaft c2/c3 ist unvertraeglich.
        assert_eq!(
            c4(&zellen, |a, b| !(a.id == "c2" && b.id == "c3")).expect_err("unvertraeglich"),
            C4Breach::Incompatible {
                left: "c2".into(),
                right: "c3".into()
            }
        );
    }

    /// QPM Regel 16.5 (Kein lokaler Sieg als Globalbeweis), gemessen an
    /// dem, was das Werkzeug ueberhaupt messen KANN.
    ///
    /// Die Nichtimplikation selbst ist eine Aussage ueber das
    /// Typsystem: aus einem [`GeoLock`] fuehrt kein Weg zu [`EpiLock`]
    /// oder [`OpLock`], und der Nachweis dafuer ist der
    /// `compile_fail`-Doctest an [`EpiLock`] - ein Laufzeittest kann
    /// nicht pruefen, dass es einen Aufruf NICHT gibt.
    ///
    /// ERWARTUNG hier: die drei Schloesser schliessen unabhaengig
    /// voneinander. Ein vollstaendiges `C4^geo` besteht neben einem
    /// unvollstaendigen `C4^epi`, und der Befund nennt die fehlende
    /// epistemische Komponente - nicht die geometrische, die vorhanden
    /// ist.
    #[test]
    fn a_complete_geo_lock_says_nothing_about_the_other_two() {
        let geo = GeoLock::close(&GeoComponent::all()).expect("vier geo");
        assert_eq!(geo.witnessed().count(), 4);

        // Die epistemische Seite bleibt davon voellig unberuehrt.
        let epi_luecke = EpiLock::close(&[
            EpiComponent::Observation,
            EpiComponent::CounterHorizon,
            EpiComponent::NullModel,
        ])
        .expect_err("das Residuum fehlt");
        assert_eq!(
            epi_luecke,
            CertificationBreach::MissingComponent {
                lock: "C4^epi",
                component: "C_residue"
            }
        );

        // Und die operative ebenso.
        let op_luecke = OpLock::close(&[OpComponent::Gate, OpComponent::Trace])
            .expect_err("Replay und PathInv fehlen");
        assert_eq!(
            op_luecke,
            CertificationBreach::MissingComponent {
                lock: "C4^op",
                component: "C_replay"
            }
        );
    }

    /// Jede der zwoelf Komponenten ist tragend - einzeln geprueft.
    ///
    /// ERWARTUNG: jede der 4+4+4 einzeln entfernt laesst ihr Schloss
    /// fallen, und der Befund nennt SIE und ihr Schloss. Ein einziger
    /// Fall je Schloss liesse offen, ob die uebrigen drei ueberhaupt
    /// geprueft werden - dieselbe Ueberlegung wie bei der
    /// komponentenweisen Vertragsprobe.
    #[test]
    fn every_one_of_the_twelve_components_is_load_bearing() {
        for fehlend in GeoComponent::all() {
            let rest: Vec<GeoComponent> = GeoComponent::all()
                .into_iter()
                .filter(|c| *c != fehlend)
                .collect();
            assert_eq!(
                GeoLock::close(&rest).expect_err("unvollstaendig"),
                CertificationBreach::MissingComponent {
                    lock: "C4^geo",
                    component: fehlend.label()
                }
            );
        }
        for fehlend in EpiComponent::all() {
            let rest: Vec<EpiComponent> = EpiComponent::all()
                .into_iter()
                .filter(|c| *c != fehlend)
                .collect();
            assert_eq!(
                EpiLock::close(&rest).expect_err("unvollstaendig"),
                CertificationBreach::MissingComponent {
                    lock: "C4^epi",
                    component: fehlend.label()
                }
            );
        }
        for fehlend in OpComponent::all() {
            let rest: Vec<OpComponent> = OpComponent::all()
                .into_iter()
                .filter(|c| *c != fehlend)
                .collect();
            assert_eq!(
                OpLock::close(&rest).expect_err("unvollstaendig"),
                CertificationBreach::MissingComponent {
                    lock: "C4^op",
                    component: fehlend.label()
                }
            );
        }
        // Und die zwoelf Bezeichnungen sind paarweise verschieden -
        // faellt eine mit einer anderen zusammen, deckte ein Schloss
        // eine fremde Komponente ab.
        let mut alle: Vec<&str> = GeoComponent::all().iter().map(|c| c.label()).collect();
        alle.extend(EpiComponent::all().iter().map(|c| c.label()));
        alle.extend(OpComponent::all().iter().map(|c| c.label()));
        assert_eq!(alle.len(), 12);
        let einzeln: BTreeSet<&str> = alle.iter().copied().collect();
        assert_eq!(einzeln.len(), 12);
    }

    /// QPM Vertrag 17.2 (Repräsentationsgrenze): beide Grenzen.
    ///
    /// ERWARTUNG: eine Observable ausserhalb des Vertrags kommt nicht
    /// in den Zwilling; und eine, die im Vertrag steht, aber NICHT
    /// beobachtet wurde, liefert keinen Wert, sondern einen Befund.
    /// Der zweite Fall traegt den Test - er ist die "Lizenz, nicht
    /// beobachtbare innere Zustaende als bekannt auszugeben", die der
    /// Vertrag ausschliesst.
    #[test]
    fn the_twin_represents_only_the_contract_and_licenses_nothing() {
        let vertrag = vertrag_mit_obs(&["temperatur", "druck"]);

        let fremd = ProjectionTwin::project(&vertrag, &[("magnetfeld".into(), "3".into())])
            .expect_err("nicht im Vertrag");
        assert_eq!(
            fremd,
            TwinBreach::NotInContract {
                observable: "magnetfeld".into()
            }
        );

        let zwilling = ProjectionTwin::project(&vertrag, &[("temperatur".into(), "21".into())])
            .expect("im Vertrag");
        assert_eq!(zwilling.read("temperatur").expect("beobachtet"), "21");

        // "druck" steht im Vertrag, wurde aber nicht beobachtet: kein
        // Wert, kein Standardwert, ein Befund.
        assert_eq!(
            zwilling.read("druck").expect_err("nicht beobachtet"),
            TwinBreach::NotObserved {
                observable: "druck".into()
            }
        );
    }

    /// QPM Struktur 17.1 (Projektionstwin): "jede Hypothese wird gegen
    /// neue beobachtbare Antworten des externen Systems revalidiert."
    ///
    /// ERWARTUNG: eine Revalidierung gegen etwas Unbeobachtetes kommt
    /// nicht zustande, und der Befund ist derselbe wie beim Lesen - es
    /// gibt nur einen Weg, an einen Wert zu kommen. Die Gegenprobe:
    /// gegen eine beobachtete Antwort geht es, und der Beleg NENNT sie.
    #[test]
    fn a_hypothesis_revalidates_only_against_something_observed() {
        let vertrag = vertrag_mit_obs(&["temperatur", "druck"]);
        let zwilling = ProjectionTwin::project(&vertrag, &[("temperatur".into(), "21".into())])
            .expect("im Vertrag");

        let h = Hypothesis {
            claim: "der Zustand ist stabil".into(),
        };
        assert_eq!(
            revalidate(&zwilling, h.clone(), "druck").expect_err("unbeobachtet"),
            TwinBreach::NotObserved {
                observable: "druck".into()
            }
        );

        let belegt = revalidate(&zwilling, h, "temperatur").expect("beobachtet");
        assert_eq!(belegt.claim(), "der Zustand ist stabil");
        assert_eq!(belegt.against(), "temperatur");
    }

    /// QPM Struktur 17.3 (Abstraktes Schloss): ZWEI Bedingungen, und
    /// keine ersetzt die andere.
    ///
    /// ERWARTUNG: C444 allein loest nicht - bei falscher Klasse faellt
    /// es mit `ClassMismatch`. Die andere Richtung ist NICHT als
    /// Laufzeitfall messbar: ohne C444 gibt es den Aufruf nicht, und
    /// der Nachweis dafuer steht als `compile_fail` an
    /// [`AbstractLock::solve`]. Ohne den Fehlerfall hier sagte der
    /// Positivfall nur, dass `solve` manchmal gelingt.
    #[test]
    fn the_abstract_lock_needs_the_class_and_the_closure() {
        let vertrag = vertrag_mit_obs(&["temperatur"]);
        let ziel = zustand(r#"{"ziel":1}"#);
        let schloss = AbstractLock::with_target(&vertrag, &ziel);
        let c444 = c444_voll();

        // C444 liegt vor, Klasse stimmt nicht: die eine Bedingung
        // ersetzt die andere nicht.
        let daneben = zustand(r#"{"ziel":2}"#);
        assert_eq!(
            schloss.solve(&daneben, &c444).expect_err("falsche Klasse"),
            LockBreach::ClassMismatch
        );

        // Beides: geoeffnet, und der Beleg nennt Vertrag UND Closure.
        let offen = schloss.solve(&ziel, &c444).expect("beides");
        assert_eq!(offen.contract_identity(), "kern-domaene");
        assert_eq!(offen.class(), &ziel.digest());
        assert_eq!(offen.closure(), &c444);
    }

    /// QPM Regel 17.6 (Irreduzibler Kern) mit
    /// QPM Definition 16.3 (4-4-4-Closure): der Fixpunkt wird erst mit
    /// beiden Bedingungen zu K*.
    ///
    /// ERWARTUNG: ein blockierender Proof-Horizon verhindert den Kern,
    /// auch bei vollstaendigem C444 und erreichtem Fixpunkt - und der
    /// Befund NENNT die blockierende Pflicht. Genau das ist die zweite
    /// Bedingung, die L7 ausdrucksfaehig gemacht hat; ohne sie waere
    /// C444 allein der Kern gewesen.
    #[test]
    fn the_fixpoint_becomes_a_core_only_with_both_conditions() {
        let c444 = c444_voll();

        let blockiert = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![ProofObligation::open("Kalibrierung steht aus")],
        };
        assert_eq!(
            certify_core(fixpunkt(), &c444, &blockiert).expect_err("blockiert"),
            CertificationBreach::ProofHorizonBlocks {
                obligation: "Kalibrierung steht aus".into()
            }
        );

        // Eine KLASSIFIZIERTE Pflicht blockiert nicht - sie bleibt
        // offen und sichtbar, und der Kern entsteht trotzdem. Das ist
        // der zweite Disjunkt aus
        // QPM Definition 16.3 (4-4-4-Closure), hier im Gebrauch.
        let klassifiziert = ProofHorizon {
            version: "1.0.0".into(),
            obligations: vec![ProofObligation {
                text: "Nullmodellfamilie ist domaenengeliefert (NRAII-OBL-002)".into(),
                standing: ObligationStanding::NotClosureEffective {
                    justification: "das Werk liefert sie nicht universell".into(),
                },
            }],
        };
        assert!(!klassifiziert.is_closed(), "die Pflicht bleibt offen");
        let kern = certify_core(fixpunkt(), &c444, &klassifiziert).expect("zulaessig");
        assert_eq!(kern.condensed_from(), "oben");
        assert_eq!(kern.digest(), fixpunkt().digest());
        // Die Zertifizierung ist am Kern ABLESBAR, nicht bloss
        // vorausgesetzt - "gate- und replayzertifiziert" steht in
        // QPM Regel 17.6 (Irreduzibler Kern).
        assert_eq!(kern.closure(), &c444);
        assert!(kern.closure().op().witnessed().any(|w| *w == "C_replay"));
        assert!(kern.closure().op().witnessed().any(|w| *w == "C_gate"));
        assert_eq!(kern.horizon_version(), "1.0.0");
    }
}
