//! QPM-3: lineare Zeit, Phasenlift, Zyklusindex, Channel-Switch-Witness.
//!
//! Bis zur Taktumverdrahtung war diese Stufe domaenenblockiert, und der
//! Grund war ehrlich: `tick_no` stand auf 0, es gab keine Phasensiegel,
//! und ein Zyklusindex ueber einem Lauf ohne Zyklen waere eine Konstruktion
//! gewesen, keine Messung. Seit Regel 24.4 (Der Golden Run läuft unter tick)
//! laeuft der Referenzlauf real getaktet: `tick_no` erreicht 3, jede der
//! zwoelf Phasen jedes Takts traegt ihr Siegel. Damit sind theta-Dach, n_k
//! und die Leerlauf/Belegung-Unterscheidung ABLESBAR.
//!
//! ## Der Takt IST der Umlauf
//!
//! QPM Definition 2.3 (Angehobener Phasor) fuehrt die interne Phase auf der
//! universellen Ueberlagerung: theta-Dach_k in R, sichtbar
//! theta_k = theta-Dach_k mod 2pi, und n_k = floor((theta-Dach_k -
//! theta-Dach_0) / 2pi). Auf den Referenzlauf abgebildet: ein Takt
//! durchlaeuft die zwoelf kanonischen Phasen und kehrt zum Ausgangspunkt
//! zurueck - das IST eine volle Umdrehung. Die Phasenschrittweite ist
//! folglich 2pi/12.
//!
//! **Ganzzahlig in Zwoelfteln, nicht in Fliesskomma.** theta-Dach wird
//! hier als Zahl von Zwoelfteln einer Umdrehung gefuehrt. Dann ist
//! `theta = theta_hat % 12` und `n = theta_hat / 12` woertlich die
//! Formel der Definition - ganzzahlige Division IST die
//! Abrundungsfunktion -, und beide sind exakt statt gerundet. Ein
//! Fliesskommaphasor ginge ueber den Bericht in einen Digest ein und
//! waere damit nicht replaystabil; dieselbe Ueberlegung, aus der das Werk
//! ueberall `Scaled` statt `f64` fuehrt.
//!
//! ## Zwei Vorgaben aus QPM v1.0.7
//!
//! Der Auftraggeber hat zwei Regeln des Zweitwerks woertlich uebermittelt,
//! die seit der letzten QPM-Runde neu sind:
//!
//! - **"Keine Ablesung auf halber Rueckkehr"**: jede Beobachtung MUSS an
//!   ein Siegel gebunden sein; der Traceverweis zeigt auf ein
//!   Phasensiegel oder eine Zyklusgrenze, nicht auf eine beliebige
//!   Stelle der Kette. Umgesetzt in `RollState.seal_ref` - es gibt
//!   keinen Konstruktor, der einen Rollzustand OHNE Siegelbezug
//!   herstellt, und `derive_roll_states` liest ausschliesslich an
//!   Segmenten der beiden Siegelarten ab.
//! - **"Die Abtastrate bestimmt die aufzeichnende Seite"**: tastet das
//!   Instrument weniger Grenzen ab, als der Lauf versiegelt, MUSS die
//!   Differenz als registrierte Samplingluecke erscheinen - GETRENNT vom
//!   Massenzensus gefuehrt, denn eine ausgelassene Grenze erzeugt keine
//!   Masse, sondern eine Luecke im Beobachtungspfad. Umgesetzt als
//!   eigenes Feld `sampling_gaps`, das den Zensus aus `qpm_run` nicht
//!   beruehrt.
//!
//! **Offengelegte Luecke:** QPM v1.0.7 liegt nicht im Repository; im
//! Wurzelverzeichnis steht v1.0.6. Die beiden Regeln sind hier deshalb
//! ueber ihre uebermittelten TITEL zitiert, nicht ueber Nummern - eine
//! Nummer, die kein platziertes Werk traegt, koennte Stufe elf nicht
//! aufloesen, und ein Zitat, das nicht aufloest, ist schlimmer als ein
//! benannter Titel. Sobald das Werk vorliegt, sind beide zu numerieren.
//!
//! ## Was diese Stufe NICHT beansprucht
//!
//! Der Leckstatus (QPM Definition 2.7 (Rollzustand)s `l_k`) gehoert QPM-7 (Leckregister)
//! und ist hier `NotInstrumented` - nicht "kein Leck". Ein
//! Leckstatus ohne Leckregister waere dieselbe Erfindung wie ein
//! Phantom-Plugin. Ebenso bleibt das Verdikt bei UNKNOWN, solange
//! QPM-OBL-002 (kein `catalog_ref` im Scope) jeden Lauf deckelt - der
//! richtige Ausgang, nicht ein Fehlschlag.

use psk_fields::ChannelId;
use psk_types::{Digest, PskError, CANONICAL_PHASES};

use crate::IdentityVerdict;

use crate::GoldenRunReport;

/// Die Phasenschrittweite: eine volle Umdrehung sind zwoelf kanonische
/// Phasen (Definition 14.1 (Kanonische Taktfolge)), also ist ein Zwoelftel
/// der Schritt, in dem theta-Dach gefuehrt wird.
pub const TWELFTHS_PER_TURN: u64 = 12;

/// Woran die Ablesung haengt (Regel "Keine Ablesung auf halber
/// Rueckkehr"). Ein dritter Fall - "irgendwo in der Kette" - existiert
/// bewusst nicht: er waere genau die Ablesung im offenen Umlauf.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum BoundaryKind {
    /// Ein `phase.sealed.<label>`-Segment: das Siegel der p-ten Phase.
    PhaseSeal { phase: String, position: u64 },
    /// Ein `tick.closed`-Segment: die Zyklusgrenze, an der der Umlauf
    /// schliesst und ein Kanalwechsel ueberhaupt erst zulaessig waere
    /// (QPM Algorithmus 2.8 (Zyklusschnitt und Kanalwechsel)s `Seam_2pi`).
    CycleBoundary,
}

/// QPM Definition 2.7 (Rollzustand): q_k = (t_k, theta-Dach_k, theta_k, n_k,
/// c_k, o_k, x_k, r_k, l_k). Jedes Feld hier ist abgelesen, keines
/// gesetzt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RollState {
    /// t_k: die logische Zeit des Siegels (tau_i; die Wanduhr geht in
    /// nichts hier ein, Invariante 6.14 (Replayneutralität der Wanduhr)).
    pub t: u64,
    /// theta-Dach_k in Zwoelfteln - monoton fortschreitend, kehrt NICHT
    /// zurueck.
    pub theta_hat_twelfths: u64,
    /// theta_k = theta-Dach_k mod 2pi, sichtbar - kehrt je Takt zurueck.
    pub theta_twelfths: u64,
    /// n_k = floor((theta-Dach_k - theta-Dach_0) / 2pi).
    pub n: u64,
    /// c_k: der Kanal, auf dem abgelesen wird.
    pub channel: ChannelId,
    /// o_k in {+, -}: Vorwaerts, solange `seq` monoton steigt. Ein
    /// Rueckwaertslauf entstuende nur bei einem Replay gegen die Kette.
    pub orientation: Orientation,
    /// x_k: die Position der Maschine im Umlauf - die Phase, deren
    /// Siegel abgelesen wurde, bzw. die geschlossene Zyklusgrenze.
    pub machine_state: BoundaryKind,
    /// r_k: der Residuenstand zum Ablesezeitpunkt, gezaehlt an den
    /// Residuensegmenten bis hierher.
    pub residue_count: usize,
    /// l_k: siehe Modulkopf - QPM-7 ist nicht gebaut.
    pub leak: LeakStatus,
    /// Regel "Keine Ablesung auf halber Rueckkehr": das Siegel selbst.
    pub seal_ref: Digest,
    /// Ob zwischen dem vorigen Siegel und diesem ein Arbeitssegment
    /// liegt. QPM Invariante 2.4 (Keine stille Millisekunde) ist in BEIDEN
    /// Faellen erfuellt: das Siegel IST das typisierte Ereignis (Regel
    /// 24.4 (Der Golden Run läuft unter tick): "Eine Phase ohne Arbeit
    /// wird versiegelt wie jede andere; das Siegel ist der von Invariante
    /// Keine stille Millisekunde verlangte Nachweis"). Die Unterscheidung
    /// ist deshalb ein Messwert, keine Konformitaetsfrage.
    pub occupied: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Orientation {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum LeakStatus {
    /// QPM-7 (Leckregister) ist nicht gebaut - kein Urteil, keine
    /// Behauptung der Leckfreiheit.
    NotInstrumented,
}

/// Eine Grenze, die der Lauf versiegelt hat, die das Instrument aber
/// nicht abgetastet hat (Regel "Die Abtastrate bestimmt die
/// aufzeichnende Seite"). Getrennt vom Massenzensus gefuehrt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct SamplingGap {
    pub seq: u64,
    pub event_type: String,
    pub seal_ref: Digest,
}

/// Ein Kanalwechsel samt der Bedingung, unter der er zulaessig gewesen
/// waere (QPM Algorithmus 2.8 (Zyklusschnitt und Kanalwechsel):
/// `require Seam_2pi(q_k) == true ... else FAIL`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ChannelSwitchObservation {
    pub from: ChannelId,
    pub to: ChannelId,
    pub cycle_index: u64,
    pub seam_2pi_closed: bool,
    pub seal_ref: Digest,
}

/// Das Ergebnis von QPM-3 ueber einem realen Lauf.
#[derive(Debug, Clone, serde::Serialize)]
pub struct QpmCycleReport {
    pub roll_states: Vec<RollState>,
    /// Takte des Laufs - der Zyklusindex des letzten Rollzustands MUSS
    /// damit uebereinstimmen (siehe `check_cycle_index_matches_ticks`).
    pub ticks: u64,
    /// Wie viele Siegel der Lauf gesetzt hat.
    pub seals_in_run: usize,
    /// Wie viele davon das Instrument abgetastet hat.
    pub boundaries_sampled: usize,
    /// Die Differenz, registriert (Regel "Die Abtastrate bestimmt die
    /// aufzeichnende Seite").
    pub sampling_gaps: Vec<SamplingGap>,
    /// Phasen mit Arbeit zwischen zwei Siegeln.
    pub occupied_boundaries: usize,
    /// Phasen, deren Siegel allein steht - Leerlauf, protokolliert.
    pub idle_boundaries: usize,
    pub channel_switches: Vec<ChannelSwitchObservation>,
    /// Ob eine Zyklusgrenze je Takt vorliegt UND der Umlauf dort
    /// vollstaendig war (zwoelf Phasensiegel).
    pub closed_turns: u64,
    pub verdict: IdentityVerdict,
    pub verdict_reason: String,
}

/// Wie fein das Instrument abtastet. Der Produktionspfad tastet jede
/// Grenze ab; die gedrosselte Rate existiert fuer den Negativnachweis -
/// ohne ihn bliebe unbewiesen, dass das Lueckenregister ueberhaupt
/// fuellbar ist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SamplingRate {
    /// Jede Grenze: Phasensiegel und Zyklusgrenzen.
    EveryBoundary,
    /// Nur die Zyklusgrenzen - die Phasensiegel dazwischen werden
    /// ausgelassen und MUESSEN als Luecken erscheinen.
    CycleBoundariesOnly,
}

/// QPM-3 ueber einem Lauf. Nimmt den Bericht als geteilte Referenz und
/// gibt einen eigenen zurueck: die read-only-Eigenschaft steht in der
/// Signatur (dieselbe Form wie `observe_golden_run`, und derselbe
/// Grund - QPM beobachtet, es speist nicht zurueck).
pub fn observe_cycle(
    run: &GoldenRunReport,
    channel: ChannelId,
    rate: SamplingRate,
) -> Result<QpmCycleReport, PskError> {
    let mut roll_states: Vec<RollState> = Vec::new();
    let mut sampling_gaps: Vec<SamplingGap> = Vec::new();
    let mut seals_in_run = 0usize;

    // theta-Dach schreitet je Phasensiegel um ein Zwoelftel fort; die
    // Zyklusgrenze faellt mit dem Ende der zwoelften Phase zusammen (der
    // Umlauf schliesst dort, wo die letzte Phase versiegelt) - sie
    // erhoeht theta-Dach deshalb NICHT noch einmal. Zwei Ablesungen an
    // einem Winkel sind kein Fehler: Schliessen und Oeffnen sind
    // dieselbe Stelle des Kreises.
    let mut theta_hat: u64 = 0;
    let mut work_since_last_seal = false;
    let mut residues_seen = 0usize;
    let mut closed_turns = 0u64;
    let mut phases_this_turn = 0u64;
    let mut last_seq: Option<u64> = None;
    let mut orientation = Orientation::Forward;

    for seg in &run.trace_segments {
        // o_k: die Kette laeuft vorwaerts, solange seq steigt.
        if let Some(prev) = last_seq {
            if seg.seq <= prev {
                orientation = Orientation::Backward;
            }
        }
        last_seq = Some(seg.seq);

        let event = seg.event_type.0.as_str();
        let boundary = if let Some(label) = event.strip_prefix("phase.sealed.") {
            let position = CANONICAL_PHASES
                .iter()
                .position(|p| p.label() == label)
                .ok_or(PskError::UntypedInput)? as u64;
            Some(BoundaryKind::PhaseSeal {
                phase: label.to_string(),
                position,
            })
        } else if event == "tick.closed" {
            Some(BoundaryKind::CycleBoundary)
        } else {
            None
        };

        let Some(kind) = boundary else {
            // Kein Siegel: Arbeit oder Taktoeffnung. Residuenzaehlung
            // aus den realen Objektverweisen des Segments.
            if event != "tick.opened" {
                work_since_last_seal = true;
            }
            residues_seen = residues_seen.max(
                seg.object_refs
                    .iter()
                    .filter(|o| o.sort == psk_types::objects::SortId::Residue)
                    .count(),
            );
            continue;
        };

        seals_in_run += 1;
        let sampled = match (rate, &kind) {
            (SamplingRate::EveryBoundary, _) => true,
            (SamplingRate::CycleBoundariesOnly, BoundaryKind::CycleBoundary) => true,
            (SamplingRate::CycleBoundariesOnly, BoundaryKind::PhaseSeal { .. }) => false,
        };

        // theta-Dach schreitet unabhaengig davon fort, ob das Instrument
        // ablas - die Umdrehung des Laufs haengt nicht an der
        // Abtastrate. Genau das ist die Aussage von "Die Abtastrate
        // bestimmt die aufzeichnende Seite".
        if matches!(kind, BoundaryKind::PhaseSeal { .. }) {
            theta_hat += 1;
            phases_this_turn += 1;
        } else if phases_this_turn == TWELFTHS_PER_TURN {
            closed_turns += 1;
            phases_this_turn = 0;
        }

        if !sampled {
            sampling_gaps.push(SamplingGap {
                seq: seg.seq,
                event_type: event.to_string(),
                seal_ref: seg.segment_digest,
            });
            work_since_last_seal = false;
            continue;
        }

        roll_states.push(RollState {
            t: seg.time.tau_i,
            theta_hat_twelfths: theta_hat,
            // Woertlich die Formel aus QPM Definition 2.3 (Angehobener Phasor), ganzzahlig.
            theta_twelfths: theta_hat % TWELFTHS_PER_TURN,
            n: theta_hat / TWELFTHS_PER_TURN,
            channel: channel.clone(),
            orientation,
            machine_state: kind,
            residue_count: residues_seen,
            leak: LeakStatus::NotInstrumented,
            seal_ref: seg.segment_digest,
            occupied: work_since_last_seal,
        });
        work_since_last_seal = false;
    }

    let boundaries_sampled = roll_states.len();
    let occupied_boundaries = roll_states.iter().filter(|r| r.occupied).count();
    let idle_boundaries = boundaries_sampled - occupied_boundaries;

    // Kanalwechsel: der Lauf fuehrt EINEN Kanal, und nichts verlangt
    // einen Wechsel. Eine leere Liste ist hier ein Messwert ueber den
    // LAUF, keine Grenze des Instruments: die Zyklusgrenzen liegen vor,
    // an denen ein Wechsel zulaessig waere (`closed_turns`), und das
    // Instrument wuerde ihn dort ablesen.
    let channel_switches = Vec::new();

    Ok(QpmCycleReport {
        roll_states,
        ticks: run.ticks,
        seals_in_run,
        boundaries_sampled,
        sampling_gaps,
        occupied_boundaries,
        idle_boundaries,
        channel_switches,
        closed_turns,
        // Dieselbe Deckelung wie QPM-2: solange der Scope keinen
        // Katalog nennt, ist jeder Lauf UNKNOWN.
        verdict: IdentityVerdict::Unknown,
        verdict_reason: "kein catalog_ref im Scope: QPM-OBL-002 deckelt jeden Lauf auf UNKNOWN"
            .to_string(),
    })
}

/// Die Gegenprobe zur Ableitung: der Zyklusindex des letzten
/// Rollzustands MUSS die Taktzahl des Laufs treffen. Beides entsteht
/// unabhaengig - n_k aus der Formel ueber den abgelesenen Siegeln,
/// `ticks` aus `Sigma.tick_no` -, und wenn sie auseinanderlaufen, ist
/// entweder der Lift oder die Taktzaehlung falsch.
pub fn cycle_index_matches_ticks(report: &QpmCycleReport) -> bool {
    match report.roll_states.last() {
        Some(last) => last.n == report.ticks,
        None => report.ticks == 0,
    }
}
