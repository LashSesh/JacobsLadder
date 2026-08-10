//! Regel 14.8 (Nebenläufigkeitsmodell), woertlich: "Nebenlaeufigkeit ist
//! zulaessig innerhalb einer Phase und ausschliesslich fuer Operationen
//! ohne gemeinsamen Schreibzustand. Die Ergebnisse werden vor der
//! Anwendung in die deterministische Ordnung der Prioritaetsregel
//! zurueckgesortiert. Der beobachtbare Effekt ist identisch zur
//! sequentiellen Ausfuehrung."
//!
//! Invariante 14.9 (Serialisierbarkeit): "Fuer jeden nebenlaeufigen Lauf
//! existiert eine sequentielle Ausfuehrung mit identischem kanonischen
//! Zustandsdigest und identischer Tracefolge."
//!
//! ## Die drei Saetze der Regel, einzeln umgesetzt
//!
//! **"innerhalb einer Phase"** - `tick_concurrent` nebenlaeufigt NUR
//! innerhalb je einer Phase; die zwoelf Phasen selbst laufen weiter
//! streng nacheinander, mit `seal_phase` dazwischen. Die Warteschlange
//! entsteht wie bei `tick` je Phase aus `select(phase, state)`.
//!
//! **"ausschliesslich fuer Operationen ohne gemeinsamen Schreibzustand"** -
//! `concurrency_eligible` (dispatch.rs) zaehlt die schreibenden
//! Arbeitsarten abschliessend auf. Die freigegebenen laufen ueber
//! `dispatch_readonly`, das Sigma nur LESEND bekommt (`&Sigma`):
//! Verweisaufloesung ist Lesen, und Lesen ist kein gemeinsamer
//! SCHREIBzustand - die Regel ist typseitig erzwungen, nicht nur
//! dokumentiert.
//!
//! **"vor der Anwendung zurueckgesortiert"** - die Ergebnisse werden nach
//! der Prioritaetsordnung angewandt, nicht nach Fertigstellungsreihen-
//! folge. Genau das ist der Schritt, den `T-CONC-001`s Negativnachweis
//! ueberspringt, um zu zeigen, dass er wirkt.
//!
//! ## Einschraenkung gegenueber `tick`: phaseninterne Ketten
//!
//! Ein spaeteres Element derselben Phase darf bei `tick` die Ergebnisse
//! der frueheren voraussetzen (Regel 5.9 (Kandidat und Gedankenkörper): Praegung findet den soeben
//! versiegelten Anker vor). Nebenlaeufig existiert dieses "frueher"
//! nicht - alle freigegebenen Elemente rechnen ueber DEMSELBEN
//! Phasenanfangszustand. Elemente, deren Verweis dort noch nicht
//! aufloest, scheitern mit `UntypedInput` und werden budgetneutral als
//! Residuum vermerkt? Nein: sie werden GAR NICHT eingereiht - diese
//! Funktion reiht nur Elemente ein, deren Verweise am Phasenanfang
//! aufloesen (`resolves_at_phase_start`), und laesst die uebrigen fuer
//! den naechsten Takt stehen. Das ist Regel 14.8 (Nebenläufigkeitsmodell)s eigener Preis:
//! Nebenlaeufigkeit ohne gemeinsamen Zustand kann keine Intra-Phase-
//! Kette sehen. Der beobachtbare ENDZUSTAND ueber genuegend Takte bleibt
//! identisch (Invariante 14.9 (Serialisierbarkeit) verlangt Gleichheit zu EINER sequentiellen
//! Ausfuehrung - der mit derselben Einreihung).

use psk_trace::RunDescriptor;
use psk_types::{DualTime, PskError, CANONICAL_PHASES};

use crate::{
    apply, charge, concurrency_eligible, dispatch_readonly, ChargeOutcome, DispatchResult,
    PendingWork, Profiling, QueuedItem, Sigma,
};

/// Wie die nebenlaeufig berechneten Ergebnisse angewandt werden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultOrder {
    /// Regel 14.8 (Nebenläufigkeitsmodell): zurueck in die Ordnung der Prioritaetsregel.
    ByPriority,
    /// NUR fuer den Negativnachweis von T-CONC-001: in der Reihenfolge
    /// der FERTIGSTELLUNG statt der Prioritaet - also genau ohne den
    /// Ruecksortierschritt. Kein Produktionspfad ruft das auf;
    /// `tick_concurrent` setzt `ByPriority` fest.
    ///
    /// Realisiert als umgekehrte Warteschlangenreihenfolge: die reale
    /// Fertigstellungsreihenfolge haengt am Scheduling und waere als
    /// Testerwartung nicht reproduzierbar - mal gleich, mal verschieden.
    /// Die Umkehrung ist deterministisch und bewusst gegen die
    /// Prioritaetsordnung gesetzt, sodass der Negativnachweis jedes Mal
    /// traegt statt nur meistens.
    ReversedForTestingOnly,
}

/// Ob die Verweise eines freigegebenen Elements am Phasenanfangszustand
/// aufloesen - nebenlaeufig gibt es kein "frueheres Element derselben
/// Phase" (siehe Modulkopf).
fn resolves_at_phase_start(work: &PendingWork, state: &Sigma) -> bool {
    match work {
        PendingWork::MintThought { .. } => !state.anchors.is_empty(),
        PendingWork::AnchorClassify { candidate } => state
            .candidates
            .get(*candidate)
            .map(|c| c.minted.is_some())
            .unwrap_or(false),
        PendingWork::ProjectLens { entry } => state
            .program
            .field_family
            .get(*entry)
            .map(|e| e.registered.is_some())
            .unwrap_or(false),
        PendingWork::CompileAssemble => !state.dependencies.is_empty(),
        PendingWork::CompileGlue => !state.assemblies.is_empty(),
        PendingWork::ExecuteRun { token } => token.is_some(),
        _ => true,
    }
}

/// Algorithmus 14.5 (Tick) mit phaseninterner Nebenlaeufigkeit nach Regel 14.8 (Nebenläufigkeitsmodell).
/// Keine Effektleitungen im Parameter: die nebenlaeufige Bahn laesst nur
/// lesende Arbeit zu (siehe Modulkopf), und die Leitung spricht allein
/// der schreibende `ExecuteRun`-Arm - ein Leitungsparameter hier waere
/// ein totes Feld.
pub fn tick_concurrent(
    state: &mut Sigma,
    rd: &RunDescriptor,
    time: DualTime,
    profiling: &mut Profiling,
) -> Result<(), PskError> {
    tick_concurrent_with_order(state, rd, time, profiling, ResultOrder::ByPriority)
}

/// Wie `tick_concurrent`, aber mit waehlbarer Anwendungsreihenfolge -
/// siehe `ResultOrder`. Oeffentlich ausschliesslich, damit T-CONC-001
/// BEIDE Richtungen belegen kann: mit Ruecksortierung gleicher
/// `sigma_digest` wie sequentiell, ohne sie ein abweichender.
pub fn tick_concurrent_with_order(
    state: &mut Sigma,
    rd: &RunDescriptor,
    time: DualTime,
    profiling: &mut Profiling,
    order: ResultOrder,
) -> Result<(), PskError> {
    let handle = psk_trace::open_tick(&mut state.trace, state.tick_no, rd.digest, time.clone())?;

    for phase in CANONICAL_PHASES {
        let queue = crate::select(phase, state);
        let mut dispatched = 0u64;
        let mut budget_skipped = 0u64;

        // Schritt 1: Budget in Prioritaetsordnung belasten (die
        // Warteschlange kommt bereits geordnet aus `select`). Das Budget
        // ist gemeinsamer Schreibzustand und bleibt deshalb sequentiell.
        let mut admitted: Vec<QueuedItem> = Vec::new();
        for item in queue {
            if !concurrency_eligible(&item.work) || !resolves_at_phase_start(&item.work, state) {
                // Schreibende Arbeit und phaseninterne Ketten gehoeren
                // nicht in den nebenlaeufigen Pfad - sie bleiben fuer
                // `tick` bzw. den naechsten Takt stehen (Modulkopf).
                continue;
            }
            let (kind, amount) = item.cost;
            if !matches!(charge(&mut state.budget, kind, amount), ChargeOutcome::Ok) {
                crate::tick::budget_residue(state, phase, &item, time.clone())?;
                budget_skipped += 1;
                continue;
            }
            admitted.push(item);
        }

        // Schritt 2: nebenlaeufig rechnen - ueber `dispatch_readonly`,
        // das Sigma nur lesend sieht (std::thread::scope, geteiltes
        // `&Sigma`).
        let shared: &Sigma = state;
        let mut results: Vec<(usize, Result<DispatchResult, PskError>)> =
            std::thread::scope(|scope| {
                let handles: Vec<_> = admitted
                    .drain(..)
                    .enumerate()
                    .map(|(idx, item)| {
                        let t = time.clone();
                        scope.spawn(move || (idx, dispatch_readonly(phase, item.work, shared, t)))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| h.join().expect("join"))
                    .collect()
            });

        // Schritt 3: "vor der Anwendung zurueckgesortiert" - nach der
        // Prioritaetsposition (Index der bereits geordneten Warteschlange),
        // oder fuer den Negativnachweis bewusst dagegen.
        match order {
            ResultOrder::ByPriority => results.sort_by_key(|(idx, _)| *idx),
            ResultOrder::ReversedForTestingOnly => {
                results.sort_by_key(|(idx, _)| std::cmp::Reverse(*idx))
            }
        }
        for (_, result) in results {
            let result = result?;
            for segment in result.trace_segments {
                state.trace.append(segment)?;
            }
            apply(state, result.outcome)?;
            dispatched += 1;
        }

        profiling.record_phase(phase, dispatched, budget_skipped);
        psk_trace::seal_phase(&mut state.trace, &handle, phase, time.clone())?;
    }

    psk_trace::close_tick(&mut state.trace, handle, time)?;
    state.tick_no += 1;
    Ok(())
}
