//! Regel 14.7 (Nebenlaeufigkeitsmodell), woertlich: "Nebenlaeufigkeit ist
//! zulaessig innerhalb einer Phase und ausschliesslich fuer Operationen
//! ohne gemeinsamen Schreibzustand. Die Ergebnisse werden vor der
//! Anwendung in die deterministische Ordnung der Prioritaetsregel
//! zurueckgesortiert. Der beobachtbare Effekt ist identisch zur
//! sequentiellen Ausfuehrung."
//!
//! Invariante 14.8 (Serialisierbarkeit): "Fuer jeden nebenlaeufigen Lauf
//! existiert eine sequentielle Ausfuehrung mit identischem kanonischen
//! Zustandsdigest und identischer Tracefolge."
//!
//! ## Die drei Saetze der Regel, einzeln umgesetzt
//!
//! **"innerhalb einer Phase"** - `tick_concurrent` nebenlaeufigt NUR
//! innerhalb je einer Phase; die zwoelf Phasen selbst laufen weiter
//! streng nacheinander, mit `seal_phase` dazwischen.
//!
//! **"ausschliesslich fuer Operationen ohne gemeinsamen Schreibzustand"** -
//! `concurrency_eligible` (dispatch.rs) zaehlt die vier Ausnahmen
//! abschliessend auf. Die freigegebenen laufen ueber
//! `dispatch_stateless`, das `Sigma` gar nicht erst bekommt: die Regel
//! ist hier nicht dokumentiert, sondern typseitig erzwungen.
//!
//! **"vor der Anwendung zurueckgesortiert"** - die Ergebnisse werden nach
//! `select()`s Ordnung angewandt, nicht nach Fertigstellungsreihenfolge.
//! Genau das ist der Schritt, den `T-CONC-001`s Negativnachweis
//! ueberspringt, um zu zeigen, dass er wirkt.
//!
//! ## Befund: M19s Anhaengereihenfolge kann gar nicht divergieren
//!
//! Die naheliegende Sorge - zwei Threads haengen gleichzeitig an, und die
//! Sperre statt der Prioritaetsordnung entscheidet die Kette - trifft
//! diese Umsetzung strukturell nicht: `TraceStore::append` nimmt `&mut
//! self`, und `Sigma` wird nie geteilt. Kein Thread KANN anhaengen. Alle
//! Segmente entstehen in der sequentiellen Anwendungsschleife unten, in
//! `select()`-Ordnung. Die Kette ist damit aus demselben Grund stabil,
//! aus dem Regel 14.7 die Nebenlaeufigkeit begrenzt: der Trace IST
//! gemeinsamer Schreibzustand, also ist Anhaengen keine freigegebene
//! Operation. Es braucht keine Sperre, weil es keinen Wettlauf gibt -
//! der Ausschluss steht im Typsystem, nicht in einer Konvention.

use std::collections::BTreeMap;

use psk_trace::RunDescriptor;
use psk_types::{DualTime, Phase, PskError, CANONICAL_PHASES};

use crate::{
    apply, charge, concurrency_eligible, dispatch, dispatch_stateless, ChargeOutcome,
    DispatchResult, Profiling, QueuedItem, Sigma,
};

/// Wie die nebenlaeufig berechneten Ergebnisse angewandt werden.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultOrder {
    /// Regel 14.7: zurueck in die Ordnung der Prioritaetsregel.
    ByPriority,
    /// NUR fuer den Negativnachweis von T-CONC-001: in der Reihenfolge,
    /// in der die Elemente in der Warteschlange standen - also genau
    /// ohne den Ruecksortierschritt. Kein Produktionspfad ruft das auf;
    /// `tick_concurrent` setzt `ByPriority` fest.
    ///
    /// Warum die Warteschlangenreihenfolge und nicht die reale
    /// Fertigstellungsreihenfolge: letztere haengt am Scheduling und
    /// waere als Testerwartung nicht reproduzierbar - mal gleich, mal
    /// verschieden. Die Warteschlangenreihenfolge ist deterministisch
    /// und im Test bewusst gegen die Prioritaetsordnung gesetzt, sodass
    /// der Negativnachweis jedes Mal traegt statt nur meistens.
    AsQueuedForTestingOnly,
}

/// Algorithmus 14.4 mit phaseninterner Nebenlaeufigkeit nach Regel 14.7.
pub fn tick_concurrent(
    state: &mut Sigma,
    rd: &RunDescriptor,
    queues: BTreeMap<Phase, Vec<QueuedItem>>,
    time: DualTime,
    profiling: &mut Profiling,
) -> Result<(), PskError> {
    tick_concurrent_with_order(state, rd, queues, time, profiling, ResultOrder::ByPriority)
}

/// Wie `tick_concurrent`, aber mit waehlbarer Anwendungsreihenfolge -
/// siehe `ResultOrder`. Oeffentlich ausschliesslich, damit T-CONC-001
/// BEIDE Richtungen belegen kann: mit Ruecksortierung gleicher
/// `sigma_digest` wie sequentiell, ohne sie ein abweichender.
pub fn tick_concurrent_with_order(
    state: &mut Sigma,
    rd: &RunDescriptor,
    mut queues: BTreeMap<Phase, Vec<QueuedItem>>,
    time: DualTime,
    profiling: &mut Profiling,
    order: ResultOrder,
) -> Result<(), PskError> {
    let handle = psk_trace::open_tick(&mut state.trace, state.tick_no, rd.digest, time.clone())?;

    for phase in CANONICAL_PHASES {
        let queue = queues.remove(&phase).unwrap_or_default();
        let mut dispatched = 0u64;
        let mut budget_skipped = 0u64;

        // Schritt 1: Prioritaetsordnung feststellen - identisch zu `tick`.
        // `queue_position` haelt fest, wo das Element VOR der Sortierung
        // stand; nur so ist "ohne Ruecksortierung" ueberhaupt
        // ausdrueckbar (siehe `ResultOrder`).
        let queue_position: Vec<(psk_types::ObjectId, usize)> = queue
            .iter()
            .enumerate()
            .map(|(i, item)| (item.schedulable.id, i))
            .collect();
        let ordered = crate::tick::ordered_by_select(queue);

        // Schritt 2: Budget in Prioritaetsordnung belasten. Das Budget ist
        // gemeinsamer Schreibzustand und bleibt deshalb sequentiell; sonst
        // haenge davon ab, welcher Thread zuerst belastet.
        let mut admitted: Vec<(usize, QueuedItem)> = Vec::new();
        for (index, item) in ordered.into_iter().enumerate() {
            let (kind, amount) = item.cost;
            if !matches!(charge(&mut state.budget, kind, amount), ChargeOutcome::Ok) {
                crate::tick::budget_residue(state, phase, &item, time.clone())?;
                budget_skipped += 1;
                continue;
            }
            admitted.push((index, item));
        }

        // Schritt 3: die freigegebenen Elemente nebenlaeufig berechnen.
        let (eligible, stateful): (Vec<_>, Vec<_>) = admitted
            .into_iter()
            .partition(|(_, item)| concurrency_eligible(&item.work));

        // Die Ergebnisse kommen ueber einen Kanal zurueck, nicht ueber
        // `join()` in Spawnreihenfolge: `join` haette sie ohnehin geordnet
        // geliefert und den Ruecksortierschritt zu totem Code gemacht -
        // real beobachtet, als T-CONC-001s Negativnachweis genau deshalb
        // fehlschlug. Ueber den Kanal treffen sie in echter
        // Fertigstellungsreihenfolge ein, und die Sortierung unten traegt
        // tatsaechlich.
        let mut computed: Vec<(usize, usize, Result<DispatchResult, PskError>)> =
            std::thread::scope(|scope| {
                let (tx, rx) = std::sync::mpsc::channel();
                let expected = eligible.len();
                for (index, item) in eligible {
                    let time = time.clone();
                    let tx = tx.clone();
                    let queued_at = queue_position
                        .iter()
                        .find(|(id, _)| *id == item.schedulable.id)
                        .map(|(_, pos)| *pos)
                        .unwrap_or(index);
                    scope.spawn(move || {
                        let result = dispatch_stateless(phase, item.work, time);
                        let _ = tx.send((index, queued_at, result));
                    });
                }
                drop(tx);
                let mut received = Vec::with_capacity(expected);
                while let Ok(item) = rx.recv() {
                    received.push(item);
                }
                received
            });

        // Schritt 4: "vor der Anwendung in die deterministische Ordnung der
        // Prioritaetsregel zurueckgesortiert" - der Satz, der die Regel
        // traegt. Ohne ihn entscheidet die Fertigstellung.
        match order {
            ResultOrder::ByPriority => computed.sort_by_key(|(rank, _, _)| *rank),
            ResultOrder::AsQueuedForTestingOnly => {
                computed.sort_by_key(|(_, queued_at, _)| *queued_at)
            }
        }
        let mut computed: Vec<(usize, Result<DispatchResult, PskError>)> = computed
            .into_iter()
            .map(|(rank, _, result)| (rank, result))
            .collect();
        let computed = std::mem::take(&mut computed);

        // Schritt 5: sequentiell anwenden. Die zustandsbehafteten Elemente
        // laufen hier - in derselben Schleife, an ihrer Prioritaetsstelle.
        let mut stateful: BTreeMap<usize, QueuedItem> = stateful.into_iter().collect();
        let mut pending_stateful: Vec<usize> = stateful.keys().copied().collect();
        pending_stateful.sort_unstable();

        let apply_one = |state: &mut Sigma, result: DispatchResult| -> Result<(), PskError> {
            for segment in result.trace_segments {
                state.trace.append(segment)?;
            }
            apply(state, result.outcome)
        };

        for (index, result) in computed {
            // Alle zustandsbehafteten Elemente, die VOR diesem stehen,
            // zuerst - sonst waere die Reihenfolge nicht die der
            // Prioritaetsregel.
            while let Some(&next) = pending_stateful.first() {
                if next >= index {
                    break;
                }
                pending_stateful.remove(0);
                let item = stateful.remove(&next).expect("gerade entnommen");
                let r = dispatch(phase, item.work, state, time.clone())?;
                apply_one(state, r)?;
                dispatched += 1;
            }
            apply_one(state, result?)?;
            dispatched += 1;
        }
        for next in pending_stateful {
            let item = stateful.remove(&next).expect("gerade entnommen");
            let r = dispatch(phase, item.work, state, time.clone())?;
            apply_one(state, r)?;
            dispatched += 1;
        }

        profiling.record_phase(phase, dispatched, budget_skipped);
        psk_trace::seal_phase(&mut state.trace, &handle, phase, time.clone())?;
    }

    psk_trace::close_tick(&mut state.trace, handle, time)?;
    state.tick_no += 1;
    Ok(())
}
