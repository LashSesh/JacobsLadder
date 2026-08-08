//! `tick(state, rd)` (Algorithmus 14.4), woertlich:
//! ```text
//! function tick(state: Sigma, rd: RunDescriptor) -> Sigma:
//!   t = M19.open_tick(state.tick_no, rd)
//!   for phase in CANONICAL_PHASES:
//!         queue = M25.select(phase, state)
//!         for item in queue:
//!              budget = M25.charge(item)
//!              if budget.exhausted:
//!                    M19.residue(item, kind: budget); continue
//!              result = dispatch(phase, item, state)
//!              M19.append(result.trace_segments)
//!              state = apply(state, result)
//!         M19.seal_phase(t, phase)
//!   M19.close_tick(t)
//!   return state
//! ```
//!
//! Diese Umsetzung nimmt `state: &mut Sigma` statt `Sigma` per Wert
//! zurueckzugeben (derselbe, an mehreren Stellen bereits begruendete Stil,
//! siehe `dispatch.rs`/`apply.rs`) und `queues: BTreeMap<Phase,
//! Vec<QueuedItem>>` statt `M25.select(phase, state)` autonom anstehende
//! Elemente aus `state` zu entdecken - siehe `dispatch.rs`s Modulkopf fuer
//! die Begruendung ("Phase-Dispatchlogik" ist hier eine vom Aufrufer
//! bereits zusammengestellte Warteschlange, `select()` selbst wird
//! trotzdem echt aufgerufen, nicht umgangen). `M19.residue`: realisiert
//! als `ResidueLedger::open` (kein neuer Name - so vom Aufrufer der
//! Umsetzung ausdruecklich verlangt).

use std::collections::BTreeMap;

use psk_trace::{ResidueInputs, RunDescriptor};
use psk_types::objects::{
    ObligationExpr, ResidueRecordSeverityKind, ResidueRecordTypeKind, ScopeExpr,
};
use psk_types::{DualTime, ModuleId, Phase, PskError, CANONICAL_PHASES};

use crate::{
    apply, charge, dispatch, select, ChargeOutcome, PendingWork, Profiling, ResourceKind,
    SchedulableItem, Sigma,
};

/// Ein fuer eine Phase anstehendes Element: Planungsmetadaten
/// (`schedulable`, geht in `select()` ein), Budgetkosten (`cost`, geht in
/// `charge()` ein) und die vollstaendigen Eingaben fuer `dispatch()`
/// (`work`).
pub struct QueuedItem {
    pub schedulable: SchedulableItem,
    pub cost: (ResourceKind, u64),
    pub work: PendingWork,
}

fn budget_residue(
    state: &mut Sigma,
    phase: Phase,
    item: &QueuedItem,
    time: DualTime,
) -> Result<(), PskError> {
    state.residues.open(ResidueInputs {
        r#type: ResidueRecordTypeKind::Budget,
        origin_module: ModuleId::Scheduler,
        origin_object: item.schedulable.id,
        scope: ScopeExpr(format!("{}/{}", phase.label(), item.schedulable.id)),
        // NonBlocking: ein erschoepftes Budget haelt nur DIESES Element an
        // (Regel 14.5 reiht es implizit fuer einen spaeteren Takt wieder
        // ein, ueber denselben SchedulableItem/ObjectId) - nicht den
        // gesamten Takt oder Lauf. Eine Einordnung als Blocking waere hier
        // eine Ratchet-Argument-artige Verschaerfung ohne Textstelle, die
        // das ausdruecklich verlangt.
        severity: ResidueRecordSeverityKind::NonBlocking,
        open_obligation: ObligationExpr(format!(
            "Budget erschoepft ({:?}) fuer {} in Phase {}",
            item.cost.0,
            item.schedulable.id,
            phase.label()
        )),
        allowed_followups: Vec::new(),
        opened_at: time,
    })?;
    Ok(())
}

/// Ordnet `queue` gemaess `select()`s realer Sortierung, ohne die
/// nicht-`Clone`-Nutzlast (`PendingWork::ExecuteRun.adapter` ist
/// `Box<dyn EffectAdapter>`) zu duplizieren: `SchedulableItem` ist `Copy`,
/// wird also fuer die Sortierung selbst extrahiert, `queue` danach anhand
/// der sortierten Reihenfolge per `remove` umsortiert.
fn ordered_by_select(mut queue: Vec<QueuedItem>) -> Vec<QueuedItem> {
    let schedulables: Vec<SchedulableItem> = queue.iter().map(|q| q.schedulable).collect();
    let ordered = select(schedulables);
    let mut result = Vec::with_capacity(queue.len());
    for target in ordered {
        let pos = queue
            .iter()
            .position(|q| q.schedulable.id == target.id)
            .expect("select() darf keine Elemente verlieren oder erfinden");
        result.push(queue.remove(pos));
    }
    result
}

/// Algorithmus 14.4. `time` wird fuer jedes in diesem Takt geschriebene
/// Traceseg­ment unveraendert weitergereicht - reale Zeitfortschreibung je
/// Ereignis ist Sache des Aufrufers (mehrere `tick()`-Aufrufe mit
/// fortschreitendem `time`), nicht dieser Funktion.
///
/// `profiling` (T-OBSV-001, I-ARCH-015) ist ein eigener Parameter und
/// KEIN Feld von `Sigma`: Messwerte duerfen den kanonischen Zustand nicht
/// erreichen, auch nicht ueber einen kuenftigen Zustandsdigest. Es gibt
/// nur diesen einen Codepfad - `record_phase` ist bei ausgeschaltetem
/// Profiling ein No-op, wird aber unverae ndert aufgerufen (siehe
/// `profiling.rs`s Modulkopf fuer beide Begruendungen).
pub fn tick(
    state: &mut Sigma,
    rd: &RunDescriptor,
    mut queues: BTreeMap<Phase, Vec<QueuedItem>>,
    time: DualTime,
    profiling: &mut Profiling,
) -> Result<(), PskError> {
    let handle = psk_trace::open_tick(&mut state.trace, state.tick_no, rd.digest, time.clone())?;

    for phase in CANONICAL_PHASES {
        let queue = queues.remove(&phase).unwrap_or_default();
        let mut dispatched = 0u64;
        let mut budget_skipped = 0u64;
        for item in ordered_by_select(queue) {
            let (kind, amount) = item.cost;
            if !matches!(charge(&mut state.budget, kind, amount), ChargeOutcome::Ok) {
                budget_residue(state, phase, &item, time.clone())?;
                budget_skipped += 1;
                continue;
            }
            let result = dispatch(phase, item.work, state, time.clone())?;
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
