//! `tick(state, rd)` (Algorithmus 14.5 (Tick)), woertlich:
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
//! Die Warteschlange entsteht JE PHASE aus `(phase, state)`, innerhalb
//! der Schleife, nach dem Zustandsupdate der Vorphase - wie der
//! Algorithmus es schreibt. Eine fruehere Fassung nahm statt dessen
//! vollstaendig vorbefuellte Warteschlangen als Parameter entgegen; diese
//! Entscheidung ist vom Auftraggeber ausdruecklich zurueckgenommen ("Die
//! heutige Form - vollstaendig vorbefuellte Warteschlangen - ist die
//! Abweichung, nicht der Algorithmus"). Siehe `select.rs`.
//!
//! Diese Umsetzung nimmt `state: &mut Sigma` statt `Sigma` per Wert
//! zurueckzugeben (derselbe, an mehreren Stellen begruendete Stil, siehe
//! `dispatch.rs`/`apply.rs`). `M19.residue`: realisiert als
//! `ResidueLedger::open` (kein neuer Name - so vom Aufrufer der
//! Umsetzung ausdruecklich verlangt).
//!
//! ## Die drei verbleibenden Parameter neben (state, rd)
//!
//! Regel 14.4 (Was tick außer Zustand und Laufvertrag entgegennimmt)
//! deckt sie seit v1.0.40 ausdruecklich: eine Umsetzung DARF
//! Zugriffsmittel entgegennehmen - "etwa gehaltene Effektleitungen, die
//! Wanduhrquelle oder einen Profilingschalter" - sofern jedes davon
//! (1) keine Planungsautoritaet traegt, (2) nicht Teil von Sigma ist und
//! damit nicht in I_t eingeht, (3) am Aufrufpunkt begruendet ist. Die
//! Regel benennt genau die drei hier stehenden und dreht die Richtung
//! des Arguments um: "Die Wanduhr und Profilingdaten stehen ausdruecklich
//! deshalb ausserhalb von Sigma, weil sie den kanonischen Digest nicht
//! erreichen duerfen; sie hereinzureichen ist die FOLGE dieser Trennung,
//! nicht ihre Verletzung." Die Punkt-fuer-Punkt-Begruendung unten IST die
//! von Punkt 3 verlangte:
//!
//! - `lines` (`psk_effect::EffectLines`): die ANGESCHLOSSENEN Leitungen
//!   der Effektgrenze - die Anwesenheit der Aussenwelt, kein Wert. Sie
//!   lassen sich weder kanonisieren noch digesten und KOENNEN deshalb
//!   kein Sigma-Feld sein (siehe Traitkommentar); das Spawnen gehoert
//!   M26 (`proc.control`), nicht M25 (`clock.read`, module_map.yaml).
//! - `time`: reale Zeitfortschreibung je Takt ist Sache des Aufrufers
//!   (mehrere `tick()`-Aufrufe mit fortschreitendem `time`) - M25 liest
//!   keine Uhr in die Entscheidung hinein, das waere Nichtdeterminismus
//!   im Scheduler.
//! - `profiling` (T-OBSV-001, I-ARCH-015): KEIN Feld von Sigma -
//!   Messwerte duerfen den kanonischen Zustand nicht erreichen, auch
//!   nicht ueber I_t. `record_phase` ist bei ausgeschaltetem Profiling
//!   ein No-op, wird aber unveraendert aufgerufen (siehe `profiling.rs`).

use psk_effect::EffectLines;
use psk_trace::{ResidueInputs, RunDescriptor};
use psk_types::objects::{
    ObligationExpr, ResidueRecordSeverityKind, ResidueRecordTypeKind, ScopeExpr,
};
use psk_types::{DualTime, ModuleId, Phase, PskError, CANONICAL_PHASES};

use crate::{apply, charge, dispatch, select, ChargeOutcome, Profiling, QueuedItem, Sigma};

pub(crate) fn budget_residue(
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
        // (`select` leitet es im naechsten Takt aus demselben Zustand
        // wieder ab) - nicht den gesamten Takt oder Lauf. Eine Einordnung
        // als Blocking waere eine Verschaerfung ohne Textstelle.
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

/// Algorithmus 14.5 (Tick). Siehe Modulkopf fuer die Parameterlage.
pub fn tick(
    state: &mut Sigma,
    rd: &RunDescriptor,
    lines: &mut dyn EffectLines,
    time: DualTime,
    profiling: &mut Profiling,
) -> Result<(), PskError> {
    let handle = psk_trace::open_tick(&mut state.trace, state.tick_no, rd.digest, time.clone())?;

    for phase in CANONICAL_PHASES {
        // Die Zeile des Algorithmus: deterministische Auswahl aus dem
        // AKTUELLEN Zustand - die Vorphase ist bereits angewandt.
        let queue = select(phase, state);
        let mut dispatched = 0u64;
        let mut budget_skipped = 0u64;
        for item in queue {
            let (kind, amount) = item.cost;
            if !matches!(charge(&mut state.budget, kind, amount), ChargeOutcome::Ok) {
                budget_residue(state, phase, &item, time.clone())?;
                budget_skipped += 1;
                continue;
            }
            let result = dispatch(phase, item.work, state, lines, time.clone())?;
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
