//! M25 Scheduler.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1 (Eine Phasenordnung)). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2 (Phasenabhängigkeit der Passfolge)).
//!
//! WP14 (I5): `select` (Regel 14.6 (Prioritätsordnung) - Prioritaetsordnung, total und
//! replaystabil), `budget` (Struktur 14.11 (BudgetLedger)/Vertrag 14.12 (Keine implizite Unendlichkeit) - Ressourcen- und
//! Risikobudgets, HOLD statt stillem Saettigen).
//!
//! v1.0.19-Umsetzung: Algorithmus 14.5 (Tick) selbst, real. Seit der
//! Taktumverdrahtung (Regel 24.4 (Der Golden Run läuft unter tick)) in
//! der WOERTLICHEN Form des Algorithmus: `select(phase, state)` leitet
//! die Warteschlange je Phase aus Sigma ab (die vorbefuellten
//! Warteschlangen waren die Abweichung - vom Auftraggeber ausdruecklich
//! zurueckgenommen), `dispatch` loest Verweise beim Aufruf aus dem
//! Zustand, `apply` faltet jedes Phasenprodukt nach Sigma zurueck, und
//! `tick` setzt die Schleife zusammen. Sigma traegt das deponierte
//! Laufprogramm und die Phasenprodukte selbst - siehe `sigma.rs`.
//!
//! `profiling` (T-OBSV-001, I-ARCH-015): der Profilingschalter, bewusst
//! ausserhalb von `Sigma` gefuehrt - siehe dortigen Modulkopf.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod select;
pub use select::{
    has_pending_work, priority_order, select, PriorityTier, QueuedItem, SchedulableItem,
};

mod budget;
pub use budget::{
    charge, charge_risk, BudgetLedger, ChargeOutcome, ResourceClass, ResourceKind, RiskClass,
};

mod sigma;
pub use sigma::{
    sigma_digest, AssemblyDeclarations, AssemblyRecord, CapsuleSpec, CellReportSet,
    ChallengeRecord, FieldFamilyEntry, GatesAndTokens, GlueSpec, PatchGateSpec, PendingRecord,
    ReceiptDeposit, ReconcileSpec, RunProgram, Sigma,
};

mod dispatch;
pub use dispatch::{
    concurrency_eligible, dispatch, dispatch_readonly, DispatchOutcome, DispatchResult, PendingWork,
};

mod apply;
pub use apply::apply;

mod profiling;
pub use profiling::{PhaseMetric, Profiling};

mod tick;
pub use tick::tick;

mod concurrent;
pub use concurrent::{tick_concurrent, tick_concurrent_with_order, ResultOrder};
