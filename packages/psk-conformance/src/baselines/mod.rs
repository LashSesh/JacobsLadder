//! Regel 24.5 (Pflichtbaselines): der Kern wird gegen mindestens zwei
//! Baselines verglichen. Regel 32.6 (Referenzauftrag) beschreibt die
//! Aufgabe fuer alle drei Systeme identisch: eine versiegelte Menge von
//! Spezifikations-/Quelltextdateien erhalten, widerspruechliche
//! Anforderungen erkennen, deren Geltung bestimmen, Feldprojektionen
//! bilden, gemeinsame Quellen quotientieren, einen Aenderungsvorschlag
//! erzeugen, adversarial pruefen lassen, ein Sandbox-Token binden, den
//! Patch anwenden, den tatsaechlichen Dateibaum mit dem Plan vergleichen.
//!
//! Der Kern-Lauf dafuer ist bereits `run_golden_run`/
//! `run_golden_run_with_certificate` (`golden_run.rs`) - Regel 32.6s
//! Schrittfolge deckt sich mit Regel 24.3s 13 Golden-Run-Schritten
//! (Anker, ThoughtBody, Feldfamilie, Dependency, Glue, Gate, Token,
//! Effekt, Beobachtung, Reconciliation), und die sechs Feldrollen aus
//! Regel 32.7 (Explorer/Historiker/Falsifikator/Konstrukteur/Auditor/
//! Integrator) instanziiert `golden_run.rs::run_static_field_family`
//! bereits ueber `ArchetypeId::ALL` - nichts davon wird hier ein zweites
//! Mal gebaut. `comparison::run_baseline_comparison` ruft den
//! bestehenden, unveraenderten Golden Run direkt auf.
//!
//! Nur die zwei Baselines (`monolithic`, `event_sourcing`) sind neu -
//! siehe deren jeweilige Modulkoepfe fuer die genaue Begruendung, was
//! sie bewusst NICHT tun.
//!
//! Regel 27.8 (Rolle eines Sprachmodells) gilt hier wie im Kern: kein
//! Live-Modellaufruf, nur typisierte Fixture-Kandidaten (dieselbe
//! Disziplin wie `golden_run.rs`s hartkodierte Claims/RealityEvidence) -
//! sonst brechen Replay und R2 fuer die gesamte Konformanzsuite.

pub mod comparison;
pub mod event_sourcing;
pub mod metrics;
pub mod monolithic;

pub use comparison::{run_baseline_comparison, BaselineComparison};
pub use metrics::BaselineMetrics;
