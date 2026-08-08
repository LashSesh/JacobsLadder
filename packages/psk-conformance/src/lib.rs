//! Testtreiber, Golden-Run-Harness (Struktur 26.1). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).

mod golden_run;
pub use golden_run::{
    run_golden_run, run_golden_run_with_certificate, GoldenRunCertification, GoldenRunReport,
};

mod conformance_catalog;

pub mod baselines;
pub use baselines::{run_baseline_comparison, BaselineComparison, BaselineMetrics};

mod feature_evidence;
pub use feature_evidence::collect_feature_evidence;

mod reports;
pub use reports::{aggregate_reports, AggregatedReports, Report};

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
