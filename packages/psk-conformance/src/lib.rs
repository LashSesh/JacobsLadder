//! Testtreiber, Golden-Run-Harness (Struktur 26.1 (Repositorybaum)). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1 (Eine Phasenordnung)). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2 (Phasenabhängigkeit der Passfolge)).

mod golden_run;
pub use golden_run::{
    run_golden_run, run_golden_run_with_certificate, GoldenRunCertification, GoldenRunReport,
};

mod conformance_catalog;

pub mod baselines;
pub use baselines::{run_baseline_comparison, BaselineComparison, BaselineMetrics};

mod corpus;
pub use corpus::{
    directory_freshness_predicate, falsifier_countermodels, freshness_predicate_holds,
    identify_contradictions, integrator_obstruction, load_requirements, open_obligation_for,
    Contradiction, Geltung, Requirement,
};

mod feature_evidence;
pub use feature_evidence::{
    collect_feature_evidence, collect_feature_evidence_from_parts, CoverageParts,
};

mod qpm_profile;
pub use qpm_profile::{load_qpm_profile, QpmProfile};

pub use psk_fields::ChannelId;

mod qpm_cycle;
pub use qpm_cycle::{
    cycle_index_matches_ticks, observe_cycle, BoundaryKind, ChannelSwitchObservation, LeakStatus,
    Orientation, QpmCycleReport, RollState, SamplingGap, SamplingRate, TWELFTHS_PER_TURN,
};

mod qpm_run;
pub use qpm_run::{
    books_balanced, census_lines, counter_horizon_note, findings_admissible, observe_golden_run,
    witness_rank, IdentityVerdict, QpmRunReport, RunGate, WitnessRank,
};

mod ir_assembly;
pub use ir_assembly::{
    build_node, edge, edge_census, load_closure_norms, load_port_matrix,
    load_reference_domain_profile, ClosureNorms, NodeEnvelope,
};

mod reports;
pub use reports::{aggregate_reports, AggregatedReports, Report};

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
