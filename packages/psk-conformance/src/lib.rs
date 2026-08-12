//! Testtreiber, Golden-Run-Harness (Struktur 26.1 (Repositorybaum)). Kein eigenes Modul.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1 (Eine Phasenordnung)). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2 (Phasenabhängigkeit der Passfolge)).

mod golden_run;
pub use golden_run::{
    run_golden_run, run_golden_run_with_certificate, CapsuleOutcome, GoldenRunCertification,
    GoldenRunReport,
};

mod conformance_catalog;

pub mod baselines;
pub use baselines::{run_baseline_comparison, BaselineComparison, BaselineMetrics};

mod corpus;
pub use corpus::{
    directory_freshness_predicate, falsifier_countermodels, freshness_predicate_holds,
    identify_contradictions, integrator_obstruction, load_manifest, load_requirements,
    open_obligation_for, Contradiction, CorpusManifest, CorpusSource, Geltung, Requirement,
};

mod feature_evidence;
pub use feature_evidence::{
    collect_feature_evidence, collect_feature_evidence_from_parts, CoverageParts,
};

mod historian;
pub use historian::reconstructed_versions;

mod qpm_profile;
pub use qpm_profile::{load_qpm_profile, QpmProfile};

pub use psk_fields::ChannelId;

mod qpm_atlas;
pub use qpm_atlas::{
    atlas_digest, build_atlas, compare_atlases, seal_reproducibility, AtlasComparison,
    SignatureAtlas, SignatureVector,
};

mod qpm_cycle;
pub use qpm_cycle::{
    cycle_index_matches_ticks, observe_cycle, BoundaryKind, ChannelSwitchObservation, LeakStatus,
    Orientation, QpmCycleReport, RollState, SamplingGap, SamplingRate, TWELFTHS_PER_TURN,
};

mod qpm_run;
pub use qpm_run::{
    books_balanced, census_lines, counter_horizon_note, evidence_breaks, findings_admissible,
    observe_golden_run, scope_contract_breaks, witness_rank, IdentityVerdict, QpmRunReport,
    RunGate, WitnessRank,
};

mod qpm_query;
pub use qpm_query::{
    open_set_decide, query_versioned_template_catalog, Candidate, CatalogQuery, ClassId,
};

mod ir_assembly;
pub use ir_assembly::{
    build_node, edge, edge_census, load_closure_norms, load_port_matrix,
    load_reference_domain_profile, ClosureNorms, NodeEnvelope,
};

mod reports;
pub use reports::{aggregate_reports, AggregatedReports, Report};

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
