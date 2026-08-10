//! M24 AdversarialKernel.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP10 (I4): `kernel` - Paesse C7 (Adversarial Canonicalization) und C8
//! (Support and Reachability). Von den neun Operatoren aus Definition 12.1
//! sind Capsule, Split, Ratchet, Support und Contraction realisiert; die
//! uebrigen vier haengen an Modulen spaeterer Phasen (siehe Modulkopf von
//! `kernel`). Die Neunerliste ist damit nicht erweitert, nur teilweise
//! realisiert.
//!
//! `cra` - PROPOSE_REVISION (Struktur 12.12, seit v1.0.29): verdichtet
//! die real vorliegenden CRA-Eingaben zu genau einem RevisionProposal,
//! fuehrt vorhandene und fehlende Eingaben getrennt (Regel 12.13).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod counter_horizon;
pub use counter_horizon::{
    CounterHorizon, CounterHorizonStanding, OutOfScopeRegion, RegionSpec, RejectedReading,
};

mod cra;
pub use cra::{cra, CraInputs, ProposalInputs};

mod kernel;
pub use kernel::{
    capsulate, check_adversarial_closure, check_closure_state, check_hardening_permitted,
    check_monotone_contraction, check_repair_is_a_branch, check_support, contract,
    effective_rank_of, is_capsule_fixpoint, is_capsule_resolved, ratchet, residue_flow_next, split,
    support, CapsuleInputs, HardeningClass, SplitResult, SupportPaths,
};
