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

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod kernel;
pub use kernel::{
    capsulate, check_adversarial_closure, check_closure_state, check_hardening_permitted,
    check_monotone_contraction, check_repair_is_a_branch, check_support, contract,
    effective_rank_of, ratchet, residue_flow_next, split, support, CapsuleInputs, HardeningClass,
    SplitResult, SupportPaths,
};
