//! M11 ClosureGlueEngine.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kapitel 9.3 (Closure erster und zweiter Ordnung): Close360/Close720
//! (Definition 9.12/9.13) sind in `closure360` als reine
//! Praedikat-Kombinatoren ueber vorgegebene Evidenz implementiert - Phi
//! (M09), Seam (M10) und Replay (M19) selbst zu berechnen bleibt
//! ausserhalb dieses Moduls (siehe dortiger Modulkopf).
//!
//! WP08 (I4): `seam` (Pass C9, Algorithmus 11.13 - Nahtvergleich,
//! ObstructionRecord bei Inkompatibilitaet, eindeutige globale Sektion
//! nach Invariante 11.14). Die Gate-Entscheidung zweiter Ordnung bleibt
//! bei M14 (WP11, Phase I6).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod closure360;
pub use closure360::{
    close360, close720, evaluate, semantically_closed, Close360Evidence, Close720Evidence,
    ClosureReport, ReturnClassification,
};

mod seam;
pub use seam::{
    check_no_single_pass_bypass, compare_restrictions, glue, obstruction_for, overlap,
    restriction_of, scan_seams, unique_global_section, CapsuleRestriction, GlueOutcome, SeamScan,
};
