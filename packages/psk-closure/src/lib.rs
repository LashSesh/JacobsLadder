//! M11 ClosureGlueEngine.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kapitel 9.3 (Closure erster und zweiter Ordnung): Close360/Close720
//! (Definition 9.11/9.12) sind in `closure360` als reine
//! Praedikat-Kombinatoren ueber vorgegebene Evidenz implementiert - Phi
//! (M09), Seam (M10) und Replay (M19) selbst zu berechnen bleibt
//! ausserhalb dieses Moduls (siehe dortiger Modulkopf).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod closure360;
pub use closure360::{
    close360, close720, evaluate, semantically_closed, Close360Evidence, Close720Evidence,
    ClosureReport, ReturnClassification,
};
