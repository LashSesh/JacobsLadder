//! Schnittstelle 9.19 (M22-Ports): `close_cell`, `close_all_18`, `descend`,
//! `holonomy`.
//!
//! Diese vier bleiben dokumentierte Modulgrenzen (`unimplemented!`) statt
//! einer vorgetaeuschten Berechnung: I2 ist einvernehmlich auf
//! Adressgrammatik, Platzierungsregel (Regel 9.10, siehe `placement`),
//! Close360/Close720 (siehe psk-closure) und IR-Codec-Rundreise begrenzt.
//! Konkret fehlt fuer diese vier je eine normativ vorausgesetzte Grundlage,
//! die es vor ihrer eigenen Phase nicht gibt (Regel 32.2,
//! Reihenfolgezwang):
//! - `close_cell`/`close_all_18` (Vertrag 9.7): "Witness- und
//!   Traceverweise aufloesbar" und "offene Differenzen residualisiert"
//!   setzen M12 (WitnessEngine) und M19 (Trace/Replay/ResidueStore)
//!   voraus; "Kanten portkompatibel" setzt die Auswertung der
//!   Sorten-Port-Matrix (architecture/sort_registry.yaml) gegen einen
//!   konkreten Graphen voraus, die hier noch nicht verdrahtet ist.
//! - `descend` (Skalenabstieg, Definition 9.17): setzt die im
//!   RuntimeManifest deklarierte Tiefenschranke N voraus (Invariante 9.18),
//!   die es vor einem realen RuntimeManifest (M04) nicht gibt.
//! - `holonomy` (Definition 9.14): setzt Phi (M09, Linsenanwendung) und
//!   den Transport-Operator T_{iota_a iota_b} voraus; keines der
//!   bestehenden Register definiert deren Berechnung.

use psk_types::objects::M13Address;
use psk_types::CellId;

/// IRGraph aus Schnittstelle 9.19 - der Graph-Teil eines IRBundle
/// (Struktur 7.21, OBJ-IRB).
pub type IRGraph = psk_types::objects::Graph;

/// Vertrag 9.7 (Zellclosure): die fuenf Bedingungen woertlich als Felder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellReport {
    pub cell: CellId,
    pub nodes_typed: bool,
    pub edges_port_compatible: bool,
    pub direction_consistent: bool,
    pub witness_trace_resolvable: bool,
    pub differences_residualized: bool,
}

impl CellReport {
    /// Vertrag 9.7: nur geschlossen, wenn alle fuenf Bedingungen gelten.
    pub fn closed(&self) -> bool {
        self.nodes_typed
            && self.edges_port_compatible
            && self.direction_consistent
            && self.witness_trace_resolvable
            && self.differences_residualized
    }
}

/// Definition 9.14: akkumulierte Rahmenaenderung entlang einer Chartroute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport(pub Vec<u8>);

pub fn close_cell(_cell: CellId, _graph: &IRGraph) -> CellReport {
    unimplemented!("Vertrag 9.7 vollstaendig auszuwerten setzt M12/M19 voraus (siehe Modulkopf)")
}

/// Pass C9 (ClosureAndGluing, M11+M22).
pub fn close_all_18(_graph: &IRGraph) -> Vec<CellReport> {
    unimplemented!("Pass C9 (M11+M22) setzt close_cell voraus (siehe Modulkopf)")
}

pub fn descend(_addr: &M13Address) -> M13Address {
    unimplemented!("Skalenabstieg setzt RuntimeManifest.max_depth voraus (Invariante 9.18)")
}

pub fn holonomy(_route: &[M13Address]) -> Transport {
    unimplemented!("Definition 9.14 setzt Phi/Transport aus M09 voraus")
}
