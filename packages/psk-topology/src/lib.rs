//! M22 M13TopologyService.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! Kapitel 9 (Topologiedienst M13): die 13/30/18-Struktur (Definition
//! 9.2-9.4) ist aus architecture/m13_topology.yaml generiert
//! (tools/psk-codegen). Platzierung (Regel 9.13) ist in `placement` real
//! implementiert; close_cell/close_all_18/holonomy rechnen seit v1.0.34
//! real (siehe `boundary`), descend traegt den vollstaendigen
//! Verweigerungspfad - offen ist allein der normativ unbestimmte
//! Eintrittspunkt im Feinchart.

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
include!(concat!(env!("OUT_DIR"), "/m13_topology.rs"));

mod placement;
pub use placement::{place, EdgeContext, PlacementOutcome};

mod wellformed;
pub use wellformed::{check_address, check_wellformed, WellformednessViolation};

mod boundary;
pub use boundary::{
    all_18_closed, close_all_18, close_cell, descend, holonomy, vacuum_closed_count, CellReport,
    ClosureContext, ClosureMode, IRGraph, Occupancy, ProbeNote, RefsResolution, Transport,
};

/// Alle 13 Knoten (Schnittstelle 9.24: `fn nodes() -> [NodeId]`).
pub fn nodes() -> [NodeId; 13] {
    NodeId::ALL
}

/// Alle 30 Kanten als (u, v, class)-Tripel (Schnittstelle 9.24: `fn edges()`).
pub fn edges() -> [(NodeId, NodeId, EdgeClass); 30] {
    EDGES.map(|e| (e.u, e.v, e.class))
}

/// Alle 18 Zellen (Schnittstelle 9.24: `fn cells() -> [Cell]`).
pub fn cells() -> [Cell; 18] {
    CELLS
}

/// Zellen, die einen gegebenen Knoten enthalten (Schnittstelle 9.24: `fn cells_of`).
pub fn cells_of(node: NodeId) -> Vec<&'static str> {
    CELLS
        .iter()
        .filter(|c| c.nodes.contains(&node))
        .map(|c| c.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_cardinality_matches_invariante_9_5() {
        assert_eq!(nodes().len(), 13);
        assert_eq!(edges().len(), 30);
        assert_eq!(cells().len(), 18);
        for c in cells() {
            match c.class {
                CellClass::Center | CellClass::Bridge | CellClass::Boundary => {}
            }
        }
    }

    #[test]
    fn every_node_is_covered_by_at_least_one_cell() {
        for n in nodes() {
            assert!(
                !cells_of(n).is_empty(),
                "Knoten {:?} liegt in keiner Zelle",
                n
            );
        }
    }
}
