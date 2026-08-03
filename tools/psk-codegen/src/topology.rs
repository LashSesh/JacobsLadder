//! Codegen fuer architecture/m13_topology.yaml (Kapitel 9, Definition 9.2-9.4).
//! Die 30 Kanten und 18 Zellen werden als konkrete Tabellen aus dem Register
//! transkribiert statt aus den Formeln neu hergeleitet, damit der generierte
//! Code exakt das bereits validierte Register widerspiegelt (kein zweiter,
//! potenziell abweichender Berechnungsweg).

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct M13Topology {
    pub nodes: TopologyNodes,
    pub edges: Vec<TopologyEdge>,
    pub cells: Vec<TopologyCell>,
}

#[derive(Debug, Deserialize)]
pub struct TopologyNodes {
    pub center: Vec<String>,
    pub inner: Vec<String>,
    pub outer: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TopologyEdge {
    pub id: String,
    pub class: String,
    pub u: String,
    pub v: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TopologyCell {
    pub id: String,
    pub class: String,
    pub nodes: Vec<String>,
    pub edges: Vec<String>,
}

pub fn load_m13_topology(root: &Path) -> M13Topology {
    crate::load_yaml(root, "architecture/m13_topology.yaml")
}

fn node_variant(raw: &str) -> String {
    // "c" -> "C", "i0".."i5" -> "I0".."I5", "o0".."o5" -> "O0".."O5"
    // (Definition 9.2: V = {c} u {i_0..i_5} u {o_0..o_5}).
    raw.to_uppercase()
}

fn edge_class_variant(raw: &str) -> String {
    // "center_inner" -> "CenterInner" usw. (Definition 9.3, edge_classes).
    raw.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

fn cell_class_variant(raw: &str) -> &'static str {
    // "center" | "bridge" | "boundary" (Definition 9.4, cell_classes).
    match raw {
        "center" => "Center",
        "bridge" => "Bridge",
        "boundary" => "Boundary",
        other => panic!("psk-codegen: unbekannte M13-Zellklasse '{other}' in m13_topology.yaml"),
    }
}

/// Erzeugt NodeId (13 Varianten), EdgeClass, Edge/EDGES (30), CellClass,
/// Cell/CELLS (18) — Kapitel 9 (Topologiedienst M13). Quelle: Definition
/// 9.2 (|V|=13), 9.3 (|E|=30), 9.4 (|Delta|=18), Invariante 9.5 (exakte
/// Kardinalitaet).
pub fn generate_m13_topology(topo: &M13Topology) -> String {
    let mut all_nodes: Vec<String> = Vec::new();
    all_nodes.extend(topo.nodes.center.iter().cloned());
    all_nodes.extend(topo.nodes.inner.iter().cloned());
    all_nodes.extend(topo.nodes.outer.iter().cloned());
    assert_eq!(
        all_nodes.len(),
        13,
        "psk-codegen: |V| muss 13 sein (Invariante 9.5)"
    );
    assert_eq!(
        topo.edges.len(),
        30,
        "psk-codegen: |E| muss 30 sein (Invariante 9.5)"
    );
    assert_eq!(
        topo.cells.len(),
        18,
        "psk-codegen: |Delta| muss 18 sein (Invariante 9.5)"
    );

    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/m13_topology.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Kapitel 9 (Topologiedienst M13),\n");
    out.push_str("// Definition 9.2-9.4, Invariante 9.5 (exakte Kardinalitaet).\n\n");

    // ---- NodeId ----
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("pub enum NodeId {\n");
    for n in &all_nodes {
        out.push_str(&format!("    {},\n", node_variant(n)));
    }
    out.push_str("}\n\n");
    out.push_str("impl NodeId {\n");
    out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
    for n in &all_nodes {
        out.push_str(&format!(
            "            NodeId::{} => \"{}\",\n",
            node_variant(n),
            n
        ));
    }
    out.push_str("        }\n    }\n\n");
    out.push_str("    pub fn from_id(id: &str) -> Option<NodeId> {\n        match id {\n");
    for n in &all_nodes {
        out.push_str(&format!(
            "            \"{}\" => Some(NodeId::{}),\n",
            n,
            node_variant(n)
        ));
    }
    out.push_str("            _ => None,\n        }\n    }\n\n");
    out.push_str(&format!(
        "    /// Alle {} Knoten (Definition 9.2, |V|=13).\n",
        all_nodes.len()
    ));
    out.push_str(&format!(
        "    pub const ALL: [NodeId; {}] = [\n",
        all_nodes.len()
    ));
    for n in &all_nodes {
        out.push_str(&format!("        NodeId::{},\n", node_variant(n)));
    }
    out.push_str("    ];\n");
    out.push_str("}\n\n");

    // ---- EdgeClass ----
    let mut edge_classes: Vec<String> = Vec::new();
    for e in &topo.edges {
        if !edge_classes.contains(&e.class) {
            edge_classes.push(e.class.clone());
        }
    }
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("pub enum EdgeClass {\n");
    for c in &edge_classes {
        out.push_str(&format!("    {},\n", edge_class_variant(c)));
    }
    out.push_str("}\n\n");

    // ---- Edge / EDGES ----
    out.push_str("#[derive(Debug, Clone, Copy)]\n");
    out.push_str("pub struct Edge {\n");
    out.push_str("    pub id: &'static str,\n");
    out.push_str("    pub class: EdgeClass,\n");
    out.push_str("    pub u: NodeId,\n");
    out.push_str("    pub v: NodeId,\n");
    out.push_str("}\n\n");
    out.push_str(&format!(
        "/// Alle {} Kanten (Definition 9.3, |E|=5*6=30).\n",
        topo.edges.len()
    ));
    out.push_str(&format!(
        "pub const EDGES: [Edge; {}] = [\n",
        topo.edges.len()
    ));
    for e in &topo.edges {
        out.push_str(&format!(
            "    Edge {{ id: \"{}\", class: EdgeClass::{}, u: NodeId::{}, v: NodeId::{} }},\n",
            e.id,
            edge_class_variant(&e.class),
            node_variant(&e.u),
            node_variant(&e.v)
        ));
    }
    out.push_str("];\n\n");

    // ---- CellClass ----
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("pub enum CellClass {\n    Center,\n    Bridge,\n    Boundary,\n}\n\n");

    // ---- Cell / CELLS ----
    out.push_str("#[derive(Debug, Clone, Copy)]\n");
    out.push_str("pub struct Cell {\n");
    out.push_str("    pub id: &'static str,\n");
    out.push_str("    pub class: CellClass,\n");
    out.push_str("    pub nodes: [NodeId; 3],\n");
    out.push_str("    pub edges: [&'static str; 3],\n");
    out.push_str("}\n\n");
    out.push_str(&format!(
        "/// Alle {} Zellen (Definition 9.4, |Delta|=3*6=18).\n",
        topo.cells.len()
    ));
    out.push_str(&format!(
        "pub const CELLS: [Cell; {}] = [\n",
        topo.cells.len()
    ));
    for c in &topo.cells {
        assert_eq!(
            c.nodes.len(),
            3,
            "psk-codegen: Zelle {} muss genau 3 Knoten haben",
            c.id
        );
        assert_eq!(
            c.edges.len(),
            3,
            "psk-codegen: Zelle {} muss genau 3 Kanten haben",
            c.id
        );
        out.push_str(&format!(
            "    Cell {{ id: \"{}\", class: CellClass::{}, nodes: [NodeId::{}, NodeId::{}, NodeId::{}], edges: [\"{}\", \"{}\", \"{}\"] }},\n",
            c.id,
            cell_class_variant(&c.class),
            node_variant(&c.nodes[0]),
            node_variant(&c.nodes[1]),
            node_variant(&c.nodes[2]),
            c.edges[0],
            c.edges[1],
            c.edges[2],
        ));
    }
    out.push_str("];\n");

    out
}
