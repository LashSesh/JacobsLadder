//! Regel 9.9 (Platzierungsregel): M22 platziert jeden IR-Knoten
//! deterministisch. Implementiert die Punkte 1-5 woertlich; Punkt 4
//! (zellgebundene Sorten) verlangt die bereits bekannte Traegerzelle vom
//! Aufrufer (`EdgeContext.bound_cell`), da "die Zelle, die den geprueften
//! Knoten traegt" nur aus dem Gesamtgraphen bestimmbar ist, nicht aus dem
//! Knoten allein.

use std::collections::BTreeSet;

use psk_canon::{can, Media};
use psk_types::objects::{IRNode, M13Address, SortCellClass};
use psk_types::{CellId, CellKind, ParsedM13Address, PskError};

/// Kontext einer Platzierung: was eine Kante (oder der bisherige
/// Platzierungslauf ueber denselben Graphen) bereits ueber die Zielzelle
/// festlegt.
#[derive(Debug, Clone, Default)]
pub struct EdgeContext {
    /// Regel 9.9 Punkt 5: "sofern nicht durch eine Kante bereits erzwungen".
    pub forced_k: Option<u8>,
    /// Regel 9.9 Punkt 4: fuer S-WIT/S-GAT/S-TRC/S-RES diejenige Zelle
    /// (z.B. "c3"), die den bereits geprueften Knoten traegt.
    pub bound_cell: Option<&'static str>,
    /// Bereits belegte Zellen derselben Klasse in diesem Platzierungslauf -
    /// die Konfliktgrundlage fuer die aufsteigende Sondierung.
    pub occupied: BTreeSet<&'static str>,
}

/// Ergebnis einer Platzierung: die Adresse plus die Folge sondierter
/// k-Werte (fuer den CellReport-Vermerk, Regel 9.9 letzter Satz).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlacementOutcome {
    pub address: M13Address,
    pub probed_k: Vec<u8>,
}

fn class_prefix(class: SortCellClass) -> char {
    match class {
        SortCellClass::Center => 'c',
        SortCellClass::Bridge => 'b',
        SortCellClass::Boundary => 'o',
        SortCellClass::CellBound => {
            unreachable!("cell_bound wird in place() gesondert behandelt")
        }
    }
}

fn kind_of(prefix: char) -> CellKind {
    match prefix {
        'c' => CellKind::Center,
        'b' => CellKind::Bridge,
        'o' => CellKind::Boundary,
        _ => unreachable!("class_prefix liefert nur c|b|o"),
    }
}

/// k0 = H(Can(node)) mod 6 (Regel 9.9 Punkt 5).
fn digest_k(node: &IRNode) -> Result<u8, PskError> {
    let json = serde_json::to_vec(node).map_err(|_| PskError::CanonicalizationFailed)?;
    let canon = can(&json, Media::Json).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(canon.digest().mod_small(6) as u8)
}

/// Regel 9.9: platziert `node` deterministisch in eine M13Address.
pub fn place(node: &IRNode, ctx: &EdgeContext) -> Result<PlacementOutcome, PskError> {
    let class = node.sort.cell_class();

    // Punkt 4: S-WIT, S-GAT, S-TRC, S-RES sind zellgebunden, nicht frei
    // platzierbar - die Traegerzelle kommt direkt aus dem Kontext.
    if class == SortCellClass::CellBound {
        let cell_id = ctx.bound_cell.ok_or(PskError::NonclosingM13Seam)?;
        let mut chars = cell_id.chars();
        let prefix = chars.next().ok_or(PskError::NonclosingM13Seam)?;
        let k: u8 = chars
            .as_str()
            .parse()
            .map_err(|_| PskError::NonclosingM13Seam)?;
        let parsed = ParsedM13Address {
            level: 0,
            ancestors: vec![],
            cell: CellId::new(kind_of(prefix), k).map_err(|_| PskError::NonclosingM13Seam)?,
            node: None,
        };
        return Ok(PlacementOutcome {
            address: M13Address::from_parsed(&parsed),
            probed_k: vec![],
        });
    }

    // Punkte 1-3: feste Zellklasse nach Sorte.
    let prefix = class_prefix(class);
    // Punkt 5: k = H(Can(node)) mod 6, sofern nicht durch eine Kante
    // bereits erzwungen.
    let k0 = match ctx.forced_k {
        Some(k) => k,
        None => digest_k(node)?,
    };

    // Konflikte: aufsteigende Sondierung k, k+1, ... (mod 6, da genau 6
    // Zellen je Klasse existieren, Invariante 9.5).
    let mut probed_k = Vec::new();
    for i in 0..6u8 {
        let k = (k0 + i) % 6;
        probed_k.push(k);
        let candidate = format!("{prefix}{k}");
        if !ctx.occupied.contains(candidate.as_str()) {
            let parsed = ParsedM13Address {
                level: 0,
                ancestors: vec![],
                cell: CellId::new(kind_of(prefix), k).expect("k < 6 durch obige Berechnung"),
                node: None,
            };
            return Ok(PlacementOutcome {
                address: M13Address::from_parsed(&parsed),
                probed_k,
            });
        }
    }
    // Alle 6 Zellen dieser Klasse belegt: keine siebte existiert
    // (Invariante 9.5) - PSK-E011 (nonclosing_m13_seam).
    Err(PskError::NonclosingM13Seam)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::SortId;
    use psk_types::{Digest, ObjectId, TraceRef};

    fn sample_node(sort: SortId, salt: &str) -> IRNode {
        let digest = Digest::sha256(salt.as_bytes());
        IRNode {
            id: ObjectId::new(sort, digest),
            sort,
            context: psk_types::objects::ContextRef("ctx".into()),
            lineage: psk_types::objects::Lineage("lin".into()),
            reality_status: psk_types::objects::RealityStatus("coherent".into()),
            facticity: psk_types::objects::FactStatus("observed".into()),
            anchor_refs: vec![],
            witness_refs: vec![],
            residue_refs: vec![],
            trace_ref: TraceRef(digest),
            payload_digest: digest,
            m13_address: M13Address(String::new()),
        }
    }

    #[test]
    fn placement_is_deterministic_for_identical_nodes() {
        let node = sample_node(SortId::Identity, "same");
        let ctx = EdgeContext::default();
        let a = place(&node, &ctx).unwrap();
        let b = place(&node, &ctx).unwrap();
        assert_eq!(a.address, b.address);
    }

    #[test]
    fn identity_context_and_branch_map_to_center() {
        // Regel 9.9 Punkt 1: S-IDT, S-CTX, S-BRN -> Delta_c.
        for sort in [SortId::Identity, SortId::Context, SortId::Branch] {
            let node = sample_node(sort, "center-case");
            let outcome = place(&node, &EdgeContext::default()).unwrap();
            let parsed = outcome.address.parse().unwrap();
            assert_eq!(parsed.cell.kind, CellKind::Center);
        }
    }

    #[test]
    fn forced_k_overrides_digest() {
        let node = sample_node(SortId::Identity, "forced");
        let ctx = EdgeContext {
            forced_k: Some(2),
            ..Default::default()
        };
        let outcome = place(&node, &ctx).unwrap();
        let parsed = outcome.address.parse().unwrap();
        assert_eq!(parsed.cell.k, 2);
        assert_eq!(outcome.probed_k, vec![2]);
    }

    #[test]
    fn collision_probes_ascending() {
        let node = sample_node(SortId::Identity, "forced-collision");
        let mut occupied = BTreeSet::new();
        occupied.insert("c2");
        occupied.insert("c3");
        let ctx = EdgeContext {
            forced_k: Some(2),
            occupied,
            ..Default::default()
        };
        let outcome = place(&node, &ctx).unwrap();
        let parsed = outcome.address.parse().unwrap();
        assert_eq!(parsed.cell.k, 4);
        assert_eq!(outcome.probed_k, vec![2, 3, 4]);
    }

    #[test]
    fn all_six_occupied_fails_closed() {
        let node = sample_node(SortId::Identity, "full");
        let mut occupied = BTreeSet::new();
        for k in 0..6 {
            occupied.insert(Box::leak(format!("c{k}").into_boxed_str()) as &str);
        }
        let ctx = EdgeContext {
            forced_k: Some(0),
            occupied,
            ..Default::default()
        };
        assert_eq!(place(&node, &ctx), Err(PskError::NonclosingM13Seam));
    }

    #[test]
    fn cell_bound_sort_uses_context_cell_verbatim() {
        // Regel 9.9 Punkt 4: S-WIT ist zellgebunden, nicht frei platzierbar.
        let node = sample_node(SortId::Witness, "witness");
        let ctx = EdgeContext {
            bound_cell: Some("b5"),
            ..Default::default()
        };
        let outcome = place(&node, &ctx).unwrap();
        assert_eq!(outcome.address.0, "m13:0/b5");
        assert!(outcome.probed_k.is_empty());
    }

    #[test]
    fn cell_bound_sort_without_context_fails_closed() {
        let node = sample_node(SortId::Witness, "witness-unbound");
        let ctx = EdgeContext::default();
        assert_eq!(place(&node, &ctx), Err(PskError::NonclosingM13Seam));
    }
}
