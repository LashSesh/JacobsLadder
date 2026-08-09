//! Regel 9.9 (Wohlgeformtheit einer M13Address), neu in PSK-RA v1.0.4.
//!
//! Die Grammatik aus Definition 9.8 allein traegt diese drei Bedingungen
//! nicht; sie werden hier zusaetzlich geprueft:
//!
//! 1. `level` ist gleich der Anzahl der Abstiegspaare
//!    `"." parent_cell_id "." parent_node_id` im scale_path. Skala 0 traegt
//!    kein Abstiegspaar; jede weitere Skalenstufe traegt genau eines.
//! 2. `parent_node_id` ist Knoten von `parent_cell_id` nach dem
//!    Zellregister; ebenso ist `node_id`, sofern angegeben, Knoten von
//!    `cell_id`. Die Zugehoerigkeit wird gegen m13_topology.yaml geprueft,
//!    nicht gegen die Schreibweise.
//! 3. `level` ueberschreitet `max_depth` des RuntimeManifest nicht.
//!
//! Eine grammatisch gueltige, aber nicht wohlgeformte Adresse erzeugt
//! PSK-E011 und DARF NICHT in eine Zelle eintreten.
//!
//! Warum diese Pruefung hier und nicht in psk-types: Punkt 2 verlangt
//! ausdruecklich das Zellregister als Pruefgrundlage. Das besitzt M22
//! (dieses Paket, generiert aus architecture/m13_topology.yaml); psk-types
//! kennt nur die Grammatik.
//!
//! ## Dokumentbefund zu Punkt 3 (gemeldet, nicht selbst aufgeloest)
//!
//! Regel 9.9 Punkt 3 und Invariante 9.18 verlangen beide `max_depth` bzw.
//! `N` "des RuntimeManifest". Struktur 7.1 (RuntimeManifest), OBJ-RTM fuehrt jedoch genau
//! zehn Felder - schema, constitution_id, architecture_id,
//! implementation_id, profile, capability_matrix, build_digest,
//! operator_versions, adapter_versions, determinism_class - und keines
//! davon ist `max_depth` oder `N`. Auch das Register selbst notiert nur
//! `scale: {max_depth: declared_in_runtime_manifest}`, also einen Verweis
//! auf ein Feld, das die Struktur nicht definiert. `max_depth` wird daher
//! hier als expliziter Parameter uebergeben, statt ein Feld zu erfinden,
//! das die Objektstruktur nicht kennt.

use psk_types::objects::M13Address;
use psk_types::{CellId, CellKind, M13NodeId, ParsedM13Address, PskError};

use crate::{Cell, NodeId, CELLS};

/// Welche der drei Bedingungen aus Regel 9.9 verletzt ist. Alle Varianten
/// erzeugen normativ denselben Fehlercode (PSK-E011); die Unterscheidung
/// dient dem CellReport und der Fehlersuche, nicht einer abweichenden
/// Reaktion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WellformednessViolation {
    /// Punkt 1: level != Anzahl der Abstiegspaare.
    LevelDoesNotMatchDescentPairs { level: u32, descent_pairs: usize },
    /// Punkt 2: parent_node_id ist kein Knoten von parent_cell_id.
    ParentNodeNotInParentCell { cell: String, node: String },
    /// Punkt 2: node_id ist kein Knoten von cell_id.
    NodeNotInCell { cell: String, node: String },
    /// Punkt 2: cell_id bzw. parent_cell_id steht nicht im Zellregister.
    UnknownCell { cell: String },
    /// Punkt 3: level > max_depth.
    DepthExceedsMaxDepth { level: u32, max_depth: u32 },
}

impl WellformednessViolation {
    /// Regel 9.9 letzter Satz: "erzeugt PSK-E011".
    pub const fn error_code(&self) -> PskError {
        PskError::NonclosingM13Seam
    }
}

impl std::fmt::Display for WellformednessViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WellformednessViolation::LevelDoesNotMatchDescentPairs {
                level,
                descent_pairs,
            } => write!(
                f,
                "Regel 9.9.1: level={level}, aber {descent_pairs} Abstiegspaare im scale_path"
            ),
            WellformednessViolation::ParentNodeNotInParentCell { cell, node } => write!(
                f,
                "Regel 9.9.2: parent_node_id {node} ist kein Knoten von parent_cell_id {cell}"
            ),
            WellformednessViolation::NodeNotInCell { cell, node } => write!(
                f,
                "Regel 9.9.2: node_id {node} ist kein Knoten von cell_id {cell}"
            ),
            WellformednessViolation::UnknownCell { cell } => {
                write!(f, "Regel 9.9.2: Zelle {cell} steht nicht im Zellregister")
            }
            WellformednessViolation::DepthExceedsMaxDepth { level, max_depth } => write!(
                f,
                "Regel 9.9.3: level={level} ueberschreitet max_depth={max_depth}"
            ),
        }
    }
}

impl std::error::Error for WellformednessViolation {}

/// Schreibweise einer `CellId` als Registerkennung ("c2", "b5", "o0").
fn cell_key(c: &CellId) -> String {
    let prefix = match c.kind {
        CellKind::Center => 'c',
        CellKind::Bridge => 'b',
        CellKind::Boundary => 'o',
    };
    format!("{prefix}{}", c.k)
}

/// Schreibweise eines `M13NodeId` als Registerkennung ("c", "i2", "o5").
fn node_key(n: &M13NodeId) -> String {
    match n {
        M13NodeId::Center => "c".to_string(),
        M13NodeId::Inner(k) => format!("i{k}"),
        M13NodeId::Outer(k) => format!("o{k}"),
    }
}

fn lookup_cell(c: &CellId) -> Option<&'static Cell> {
    let key = cell_key(c);
    CELLS.iter().find(|cell| cell.id == key)
}

/// Regel 9.9 Punkt 2: Zugehoerigkeit gegen das Zellregister, nicht gegen
/// die Schreibweise. `NodeId::from_id` uebersetzt die Adressschreibweise in
/// den Registerknoten; steht sie dort nicht, ist sie kein Knoten.
fn cell_contains(cell: &'static Cell, node: &M13NodeId) -> bool {
    match NodeId::from_id(&node_key(node)) {
        Some(n) => cell.nodes.contains(&n),
        None => false,
    }
}

/// Prueft Regel 9.9 vollstaendig. `max_depth` stammt normativ aus dem
/// RuntimeManifest (siehe Dokumentbefund im Modulkopf) und wird deshalb
/// explizit uebergeben.
pub fn check_wellformed(
    addr: &ParsedM13Address,
    max_depth: u32,
) -> Result<(), WellformednessViolation> {
    // Punkt 1: level == Anzahl der Abstiegspaare.
    if addr.level as usize != addr.ancestors.len() {
        return Err(WellformednessViolation::LevelDoesNotMatchDescentPairs {
            level: addr.level,
            descent_pairs: addr.ancestors.len(),
        });
    }

    // Punkt 3: level <= max_depth. Vor Punkt 2 geprueft, weil eine zu tiefe
    // Adresse unabhaengig von ihrer Zellzugehoerigkeit unzulaessig ist.
    if addr.level > max_depth {
        return Err(WellformednessViolation::DepthExceedsMaxDepth {
            level: addr.level,
            max_depth,
        });
    }

    // Punkt 2, Ahnenkette: parent_node_id ist Knoten von parent_cell_id.
    for ancestor in &addr.ancestors {
        let cell = lookup_cell(&ancestor.cell).ok_or(WellformednessViolation::UnknownCell {
            cell: cell_key(&ancestor.cell),
        })?;
        if !cell_contains(cell, &ancestor.node) {
            return Err(WellformednessViolation::ParentNodeNotInParentCell {
                cell: cell_key(&ancestor.cell),
                node: node_key(&ancestor.node),
            });
        }
    }

    // Punkt 2, Zieladresse: node_id ist, sofern angegeben, Knoten von cell_id.
    let target = lookup_cell(&addr.cell).ok_or(WellformednessViolation::UnknownCell {
        cell: cell_key(&addr.cell),
    })?;
    if let Some(node) = &addr.node {
        if !cell_contains(target, node) {
            return Err(WellformednessViolation::NodeNotInCell {
                cell: cell_key(&addr.cell),
                node: node_key(node),
            });
        }
    }

    Ok(())
}

/// Bequemlichkeitsform auf der Drahtform: parst und prueft in einem Schritt.
/// Ein Grammatikfehler und eine Wohlgeformtheitsverletzung erzeugen beide
/// PSK-E011 an dieser Grenze - die Adresse DARF in keinem der beiden Faelle
/// in eine Zelle eintreten.
pub fn check_address(addr: &M13Address, max_depth: u32) -> Result<(), PskError> {
    let parsed = addr.parse().map_err(|_| PskError::NonclosingM13Seam)?;
    check_wellformed(&parsed, max_depth).map_err(|v| v.error_code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::parse_m13_address as parse;

    #[test]
    fn definition_9_8_examples_are_wellformed() {
        // Alle drei Beispiele aus Definition 9.8 (v1.0.4). Beispiel 3 ist
        // die in v1.0.4 korrigierte Fassung; sie ist genau deshalb
        // wohlgeformt, weil i2 in c2 und o5 in b5 liegt.
        for (addr, max_depth) in [
            ("m13:0/c3", 0),
            ("m13:0/b4/o4", 0),
            ("m13:1.c2.i2/b5/o5", 1),
        ] {
            let p = parse(addr).unwrap();
            assert_eq!(
                check_wellformed(&p, max_depth),
                Ok(()),
                "Beispiel {addr} muesste wohlgeformt sein"
            );
        }
    }

    #[test]
    fn rule_9_9_1_level_must_equal_descent_pair_count() {
        // Die bis v1.0.3 gedruckte Ahnenkette "0.c2.i2" hatte level 0 bei
        // einem Abstiegspaar - genau der Fall, den Punkt 1 ausschliesst.
        let p = parse("m13:0.c2.i2/b5/o5").unwrap();
        assert_eq!(
            check_wellformed(&p, 5),
            Err(WellformednessViolation::LevelDoesNotMatchDescentPairs {
                level: 0,
                descent_pairs: 1,
            })
        );
    }

    #[test]
    fn rule_9_9_1_rejects_level_higher_than_descent_pairs() {
        let p = parse("m13:2.c2.i2/b5/o5").unwrap();
        assert_eq!(
            check_wellformed(&p, 5),
            Err(WellformednessViolation::LevelDoesNotMatchDescentPairs {
                level: 2,
                descent_pairs: 1,
            })
        );
    }

    #[test]
    fn rule_9_9_2_rejects_node_not_in_target_cell() {
        // o5 liegt in b5, aber nicht in c3: Zentrumzellen sind
        // (c, i_k, i_k+1) und enthalten nie einen Aussenknoten.
        let p = parse("m13:0/c3/o5").unwrap();
        assert_eq!(
            check_wellformed(&p, 0),
            Err(WellformednessViolation::NodeNotInCell {
                cell: "c3".into(),
                node: "o5".into(),
            })
        );
    }

    #[test]
    fn rule_9_9_2_rejects_parent_node_not_in_parent_cell() {
        // c2 = (c, i2, i3): i4 gehoert nicht dazu.
        let p = parse("m13:1.c2.i4/b5/o5").unwrap();
        assert_eq!(
            check_wellformed(&p, 1),
            Err(WellformednessViolation::ParentNodeNotInParentCell {
                cell: "c2".into(),
                node: "i4".into(),
            })
        );
    }

    #[test]
    fn rule_9_9_2_checks_against_register_not_spelling() {
        // b5 = (i5, i0, o5). "i0" gehoert dazu, obwohl die Ziffer nicht zur
        // Zellnummer passt - die Pruefung folgt dem Register, nicht der
        // Schreibweise.
        let p = parse("m13:0/b5/i0").unwrap();
        assert_eq!(check_wellformed(&p, 0), Ok(()));
    }

    #[test]
    fn rule_9_9_3_rejects_level_above_max_depth() {
        let p = parse("m13:1.c2.i2/b5/o5").unwrap();
        assert_eq!(
            check_wellformed(&p, 0),
            Err(WellformednessViolation::DepthExceedsMaxDepth {
                level: 1,
                max_depth: 0,
            })
        );
    }

    #[test]
    fn every_violation_maps_to_psk_e011() {
        let violations = [
            WellformednessViolation::LevelDoesNotMatchDescentPairs {
                level: 0,
                descent_pairs: 1,
            },
            WellformednessViolation::ParentNodeNotInParentCell {
                cell: "c2".into(),
                node: "i4".into(),
            },
            WellformednessViolation::NodeNotInCell {
                cell: "c3".into(),
                node: "o5".into(),
            },
            WellformednessViolation::UnknownCell { cell: "c9".into() },
            WellformednessViolation::DepthExceedsMaxDepth {
                level: 1,
                max_depth: 0,
            },
        ];
        for v in violations {
            assert_eq!(v.error_code(), PskError::NonclosingM13Seam);
        }
    }

    #[test]
    fn placement_output_is_always_wellformed() {
        // Regel 9.10 erzeugt Adressen auf Skala 0 ohne Ahnenkette und ohne
        // node_id; sie muessen Regel 9.9 immer erfuellen, sonst koennte der
        // Compiler eine Adresse erzeugen, die nicht in ihre Zelle darf.
        use crate::{place, EdgeContext};
        use psk_types::objects::SortId;
        use psk_types::{Digest, ObjectId, TraceRef};

        for sort in [
            SortId::Identity,
            SortId::Projection,
            SortId::Anchor,
            SortId::Horizon,
        ] {
            let digest = Digest::sha256(sort.id().as_bytes());
            let node = psk_types::objects::IRNode {
                id: ObjectId::new(sort, digest),
                sort,
                context: psk_types::objects::ContextRef("ctx".into()),
                lineage: psk_types::objects::Lineage("lin".into()),
                reality_status: psk_types::objects::RealityStatus::Coherent,
                facticity: psk_types::objects::FactStatus::Observed,
                anchor_refs: vec![],
                witness_refs: vec![],
                residue_refs: vec![],
                trace_ref: TraceRef(digest),
                payload_digest: digest,
                m13_address: M13Address(String::new()),
            };
            let outcome = place(&node, &EdgeContext::default()).unwrap();
            assert_eq!(
                check_address(&outcome.address, 0),
                Ok(()),
                "Platzierung von {} erzeugte eine nicht wohlgeformte Adresse",
                sort.id()
            );
        }
    }
}
