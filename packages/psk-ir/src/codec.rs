//! Algorithmus 10.3 (IR-Codec): `ir_encode`/`ir_decode`.
//!
//! Definition 10.5 (Ordnungssemantische Listen): `normative_files`,
//! `trajectories`, `allowed_next`, `transitions`, `observations`,
//! `receipt_refs` DARF NICHT sortiert werden. IRBundle selbst fuehrt
//! aktuell keines dieser Felder (Struktur 7.21), die Ausschlussliste steht
//! dennoch woertlich hier, damit ein spaeter hinzugefuegtes gleichnamiges
//! Feld automatisch korrekt behandelt wird statt versehentlich sortiert.
//!
//! `strip(b, volatile_fields)`: tau_e, Laufzeitmesswerte,
//! Personaprojektionen. Im aktuellen IRBundle-Schema existiert keines
//! dieser Felder auf oberster Ebene; der Schritt bleibt dennoch als
//! expliziter (aktuell leerer) Durchlauf erhalten statt stillschweigend
//! ausgelassen, damit ein spaeter ergaenztes volatiles Feld korrekt greift.

use serde_json::Value;

use psk_types::objects::IRBundle;
use psk_types::PskError;

/// Definition 10.5.
const ORDER_SEMANTIC_LISTS: &[&str] = &[
    "normative_files",
    "trajectories",
    "allowed_next",
    "transitions",
    "observations",
    "receipt_refs",
];

/// "tau_e, Laufzeitmesswerte, Personaprojektionen" (Algorithmus 10.3) -
/// aktuell leer, siehe Modulkopf.
const VOLATILE_FIELDS: &[&str] = &[];

fn element_sort_key(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Object(map) => map
            .get("id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| serde_json::to_string(v).unwrap_or_default()),
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

/// "for each list-valued field of b that is NOT order-semantic: sort
/// lexicographically by element id" - rekursiv ueber den gesamten Baum;
/// `field_name` ist der Schluessel, unter dem `v` in seinem Elternobjekt
/// steht (None fuer Array-Elemente, die selbst kein benanntes Feld sind).
fn sort_non_order_semantic_lists(v: &mut Value, field_name: Option<&str>) {
    match v {
        Value::Array(items) => {
            for item in items.iter_mut() {
                sort_non_order_semantic_lists(item, None);
            }
            let is_order_semantic = field_name
                .map(|n| ORDER_SEMANTIC_LISTS.contains(&n))
                .unwrap_or(false);
            if !is_order_semantic {
                items.sort_by_key(element_sort_key);
            }
        }
        Value::Object(map) => {
            for (k, val) in map.iter_mut() {
                sort_non_order_semantic_lists(val, Some(k.as_str()));
            }
        }
        _ => {}
    }
}

fn strip_volatile_fields(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for f in VOLATILE_FIELDS {
                map.remove(*f);
            }
            for val in map.values_mut() {
                strip_volatile_fields(val);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                strip_volatile_fields(item);
            }
        }
        _ => {}
    }
}

fn str_field(v: &Value, name: &str) -> String {
    v.get(name)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

// Der frueher hier stehende `compile_ir_bundle`-Stub ist entfallen: seine
// Begruendung ("keine Funktion hier oder in psk-dependency baut ein NEUES
// Kandidatenbundle zusammen") trifft seit v1.0.24 nicht mehr zu. Regel
// 10.8 hat die letzte offene Frage geschlossen - woher die
// Kantenbedingungen stammen - und `assembly::assemble_ir_bundle` baut das
// Bundle jetzt real. `ir_encode`/`ir_decode` runden fertige Bundles ab,
// wie bisher.

/// `ir_encode(bundle: IRBundle) -> bytes` (Algorithmus 10.3).
pub fn ir_encode(bundle: &IRBundle) -> Result<Vec<u8>, PskError> {
    let mut value = serde_json::to_value(bundle).map_err(|_| PskError::CanonicalizationFailed)?;

    // graph.nodes = sort_by(nodes, key = node.id) // stabil
    // graph.edges = sort_by(edges, key = (edge.source, edge.target, edge.id))
    if let Some(graph) = value.get_mut("graph").and_then(Value::as_object_mut) {
        if let Some(Value::Array(nodes)) = graph.get_mut("nodes") {
            nodes.sort_by_key(|n| str_field(n, "id"));
        }
        if let Some(Value::Array(edges)) = graph.get_mut("edges") {
            edges.sort_by(|a, b| {
                let ka = (
                    str_field(a, "source"),
                    str_field(a, "target"),
                    str_field(a, "id"),
                );
                let kb = (
                    str_field(b, "source"),
                    str_field(b, "target"),
                    str_field(b, "id"),
                );
                ka.cmp(&kb)
            });
        }
    }

    // "for each list-valued field of b that is NOT order-semantic": graph
    // ist bereits eigens behandelt (nodes/edges haben eigene Sortierschluessel
    // statt der generischen "nach Element-ID"-Regel); der generische
    // Durchlauf sortiert daher nur die uebrigen Felder.
    if let Value::Object(top) = &mut value {
        for (k, v) in top.iter_mut() {
            if k == "graph" {
                continue;
            }
            sort_non_order_semantic_lists(v, Some(k.as_str()));
        }
    }

    strip_volatile_fields(&mut value);

    let json = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let canon = psk_canon::can(&json, psk_canon::Media::Json)?;
    Ok(canon.into_bytes())
}

/// `ir_decode(bytes) -> IRBundle` (Algorithmus 10.3). `schema_valid(obj,
/// "psk.ir/1.0")` wird durch die typisierte Deserialisierung selbst
/// durchgesetzt: ein IRBundle mit fehlenden oder falsch getypten Feldern
/// schlaegt strukturell an denselben Stellen fehl, die ein gesondertes
/// JSON-Schema pruefen wuerde - object_schemas.yaml/OBJ-IRB ist bereits die
/// gemeinsame Quelle beider (kein zusaetzliches schemas/ir.schema.json
/// noetig, das nur dieselbe Information verdoppeln wuerde).
pub fn ir_decode(bytes: &[u8]) -> Result<IRBundle, PskError> {
    serde_json::from_slice(bytes).map_err(|_| PskError::UntypedInput)
}

/// Das Praedikat, mit dem T-IR-001s Fixture seine Kante besetzt.
///
/// Es ist stets wahr - und Regel 10.9 nennt genau das einen
/// Konformitaetsdefekt. Hier ist es dennoch richtig: das Fixture prueft
/// den CODEC (Sortierung, Kanonisierung, Round-Trip), nicht die
/// Kantensemantik, und ein Round-Trip-Test braucht irgendeinen
/// syntaktisch gueltigen Wert.
///
/// Damit es nicht als schlechtes Beispiel danebensteht, ist es hier
/// benannt und wird von `assembly::tests::the_t_ir_001_fixture_predicate_
/// is_refused_by_the_production_path` als EINGABE verwendet: das Fixture
/// belegt so die Wache, statt ihr zu widersprechen. Wer diesen Wert
/// aendert, aendert beide Stellen zugleich - dasselbe Muster wie bei den
/// compile_fail-Doctests, die ohne Positivkontrolle aus dem falschen
/// Grund bestehen koennten.
#[cfg(test)]
pub(crate) const T_IR_001_FIXTURE_PREDICATE: &str = "true";

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        Graph, IRBundleEmissionClassKind, IREdge, IREdgeDirectionKind, IRNode, M13Address, SortId,
    };
    use psk_types::{Digest, ObjectId, TraceRef};

    fn node(sort: SortId, salt: &str) -> IRNode {
        let digest = Digest::sha256(salt.as_bytes());
        IRNode {
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
            m13_address: M13Address("m13:0/c0".into()),
        }
    }

    fn sample_bundle() -> IRBundle {
        // Knoten absichtlich NICHT nach id sortiert eingefuegt, um zu
        // pruefen, dass ir_encode selbst sortiert (Algorithmus 10.3).
        let n_z = node(SortId::Branch, "z-node");
        let n_a = node(SortId::Identity, "a-node");
        let edge = IREdge {
            id: ObjectId::new(SortId::Trace, Digest::sha256(b"edge")),
            source: n_a.id,
            target: n_z.id,
            relation_sort: psk_types::objects::RelationSortId::Forks,
            direction: IREdgeDirectionKind::Forward,
            preconditions: vec![psk_types::objects::PredicateExpr(
                T_IR_001_FIXTURE_PREDICATE.into(),
            )],
            postconditions: vec![psk_types::objects::PredicateExpr(
                T_IR_001_FIXTURE_PREDICATE.into(),
            )],
            gate_ref: None,
            dependency_refs: vec![],
            trace_ref: TraceRef(Digest::sha256(b"edge-trace")),
        };
        IRBundle {
            schema: "psk.ir/1.0".into(),
            version: psk_types::objects::SemVer("1.0.0".into()),
            constitution_id: Digest::sha256(b"constitution"),
            anchor_refs: vec![],
            graph: Graph {
                nodes: vec![n_z, n_a],
                edges: vec![edge],
            },
            field_projections: vec![],
            dependencies: ObjectId::new(SortId::Dependency, Digest::sha256(b"dep")),
            witnesses: vec![],
            residues: vec![],
            gate_reports: vec![],
            trace_ref: TraceRef(Digest::sha256(b"bundle-trace")),
            capabilities: vec![],
            effect_contracts: vec![],
            emission_class: IRBundleEmissionClassKind::Executable,
            digest: Digest::sha256(b"bundle"),
        }
    }

    #[test]
    fn encode_sorts_nodes_by_id() {
        let bytes = ir_encode(&sample_bundle()).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        let ids: Vec<String> = value["graph"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_str().unwrap().to_string())
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
    }

    #[test]
    fn encode_is_deterministic() {
        let a = ir_encode(&sample_bundle()).unwrap();
        let b = ir_encode(&sample_bundle()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn t_ir_001_round_trip_is_lossless() {
        // T-IR-001 (architecture/ra_tests.yaml): encode(decode(x)) == x
        // fuer jedes kanonische x.
        let x = ir_encode(&sample_bundle()).unwrap();
        let decoded = ir_decode(&x).unwrap();
        let re_encoded = ir_encode(&decoded).unwrap();
        assert_eq!(re_encoded, x);
    }

    #[test]
    fn decode_rejects_malformed_input() {
        assert_eq!(ir_decode(b"not json"), Err(PskError::UntypedInput));
        assert_eq!(ir_decode(b"{}"), Err(PskError::UntypedInput));
    }
}
