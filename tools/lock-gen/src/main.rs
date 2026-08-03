//! Versiegelt architecture.lock.json, constitution.lock.json und PSK.lock
//! mit den nach Algorithmus 6.1 / Definition 6.6 / Regel 6.7 tatsaechlich
//! berechneten Werten (I_A, I_C). I_M und I_t bleiben null - sie setzen
//! einen realen Build- bzw. Laufzeitzustand voraus (Regel 6.7: I_M =
//! H(Code||Schemas||Compiler||Profil), I_t = H(Can(Sigma_t))), den es vor
//! einem echten Build/Lauf nicht gibt.
//!
//! Dieses Werkzeug SCHREIBT, waehrend verify-bundle/verify-architecture nur
//! LESEN/VERGLEICHEN. Die Dateiliste architecture/* ist mit
//! tools/verify-architecture dupliziert (dieselbe Struktur-25.3-Quelle);
//! bei einer Aenderung der Bundle-Struktur beide Stellen nachziehen.

use std::fs;
use std::path::PathBuf;

use psk_canon::{can, collection_digest, CanonicalBytes, Media};
use serde_json::Value;

const ARCHITECTURE_FILES_YAML: &[&str] = &[
    "module_map.yaml",
    "port_registry.yaml",
    "sort_registry.yaml",
    "object_registry.yaml",
    "object_schemas.yaml",
    "lifecycle_registry.yaml",
    "m13_topology.yaml",
    "pass_registry.yaml",
    "isa_registry.yaml",
    "memory_registry.yaml",
    "gate_registry.yaml",
    "ra_invariants.yaml",
    "ra_requirements.yaml",
    "ra_tests.yaml",
    "refinement_map.yaml",
    "obligations.yaml",
];

const ARCHITECTURE_SCHEMAS: &[&str] = &[
    "schemas/module_map.schema.json",
    "schemas/port_registry.schema.json",
    "schemas/sort_registry.schema.json",
    "schemas/object_registry.schema.json",
    "schemas/object_schemas.schema.json",
    "schemas/lifecycle_registry.schema.json",
    "schemas/m13_topology.schema.json",
    "schemas/pass_registry.schema.json",
    "schemas/isa_registry.schema.json",
    "schemas/memory_registry.schema.json",
    "schemas/gate_registry.schema.json",
    "schemas/ra_invariants.schema.json",
    "schemas/ra_requirements.schema.json",
    "schemas/ra_tests.schema.json",
    "schemas/refinement_map.schema.json",
    "schemas/obligations.schema.json",
];

fn workspace_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
            return dir;
        }
        if !dir.pop() {
            panic!("keine Workspace-Wurzel (Cargo.toml + .git) gefunden");
        }
    }
}

fn media_of(name: &str) -> Media {
    if name.ends_with(".json") {
        Media::Json
    } else {
        Media::Yaml
    }
}

fn canon_of(path: &std::path::Path, media: Media) -> CanonicalBytes {
    let bytes =
        fs::read(path).unwrap_or_else(|e| panic!("kann {} nicht lesen: {e}", path.display()));
    can(&bytes, media).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn write_json(path: &std::path::Path, v: &Value) {
    let text = serde_json::to_string_pretty(v).unwrap() + "\n";
    fs::write(path, text)
        .unwrap_or_else(|e| panic!("kann {} nicht schreiben: {e}", path.display()));
}

fn main() {
    let root = workspace_root();

    // --- architecture.lock.json ---
    let arch_dir = root.join("architecture");
    let mut arch_refs: Vec<(String, CanonicalBytes)> = Vec::new();
    for name in ARCHITECTURE_FILES_YAML {
        arch_refs.push((
            (*name).to_string(),
            canon_of(&arch_dir.join(name), Media::Yaml),
        ));
    }
    for name in ARCHITECTURE_SCHEMAS {
        arch_refs.push((
            (*name).to_string(),
            canon_of(&arch_dir.join(name), Media::Json),
        ));
    }
    let arch_refs_view: Vec<(&str, &CanonicalBytes)> =
        arch_refs.iter().map(|(n, c)| (n.as_str(), c)).collect();
    let ia = collection_digest(&arch_refs_view);

    let arch_lock_path = arch_dir.join("architecture.lock.json");
    let mut arch_lock: Value =
        serde_json::from_str(&fs::read_to_string(&arch_lock_path).unwrap()).unwrap();
    arch_lock["architecture_id"] = Value::String(ia.to_string());
    arch_lock["parent_constitution_id"] = Value::String(
        "declared_ancestor unreachable, see constitution/constitution.lock.json (OBL-009)".into(),
    );
    arch_lock["sealed_over_files"] = Value::from(
        ARCHITECTURE_FILES_YAML
            .iter()
            .chain(ARCHITECTURE_SCHEMAS.iter())
            .map(|s| Value::String((*s).to_string()))
            .collect::<Vec<_>>(),
    );
    write_json(&arch_lock_path, &arch_lock);
    println!(
        "architecture.lock.json: I_A = {ia} ({} Dateien)",
        arch_refs.len()
    );

    // --- constitution.lock.json ---
    let const_dir = root.join("constitution");
    let const_lock_path = const_dir.join("constitution.lock.json");
    let mut const_lock: Value =
        serde_json::from_str(&fs::read_to_string(&const_lock_path).unwrap()).unwrap();
    let normative_files: Vec<String> = const_lock["normative_files"]
        .as_array()
        .expect("normative_files")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();

    let mut const_refs: Vec<(String, CanonicalBytes)> = Vec::new();
    for name in &normative_files {
        const_refs.push((
            name.clone(),
            canon_of(&const_dir.join(name), media_of(name)),
        ));
    }
    let const_refs_view: Vec<(&str, &CanonicalBytes)> =
        const_refs.iter().map(|(n, c)| (n.as_str(), c)).collect();
    let ic = collection_digest(&const_refs_view);

    let mut digests = serde_json::Map::new();
    for (name, canon) in &const_refs {
        digests.insert(name.clone(), Value::String(canon.digest().to_string()));
    }
    const_lock["canonical_digests"] = Value::Object(digests);
    const_lock["constitution_id"] = Value::String(ic.to_string());
    write_json(&const_lock_path, &const_lock);
    println!(
        "constitution.lock.json: I_C = {ic} ({} Dateien)",
        const_refs.len()
    );

    // --- PSK.lock ---
    let psk_lock_path = root.join("PSK.lock");
    let mut psk_lock: Value =
        serde_json::from_str(&fs::read_to_string(&psk_lock_path).unwrap()).unwrap();
    psk_lock["constitution_id"] = Value::String(ic.to_string());
    psk_lock["architecture_id"] = Value::String(ia.to_string());
    write_json(&psk_lock_path, &psk_lock);
    println!("PSK.lock: I_C = {ic}, I_A = {ia}");
    println!("(I_M, I_t bleiben null: setzen einen realen Build/Lauf voraus, Regel 6.7)");
}
