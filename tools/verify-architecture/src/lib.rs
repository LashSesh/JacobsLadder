//! `psk architecture verify <bundle>` (Struktur 27.6): prueft I_A gegen
//! architecture/architecture.lock.json (Boot-Schritt 10, Algorithmus 17.1)
//! UND prueft die 18 Architekturregister strukturell gegen ihre Schemas in
//! architecture/schemas/ (Struktur 25.3).
//!
//! Bibliotheksteil - siehe verify-bundle/src/lib.rs's Modulkopf fuer die
//! Motivation (dieselbe Pruefung auch aus `psk-conformance`/`psk-cli`
//! aufrufbar, ohne die Logik ein zweites Mal zu schreiben).

use std::fs;
use std::path::Path;

use jsonschema::validator_for;
use psk_canon::{can, collection_digest, CanonicalBytes, Media};
use psk_types::Digest;
use serde::Deserialize;
use serde_json::Value;

pub const ARCHITECTURE_FILES_YAML: &[&str] = &[
    "module_map.yaml",
    "port_registry.yaml",
    "sort_registry.yaml",
    "object_registry.yaml",
    "object_schemas.yaml",
    "volatile_fields.yaml",
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
    "capability_matrix.yaml",
];

pub const ARCHITECTURE_SCHEMAS: &[&str] = &[
    "schemas/module_map.schema.json",
    "schemas/port_registry.schema.json",
    "schemas/sort_registry.schema.json",
    "schemas/object_registry.schema.json",
    "schemas/object_schemas.schema.json",
    "schemas/volatile_fields.schema.json",
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
    "schemas/capability_matrix.schema.json",
];

#[derive(Debug, Deserialize)]
struct ArchitectureLock {
    architecture_id: Option<String>,
}

fn canon_of(path: &Path, media: Media) -> Result<CanonicalBytes, String> {
    let bytes = fs::read(path).map_err(|e| format!("kann {} nicht lesen: {e}", path.display()))?;
    can(&bytes, media).map_err(|e| format!("{}: {e}", path.display()))
}

/// Strukturprueft ein Architekturregister gegen sein generiertes Schema.
/// Rueckgabe: Liste der Validierungsfehler (leer = PASS).
pub fn validate_register(root: &Path, yaml_name: &str) -> Result<Vec<String>, String> {
    let yaml_path = root.join("architecture").join(yaml_name);
    let yaml_text = fs::read_to_string(&yaml_path)
        .map_err(|e| format!("kann {} nicht lesen: {e}", yaml_path.display()))?;
    let doc: Value = serde_yaml::from_str(&yaml_text)
        .map_err(|e| format!("{}: kein gueltiges YAML: {e}", yaml_path.display()))?;

    let schema_name = yaml_name.replace(".yaml", ".schema.json");
    let schema_path = root.join("architecture").join("schemas").join(&schema_name);
    let schema_text = fs::read_to_string(&schema_path)
        .map_err(|e| format!("kann {} nicht lesen: {e}", schema_path.display()))?;
    let schema: Value = serde_json::from_str(&schema_text)
        .map_err(|e| format!("{}: kein gueltiges JSON: {e}", schema_path.display()))?;

    let validator = validator_for(&schema)
        .map_err(|e| format!("{}: kein gueltiges JSON-Schema: {e}", schema_path.display()))?;
    let errors: Vec<String> = validator
        .iter_errors(&doc)
        .map(|e| format!("{} ({})", e, e.instance_path))
        .collect();
    Ok(errors)
}

pub struct ArchitectureCheck {
    pub schema_failures: Vec<(String, Vec<String>)>,
    pub missing: Vec<String>,
    pub total_expected: usize,
    pub computed_architecture_id: Digest,
    pub stored_architecture_id: Option<String>,
}

impl ArchitectureCheck {
    pub fn schema_conformant(&self) -> bool {
        self.schema_failures.is_empty()
    }

    pub fn matches(&self) -> bool {
        self.stored_architecture_id.as_deref()
            == Some(self.computed_architecture_id.to_string().as_str())
    }

    pub fn sealed(&self) -> bool {
        self.stored_architecture_id.is_some()
    }
}

/// `root` ist die Workspace-Wurzel (enthaelt `architecture/`). Prueft
/// zuerst alle 18 Register strukturell gegen ihre Schemas, bildet danach
/// I_A ueber die 18 YAML-Register + 18 Registerschemas und vergleicht
/// gegen `architecture.lock.json`.
pub fn check_architecture_bundle(root: &Path) -> Result<ArchitectureCheck, String> {
    let arch_dir = root.join("architecture");

    let mut schema_failures = Vec::new();
    for name in ARCHITECTURE_FILES_YAML {
        match validate_register(root, name) {
            Ok(errors) if errors.is_empty() => {}
            Ok(errors) => schema_failures.push(((*name).to_string(), errors)),
            Err(e) => schema_failures.push(((*name).to_string(), vec![e])),
        }
    }

    let mut present: Vec<(String, CanonicalBytes)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for name in ARCHITECTURE_FILES_YAML {
        let path = arch_dir.join(name);
        if !path.is_file() {
            missing.push((*name).to_string());
            continue;
        }
        present.push(((*name).to_string(), canon_of(&path, Media::Yaml)?));
    }
    for name in ARCHITECTURE_SCHEMAS {
        let path = arch_dir.join(name);
        if !path.is_file() {
            missing.push((*name).to_string());
            continue;
        }
        present.push(((*name).to_string(), canon_of(&path, Media::Json)?));
    }
    let total_expected = ARCHITECTURE_FILES_YAML.len() + ARCHITECTURE_SCHEMAS.len();

    let refs: Vec<(&str, &CanonicalBytes)> = present.iter().map(|(n, c)| (n.as_str(), c)).collect();
    let computed_architecture_id = collection_digest(&refs);

    let lock_path = arch_dir.join("architecture.lock.json");
    let lock_text = fs::read_to_string(&lock_path)
        .map_err(|e| format!("kann {} nicht lesen: {e}", lock_path.display()))?;
    let lock: ArchitectureLock = serde_json::from_str(&lock_text)
        .map_err(|e| format!("{} nicht lesbar: {e}", lock_path.display()))?;

    Ok(ArchitectureCheck {
        schema_failures,
        missing,
        total_expected,
        computed_architecture_id,
        stored_architecture_id: lock.architecture_id,
    })
}
