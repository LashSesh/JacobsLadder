//! `psk architecture verify <bundle>` (Struktur 27.5): prueft I_A gegen
//! architecture/architecture.lock.json (Boot-Schritt 10, Algorithmus 17.1)
//! UND prueft die 16 Architekturregister strukturell gegen ihre Schemas in
//! architecture/schemas/ (Struktur 25.3, PSK-RA v1.0.3 Fehlerkorrektur
//! Punkt 6: "schemas/ = JSON-Schemas der 16 Architekturregister selbst,
//! NICHT Kopien der Objektschemas aus constitution/").
//!
//! I_A = H(Can(architecture/*)) (architecture.lock.json: "computed_by"),
//! analog zu I_C in constitution/constitution.lock.json: die 16
//! Registerschemas sind dort normative Dateien des Bundles wie die 16
//! YAML-Register selbst (32 Dateien gesamt) - keine reinen Hilfsartefakte,
//! die aus dem Digest herausfallen duerften.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use jsonschema::validator_for;
use psk_canon::{can, collection_digest, CanonicalBytes, Media};
use serde::Deserialize;
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

#[derive(Debug, Deserialize)]
struct ArchitectureLock {
    architecture_id: Option<String>,
}

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

fn canon_of(path: &Path, media: Media) -> Result<CanonicalBytes, String> {
    let bytes = fs::read(path).map_err(|e| format!("kann {} nicht lesen: {e}", path.display()))?;
    can(&bytes, media).map_err(|e| format!("{}: {e}", path.display()))
}

/// Strukturprueft ein Architekturregister gegen sein generiertes Schema
/// (architecture/schemas/<name>.schema.json). Rueckgabe: Liste der
/// Validierungsfehler (leer = PASS).
fn validate_register(root: &Path, yaml_name: &str) -> Result<Vec<String>, String> {
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

fn main() -> ExitCode {
    let root = workspace_root();
    let arch_dir = root.join("architecture");

    // --- Strukturpruefung der 16 Register gegen architecture/schemas/ ---
    let mut schema_failures = 0usize;
    for name in ARCHITECTURE_FILES_YAML {
        match validate_register(&root, name) {
            Ok(errors) if errors.is_empty() => {}
            Ok(errors) => {
                schema_failures += 1;
                eprintln!("verify-architecture: SCHEMA-FAIL {name}:");
                for e in errors {
                    eprintln!("    - {e}");
                }
            }
            Err(e) => {
                schema_failures += 1;
                eprintln!("verify-architecture: SCHEMA-FAIL {name}: {e}");
            }
        }
    }
    if schema_failures > 0 {
        eprintln!(
            "verify-architecture: {schema_failures} von {} Registern nicht schemakonform.",
            ARCHITECTURE_FILES_YAML.len()
        );
        return ExitCode::FAILURE;
    }
    eprintln!(
        "verify-architecture: alle {} Register strukturell schemakonform.",
        ARCHITECTURE_FILES_YAML.len()
    );

    // --- I_A: Kollektionsdigest ueber die 16 YAML-Register + 16 Registerschemas ---
    let mut present: Vec<(String, CanonicalBytes)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for name in ARCHITECTURE_FILES_YAML {
        let path = arch_dir.join(name);
        if !path.is_file() {
            missing.push((*name).to_string());
            continue;
        }
        match canon_of(&path, Media::Yaml) {
            Ok(c) => present.push(((*name).to_string(), c)),
            Err(e) => {
                eprintln!("verify-architecture: FAIL — {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    for name in ARCHITECTURE_SCHEMAS {
        let path = arch_dir.join(name);
        if !path.is_file() {
            missing.push((*name).to_string());
            continue;
        }
        match canon_of(&path, Media::Json) {
            Ok(c) => present.push(((*name).to_string(), c)),
            Err(e) => {
                eprintln!("verify-architecture: FAIL — {e}");
                return ExitCode::FAILURE;
            }
        }
    }
    let total_expected = ARCHITECTURE_FILES_YAML.len() + ARCHITECTURE_SCHEMAS.len();
    if !missing.is_empty() {
        eprintln!(
            "verify-architecture: {} von {} erwarteten Bundle-Dateien fehlen: {}",
            missing.len(),
            total_expected,
            missing.join(", ")
        );
        return ExitCode::FAILURE;
    }

    let refs: Vec<(&str, &CanonicalBytes)> = present.iter().map(|(n, c)| (n.as_str(), c)).collect();
    let computed_ia = collection_digest(&refs);

    let lock_path = arch_dir.join("architecture.lock.json");
    let lock_text = match fs::read_to_string(&lock_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "verify-architecture: kann {} nicht lesen: {e}",
                lock_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let lock: ArchitectureLock = match serde_json::from_str(&lock_text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "verify-architecture: {} nicht lesbar: {e}",
                lock_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    match lock.architecture_id {
        None => {
            eprintln!(
                "verify-architecture: NOCH NICHT VERSIEGELT — architecture_id ist null. Berechneter Wert: {computed_ia}"
            );
            ExitCode::SUCCESS
        }
        Some(stored) => {
            if stored == computed_ia.to_string() {
                eprintln!(
                    "verify-architecture: PASS — architecture_id stimmt ueberein ({computed_ia})."
                );
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "verify-architecture: FAIL — architecture_id weicht ab. Gespeichert: {stored}, berechnet: {computed_ia}"
                );
                ExitCode::FAILURE
            }
        }
    }
}
