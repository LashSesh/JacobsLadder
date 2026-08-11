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

/// Die Zweitschicht-Register (QPM/NRAII-RA, Listings A.1-D.1).
///
/// Sie liegen BEWUSST ausserhalb von `architecture/` und gehen deshalb
/// NICHT in I_A ein: das Werk fuehrt eigenstaendige Identitaeten, und
/// QPM Regel 0.2 (Zwei eigene Locks, kein gemeinsamer) begruendet das
/// normativ - eine gemeinsame Identitaet waere die von
/// QPM Axiom 19.2 (Keine Autoritätsverschmelzung) untersagte
/// Verschmelzung, und das Nahtregister fuehrt
/// `shared-identity-in-certificate` als blockierenden Negativtest.
///
/// Ungesiegelt duerfen sie deshalb aber nicht bleiben. Dieselbe Regel:
/// "Ein Register, dessen Aenderung keinen Digest bewegt, ist gegen
/// unbemerkte Aenderung nicht geschuetzt - die Bindungspruefung stellt
/// fest, dass eine Behauptung haelt, nicht dass niemand sie
/// ausgetauscht hat." Siehe [`SECOND_LAYER_SEALS`].
pub const SECOND_LAYER_REGISTERS: &[&str] = &[
    "qpm-nraii-architecture/qpm_object_registry.yaml",
    "qpm-nraii-architecture/qpm_gate_registry.yaml",
    "qpm-nraii-architecture/qpm_conformance.yaml",
    "qpm-nraii-architecture/seam_registry.yaml",
    "nraii-architecture/nraii_layer_registry.yaml",
    "nraii-architecture/nraii_gate_registry.yaml",
    "nraii-architecture/nraii_conformance.yaml",
];

/// Eine Zweitschicht-Identitaet: welches Verzeichnis sie siegelt, wo
/// ihr Lock liegt, unter welchem Feldnamen der Wert steht.
pub struct SecondLayerSeal {
    /// Die Identitaet, wie das Werk sie nennt.
    pub identity: &'static str,
    /// Das Verzeichnis, ueber dem H(Can(...)) gebildet wird.
    pub directory: &'static str,
    /// Die versiegelten Dateien, in fester Reihenfolge - der
    /// Kollektionsdigest haengt an ihr (Definition 6.9 (Kollektionsdigest)).
    pub files: &'static [&'static str],
    /// Der Lock, der den Wert traegt. Liegt IM Verzeichnis, gehoert
    /// aber NICHT zu `files`: ein Siegel, das sich selbst siegelte,
    /// haette keinen Fixpunkt.
    pub lock: &'static str,
    pub field: &'static str,
}

/// Die beiden Berechnungsorte aus
/// QPM Regel 0.2 (Zwei eigene Locks, kein gemeinsamer), woertlich:
/// "I_QPM = H(Can(qpm-nraii-architecture/*)),
/// I_NRAII = H(Can(nraii-architecture/*))".
///
/// Befund zur Naht, gemeldet statt umentschieden: `seam_registry.yaml`
/// liegt in `qpm-nraii-architecture/` und faellt damit nach dem
/// Wortlaut unter I_QPM - eine Aenderung an der Naht bewegt also die
/// QPM-Identitaet, nicht die NRAII-Identitaet. Gesiegelt ist sie
/// dadurch; die Zuordnung ist aber asymmetrisch, obwohl die Naht
/// beiden Seiten gehoert ("Owner beide Seiten gemeinsam",
/// QPM Struktur 21.2 (NRAIIQPMSeam)).
pub const SECOND_LAYER_SEALS: &[SecondLayerSeal] = &[
    SecondLayerSeal {
        identity: "I_QPM",
        directory: "qpm-nraii-architecture",
        files: &[
            "qpm_object_registry.yaml",
            "qpm_gate_registry.yaml",
            "qpm_conformance.yaml",
            "seam_registry.yaml",
        ],
        lock: "qpm.lock.json",
        field: "qpm_id",
    },
    SecondLayerSeal {
        identity: "I_NRAII",
        directory: "nraii-architecture",
        files: &[
            "nraii_layer_registry.yaml",
            "nraii_gate_registry.yaml",
            "nraii_conformance.yaml",
        ],
        lock: "nraii.lock.json",
        field: "nraii_id",
    },
];

/// Berechnet H(Can(<verzeichnis>/*)) fuer eine Zweitschicht-Identitaet.
///
/// Dieselbe Bildung wie I_A und I_C: `collection_digest` ueber die
/// kanonisierten Dateien (Definition 6.9 (Kollektionsdigest)). Eine
/// zweite Digestbildung waere hier genau der Verstoss, den
/// QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)
/// benennt - auch fuer ein Werkzeug.
pub fn compute_second_layer_id(root: &Path, seal: &SecondLayerSeal) -> Result<Digest, String> {
    let dir = root.join(seal.directory);
    let mut present: Vec<(String, CanonicalBytes)> = Vec::new();
    for name in seal.files {
        present.push(((*name).to_string(), canon_of(&dir.join(name), Media::Yaml)?));
    }
    let refs: Vec<(&str, &CanonicalBytes)> = present.iter().map(|(n, c)| (n.as_str(), c)).collect();
    Ok(collection_digest(&refs))
}

/// Prueft beide Zweitschicht-Siegel gegen ihre Locks.
///
/// Gibt je Identitaet (Name, berechnet, gespeichert) zurueck; der
/// Aufrufer entscheidet ueber den Ausgang. Ein fehlender Lock ist ein
/// Fehler, kein Vorgabewert - ohne ihn waere die Wache abwesend, und
/// genau das war der Zustand, den QPM Regel 0.2 (Zwei eigene Locks, kein gemeinsamer)
/// behebt.
pub fn check_second_layer_seals(
    root: &Path,
) -> Result<Vec<(&'static str, Digest, String)>, String> {
    let mut out = Vec::new();
    for seal in SECOND_LAYER_SEALS {
        let computed = compute_second_layer_id(root, seal)?;
        let lock_path = root.join(seal.directory).join(seal.lock);
        let text = fs::read_to_string(&lock_path).map_err(|e| {
            format!(
                "{}: {e} - {} braucht einen Berechnungsort \
                 (QPM Regel 0.2 (Zwei eigene Locks, kein gemeinsamer))",
                lock_path.display(),
                seal.identity
            )
        })?;
        let lock: Value = serde_json::from_str(&text)
            .map_err(|e| format!("{} nicht lesbar: {e}", lock_path.display()))?;
        let stored = lock[seal.field]
            .as_str()
            .ok_or_else(|| format!("{} fuehrt kein Feld `{}`", lock_path.display(), seal.field))?
            .to_string();
        out.push((seal.identity, computed, stored));
    }
    Ok(out)
}

/// Prueft die Bindungsbehauptungen der Zweitschicht gegen PSK-RA:
/// jede genannte Sorte, jedes Modul und jeder Pass MUSS im gebundenen
/// PSK-RA-Register wirklich existieren, und die deklarierten Zaehler
/// muessen zu den Listen passen.
///
/// Ohne diese Pruefung waere `binds_to` eine Behauptung wie jede
/// andere - dieselbe Klasse, die schon bei den Registerrueckverweisen
/// zugeschlagen hat.
pub fn check_second_layer_binding(root: &Path) -> Result<Vec<String>, String> {
    let mut problems = Vec::new();

    let load = |rel: &str| -> Result<Value, String> {
        let path = root.join(rel);
        let text = fs::read_to_string(&path).map_err(|e| format!("kann {rel} nicht lesen: {e}"))?;
        serde_yaml::from_str::<Value>(&text).map_err(|e| format!("{rel} nicht lesbar: {e}"))
    };

    // Bekannte PSK-RA-Kennungen aus den versiegelten Registern.
    let sorts = load("architecture/sort_registry.yaml")?;
    let known_sorts: Vec<String> = sorts["sorts"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|s| s["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let modules = load("architecture/module_map.yaml")?;
    let known_modules: Vec<String> = modules["modules"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|m| m["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let passes = load("architecture/pass_registry.yaml")?;
    let known_passes: Vec<String> = passes["passes"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|p| p["id"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if known_sorts.is_empty() || known_modules.is_empty() || known_passes.is_empty() {
        return Err("PSK-RA-Register liefern keine Kennungen - Leser kaputt".to_string());
    }

    // Ein Eignerfeld kann mehrere Module nennen ("M08/M09").
    let check_owner = |raw: &str, where_: &str, problems: &mut Vec<String>| {
        for part in raw.split('/') {
            let m = part.trim();
            if !known_modules.iter().any(|k| k == m) {
                problems.push(format!(
                    "{where_}: Modul {m} steht nicht in module_map.yaml"
                ));
            }
        }
    };

    // ---- Listing A.1: Sortenbindung.
    let objects = load(SECOND_LAYER_REGISTERS[0])?;
    let list = objects["objects"]
        .as_array()
        .ok_or("qpm_object_registry.yaml: objects fehlt")?;
    for o in list {
        let id = o["id"].as_str().unwrap_or("?");
        match o["psk_sort"].as_str() {
            Some(s) if known_sorts.iter().any(|k| k == s) => {}
            Some(s) => problems.push(format!(
                "qpm_object_registry.yaml: {id} bindet an Sorte {s}, die sort_registry.yaml nicht fuehrt"
            )),
            None => problems.push(format!("qpm_object_registry.yaml: {id} ohne psk_sort")),
        }
        if let Some(owner) = o["owner"].as_str() {
            check_owner(
                owner,
                &format!("qpm_object_registry.yaml/{id}"),
                &mut problems,
            );
        }
    }
    // "count: 15" ist eine Behauptung ueber die Liste daneben.
    if let Some(claimed) = objects["count"].as_u64() {
        if claimed as usize != list.len() {
            problems.push(format!(
                "qpm_object_registry.yaml: count {claimed}, Liste traegt {}",
                list.len()
            ));
        }
    }
    // no_new_primary_sort: true heisst, KEIN Objekt fuehrt eine Sorte
    // ein - das ist genau die obige Pruefung, hier nur benannt.
    if objects["no_new_primary_sort"].as_bool() != Some(true) {
        problems.push(
            "qpm_object_registry.yaml: no_new_primary_sort nicht als true gefuehrt".to_string(),
        );
    }

    // ---- Listing B.1: Gate- und Passbindung.
    let gates = load(SECOND_LAYER_REGISTERS[1])?;
    for g in gates["gates"].as_array().into_iter().flatten() {
        let id = g["id"].as_str().unwrap_or("?");
        if let Some(module) = g["module"].as_str() {
            check_owner(
                module,
                &format!("qpm_gate_registry.yaml/{id}"),
                &mut problems,
            );
        }
    }
    for (pass, _) in gates["pass_binding"]
        .as_object()
        .into_iter()
        .flat_map(|m| m.iter())
    {
        if !known_passes.iter().any(|k| k == pass) {
            problems.push(format!(
                "qpm_gate_registry.yaml: pass_binding nennt {pass}, den pass_registry.yaml nicht fuehrt"
            ));
        }
    }

    // ---- Listing C.1: Schichtzaehler.
    let layers = load(SECOND_LAYER_REGISTERS[4])?;
    let ls = layers["layers"].as_array().map(|a| a.len()).unwrap_or(0);
    if let Some(claimed) = layers["count"].as_u64() {
        if claimed as usize != ls {
            problems.push(format!(
                "nraii_layer_registry.yaml: count {claimed}, Liste traegt {ls}"
            ));
        }
    }

    // ---- Listing D.1: die Naht zeigt auf PSK-RA-Module.
    let seam = load(SECOND_LAYER_REGISTERS[3])?;
    for p in seam["ports"].as_array().into_iter().flatten() {
        let id = p["id"].as_str().unwrap_or("?");
        for end in ["from", "to"] {
            let Some(raw) = p[end].as_str() else { continue };
            // Form "QPM.M19" / "NRAII.L9" - nur die QPM-Seite bindet an
            // ein PSK-RA-Modul; die NRAII-Seite an eine eigene Schicht.
            if let Some(module) = raw.strip_prefix("QPM.") {
                check_owner(
                    module,
                    &format!("seam_registry.yaml/{id}.{end}"),
                    &mut problems,
                );
            }
        }
    }

    // Nullwache: die Register existieren, also MUSS geprueft worden sein.
    if list.is_empty() {
        return Err("Zweitschichtpruefung fand keine Objekte - Leser kaputt".to_string());
    }
    Ok(problems)
}
