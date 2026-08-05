//! `psk constitution verify <bundle>` (Struktur 27.6): prueft I_C gegen
//! constitution.lock.json (Boot-Schritte 4-6, Algorithmus 17.1).
//!
//! Bibliotheksteil: extrahiert aus `main.rs`, damit dieselbe Pruefung auch
//! aus `psk-conformance` (T-ARCH-001/T-ID-001, negative Digest-Mismatch-
//! Tests) und `psk-cli` aufgerufen werden kann, ohne die Logik ein zweites
//! Mal zu schreiben. `main.rs` bleibt ein duenner Wrapper um
//! `check_constitution_bundle` mit identischer Ausgabe wie zuvor.

use std::fs;
use std::path::Path;

use psk_canon::{can, collection_digest, CanonicalBytes, Media};
use psk_types::Digest;
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct ConstitutionLock {
    constitution_id: Option<String>,
    normative_files: Vec<String>,
    #[serde(default)]
    declared_ancestor_constitution_id: Option<Value>,
}

fn media_of(name: &str) -> Media {
    if name.ends_with(".json") {
        Media::Json
    } else {
        Media::Yaml
    }
}

fn canon_of(path: &Path, media: Media) -> Result<CanonicalBytes, String> {
    let bytes = fs::read(path).map_err(|e| format!("kann {} nicht lesen: {e}", path.display()))?;
    can(&bytes, media).map_err(|e| format!("{}: {e}", path.display()))
}

/// Ergebnis einer Bundle-Pruefung - Werte, keine Ausgabe. `main.rs` formatiert
/// daraus die Konsolenmeldung; Aufrufer wie `psk-conformance` lesen die
/// Felder direkt.
pub struct BundleCheck {
    pub present_count: usize,
    pub missing: Vec<String>,
    pub total_normative_files: usize,
    pub computed_constitution_id: Digest,
    pub stored_constitution_id: Option<String>,
    pub declared_ancestor_status: Option<String>,
}

impl BundleCheck {
    /// PASS im Sinne von verify-bundle: `constitution_id` ist gesetzt UND
    /// stimmt mit dem berechneten Wert ueberein. `None` (noch nicht
    /// versiegelt) ist weder PASS noch FAIL in diesem Sinn - siehe
    /// `sealed()`.
    pub fn matches(&self) -> bool {
        self.stored_constitution_id.as_deref()
            == Some(self.computed_constitution_id.to_string().as_str())
    }

    pub fn sealed(&self) -> bool {
        self.stored_constitution_id.is_some()
    }
}

/// Liest `bundle/constitution.lock.json`, kanonisiert die dort gelisteten
/// `normative_files` relativ zu `bundle` und bildet den Kollektionsdigest.
/// Fehlende Dateien sind hier (wie im urspruenglichen `main.rs`) NICHT
/// fatal - sie werden gezaehlt, der Digest wird ueber die vorhandenen
/// Dateien gebildet.
pub fn check_constitution_bundle(bundle: &Path) -> Result<BundleCheck, String> {
    let lock_path = bundle.join("constitution.lock.json");
    let lock_text = fs::read_to_string(&lock_path)
        .map_err(|e| format!("kann {} nicht lesen: {e}", lock_path.display()))?;
    let lock: ConstitutionLock = serde_json::from_str(&lock_text)
        .map_err(|e| format!("{} nicht lesbar: {e}", lock_path.display()))?;

    let declared_ancestor_status = lock
        .declared_ancestor_constitution_id
        .as_ref()
        .and_then(|anc| anc.get("status"))
        .and_then(|v| v.as_str())
        .map(str::to_string);

    let mut present: Vec<(String, CanonicalBytes)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for name in &lock.normative_files {
        let path = bundle.join(name);
        if !path.is_file() {
            missing.push(name.clone());
            continue;
        }
        present.push((name.clone(), canon_of(&path, media_of(name))?));
    }

    let refs: Vec<(&str, &CanonicalBytes)> = present.iter().map(|(n, c)| (n.as_str(), c)).collect();
    let computed_constitution_id = collection_digest(&refs);

    Ok(BundleCheck {
        present_count: present.len(),
        total_normative_files: lock.normative_files.len(),
        missing,
        computed_constitution_id,
        stored_constitution_id: lock.constitution_id,
        declared_ancestor_status,
    })
}
