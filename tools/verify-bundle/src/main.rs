//! `psk constitution verify <bundle>` (Struktur 27.5): prueft I_C gegen
//! constitution.lock.json (Boot-Schritte 4-6, Algorithmus 17.1).
//!
//! Prueft die REKONSTRUIERTE constitution/ auf Selbstkonsistenz: die in
//! `normative_files` gelistete, ordnungssemantische Dateireihenfolge wird
//! kanonisiert und ueber Definition 6.6 zu einer Konstitutions-ID verdichtet,
//! die gegen den in derselben Lockdatei gespeicherten Wert geprueft wird.
//!
//! Was diese Pruefung NICHT tut: gegen `declared_ancestor_constitution_id`
//! (aa10aa5a...) vergleichen. Dieser Wert ist laut OBL-009 unreachable —
//! kein eingebettetes Bundle, widerspruechliche Digest-Saetze zwischen
//! CPSK Kapitel 44.1 und Kapitel F. Er wird informativ ausgegeben, nie
//! als Pruefziel verwendet.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use psk_canon::{can, collection_digest, CanonicalBytes, Media};
use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Deserialize)]
struct ConstitutionLock {
    constitution_id: Option<String>,
    normative_files: Vec<String>,
    #[serde(default)]
    declared_ancestor_constitution_id: Option<Value>,
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

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let root = workspace_root();
    let bundle = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("constitution"));

    let lock_path = bundle.join("constitution.lock.json");
    let lock_text = match fs::read_to_string(&lock_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "verify-bundle: kann {} nicht lesen: {e}",
                lock_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let lock: ConstitutionLock = match serde_json::from_str(&lock_text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("verify-bundle: {} nicht lesbar: {e}", lock_path.display());
            return ExitCode::FAILURE;
        }
    };

    if let Some(anc) = &lock.declared_ancestor_constitution_id {
        if let Some(status) = anc.get("status").and_then(|v| v.as_str()) {
            eprintln!("verify-bundle: Hinweis — declared_ancestor_constitution_id: {status} (OBL-009, nicht Pruefziel)");
        }
    }

    let mut present: Vec<(String, CanonicalBytes)> = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    for name in &lock.normative_files {
        let path = bundle.join(name);
        if !path.is_file() {
            missing.push(name.clone());
            continue;
        }
        match canon_of(&path, media_of(name)) {
            Ok(c) => present.push((name.clone(), c)),
            Err(e) => {
                eprintln!("verify-bundle: FAIL — {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    if !missing.is_empty() {
        eprintln!(
            "verify-bundle: {} von {} in normative_files gelisteten Dateien fehlen: {}",
            missing.len(),
            lock.normative_files.len(),
            missing.join(", ")
        );
    }

    let refs: Vec<(&str, &CanonicalBytes)> = present.iter().map(|(n, c)| (n.as_str(), c)).collect();
    let computed_ic = collection_digest(&refs);

    match lock.constitution_id {
        None => {
            eprintln!(
                "verify-bundle: NOCH NICHT VERSIEGELT — constitution_id ist null. \
                 Berechneter Wert ueber {} vorhandene Datei(en): {computed_ic}",
                present.len()
            );
            if missing.is_empty() {
                eprintln!(
                    "verify-bundle: vollstaendiger Dateisatz vorhanden — bereit zum Versiegeln."
                );
            }
            ExitCode::SUCCESS
        }
        Some(stored) => {
            if stored == computed_ic.to_string() {
                eprintln!("verify-bundle: PASS — constitution_id stimmt ueberein ({computed_ic}).");
                ExitCode::SUCCESS
            } else {
                eprintln!(
                    "verify-bundle: FAIL — constitution_id weicht ab. Gespeichert: {stored}, berechnet: {computed_ic}"
                );
                ExitCode::FAILURE
            }
        }
    }
}
