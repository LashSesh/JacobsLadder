//! Erzeugt SBOM.json (Regel 26.5.iii): Materialstueckliste mit Digests.
//! Quelle ist Cargo.lock — die bereits gepinnte, digestgebundene
//! Abhaengigkeitsmenge (Vertrag 26.4). Kein zweiter Aufloesungsschritt,
//! keine Netzwerkzugriffe.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
struct CargoLock {
    package: Vec<LockedPackage>,
}

#[derive(Debug, Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    checksum: Option<String>,
}

#[derive(Debug, Serialize)]
struct SbomEntry {
    name: String,
    version: String,
    source: String,
    checksum: Option<String>,
}

#[derive(Debug, Serialize)]
struct Sbom {
    schema: &'static str,
    generated_from: &'static str,
    component_count: usize,
    components: Vec<SbomEntry>,
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

fn main() -> ExitCode {
    let root = workspace_root();
    let lock_path = root.join("Cargo.lock");
    let text = match fs::read_to_string(&lock_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "sbom-gen: kann {} nicht lesen ({e}). Erst `cargo build --workspace` ausfuehren.",
                lock_path.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let lock: CargoLock = match toml::from_str(&text) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("sbom-gen: Cargo.lock nicht lesbar: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut components: Vec<SbomEntry> = lock
        .package
        .into_iter()
        // Workspace-eigene Pakete haben keine "source" (kein Registry-Bezug)
        // und sind kein externes Material; sie werden ausgelassen.
        .filter_map(|p| {
            p.source.map(|source| SbomEntry {
                name: p.name,
                version: p.version,
                source,
                checksum: p.checksum,
            })
        })
        .collect();
    components.sort_by(|a, b| {
        (a.name.as_str(), a.version.as_str()).cmp(&(b.name.as_str(), b.version.as_str()))
    });

    let sbom = Sbom {
        schema: "psk.sbom/1.0",
        generated_from: "Cargo.lock",
        component_count: components.len(),
        components,
    };

    let out_path = root.join("SBOM.json");
    let json = serde_json::to_string_pretty(&sbom).expect("Serialisierung");
    if let Err(e) = fs::write(&out_path, format!("{json}\n")) {
        eprintln!("sbom-gen: kann {} nicht schreiben: {e}", out_path.display());
        return ExitCode::FAILURE;
    }
    eprintln!(
        "sbom-gen: {} externe Komponenten nach {} geschrieben.",
        sbom.component_count,
        out_path.display()
    );
    ExitCode::SUCCESS
}
