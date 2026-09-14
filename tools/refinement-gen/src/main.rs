//! Schreibt architecture/refinement_map.yaml aus constitution/state_machines.yaml.
//!
//! Vertrag 23.5 (Maschinencheckbare Verfeinerung) verlangt fuer jeden
//! konkreten Zustandsautomaten eine explizite, maschinenlesbare Abbildung in
//! den abstrakten Automaten aus Kapitel 13; unabgebildete Transitionen sind
//! blocking. Der konkrete Automat in psk-types wird von demselben Generator
//! aus derselben Registerquelle erzeugt wie diese Abbildung - die Abbildung
//! ist damit die Identitaet, und Drift zwischen konkret und abstrakt ist
//! konstruktiv ausgeschlossen, nicht bloss nachtraeglich geprueft.
//!
//! Dieses Werkzeug SCHREIBT; verify-refinement LIEST und vergleicht.

use std::fs;
use std::path::PathBuf;

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

fn main() {
    let root = workspace_root();
    let doc = psk_codegen::load_state_machines(&root);
    let text = psk_codegen::generate_refinement_map(&doc);
    let path = root.join("architecture").join("refinement_map.yaml");
    fs::write(&path, &text)
        .unwrap_or_else(|e| panic!("kann {} nicht schreiben: {e}", path.display()));
    let transitions = text.matches("  - concrete:").count();
    println!(
        "refinement_map.yaml: {} Automaten, {} Transitionen abgebildet",
        doc.machines.len(),
        transitions
    );
}
