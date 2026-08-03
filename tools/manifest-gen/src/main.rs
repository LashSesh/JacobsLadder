//! Erzeugt MANIFEST.sha256 (Regel 26.5.ii): SHA-256-Digest jeder
//! versionierten Datei. "Versioniert" wird ueber `git ls-files`
//! bestimmt — das ist exakt die Menge, die ein Checkout tatsaechlich
//! versioniert, ohne eine eigene Ignore-Logik nachzubilden.
//!
//! Ausgabeformat: `<64-stelliger Kleinbuchstaben-Hex-Digest>  <Pfad>` je
//! Zeile, nach Pfad sortiert, LF-Zeilenenden. Zwei Laeufe ueber denselben
//! Stand erzeugen byteidentische Ausgabe (Vertrag 26.4, Reproduzierbarkeit).

use std::fs;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

use psk_types::Digest;

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

fn tracked_files(root: &std::path::Path) -> Vec<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-files")
        .arg("-z")
        .output()
        .expect("git ls-files fehlgeschlagen (ist git installiert und PATH korrekt?)");
    if !out.status.success() {
        panic!(
            "git ls-files: exit {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let mut files: Vec<String> = String::from_utf8(out.stdout)
        .expect("git ls-files lieferte kein UTF-8")
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(|s| s.replace('\\', "/"))
        .collect();
    files.sort();
    files
}

fn main() -> ExitCode {
    let root = workspace_root();
    let out_path = root.join("MANIFEST.sha256");
    let manifest_name = "MANIFEST.sha256";

    let files = tracked_files(&root);
    if files.is_empty() {
        eprintln!("manifest-gen: git ls-files lieferte keine Dateien; abgebrochen.");
        return ExitCode::FAILURE;
    }

    let mut lines = Vec::with_capacity(files.len());
    for rel in &files {
        if rel == manifest_name {
            // Das Manifest verzeichnet sich nicht selbst.
            continue;
        }
        let abs = root.join(rel);
        let bytes = match fs::read(&abs) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("manifest-gen: kann {rel} nicht lesen: {e}");
                return ExitCode::FAILURE;
            }
        };
        let digest = Digest::sha256(&bytes);
        lines.push(format!("{digest}  {rel}\n"));
    }

    let content: String = lines.concat();
    if let Err(e) = fs::write(&out_path, &content) {
        eprintln!(
            "manifest-gen: kann {} nicht schreiben: {e}",
            out_path.display()
        );
        return ExitCode::FAILURE;
    }

    eprintln!(
        "manifest-gen: {} Eintraege nach {} geschrieben.",
        lines.len(),
        out_path.display()
    );
    ExitCode::SUCCESS
}
