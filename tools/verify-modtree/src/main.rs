//! `verify-modtree` (kein eigenes Vertragsverb, interne CI-Haerte-
//! Massnahme, Vorschlag aus der I7-Abnahme): findet Dateien unter src/,
//! die zwar existieren, aber ueber keine mod-Kette ab lib.rs/main.rs
//! erreichbar sind - genau die Fehlerklasse, die
//! `effect-local-fs/src/apply.rs` zeigte (real implementiert, aber nie
//! mit `mod apply;` verdrahtet, deshalb nie kompiliert und nie getestet,
//! bis eine unabhaengige Aenderung an einer Nachbardatei das Problem
//! sichtbar machte).
//!
//! Erkennt `mod X;` und `pub(...)? mod X {`-Deklarationen zeilenweise -
//! keine echte Rust-Syntaxanalyse (keine `syn`-Abhaengigkeit, passend zum
//! Rest dieses Werkzeugsatzes). Deckt `foo.rs`/`foo/mod.rs` sowie
//! `#[path = "..."]`-Ueberschreibungen ab.
//!
//! Befund (v1.0.19-Umsetzung), ehrlich vermerkt statt still korrigiert:
//! die urspruengliche Fassung dieses Kopfkommentars fuehrte "keine
//! `#[path]`-Ueberschreibungen" als Annahme UND behauptete zugleich "kein
//! Fall, den dieses Werkzeug nicht wenigstens versucht abzudecken" - beides
//! zusammen war schon damals unhaltbar, und die T-SEC-001-Umsetzung
//! (psk-lifecycle`s plattformbedingte Aufteilung in `process_windows.rs`/
//! `process_unsupported.rs` ueber `#[cfg]` + `#[path]`) machte es real:
//! das Werkzeug meldete vier Fehler auf voellig korrektem, auf BEIDEN
//! Plattformen uebersetzbarem Code - zwei "mod verweist auf keine
//! vorhandene Datei" und zwei "Datei ueber keine mod-Kette erreichbar",
//! also genau die Fehlerklasse, die es finden soll, nur falsch herum.
//! Ein Falschbefund dieser Art ist schlimmer als eine Deckungsluecke: er
//! draengt dazu, richtigen Code an ein unvollstaendiges Werkzeugmodell
//! anzupassen. Deshalb hier das Modell erweitert, nicht der Code verbogen.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

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

/// Liest `Cargo.toml`s `[workspace] members` roh als Zeilenliste - dieselbe
/// bewusste Einfachheit wie beim mod-Scan: kein TOML-Parser, nur genug
/// Textverarbeitung fuer das tatsaechliche Format dieser einen Datei.
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let text = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml lesbar");
    let mut members = Vec::new();
    let mut in_members = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("members") && trimmed.contains('[') {
            in_members = true;
            continue;
        }
        if in_members {
            if trimmed.starts_with(']') {
                break;
            }
            let cleaned = trimmed.trim_end_matches(',').trim_matches('"');
            if !cleaned.is_empty() {
                members.push(root.join(cleaned));
            }
        }
    }
    members
}

/// Ein `mod`-Fund: Name, ob er einen eigenen Dateikoerper braucht
/// (`mod X;`) oder inline ist (`mod X { ... }`, kein separates File), und
/// die etwaige `#[path = "..."]`-Ueberschreibung seines Dateinamens.
struct ModDecl {
    name: String,
    inline: bool,
    path_override: Option<String>,
}

/// Liest `#[path = "..."]` (auch `#![path = ...]`-freie Schreibvarianten mit
/// abweichenden Leerzeichen) und gibt den Dateinamen zurueck.
fn parse_path_attribute(line: &str) -> Option<String> {
    let rest = line.strip_prefix("#[")?.trim_start();
    let rest = rest.strip_prefix("path")?.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix('"')?;
    let (value, _) = rest.split_once('"')?;
    Some(value.to_string())
}

fn scan_mod_decls(text: &str) -> Vec<ModDecl> {
    let mut out = Vec::new();
    // Ein `#[path]`-Attribut steht auf einer eigenen Zeile VOR seinem `mod`
    // und ueberlebt dazwischenliegende weitere Attribute (`#[cfg(...)]`) -
    // genau die Form, die psk-lifecycle nutzt.
    let mut pending_path: Option<String> = None;
    for raw_line in text.lines() {
        let line = raw_line.trim_start();
        if line.starts_with("//") {
            continue;
        }
        if line.starts_with("#[") {
            if let Some(p) = parse_path_attribute(line) {
                pending_path = Some(p);
            }
            continue;
        }
        // Ueberspringt optionales `pub`, `pub(crate)`, `pub(super)` etc.
        let after_pub = if let Some(rest) = line.strip_prefix("pub(") {
            rest.split_once(')').map(|(_, r)| r.trim_start())
        } else {
            line.strip_prefix("pub").map(str::trim_start)
        }
        .unwrap_or(line);
        let Some(after_mod) = after_pub.strip_prefix("mod ") else {
            // Eine gewoehnliche Codezeile beendet die Attributgruppe - ein
            // `#[path]` weit oberhalb gehoert nicht mehr zum naechsten `mod`.
            if !line.is_empty() {
                pending_path = None;
            }
            continue;
        };
        let name_part = after_mod.trim_start();
        let name: String = name_part
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if name.is_empty() {
            continue;
        }
        let after_name = name_part[name.len()..].trim_start();
        // Weder `;` noch `{` unmittelbar danach (z.B. ein Attribut
        // dazwischen) wird bewusst NICHT erkannt - lieber ein uebersehener
        // seltener Stil als ein falsch-positiver Treffer auf z.B. eine
        // Variable namens `mod_something`.
        if after_name.starts_with(';') {
            out.push(ModDecl {
                name,
                inline: false,
                path_override: pending_path.take(),
            });
        } else if after_name.starts_with('{') {
            out.push(ModDecl {
                name,
                inline: true,
                path_override: pending_path.take(),
            });
        }
    }
    out
}

/// Sammelt rekursiv alle ueber die mod-Kette erreichbaren Dateien,
/// relativ zu `src_root`. `prefix` ist der Verzeichnispfad, unter dem
/// file-basierte mods dieser Ebene gesucht werden (leer an der Wurzel).
fn collect_reachable(
    src_root: &Path,
    entry_file: &Path,
    prefix: &Path,
    reachable: &mut BTreeSet<PathBuf>,
    problems: &mut Vec<String>,
) {
    let Ok(text) = fs::read_to_string(entry_file) else {
        return;
    };
    for decl in scan_mod_decls(&text) {
        if decl.inline {
            continue; // kein eigenes File erwartet
        }
        // `#[path = "..."]` ueberschreibt die Dateinamenskonvention
        // vollstaendig; Submodule des so geladenen Moduls liegen danach
        // unter dem Pfad OHNE Endung (Rusts eigene Regel: ein aus
        // `dir/datei.rs` geladenes Modul sucht seine Kinder in
        // `dir/datei/`), nicht unter dem Modulnamen.
        if let Some(rel) = &decl.path_override {
            let rel_path = prefix.join(rel);
            if src_root.join(&rel_path).is_file() {
                let next_prefix = rel_path.with_extension("");
                if reachable.insert(rel_path.clone()) {
                    collect_reachable(
                        src_root,
                        &src_root.join(&rel_path),
                        &next_prefix,
                        reachable,
                        problems,
                    );
                }
            } else {
                problems.push(format!(
                    "`#[path = \"{}\"] mod {}` in {} verweist auf keine vorhandene Datei ({})",
                    rel,
                    decl.name,
                    entry_file.display(),
                    src_root.join(&rel_path).display(),
                ));
            }
            continue;
        }

        let flat = prefix.join(format!("{}.rs", decl.name));
        let nested = prefix.join(&decl.name).join("mod.rs");
        // Beide Formen (`foo.rs` und `foo/mod.rs`) verschieben den Praefix
        // fuer WEITERE, in `foo` deklarierte Submodule gleichermassen auf
        // `prefix/foo` - ein `mod bar;` innerhalb von `src/outer.rs` meint
        // `src/outer/bar.rs`, nicht `src/bar.rs`.
        let found = if src_root.join(&flat).is_file() {
            Some((flat.clone(), prefix.join(&decl.name)))
        } else if src_root.join(&nested).is_file() {
            Some((nested.clone(), prefix.join(&decl.name)))
        } else {
            None
        };
        match found {
            Some((rel_path, next_prefix)) => {
                if reachable.insert(rel_path.clone()) {
                    collect_reachable(
                        src_root,
                        &src_root.join(&rel_path),
                        &next_prefix,
                        reachable,
                        problems,
                    );
                }
            }
            None => {
                problems.push(format!(
                    "`mod {}` in {} verweist auf keine vorhandene Datei ({} oder {} fehlen)",
                    decl.name,
                    entry_file.display(),
                    src_root.join(&flat).display(),
                    src_root.join(&nested).display(),
                ));
            }
        }
    }
}

fn all_rs_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            all_rs_files_under(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn check_crate(crate_dir: &Path) -> Vec<String> {
    let src = crate_dir.join("src");
    if !src.is_dir() {
        return Vec::new();
    }

    let mut reachable: BTreeSet<PathBuf> = BTreeSet::new();
    let mut problems: Vec<String> = Vec::new();

    for entry_name in ["lib.rs", "main.rs"] {
        let entry = src.join(entry_name);
        if entry.is_file() {
            reachable.insert(PathBuf::from(entry_name));
            collect_reachable(&src, &entry, Path::new(""), &mut reachable, &mut problems);
        }
    }

    if reachable.is_empty() {
        // Weder lib.rs noch main.rs - kein von diesem Werkzeug pruefbarer
        // Krateneinstieg (sollte durch `cargo build` ohnehin auffallen).
        return problems;
    }

    let mut present: Vec<PathBuf> = Vec::new();
    all_rs_files_under(&src, &mut present);
    for abs_path in present {
        let rel = abs_path.strip_prefix(&src).unwrap().to_path_buf();
        // src/bin/*.rs sind von Cargo automatisch als eigene Binaries
        // erkannte Einstiegspunkte, keine ueber mod erreichbaren Module.
        if rel.starts_with("bin") {
            continue;
        }
        if !reachable.contains(&rel) {
            problems.push(format!(
                "{} existiert unter src/, ist aber ueber keine mod-Kette ab lib.rs/main.rs erreichbar \
                 (dieselbe Fehlerklasse wie effect-local-fs/src/apply.rs vor seiner Behebung)",
                crate_dir.join("src").join(&rel).display()
            ));
        }
    }

    problems
}

fn main() -> ExitCode {
    let root = workspace_root();
    let members = workspace_members(&root);

    let mut total_problems = 0usize;
    for member in &members {
        let problems = check_crate(member);
        if !problems.is_empty() {
            eprintln!("verify-modtree: {}:", member.display());
            for p in &problems {
                eprintln!("    - {p}");
            }
            total_problems += problems.len();
        }
    }

    if total_problems > 0 {
        eprintln!(
            "verify-modtree: FAIL — {total_problems} Problem(e) in {} geprueften Paketen.",
            members.len()
        );
        ExitCode::FAILURE
    } else {
        eprintln!(
            "verify-modtree: PASS — alle Dateien unter src/ in {} Paketen ueber ihre mod-Kette erreichbar.",
            members.len()
        );
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_crate(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("verify-modtree-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("src")).unwrap();
        dir
    }

    #[test]
    fn scan_mod_decls_recognizes_semicolon_and_brace_forms_but_not_lookalikes() {
        let text = "mod a;\npub mod b;\npub(crate) mod c;\nmod d {\n    // inline\n}\nlet mod_something = 1;\n// mod e;\n";
        let found: Vec<String> = scan_mod_decls(text).into_iter().map(|d| d.name).collect();
        assert_eq!(found, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn check_crate_flags_a_file_the_mod_chain_never_reaches() {
        // Reproduziert genau den effect-local-fs/apply.rs-Fall: eine reale
        // Datei existiert, aber lib.rs deklariert kein `mod`.
        let dir = scratch_crate("orphan");
        fs::write(dir.join("src/lib.rs"), "pub fn f() {}\n").unwrap();
        fs::write(dir.join("src/apply.rs"), "pub fn g() {}\n").unwrap();

        let problems = check_crate(&dir);
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("apply.rs"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn check_crate_passes_once_the_file_is_wired_in() {
        let dir = scratch_crate("wired");
        fs::write(dir.join("src/lib.rs"), "mod apply;\npub use apply::g;\n").unwrap();
        fs::write(dir.join("src/apply.rs"), "pub fn g() {}\n").unwrap();

        let problems = check_crate(&dir);
        assert!(problems.is_empty(), "{problems:?}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn path_attribute_is_parsed_in_its_real_and_spaced_forms() {
        assert_eq!(
            parse_path_attribute("#[path = \"process_windows.rs\"]").as_deref(),
            Some("process_windows.rs")
        );
        assert_eq!(
            parse_path_attribute("#[path=\"a/b.rs\"]").as_deref(),
            Some("a/b.rs")
        );
        // Kein path-Attribut: darf nicht faelschlich greifen.
        assert_eq!(parse_path_attribute("#[cfg(windows)]"), None);
        assert_eq!(parse_path_attribute("#[derive(Debug)]"), None);
    }

    #[test]
    fn check_crate_resolves_the_real_cfg_plus_path_split_used_by_psk_lifecycle() {
        // Genau psk-lifecycles Form (T-SEC-001): zwei `mod process;` unter
        // gegensaetzlichem cfg, beide per #[path] auf eigene Dateien
        // gelenkt. Vor dieser Erweiterung meldete das Werkzeug hier vier
        // Fehler auf voellig korrektem Code.
        let dir = scratch_crate("cfgpath");
        fs::write(
            dir.join("src/lib.rs"),
            "#[cfg(windows)]\n#[path = \"process_windows.rs\"]\nmod process;\n\
             #[cfg(not(windows))]\n#[path = \"process_unsupported.rs\"]\nmod process;\n\
             pub use process::ChildProcess;\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/process_windows.rs"),
            "pub struct ChildProcess;\n",
        )
        .unwrap();
        fs::write(
            dir.join("src/process_unsupported.rs"),
            "pub struct ChildProcess;\n",
        )
        .unwrap();

        let problems = check_crate(&dir);
        assert!(problems.is_empty(), "{problems:#?}");

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_path_attribute_pointing_at_a_missing_file_is_still_flagged() {
        // Die Erweiterung darf die eigentliche Pruefung nicht abstumpfen:
        // ein #[path] ins Leere bleibt ein Fehler.
        let dir = scratch_crate("pathmissing");
        fs::write(
            dir.join("src/lib.rs"),
            "#[path = \"nicht_da.rs\"]\nmod process;\n",
        )
        .unwrap();

        let problems = check_crate(&dir);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(problems[0].contains("nicht_da.rs"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_orphan_file_is_still_flagged_even_when_a_path_module_exists() {
        // Regressionswache: die #[path]-Erweiterung darf nicht dazu fuehren,
        // dass danebenliegende, wirklich unerreichbare Dateien durchrutschen.
        let dir = scratch_crate("pathorphan");
        fs::write(
            dir.join("src/lib.rs"),
            "#[path = \"real.rs\"]\nmod process;\n",
        )
        .unwrap();
        fs::write(dir.join("src/real.rs"), "pub fn f() {}\n").unwrap();
        fs::write(dir.join("src/verwaist.rs"), "pub fn g() {}\n").unwrap();

        let problems = check_crate(&dir);
        assert_eq!(problems.len(), 1, "{problems:#?}");
        assert!(problems[0].contains("verwaist.rs"));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn check_crate_follows_nested_mod_declarations() {
        let dir = scratch_crate("nested");
        fs::create_dir_all(dir.join("src/outer")).unwrap();
        fs::write(dir.join("src/lib.rs"), "mod outer;\n").unwrap();
        fs::write(dir.join("src/outer.rs"), "mod inner;\n").unwrap();
        fs::write(dir.join("src/outer/inner.rs"), "pub fn h() {}\n").unwrap();

        let problems = check_crate(&dir);
        assert!(problems.is_empty(), "{problems:?}");

        fs::remove_dir_all(&dir).ok();
    }
}
