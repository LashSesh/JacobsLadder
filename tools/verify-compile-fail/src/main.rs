//! `verify-compile-fail`: uebersetzt jeden `compile_fail`-Doctest gegen
//! ein echtes Pruefpaket und verlangt den ERWARTETEN Fehlercode in
//! stderr.
//!
//! ## Anlass
//!
//! Mehrere Schranken dieses Baums sind Typschranken statt
//! Laufzeitpruefungen - `GateAuthorization`, `CanonicalBytes`,
//! `NullAnchor`, `PrivateJustification`. Jede ist mit einem
//! `compile_fail`-Doctest festgehalten, und jeder dieser Doctests traegt
//! den Fehlercode, der den GRUND benennt.
//!
//! GEMESSEN (L3-Runde): **rustdoc erzwingt den Code nicht.** Ein
//! Doctest mit `compile_fail,E0451`, dessen tatsaechlicher Fehler E0308
//! war, lief gruen durch - ohne Warnung. Damit war der Code ein
//! einmaliges Messprotokoll und keine laufende Wache: ein Umbau, der
//! aendert, WARUM etwas nicht kompiliert, laesst den Doctest gruen, und
//! der Nachweis bedeutet danach etwas anderes, ohne dass es jemand
//! erfaehrt.
//!
//! Dieses Werkzeug schliesst die Luecke. Es tut fortlaufend, was bisher
//! von Hand gemessen wurde: den Beispielcode in ein Pruefpaket setzen,
//! uebersetzen, und im stderr `error[EXXXX]` mit genau dem erwarteten
//! Code verlangen.
//!
//! ## Warum `rustc` und nicht `cargo`
//!
//! Ein Cargo-Projekt je Fall waere korrekt und langsam. Stattdessen
//! ruft dieses Werkzeug `rustc` direkt gegen die bereits gebauten
//! `.rlib`s aus `target/debug/deps` - dieselbe Uebersetzung, ohne
//! Projektgeruest. Das setzt einen vorherigen `cargo build` voraus, und
//! genau darauf laeuft es hinaus: das Werkzeug baut nicht, es prueft.
//!
//! ## Codelose Faelle
//!
//! Ein `compile_fail` ohne Code ist schon gruen, wenn IRGENDETWAS nicht
//! uebersetzt - ein Tippfehler im Beispiel bewiese dann nichts. Solche
//! Faelle sind hier gezaehlt und gegen eine Obergrenze gefuehrt, die nur
//! SINKEN darf: dasselbe Ratchetmuster wie bei den titellosen
//! Zitierungen. Wer eine Datei anfasst, misst den Code nach.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

/// Obergrenze fuer `compile_fail`-Faelle OHNE Fehlercode. Darf nur
/// sinken - siehe Modulkopf.
///
/// Stand bei Einfuehrung: DREI, alle in `psk-thought/src/forecast.rs`.
/// Ihr Code ist nicht eingetragen, weil dieser Pruefaufbau ihn hier
/// nicht sauber messen kann - siehe [`all_rlibs`], Abschnitt "Grenze
/// des Aufbaus". Die uebrigen sechs zuvor codelosen Faelle sind in
/// derselben Runde gemessen und eingetragen worden (E0639, E0277,
/// E0560, dreimal E0599).
const UNCODED_CEILING: usize = 3;

#[derive(Debug)]
struct Case {
    file: PathBuf,
    line: usize,
    package: String,
    expected: Option<String>,
    code: String,
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

/// Das Paket, zu dem eine Datei gehoert: `packages/<name>/src/...`.
fn package_of(root: &Path, file: &Path) -> Option<String> {
    let rel = file.strip_prefix(root).ok()?;
    let mut parts = rel.components();
    if parts.next()?.as_os_str() != "packages" {
        return None;
    }
    Some(parts.next()?.as_os_str().to_string_lossy().to_string())
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().map(|n| n == "target").unwrap_or(false) {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().map(|x| x == "rs").unwrap_or(false) {
            out.push(p);
        }
    }
}

/// Liest die `compile_fail`-Bloecke einer Datei.
///
/// Ein Block beginnt mit einer Doc-Zeile, die ```` ```compile_fail ````
/// enthaelt, und endet an der naechsten Doc-Zeile mit ```` ``` ````. Die
/// Zeilen dazwischen sind der Beispielcode, ohne ihr Doc-Praefix.
fn cases_in(root: &Path, file: &Path) -> Vec<Case> {
    let Ok(text) = fs::read_to_string(file) else {
        return Vec::new();
    };
    let Some(package) = package_of(root, file) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0usize;
    while i < lines.len() {
        let trimmed = lines[i].trim_start();
        let Some(rest) = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//!"))
        else {
            i += 1;
            continue;
        };
        let rest = rest.trim();
        if !rest.starts_with("```compile_fail") {
            i += 1;
            continue;
        }
        let expected = rest
            .strip_prefix("```compile_fail")
            .and_then(|s| s.strip_prefix(','))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let start = i;
        let mut code = String::new();
        i += 1;
        while i < lines.len() {
            let t = lines[i].trim_start();
            let Some(body) = t.strip_prefix("///").or_else(|| t.strip_prefix("//!")) else {
                break;
            };
            if body.trim() == "```" {
                break;
            }
            let line = body.strip_prefix(' ').unwrap_or(body);
            // Versteckte Doctestzeilen: rustdoc entfernt bei `# ` (und
            // bei einem alleinstehenden `#`) das Praefix und uebersetzt
            // den Rest. Ein Pruefaufbau, der es stehen liesse, erzeugte
            // einen Syntaxfehler statt der gemeinten Schranke - GEMESSEN
            // an drei Doctests in psk-thought, die daraufhin "kein Code"
            // meldeten.
            //
            // `#[` und `#!` sind dagegen echter Code (Attribute) und
            // bleiben unangetastet.
            let line = if line == "#" {
                ""
            } else if let Some(rest) = line.strip_prefix("# ") {
                rest
            } else {
                line
            };
            code.push_str(line);
            code.push('\n');
            i += 1;
        }
        out.push(Case {
            file: file.to_path_buf(),
            line: start + 1,
            package: package.clone(),
            expected,
            code,
        });
        i += 1;
    }
    out
}

/// Sammelt ALLE gebauten `.rlib`s aus `target/debug/deps`, je Cratename
/// die juengste.
///
/// Nicht nur die des eigenen Pakets: rustdoc stellt einem Doctest die
/// ganze Abhaengigkeitsmenge seines Pakets zur Verfuegung, und ein
/// Pruefaufbau, der weniger verlinkt, misst seinen eigenen Mangel
/// statt der Schranke.
///
/// GEMESSEN, und darum steht es hier: die erste Fassung dieses
/// Werkzeugs verlinkte nur das eigene Paket. Drei Doctests meldeten
/// daraufhin E0433 ("failed to resolve") - sie nennen `psk_types` und
/// `serde`. Haette ich diese Codes ungeprueft als "gemessen"
/// eingetragen, stuende jetzt in drei Modulen ein Fehlercode, der eine
/// fehlende Verlinkung dokumentiert statt einer Typschranke.
///
/// ## Grenze des Aufbaus
///
/// "Je Cratename die juengste" ist eine Naeherung. `target/debug/deps`
/// enthaelt mehrere `.rlib`s desselben Crates (gemessen: fuenf fuer
/// `psk_types`), und welche davon ein bestimmtes Paket beim Bau
/// verwendet hat, steht hier nicht. Trifft die Auswahl daneben, sind
/// zwei gleichnamige Typen aus verschiedenen `.rlib`s verschieden, und
/// der Fall meldet E0308 statt seiner Schranke.
///
/// GEMESSEN an den drei Doctests in `psk-thought/src/forecast.rs`: sie
/// melden hier vier E0308 auf Feldern, die im Quelltext korrekt
/// besetzt sind. Diese drei tragen deshalb KEINEN Code und stehen unter
/// [`UNCODED_CEILING`] - ein gemessenes Artefakt einzutragen waere
/// schlimmer als die Luecke offen zu lassen. Die saubere Loesung waere,
/// die tatsaechliche Abhaengigkeitsmenge je Paket von Cargo zu erfragen
/// (`--message-format=json`); sie ist nicht Teil dieser Runde.
fn all_rlibs(root: &Path) -> BTreeMap<String, PathBuf> {
    let deps = root.join("target").join("debug").join("deps");
    let mut best: BTreeMap<String, (std::time::SystemTime, PathBuf)> = BTreeMap::new();
    let Ok(entries) = fs::read_dir(deps) else {
        return BTreeMap::new();
    };
    for e in entries.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().map(|n| n.to_string_lossy().to_string()) else {
            continue;
        };
        let Some(stem) = name
            .strip_prefix("lib")
            .and_then(|s| s.strip_suffix(".rlib"))
        else {
            continue;
        };
        // `libpsk_types-1a2b3c.rlib` -> `psk_types`
        let Some((crate_name, _hash)) = stem.rsplit_once('-') else {
            continue;
        };
        let Ok(t) = e.metadata().and_then(|m| m.modified()) else {
            continue;
        };
        let entry = best.entry(crate_name.to_string()).or_insert((t, p.clone()));
        if t > entry.0 {
            *entry = (t, p);
        }
    }
    best.into_iter().map(|(k, (_, p))| (k, p)).collect()
}

/// Uebersetzt einen Fall und gibt den stderr zurueck.
fn compile(
    root: &Path,
    case: &Case,
    scratch: &Path,
    rlibs: &BTreeMap<String, PathBuf>,
) -> Result<String, String> {
    let own = case.package.replace('-', "_");
    if !rlibs.contains_key(&own) {
        return Err(format!(
            "keine .rlib fuer {} in target/debug/deps - vorher `cargo build` laufen lassen",
            case.package
        ));
    }
    let src = scratch.join("fall.rs");
    // Ein Doctest ohne `fn main` bekommt von rustdoc eines umgelegt;
    // hier ebenso, damit derselbe Code denselben Fehler erzeugt.
    let body = if case.code.contains("fn main") {
        case.code.clone()
    } else {
        format!("fn main() {{\n{}\n}}\n", case.code)
    };
    fs::write(&src, body).map_err(|e| format!("{}: {e}", src.display()))?;

    let mut cmd = Command::new("rustc");
    cmd.arg("--edition")
        .arg("2021")
        .arg("--crate-type")
        .arg("bin")
        .arg("--emit")
        .arg("metadata")
        .arg("-L")
        .arg(root.join("target").join("debug").join("deps"));
    for (name, path) in rlibs {
        cmd.arg("--extern")
            .arg(format!("{name}={}", path.display()));
    }
    let out = cmd
        .arg("-o")
        .arg(scratch.join("fall.meta"))
        .arg(&src)
        .output()
        .map_err(|e| format!("rustc nicht startbar: {e}"))?;

    Ok(String::from_utf8_lossy(&out.stderr).to_string())
}

fn main() -> ExitCode {
    let root = workspace_root();
    let mut files = Vec::new();
    rust_files(&root.join("packages"), &mut files);
    files.sort();

    let mut cases: Vec<Case> = Vec::new();
    for f in &files {
        cases.extend(cases_in(&root, f));
    }

    let scratch = std::env::temp_dir().join(format!("psk-compile-fail-{}", std::process::id()));
    let _ = fs::remove_dir_all(&scratch);
    if let Err(e) = fs::create_dir_all(&scratch) {
        eprintln!("verify-compile-fail: FAIL - kein Arbeitsverzeichnis: {e}");
        return ExitCode::FAILURE;
    }

    let mut problems: Vec<String> = Vec::new();
    let mut checked = 0usize;
    let mut uncoded: Vec<String> = Vec::new();
    let mut per_package: BTreeMap<String, usize> = BTreeMap::new();
    let rlibs = all_rlibs(&root);

    for case in &cases {
        let where_ = format!("{}:{}", case.file.display(), case.line);
        let Some(expected) = case.expected.as_deref() else {
            uncoded.push(where_);
            continue;
        };
        let stderr = match compile(&root, case, &scratch, &rlibs) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("{where_}: {e}"));
                continue;
            }
        };
        // Der Fall MUSS scheitern - sonst ist der `compile_fail` selbst
        // falsch, und rustdoc haette es gemeldet. Hier zaehlt trotzdem:
        // ein Beispiel, das uebersetzt, hat keinen Fehlercode.
        if !stderr.contains("error") {
            problems.push(format!(
                "{where_}: uebersetzt OHNE Fehler - der `compile_fail` behauptet eine Schranke, \
                 die es nicht gibt"
            ));
            continue;
        }
        let marker = format!("error[{expected}]");
        if !stderr.contains(&marker) {
            let tatsaechlich: Vec<String> = stderr
                .lines()
                .filter_map(|l| {
                    let s = l.trim_start();
                    s.strip_prefix("error[")
                        .and_then(|r| r.split(']').next())
                        .map(|c| format!("E-{c}").replace("E-E", "E"))
                })
                .collect();
            problems.push(format!(
                "{where_}: erwartet {expected}, tatsaechlich {} - der Nachweis faellt aus einem \
                 ANDEREN Grund als dem benannten",
                if tatsaechlich.is_empty() {
                    "kein Code".to_string()
                } else {
                    tatsaechlich.join(", ")
                }
            ));
            continue;
        }
        checked += 1;
        *per_package.entry(case.package.clone()).or_default() += 1;
    }

    let _ = fs::remove_dir_all(&scratch);

    for (pkg, n) in &per_package {
        eprintln!("    {pkg}: {n} Faelle, Code bestaetigt");
    }
    if !uncoded.is_empty() {
        eprintln!(
            "    ohne Fehlercode: {} (Obergrenze {UNCODED_CEILING})",
            uncoded.len()
        );
        for u in &uncoded {
            eprintln!("      - {u}");
        }
    }

    if uncoded.len() > UNCODED_CEILING {
        problems.push(format!(
            "{} `compile_fail`-Faelle ohne Fehlercode, Obergrenze {UNCODED_CEILING} - ein Fall \
             ohne Code ist gruen, sobald IRGENDETWAS nicht uebersetzt. Die Grenze darf nur sinken.",
            uncoded.len()
        ));
    }

    if problems.is_empty() {
        eprintln!(
            "verify-compile-fail: PASS - {checked} Faelle uebersetzt, jeder mit dem erwarteten \
             Fehlercode in stderr."
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("verify-compile-fail: FAIL -");
        for p in &problems {
            eprintln!("    - {p}");
        }
        ExitCode::FAILURE
    }
}
