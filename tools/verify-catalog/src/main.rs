//! `verify-catalog`: haelt `conformance_catalog.rs`s Kategorie (c)
//! ("derzeit nicht realisierbar") gegen die Wirklichkeit.
//!
//! Regel: **Fuer jede ID in Kategorie (c) DARF kein gruener Test
//! existieren, der mit dieser ID beschriftet ist.** Findet sich einer,
//! ist der Katalog veraltet - die Stufe schlaegt fehl.
//!
//! ## Anlass
//!
//! Dieselbe Fehlerklasse wie die Objektzahl-Drifts: ein Register, das der
//! Wirklichkeit widerspricht, weil es gepflegt statt geprueft wird. Real
//! eingetreten: T-CONC-001 war gebaut, gruen und committet, stand aber
//! weiter unter (c) mit der Begruendung "Diese Rueckordnung ist noch
//! nicht gebaut". Aufgefallen ist es nur, weil jemand die Zahlen von Hand
//! nachzaehlte.
//!
//! ## Die Matching-Regel, bewusst eng
//!
//! Beschriftung heisst: der TESTFUNKTIONSNAME traegt die ID in
//! Schlangenschreibweise (`T-CONC-001` -> `t_conc_001`), so wie es die
//! 15 bereits bestehenden Katalogtests halten
//! (`t_arch_001_altering_a_register_without_resealing_the_lock_fails_i_a`).
//! Ein Funktionsname ist eine Zusicherung: jemand hat den Test
//! ausdruecklich dieser ID zugeordnet.
//!
//! NICHT als Beleg zaehlt eine blosse Erwaehnung - eine ID im
//! Kommentar ("anders als T-X", "siehe T-Y") oder in einem
//! Zeichenkettenliteral. Der Grund ist derselbe wie bei `verify-modtree`
//! und `#[path]`: eine zu weite Regel macht die Stufe selbst zur Quelle
//! von Falschpositiven, und ein Falschpositiv setzt korrekten Code unter
//! Druck, sich einem unvollstaendigen Pruefer anzupassen. Lieber eine
//! Luecke, die nichts behauptet, als eine Meldung, die nicht stimmt.
//!
//! Ein `#[ignore]`-Test zaehlt ebenfalls nicht: die Regel fragt nach
//! einem GRUENEN Test, und ein uebersprungener belegt nichts.
//!
//! ## Was diese Stufe NICHT prueft (ehrliche Deckungsluecke)
//!
//! Die Gegenrichtung - "jede ID unter (a)/(b) hat auch wirklich einen
//! Test" - prueft sie nicht. Dafuer waere dieselbe Beschriftung in
//! ALLEN Paketen noetig; Kategorie (b) verweist heute teils per Pfad auf
//! Tests, die ihre ID nicht im Namen tragen
//! (z.B. `ratchet_is_monotone_over_repeated_rounds` fuer T-RATCHET-001).
//! Diese Stufe deckt deshalb genau die eine Richtung ab, in der ein
//! veralteter Katalog etwas Falsches BEHAUPTET, nicht die, in der er
//! etwas schuldig bleibt.

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

/// Alle `T-*`-IDs, die im Abschnitt "## (c)" als EINTRAG gefuehrt werden.
///
/// Ein Eintrag beginnt mit "- " und laeuft ueber Fortsetzungszeilen; sein
/// Betreff sind die IDs VOR dem ersten Doppelpunkt. Alles danach ist
/// Begruendungsprosa und zaehlt nicht - dort stehen regelmaessig IDs
/// anderer Kategorien als Vergleich ("anders als z.B. Personas Feldliste
/// bei T-PERSONA-001").
///
/// Diese Enge ist nicht kosmetisch: real beobachtet: eine erste Fassung
/// las den ganzen Abschnitt und hielt dadurch T-PERSONA-001 fuer einen
/// (c)-Eintrag, obwohl es unter (b) gruen gefuehrt ist. Ein so
/// eingesammeltes ID haette die Stufe bei jedem passend benannten Test
/// falsch fehlschlagen lassen - genau das Falschpositiv, gegen das die
/// Regel eng gefasst ist.
fn category_c_ids(catalog: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    let mut inside = false;
    let mut entry: Option<String> = None;

    let flush = |entry: &mut Option<String>, ids: &mut BTreeSet<String>| {
        if let Some(text) = entry.take() {
            let subject = text.split_once(':').map(|(head, _)| head).unwrap_or(&text);
            ids.extend(extract_ids(subject));
        }
    };

    for line in catalog.lines() {
        let Some(doc) = line.strip_prefix("//!") else {
            if inside {
                break; // Modulkopf zu Ende
            }
            continue;
        };
        let doc = doc.trim();
        if doc.starts_with("## ") {
            flush(&mut entry, &mut ids);
            inside = doc.starts_with("## (c)");
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(rest) = doc.strip_prefix("- ") {
            flush(&mut entry, &mut ids);
            entry = Some(rest.to_string());
        } else if let Some(current) = entry.as_mut() {
            current.push(' ');
            current.push_str(doc);
        }
    }
    flush(&mut entry, &mut ids);
    ids
}

/// Findet `T-<BUCHSTABEN>-<ZIFFERN>` in einer Zeile.
fn extract_ids(line: &str) -> Vec<String> {
    let bytes: Vec<char> = line.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i] == 'T' && bytes[i + 1] == '-' {
            let mut j = i + 2;
            let start_alpha = j;
            while j < bytes.len() && (bytes[j].is_ascii_uppercase() || bytes[j].is_ascii_digit()) {
                j += 1;
            }
            if j > start_alpha && j < bytes.len() && bytes[j] == '-' {
                let mid = j;
                j += 1;
                let start_num = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                if j > start_num {
                    let _ = mid;
                    out.push(bytes[i..j].iter().collect::<String>());
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    out
}

/// `T-CONC-001` -> `t_conc_001`.
fn snake(id: &str) -> String {
    id.to_ascii_lowercase().replace('-', "_")
}

fn all_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            all_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Ein gruener, mit `id_snake` beschrifteter Test: eine `fn`-Zeile, deren
/// NAME das Praefix traegt, unmittelbar davor `#[test]` und kein
/// `#[ignore]` in derselben Attributgruppe.
fn labelled_green_test(text: &str, id_snake: &str) -> bool {
    let needle = format!("fn {id_snake}_");
    let lines: Vec<&str> = text.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if !line.contains(&needle) {
            continue;
        }
        let mut has_test = false;
        let mut has_ignore = false;
        // Attributgruppe unmittelbar oberhalb.
        for prev in lines[..i].iter().rev() {
            let t = prev.trim();
            if t.starts_with("#[") {
                if t.starts_with("#[test") {
                    has_test = true;
                }
                if t.starts_with("#[ignore") {
                    has_ignore = true;
                }
                continue;
            }
            if t.starts_with("///") || t.starts_with("//") || t.is_empty() {
                continue;
            }
            break;
        }
        if has_test && !has_ignore {
            return true;
        }
    }
    false
}

fn main() -> ExitCode {
    let root = workspace_root();
    let catalog_path = root.join("packages/psk-conformance/src/conformance_catalog.rs");
    let catalog = fs::read_to_string(&catalog_path).expect("conformance_catalog.rs lesbar");

    let ids = category_c_ids(&catalog);
    if ids.is_empty() {
        eprintln!("verify-catalog: FAIL — Kategorie (c) enthaelt keine einzige ID; Parser oder Katalog ist kaputt.");
        return ExitCode::FAILURE;
    }

    let mut files = Vec::new();
    all_rs_files(&root.join("packages"), &mut files);
    all_rs_files(&root.join("adapters"), &mut files);
    let sources: Vec<String> = files
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok().map(|s| (p, s)))
        .map(|(_, s)| s)
        .collect();

    let mut problems = Vec::new();
    for id in &ids {
        let needle = snake(id);
        if sources.iter().any(|s| labelled_green_test(s, &needle)) {
            problems.push(format!(
                "{id} steht unter Kategorie (c) (\"derzeit nicht realisierbar\"), aber ein gruener \
                 Test `fn {needle}_...` existiert - der Katalog ist veraltet"
            ));
        }
    }

    eprintln!(
        "    Kategorie (c): {} IDs geprueft ({})",
        ids.len(),
        ids.iter().cloned().collect::<Vec<_>>().join(", ")
    );

    if problems.is_empty() {
        eprintln!(
            "verify-catalog: PASS — keine der {} als nicht realisierbar gefuehrten IDs hat einen gruenen, so beschrifteten Test.",
            ids.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("verify-catalog: FAIL —");
        for p in &problems {
            eprintln!("    - {p}");
        }
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ids_finds_real_ids_and_ignores_lookalikes() {
        assert_eq!(extract_ids("- T-CONC-001 (Stress)"), vec!["T-CONC-001"]);
        assert_eq!(
            extract_ids("T-UNKNOWN-001 und T-FIELD-001: beide"),
            vec!["T-UNKNOWN-001", "T-FIELD-001"]
        );
        assert!(extract_ids("kein Treffer hier").is_empty());
        assert!(extract_ids("T-OHNE-NUMMER").is_empty());
    }

    #[test]
    fn snake_matches_the_established_test_naming() {
        assert_eq!(snake("T-CONC-001"), "t_conc_001");
        assert_eq!(snake("T-ARCH-002"), "t_arch_002");
    }

    #[test]
    fn a_labelled_green_test_counts() {
        let src = "    #[test]\n    fn t_conc_001_does_the_thing() {}\n";
        assert!(labelled_green_test(src, "t_conc_001"));
    }

    #[test]
    fn a_mere_mention_in_a_comment_does_not_count() {
        // Genau der Falschpositiv-Fall, gegen den die Regel eng gefasst
        // ist: die ID kommt vor, aber niemand hat einen Test ihr zugeordnet.
        let src =
            "    // anders als T-CONC-001, siehe dort\n    #[test]\n    fn something_else() {}\n";
        assert!(!labelled_green_test(src, "t_conc_001"));
    }

    #[test]
    fn a_string_literal_mention_does_not_count() {
        let src = "    #[test]\n    fn other() { let s = \"t_conc_001\"; }\n";
        assert!(!labelled_green_test(src, "t_conc_001"));
    }

    #[test]
    fn an_ignored_test_does_not_count_as_green() {
        let src = "    #[test]\n    #[ignore = \"offen\"]\n    fn t_conc_001_does_the_thing() {}\n";
        assert!(!labelled_green_test(src, "t_conc_001"));
    }

    #[test]
    fn a_plain_fn_without_the_test_attribute_does_not_count() {
        let src = "    fn t_conc_001_helper() {}\n";
        assert!(!labelled_green_test(src, "t_conc_001"));
    }

    #[test]
    fn a_prose_mention_after_the_colon_is_not_a_category_c_entry() {
        // Der real aufgetretene Falschpositiv-Fall: T-PERSONA-001 steht
        // unter (b) und wird in (c) nur als Vergleich genannt.
        let catalog = "//! ## (c) Derzeit nicht realisierbar\n\
                       //! - T-UNKNOWN-001 (x) und T-FIELD-001 (y): beide\n\
                       //!   anders als z.B. T-PERSONA-001 gefasst.\n\
                       \nfn after() {}\n";
        let ids = category_c_ids(catalog);
        assert!(ids.contains("T-UNKNOWN-001"));
        assert!(ids.contains("T-FIELD-001"));
        assert!(
            !ids.contains("T-PERSONA-001"),
            "eine Erwaehnung in der Begruendung ist kein Eintrag: {ids:?}"
        );
    }

    #[test]
    fn ids_from_other_categories_are_not_collected() {
        let catalog = "//! ## (b) Bereits getestet\n\
                       //! - T-IR-001 (Round-Trip): irgendwo.\n\
                       //! ## (c) Derzeit nicht realisierbar\n\
                       //! - T-PASS-001 (x): Begruendung.\n\
                       \nfn after() {}\n";
        let ids = category_c_ids(catalog);
        assert_eq!(ids.len(), 1, "{ids:?}");
        assert!(ids.contains("T-PASS-001"));
    }

    #[test]
    fn the_real_catalog_yields_a_nonempty_category_c() {
        let root = workspace_root();
        let catalog =
            fs::read_to_string(root.join("packages/psk-conformance/src/conformance_catalog.rs"))
                .unwrap();
        let ids = category_c_ids(&catalog);
        assert!(!ids.is_empty(), "Parser muss (c) finden: {ids:?}");
        assert!(
            ids.contains("T-PASS-001"),
            "T-PASS-001 steht real unter (c): {ids:?}"
        );
    }
}
