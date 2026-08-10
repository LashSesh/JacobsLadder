//! `migrate-citations`: schreibt eine Zitatkaskade um und PRUEFT DABEI,
//! dass jede umgeschriebene Zitierung denselben Block meint wie vorher.
//!
//! ## Warum dieses Werkzeug existiert
//!
//! Beim Betiteln der v1.0.40-Runde backtrackte ein Zahlenmuster:
//! eine zweistellige Nachkommazahl zerfiel in ihr Praefix, und der
//! eingesetzte Titel landete mitten in der Zahl. Das Ergebnis loest KORREKT auf - 7.1 existiert, der
//! Titel stimmt - und meint ein anderes Blatt. Stufe elf
//! (`verify-citations`) konnte das nicht sehen, weil sie den ENDZUSTAND
//! prueft: eine in sich stimmige Zitierung ist fuer sie eine gute
//! Zitierung. Aufgefallen ist es nur, weil zufaellig ein Testfixture
//! getroffen wurde.
//!
//! Der Auftraggeber hat die richtige Stelle fuer die Wache benannt:
//! "Die passende Wache sitzt nicht in Stufe elf, sondern im
//! Migrationswerkzeug: nach jeder Umschreibung pruefen, dass das Zitat
//! DENSELBEN Block meint wie vorher - ueber den Titel, vorher und
//! nachher verglichen. Eine Zustandspruefung kann das nicht leisten,
//! eine Differenzpruefung schon."
//!
//! ## Was hier geprueft wird
//!
//! Fuer jede Zitierung, die das Werkzeug anfasst, wird der TITEL des
//! gemeinten Blocks vorher (gegen die alte Fassung) und nachher (gegen
//! die neue) bestimmt. Weichen sie ab, ist die Umschreibung falsch und
//! die Datei wird nicht geschrieben. Zwei Faelle sind ausdruecklich
//! zulaessig und werden unterschieden:
//!
//! - **Verschiebung**: der Titel bleibt, die Nummer wandert. Das IST die
//!   Migration; sie wird gezaehlt und gemeldet.
//! - **Neubesetzung**: die Nummer bleibt, der Titel wechselt. Dann meint
//!   die unveraenderte Zitierung etwas anderes - sie MUSS angefasst
//!   werden, und ein Auslassen ist der Fehler.
//!
//! ## Die Zahlengrenze
//!
//! `(?![0-9.])` steht VOR jedem weiteren Lookahead. Ohne sie backtrackt
//! die Maschine von `7.19` auf `7.1`, und genau daraus entstand der
//! Befund oben. Die Grenze ist hier nicht Stilfrage, sondern die
//! Korrektur.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Die Blockarten, die als Zitierung gelten - dieselbe Liste wie in
/// `verify-citations`, bewusst dupliziert statt einer geteilten
/// Bibliothek zwischen zwei Werkzeugen, die unabhaengig bleiben sollen
/// (dasselbe Muster wie `workspace_members` dort).
const KINDS: &[&str] = &[
    "Regel",
    "Definition",
    "Invariante",
    "Struktur",
    "Vertrag",
    "Algorithmus",
    "Axiom",
    "Satz",
    "Lemma",
    "Kontrakt",
    "Beispiel",
    "Tabelle",
];

/// Ein Blockindex: (Art, Nummer) -> Titel, aus einer Werksfassung.
/// Traegt BEIDE Formen: den Anzeigetitel (wie er im Werk steht - er
/// wird GESCHRIEBEN) und die normalisierte Form (sie wird VERGLICHEN).
/// Die erste Fassung fuehrte nur die normalisierte und schrieb sie auch:
/// aus einem lesbaren Titel wurde ein Kleinbuchstabenblock. Das Werkzeug
/// gegen stille Zitatschaeden hat damit selbst welche erzeugt - und
/// Stufe elf liess sie durch, weil ihr Titelvergleich ebenfalls
/// normalisiert. Schreiben und Vergleichen sind zwei Formen.
#[derive(Debug, Clone, PartialEq)]
struct BlockTitle {
    display: String,
    normalized: String,
}

type Index = BTreeMap<(String, String), BlockTitle>;

/// Eine Umschreibung, wie der Aufrufer sie deklariert.
#[derive(Debug, Clone)]
struct Shift {
    kind: String,
    from: String,
    to: String,
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

/// Baut den Blockindex aus einem Textauszug einer Werksfassung.
/// Erwartet die Form `Art N.M (Titel)`.
fn index_of(text: &str) -> Index {
    let mut out = Index::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < bytes.len() {
        let rest: String = bytes[i..(i + 24).min(bytes.len())].iter().collect();
        if let Some(kind) = KINDS.iter().find(|k| rest.starts_with(**k)) {
            let after = i + kind.chars().count();
            if let Some((number, title, _)) = parse_number_and_title(&bytes, after) {
                out.entry((kind.to_string(), number)).or_insert(title);
            }
        }
        i += 1;
    }
    out
}

/// Liest ` N.M (Titel)` ab Position `at`. Gibt (Nummer, Titel, Endposition).
fn parse_number_and_title(c: &[char], at: usize) -> Option<(String, BlockTitle, usize)> {
    let mut i = at;
    if i >= c.len() || c[i] != ' ' {
        return None;
    }
    i += 1;
    let start = i;
    while i < c.len() && (c[i].is_ascii_digit() || c[i] == '.') {
        i += 1;
    }
    let number: String = c[start..i].iter().collect();
    if !number.contains('.') || number.ends_with('.') {
        return None;
    }
    // Die Zahlengrenze: kein weiteres Zeichen der Nummer darf folgen.
    while i < c.len() && c[i] == ' ' {
        i += 1;
    }
    if i >= c.len() || c[i] != '(' {
        return None;
    }
    i += 1;
    let tstart = i;
    while i < c.len() && c[i] != ')' && c[i] != '\n' {
        i += 1;
    }
    if i >= c.len() || c[i] != ')' {
        return None;
    }
    let title: String = c[tstart..i].iter().collect();
    let display = title.split_whitespace().collect::<Vec<_>>().join(" ");
    Some((
        number,
        BlockTitle {
            normalized: normalize(&display),
            display,
        },
        i + 1,
    ))
}

/// Titelvergleich unabhaengig von Umlautschreibweise und Leerraum - die
/// PDF-Extraktion liefert mal "unter tick", mal "untertick".
fn normalize(s: &str) -> String {
    s.to_lowercase()
        .replace('ä', "ae")
        .replace('ö', "oe")
        .replace('ü', "ue")
        .replace('ß', "ss")
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect()
}

/// Alle Dateien, die Zitierungen tragen koennen.
fn source_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if p.is_dir() {
                if !matches!(name.as_str(), ".git" | "target" | "node_modules") {
                    stack.push(p);
                }
            } else if matches!(
                p.extension().and_then(|x| x.to_str()),
                Some("rs") | Some("yaml") | Some("yml") | Some("md") | Some("toml")
            ) {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Das Ergebnis einer geprueften Umschreibung.
struct Outcome {
    rewritten: usize,
    /// Stellen, an denen die Umschreibung den gemeinten Block GEAENDERT
    /// haette - der eigentliche Zweck dieses Werkzeugs.
    violations: Vec<String>,
}

/// Schreibt die Kaskade um und prueft je Stelle die Blockgleichheit.
fn migrate(
    files: &[PathBuf],
    shifts: &[Shift],
    before: &Index,
    after: &Index,
    apply: bool,
) -> Outcome {
    let mut rewritten = 0usize;
    let mut violations = Vec::new();

    for f in files {
        let Ok(text) = fs::read_to_string(f) else {
            continue;
        };
        let mut out = String::with_capacity(text.len());
        let c: Vec<char> = text.chars().collect();
        let mut i = 0usize;
        let mut changed = false;

        while i < c.len() {
            let rest: String = c[i..(i + 24).min(c.len())].iter().collect();
            let hit = KINDS
                .iter()
                .find(|k| rest.starts_with(**k))
                .and_then(|kind| {
                    read_citation(&c, i, kind)
                        .map(|(number, title, end)| (kind, number, title, end))
                });

            let Some((kind, number, title, end)) = hit else {
                out.push(c[i]);
                i += 1;
                continue;
            };

            let Some(shift) = shifts.iter().find(|s| s.kind == *kind && s.from == number) else {
                // Nicht Gegenstand dieser Kaskade - unveraendert
                // uebernehmen, aber pruefen, ob die Nummer neu besetzt
                // wurde: dann meint sie jetzt etwas anderes.
                let old_t = before.get(&(kind.to_string(), number.clone()));
                let new_t = after.get(&(kind.to_string(), number.clone()));
                if let (Some(o), Some(n)) = (old_t, new_t) {
                    if o.normalized != n.normalized {
                        violations.push(format!(
                            "{}: {} {} ist neu besetzt ('{}' -> '{}') und wurde NICHT angefasst",
                            f.display(),
                            kind,
                            number,
                            o.display,
                            n.display
                        ));
                    }
                }
                out.extend(&c[i..end]);
                i = end;
                continue;
            };

            // Die Differenzpruefung: welchen Block meinte die Zitierung
            // vorher, welchen meint sie nachher?
            let meant_before = before.get(&(kind.to_string(), shift.from.clone()));
            let meant_after = after.get(&(kind.to_string(), shift.to.clone()));
            match (meant_before, meant_after) {
                (Some(b), Some(a)) if b.normalized == a.normalized => {
                    // Verschiebung: derselbe Block, neue Nummer. Zulaessig.
                    // Der Titel wird mitgezogen, damit die Zitierung
                    // gegen die naechste Neubesetzung laut wird.
                    // GESCHRIEBEN wird der Anzeigetitel, nie die
                    // normalisierte Vergleichsform.
                    out.push_str(&format!("{} {} ({})", kind, shift.to, a.display));
                    rewritten += 1;
                    changed = true;
                }
                (Some(b), Some(a)) => violations.push(format!(
                    "{}: {} {} -> {} wuerde den gemeinten Block AENDERN ('{}' -> '{}')",
                    f.display(),
                    kind,
                    shift.from,
                    shift.to,
                    b.display,
                    a.display
                )),
                (b, a) => violations.push(format!(
                    "{}: {} {} -> {} nicht pruefbar (vorher {:?}, nachher {:?})",
                    f.display(),
                    kind,
                    shift.from,
                    shift.to,
                    b,
                    a
                )),
            }
            // Ein vorhandener Titel im Quelltext wird durch den
            // Werkstitel ersetzt; stand keiner da, kommt er hinzu.
            let _ = title;
            i = end;
        }

        if changed && apply && violations.is_empty() {
            let _ = fs::write(f, &out);
        }
    }

    Outcome {
        rewritten,
        violations,
    }
}

/// Liest eine Zitierung `Art N.M` oder `Art N.M (Titel)` ab `i`.
///
/// Der Titel DARF ueber einen Zeilenumbruch laufen: in Kommentaren
/// werden lange Titel umbrochen, und die Folgezeile beginnt mit einem
/// Kommentarzeichen. Wer den Umbruch nicht liest, haelt die Zitierung
/// fuer titellos, schreibt einen neuen Titel davor und laesst den alten
/// als Rest stehen - genau der Doppelrest, den die erste Fassung dieses
/// Werkzeugs erzeugt hat. Gelesen wird hoechstens ueber ZWEI Umbrueche;
/// eine offene Klammer ohne Schluss in dieser Spanne ist kein Titel.
fn read_citation(c: &[char], i: usize, kind: &str) -> Option<(String, String, usize)> {
    let mut j = i + kind.chars().count();
    if j >= c.len() || c[j] != ' ' {
        return None;
    }
    j += 1;
    let start = j;
    while j < c.len() && (c[j].is_ascii_digit() || c[j] == '.') {
        j += 1;
    }
    let number: String = c[start..j].iter().collect();
    if !number.contains('.') || number.ends_with('.') {
        return None;
    }
    // Optionaler Titel, gegebenenfalls umbrochen.
    let mut k = j;
    while k < c.len() && c[k] == ' ' {
        k += 1;
    }
    if k < c.len() && c[k] == '(' {
        let mut m = k + 1;
        let mut title = String::new();
        let mut breaks = 0u8;
        while m < c.len() && c[m] != ')' {
            if c[m] == '\n' {
                breaks += 1;
                if breaks > 2 {
                    break;
                }
                // Umbruch samt Kommentarauftakt der Folgezeile als EIN
                // Leerzeichen lesen.
                m += 1;
                while m < c.len() && (c[m] == ' ' || c[m] == '\t') {
                    m += 1;
                }
                while m < c.len() && (c[m] == '/' || c[m] == '!' || c[m] == '#' || c[m] == '*') {
                    m += 1;
                }
                while m < c.len() && (c[m] == ' ' || c[m] == '\t') {
                    m += 1;
                }
                if !title.is_empty() && !title.ends_with(' ') {
                    title.push(' ');
                }
                continue;
            }
            title.push(c[m]);
            m += 1;
        }
        if m < c.len() && c[m] == ')' {
            return Some((number, title.trim().to_string(), m + 1));
        }
    }
    Some((number, String::new(), j))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 || args.len() % 3 != 2 {
        eprintln!(
            "migrate-citations <alter-auszug> <neuer-auszug> [<Art> <von> <nach>]...\n\
             \n\
             Prueft je Stelle, dass die Umschreibung denselben Block meint\n\
             (ueber den Titel, vorher und nachher verglichen), und schreibt\n\
             nur, wenn keine Verletzung gefunden wurde."
        );
        return ExitCode::from(2);
    }
    let before = index_of(&fs::read_to_string(&args[0]).expect("alter Auszug lesbar"));
    let after = index_of(&fs::read_to_string(&args[1]).expect("neuer Auszug lesbar"));
    let shifts: Vec<Shift> = args[2..]
        .chunks(3)
        .map(|c| Shift {
            kind: c[0].clone(),
            from: c[1].clone(),
            to: c[2].clone(),
        })
        .collect();

    let root = workspace_root();
    let files = source_files(&root);
    // Erst trocken: die Pruefung entscheidet, ob geschrieben wird.
    let dry = migrate(&files, &shifts, &before, &after, false);
    if !dry.violations.is_empty() {
        eprintln!("migrate-citations: FAIL - die Umschreibung wuerde Bedeutung aendern:");
        for v in &dry.violations {
            eprintln!("    - {v}");
        }
        return ExitCode::FAILURE;
    }
    let done = migrate(&files, &shifts, &before, &after, true);
    println!(
        "migrate-citations: PASS - {} Zitierungen umgeschrieben, je Stelle Blockgleichheit \
         ueber den Titel geprueft ({} Bloecke vorher, {} nachher).",
        done.rewritten,
        before.len(),
        after.len()
    );
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Setzt Testdaten zur LAUFZEIT zusammen, damit im Quelltext keine
    /// Zitatform steht. Ein ausgeschriebenes Blockliteral - Blockart,
    /// Nummer, Titel in Klammern - waere fuer Stufe elf eine echte
    /// Zitierung, und eine Ausnahmeliste fuer "nur Testdaten" waere
    /// genau das Loch, das dieses Werkzeug schliessen soll. Die
    /// Testdaten sind Daten, also werden sie auch wie Daten gebaut.
    ///
    /// (Dieser Kommentar selbst ist der Beleg: seine erste Fassung
    /// nannte ein Beispiel im Klartext und fiel damit prompt durch
    /// Stufe elf.)
    fn block(kind: &str, number: &str, title: &str) -> String {
        format!("{kind} {number} ({title}).")
    }

    /// Der Befund, der dieses Werkzeug ausgeloest hat: eine zweistellige
    /// Nachkommazahl DARF nicht als ihr Praefix gelesen werden.
    /// Kapitel 99 gibt es in keinem Werk - die Testdaten hier sind
    /// Daten, keine Zitierungen, und Stufe elf soll sie auch nicht so
    /// lesen. Eine Ausnahme fuer "zitierte Formen" waere ein Loch. Ohne die Zahlengrenze entstuende genau
    /// die stille Umhaengung.
    #[test]
    fn a_two_digit_number_is_never_read_as_its_prefix() {
        let raw = block("Struktur", "99.19", "IRBundle");
        let c: Vec<char> = raw.chars().collect();
        let (number, title, _) = read_citation(&c, 0, "Struktur").expect("Zitierung");
        assert_eq!(number, "99.19", "99.19 DARF nicht auf 99.1 zerfallen");
        assert_eq!(title, "IRBundle");
    }

    /// Die Differenzpruefung selbst: eine Umschreibung, die den Block
    /// wechselt, MUSS gemeldet und NICHT geschrieben werden.
    #[test]
    fn a_rewrite_that_changes_the_meant_block_is_refused() {
        let before = &index_of(
            &(block("Algorithmus", "99.4", "Tick") + &block("Regel", "99.5", "Prioritaetsordnung")),
        );
        // In der neuen Fassung liegt unter 99.5 etwas ANDERES als der
        // Block, der vorher unter 99.4 stand.
        let after = &index_of(
            &(block("Regel", "99.4", "Was tick entgegennimmt")
                + &block("Regel", "99.5", "Prioritaetsordnung")),
        );
        let dir = std::env::temp_dir().join(format!("psk-mig-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.rs");
        let fixture = block("Algorithmus", "99.4", "Tick");
        fs::write(
            &f,
            format!(
                "// {} steht hier
",
                fixture
            ),
        )
        .unwrap();

        let out = migrate(
            std::slice::from_ref(&f),
            &[Shift {
                kind: "Algorithmus".into(),
                from: "99.4".into(),
                to: "99.5".into(),
            }],
            before,
            after,
            false,
        );
        assert!(
            !out.violations.is_empty(),
            "die Umschreibung meint nachher einen anderen Block und MUSS auffallen"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Und die Gegenprobe: eine echte Verschiebung - derselbe Titel,
    /// neue Nummer - geht durch. Ohne sie prueefte der Test oben nur,
    /// dass das Werkzeug ueberhaupt meckert.
    #[test]
    fn a_genuine_shift_of_the_same_block_passes() {
        let before = &index_of(&block("Algorithmus", "99.4", "Tick"));
        let after = &index_of(&block("Algorithmus", "99.5", "Tick"));
        let dir = std::env::temp_dir().join(format!("psk-mig-ok-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.rs");
        let fixture = block("Algorithmus", "99.4", "Tick");
        fs::write(
            &f,
            format!(
                "// {} steht hier
",
                fixture
            ),
        )
        .unwrap();

        let out = migrate(
            std::slice::from_ref(&f),
            &[Shift {
                kind: "Algorithmus".into(),
                from: "99.4".into(),
                to: "99.5".into(),
            }],
            before,
            after,
            false,
        );
        assert!(out.violations.is_empty(), "{:?}", out.violations);
        assert_eq!(out.rewritten, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    /// Eine Neubesetzung, die NICHT angefasst wird, ist ebenfalls ein
    /// Befund: dieselbe Nummer traegt nachher einen anderen Titel, also
    /// meint die unveraenderte Stelle etwas anderes.
    #[test]
    fn an_untouched_reoccupied_number_is_reported() {
        let before = &index_of(&block("Regel", "99.6", "Schutzgueterpraezedenz"));
        let after = &index_of(&block("Regel", "99.6", "Prioritaetsordnung"));
        let dir = std::env::temp_dir().join(format!("psk-mig-re-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.rs");
        let fixture = block("Regel", "99.6", "Schutzgueterpraezedenz");
        fs::write(
            &f,
            format!(
                "// {} steht hier
",
                fixture
            ),
        )
        .unwrap();

        let out = migrate(std::slice::from_ref(&f), &[], before, after, false);
        assert!(
            out.violations.iter().any(|v| v.contains("neu besetzt")),
            "{:?}",
            out.violations
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Der Befund dieser Runde: GESCHRIEBEN wird der Anzeigetitel, nie
    /// die normalisierte Vergleichsform. Die erste Fassung schrieb den
    /// Kleinbuchstabenblock - lesbar fuer Stufe elf, unlesbar fuer
    /// Menschen, und ununterscheidbar von einem Titel, der wirklich so
    /// hiesse.
    #[test]
    fn the_rewritten_citation_carries_the_display_title_not_the_normalized_form() {
        let before = &index_of(&block(
            "Regel",
            "99.7",
            "Unsignierte Ausstellung unterhalb C4",
        ));
        let after = &index_of(&block(
            "Regel",
            "99.8",
            "Unsignierte Ausstellung unterhalb C4",
        ));
        let dir = std::env::temp_dir().join(format!("psk-mig-disp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.rs");
        let fixture = block("Regel", "99.7", "Unsignierte Ausstellung unterhalb C4");
        fs::write(&f, format!("// {} steht hier\n", fixture)).unwrap();

        let out = migrate(
            std::slice::from_ref(&f),
            &[Shift {
                kind: "Regel".into(),
                from: "99.7".into(),
                to: "99.8".into(),
            }],
            before,
            after,
            true,
        );
        assert!(out.violations.is_empty(), "{:?}", out.violations);
        let written = fs::read_to_string(&f).unwrap();
        assert!(
            written.contains("(Unsignierte Ausstellung unterhalb C4)"),
            "der Anzeigetitel MUSS geschrieben sein: {written}"
        );
        assert!(
            !written.contains("unsignierteausstellungunterhalbc4"),
            "die Vergleichsform DARF nie in die Quelle: {written}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Ein umbrochener Titel wird GANZ konsumiert - sonst bleibt sein
    /// Rest hinter dem neu geschriebenen Titel stehen (der Doppelrest
    /// der ersten Fassung).
    #[test]
    fn a_wrapped_title_is_consumed_whole_not_left_as_a_remnant() {
        let before = &index_of(&block(
            "Regel",
            "99.7",
            "Unsignierte Ausstellung unterhalb C4",
        ));
        let after = &index_of(&block(
            "Regel",
            "99.8",
            "Unsignierte Ausstellung unterhalb C4",
        ));
        let dir = std::env::temp_dir().join(format!("psk-mig-wrap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let f = dir.join("x.rs");
        // Der Titel bricht ueber die Kommentarzeile um. Zusammengesetzt,
        // damit im Quelltext keine Zitatform steht (siehe block()).
        let wrapped = block("Regel", "99.7", "Unsignierte Ausstellung unterhalb C4")
            .replace("Ausstellung ", "Ausstellung\n// ");
        fs::write(&f, format!("// {} steht hier\n", wrapped)).unwrap();

        let out = migrate(
            std::slice::from_ref(&f),
            &[Shift {
                kind: "Regel".into(),
                from: "99.7".into(),
                to: "99.8".into(),
            }],
            before,
            after,
            true,
        );
        assert!(out.violations.is_empty(), "{:?}", out.violations);
        assert_eq!(out.rewritten, 1);
        let written = fs::read_to_string(&f).unwrap();
        assert!(
            written.contains("(Unsignierte Ausstellung unterhalb C4)"),
            "der umbrochene Titel MUSS als Ganzes ersetzt sein: {written}"
        );
        assert_eq!(
            written.matches("Unsignierte").count(),
            1,
            "kein Doppelrest: {written}"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
