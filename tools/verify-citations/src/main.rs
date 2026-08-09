//! `verify-citations` - elfte Gatestufe: jede Zitierung eines normativen
//! Blocks im Code MUSS gegen die aktuelle Fassung aufloesbar sein.
//!
//! ## Anlass
//!
//! Regel "Zitierform normativer Bloecke" (v1.0.28): Titel sind der
//! Bezeichner, Nummern sind Bequemlichkeit, und eine genannte Nummer MUSS
//! maschinell gegen die aktuelle Fassung geprueft werden. Der Fall, den
//! diese Stufe verhindert, ist eingetreten: v1.0.20 verschob mit einer
//! Einfuegung ganz Kapitel 7 ab 7.39, die Kaskade wurde nicht propagiert,
//! und der Code zitierte SECHS EDITIONEN lang v1.0.19-Staende - darunter
//! zwei, die zusaetzlich in der ART falsch waren (Axiom fuer eine Regel,
//! Struktur fuer ein Feld). Diese Stufe haette den Fehler bei der ersten
//! betroffenen Edition gefunden.
//!
//! ## Mehrere Normdokumente, benannte Raeume
//!
//! Indiziert werden alle normativen Quellen, jede in ihrem eigenen
//! NAMENSRAUM: die aktuelle PSK-RA-Fassung (PDF, hoechste Versionsnummer
//! im Wurzelverzeichnis), der konstitutionelle Maschinenvertrag
//! (Markdown) und - sobald vorhanden - die QPM/NRAII-Zweitschicht.
//!
//! Die Nummernraeume UEBERSCHNEIDEN sich: `Definition 15.1` ist in PSK-RA
//! die Instruktionsmenge und in QPM/NRAII das Lokale Vierfachprimitiv.
//! Wie VIELE solche Kollisionen es gibt, steht bewusst nicht hier: die
//! Zahl haengt an zwei unabhaengig fortgeschriebenen Werken und war nach
//! einer einzigen Einfuegung in QPM-Kapitel 2 bereits falsch (18 gegen
//! v1.0.32/QPM v1.0.0, 16 gegen v1.0.33/QPM v1.0.1, ohne dass PSK-RA
//! einen Block bewegt haette). Der Lauf misst sie stattdessen und nennt
//! sie in der Berichtszeile. Eine
//! Aufloesung gegen "irgendeine Quelle" wuerde eine QPM-Nummer gegen
//! einen gleichnummerierten PSK-RA-Block durchwinken - der Titelvergleich
//! faengt das nur bei den Zitaten MIT Titel, die uebrigen liefen blind
//! durch. Deshalb benennt das Zitat seinen Raum:
//!
//!   `Struktur 7.38`            -> PSK-RA (implizit, ohne Praefix)
//!   `QPM Struktur 1.2`         -> QPM/NRAII-RA
//!   `CPSK Definition 7.1`      -> Maschinenvertrag
//!
//! Ohne Praefix gilt PSK-RA. Das haelt die bestehenden Zitate gueltig,
//! ohne Migration, und macht das Praefix fuer alles andere zur Pflicht.
//! Ein UNBEKANNTES Praefix ist ein Fehler, kein stiller Standardfall:
//! sonst waere ein Tippfehler im Raumnamen von "meint PSK-RA" nicht zu
//! unterscheiden.
//!
//! ## Was geprueft wird
//!
//! 1. Aufloesbarkeit: `<Art> <N.M>` existiert in einer Quelle.
//! 2. Titeltreue: steht auf derselben Zeile `<Art> <N.M> (<Titel...>`,
//!    MUSS der Titel dem der Quelle entsprechen (normalisiert:
//!    Umlautschreibweisen, Gross/Klein, Leerraum).
//!
//! Nullbefund ueber nichtleerer Arbeitsliste ist Fehlschlag: findet der
//! Scanner in einem Repo dieser Groesse keine einzige Zitierung, ist der
//! Scanner kaputt, nicht das Repo sauber.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Die deklarierten Namensraeume. Ein Praefix, das hier nicht steht, ist
/// ein Fehler - siehe Modulkopf.
const NAMESPACES: [&str; 2] = ["QPM", "CPSK"];

const KINDS: [&str; 8] = [
    "Struktur",
    "Regel",
    "Vertrag",
    "Axiom",
    "Invariante",
    "Definition",
    "Algorithmus",
    "Schnittstelle",
];

/// Normalisiert fuer den Titelvergleich: Kleinbuchstaben, Umlaute in
/// ASCII-Schreibweise, Leerraum kollabiert. Der Code schreibt
/// "Zulaessige", das PDF "Zulässige" - beides ist derselbe Titel.
fn normalize(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            'ä' | 'Ä' => out.push_str("ae"),
            'ö' | 'Ö' => out.push_str("oe"),
            'ü' | 'Ü' => out.push_str("ue"),
            'ß' => out.push_str("ss"),
            // Leerraum faellt GANZ weg: die PDF-Extraktion verliert
            // Leerzeichen unvorhersehbar ("untershadow"), also ist nur
            // der leerraumfreie Vergleich extraktionsfest.
            c if c.is_whitespace() => {}
            // Anfuehrungszeichen sind Zitatform, kein Titelinhalt.
            '"' | '„' | '“' | '”' | '\'' => {}
            c => out.extend(c.to_lowercase()),
        }
    }
    out
}

/// Der Blockindex einer Quelle: (Art, Nummer) -> normalisierter Titel.
type BlockIndex = BTreeMap<(String, String), String>;

/// Indiziert einen Quelltext. Blockmuster: `<Art> <N.M> (<Titel>)`,
/// tolerant gegen die Leerraumverluste der PDF-Extraktion
/// ("RegelWas eine..." kommt vor; zwischen Art und Nummer steht aber in
/// beiden Extraktoren zuverlaessig Leerraum).
fn index_source(text: &str) -> BlockIndex {
    let mut idx = BlockIndex::new();
    let bytes = text.as_bytes();
    for kind in KINDS {
        let mut from = 0;
        while let Some(pos) = text[from..].find(kind) {
            let start = from + pos;
            from = start + kind.len();
            let rest = &text[start + kind.len()..];
            // Nummer, mit oder ohne Leerraum davor: die PDF-Extraktion
            // verliert Leerzeichen ("Struktur22.5" kommt vor). Die
            // Wortgrenze VOR der Art unten verhindert Fehltreffer wie
            // "Unterstruktur".
            let rest_trim = rest.trim_start();
            let num: String = rest_trim
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if !num.contains('.') || num.ends_with('.') || num.starts_with('.') {
                continue;
            }
            // Wortgrenze vor der Art (kein "Unterstruktur" o.ae.).
            if start > 0 {
                let prev = bytes[start - 1] as char;
                if prev.is_alphanumeric() {
                    continue;
                }
            }
            let after_num = &rest_trim[num.len()..];
            let after_trim = after_num.trim_start();
            if !after_trim.starts_with('(') {
                continue;
            }
            let title: String = after_trim[1..].chars().take_while(|c| *c != ')').collect();
            // Kurztitel wie "(C3)" sind echte Titel - nur Leeres und
            // Ueberlanges faellt heraus.
            if title.is_empty() || title.len() > 90 {
                continue;
            }
            idx.entry((kind.to_string(), num))
                .or_insert_with(|| normalize(&title));
        }
    }
    idx
}

/// Findet die aktuelle PSK-RA-PDF im Wurzelverzeichnis (hoechste
/// Version; die historischen v1.0.1-v1.0.13 bleiben liegen, die Politik
/// "nur die aktuelle Fassung" gilt ab v1.0.14).
fn current_edition_pdf(root: &Path) -> Option<PathBuf> {
    let mut best: Option<(u32, PathBuf)> = None;
    for entry in std::fs::read_dir(root).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix("PSK_Referenzarchitektur_v1.0.") else {
            continue;
        };
        let Some(minor) = rest.strip_suffix(".pdf") else {
            continue;
        };
        let Ok(m) = minor.parse::<u32>() else {
            continue;
        };
        if best.as_ref().map(|(b, _)| m > *b).unwrap_or(true) {
            best = Some((m, entry.path()));
        }
    }
    best.map(|(_, p)| p)
}

struct Citation {
    file: String,
    line: usize,
    /// Der benannte Raum: `None` heisst PSK-RA (Standardfall ohne
    /// Praefix), `Some("QPM")` bzw. `Some("CPSK")` heisst genau dieses
    /// Werk. `Some(unbekannt)` kommt bis zur Pruefung mit und wird dort
    /// zum Fehler.
    namespace: Option<String>,
    kind: String,
    number: String,
    /// Titel auf derselben Zeile, falls vorhanden.
    inline_title: Option<String>,
}

/// Sammelt alle Zitierungen aus .rs/.yaml unter den gegebenen Wurzeln.
/// Auch zeilenumbrochene ("... Regel\n//! 7.47 ...") und possessive
/// ("Regel 7.47s") Formen - beide sind real vorgekommen.
fn scan_citations(roots: &[&Path]) -> Vec<Citation> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = roots.iter().map(|r| r.to_path_buf()).collect();
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                if p.file_name().map(|n| n == "target").unwrap_or(false) {
                    continue;
                }
                stack.push(p);
                continue;
            }
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if ext != "rs" && ext != "yaml" {
                continue;
            }
            // Der Pruefer prueft sich nicht selbst: seine Testkorpora und
            // Beispielzitate SIND absichtlich veraltete Nummern (sie
            // testen genau deren Erkennung) und wuerden als Befund
            // erscheinen.
            if p.components().any(|c| c.as_os_str() == "verify-citations") {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let lines: Vec<&str> = text.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                for kind in KINDS {
                    let mut from = 0;
                    while let Some(pos) = line[from..].find(kind) {
                        let start = from + pos;
                        from = start + kind.len();
                        // Was unmittelbar VOR der Art steht, entscheidet
                        // ueber Wortgrenze und Namensraum in einem Zug.
                        let before = &line[..start];
                        let trimmed_before = before.trim_end();
                        let namespace = NAMESPACES
                            .iter()
                            .find(|ns| trimmed_before.ends_with(*ns))
                            .map(|ns| ns.to_string())
                            .or_else(|| {
                                // Ein grossgeschriebenes Wort direkt vor der
                                // Art, das KEIN bekannter Raum ist: als
                                // Praefixversuch mitnehmen, damit die
                                // Pruefung ihn melden kann. Nur wenn es
                                // wirklich wie ein Raumname aussieht
                                // (Grossbuchstaben/Ziffern, 2..=8 Zeichen)
                                // - sonst ist es normaler Fliesstext.
                                let word =
                                    trimmed_before.rsplit(|c: char| c.is_whitespace()).next()?;
                                let looks_like_ns = word.len() >= 2
                                    && word.len() <= 8
                                    && word.chars().all(|c| {
                                        c.is_ascii_uppercase() || c.is_ascii_digit() || c == '-'
                                    });
                                if looks_like_ns && trimmed_before.len() < before.len() {
                                    Some(word.to_string())
                                } else {
                                    None
                                }
                            });
                        // Wortgrenze: unmittelbar anschliessende
                        // Buchstaben/Ziffern ohne Leerraum sind kein Zitat
                        // ("Unterstruktur"), ein Praefix mit Leerraum schon.
                        if namespace.is_none()
                            && before
                                .chars()
                                .next_back()
                                .map(|c| c.is_alphanumeric())
                                .unwrap_or(false)
                        {
                            continue;
                        }
                        let rest = &line[start + kind.len()..];
                        // Inline: "<Art> <N.M>..."
                        let (num, tail) = read_number(rest);
                        let (num, tail) = if num.is_some() {
                            (num, tail)
                        } else if rest.trim_start().is_empty() {
                            // Zeilenumbrochen: Nummer am Anfang der
                            // Folgezeile, hinter Kommentarpraefix.
                            match lines.get(i + 1) {
                                Some(next) => {
                                    let stripped = next
                                        .trim_start()
                                        .trim_start_matches("//!")
                                        .trim_start_matches("//")
                                        .trim_start_matches('#')
                                        .trim_start();
                                    let (n, _) = read_number(&format!(" {stripped}"));
                                    (n, "")
                                }
                                None => (None, ""),
                            }
                        } else {
                            (None, "")
                        };
                        let Some(number) = num else { continue };
                        // Titelanspruch nur, wenn die Klammer auf
                        // DERSELBEN Zeile schliesst und ihr Inhalt wie
                        // ein Titel aussieht. Klammern mit Editions-,
                        // Verweis- oder Codekontext ("(PSK-RA v...",
                        // "(siehe ...", "(Kapitel ...", "(v1.0...") sind
                        // Kontextangaben, keine Titelbehauptungen.
                        let inline_title = tail
                            .trim_start()
                            .strip_prefix('(')
                            .filter(|t| t.contains(')'))
                            .map(|t| t.chars().take_while(|c| *c != ')').collect::<String>())
                            .filter(|t| t.len() >= 3)
                            .filter(|t| {
                                let low = t.trim().to_lowercase();
                                !(low.starts_with("psk-ra")
                                    || low.starts_with("v1.")
                                    || low.starts_with("siehe")
                                    || low.starts_with("kapitel")
                                    || low.contains('#')
                                    || low.contains('`'))
                            });
                        out.push(Citation {
                            file: p.display().to_string(),
                            line: i + 1,
                            namespace,
                            kind: kind.to_string(),
                            number,
                            inline_title,
                        });
                    }
                }
            }
        }
    }
    out
}

/// Liest `<ws>+<N.M>[s]` vom Zeilenrest; gibt (Nummer, Rest danach).
fn read_number(rest: &str) -> (Option<String>, &str) {
    let trimmed = rest.trim_start();
    if trimmed.len() == rest.len() && !rest.is_empty() {
        return (None, rest); // kein Leerraum -> keine Zitierung
    }
    let num: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    if !num.contains('.') || num.ends_with('.') || num.starts_with('.') {
        return (None, rest);
    }
    let mut after = &trimmed[num.len()..];
    // Possessiv: "Regel 7.49s Gegenstand".
    if let Some(stripped) = after.strip_prefix('s') {
        after = stripped;
    }
    (Some(num), after)
}

fn main() -> ExitCode {
    let root = {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
        dir
    };

    // ---- Quellen indizieren.
    let Some(pdf) = current_edition_pdf(&root) else {
        eprintln!("verify-citations: FAIL — keine aktuelle PSK-RA-PDF im Wurzelverzeichnis.");
        return ExitCode::FAILURE;
    };
    let ra_text = match pdf_extract::extract_text(&pdf) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "verify-citations: FAIL — PDF-Extraktion scheiterte ({}): {e}",
                pdf.display()
            );
            return ExitCode::FAILURE;
        }
    };
    let ra_index = index_source(&ra_text);
    let cpsk_text =
        std::fs::read_to_string(root.join("CPSK_Konstitutioneller_Maschinenvertrag.md"))
            .unwrap_or_default();
    let cpsk_index = index_source(&cpsk_text);

    // Die Zweitschicht, sobald sie im Repo liegt. Fehlt sie, ist das kein
    // Fehler - erst ein QPM-PRAEFIX ohne Dokument ist einer.
    let qpm_index = std::fs::read_dir(&root)
        .ok()
        .and_then(|entries| {
            entries.flatten().map(|e| e.path()).find(|p| {
                p.file_name()
                    .map(|n| {
                        n.to_string_lossy()
                            .starts_with("PSK_QPM_NRAII_Referenzarchitektur")
                    })
                    .unwrap_or(false)
            })
        })
        .and_then(|p| pdf_extract::extract_text(&p).ok())
        .map(|t| index_source(&t));

    // Nullwache auf der Indexseite: ein Werk mit leerem Blockindex heisst,
    // die Extraktion oder das Muster ist kaputt - nicht, dass das Werk
    // keine Bloecke hat.
    if ra_index.len() < 100 {
        eprintln!(
            "verify-citations: FAIL — RA-Index verdaechtig klein ({} Bloecke aus {}); \
             Extraktion oder Muster pruefen.",
            ra_index.len(),
            pdf.display()
        );
        return ExitCode::FAILURE;
    }

    // ---- Zitierungen einsammeln.
    let roots = [
        root.join("packages"),
        root.join("tools"),
        root.join("architecture"),
        root.join("constitution"),
        root.join("domains"),
        root.join("adapters"),
    ];
    let refs: Vec<&Path> = roots.iter().map(|p| p.as_path()).collect();
    let citations = scan_citations(&refs);
    if citations.is_empty() {
        eprintln!("verify-citations: FAIL — keine einzige Zitierung gefunden; Scanner kaputt.");
        return ExitCode::FAILURE;
    }

    // ---- Pruefen.
    let mut problems: Vec<String> = Vec::new();
    let mut titled = 0usize;
    for c in &citations {
        // "Regel 9.13.2" zitiert Punkt 2 der Regel 9.13 - der BLOCK ist
        // 9.9, und nur Bloecke tragen Nummern im Werk.
        let block_number = {
            let parts: Vec<&str> = c.number.split('.').collect();
            if parts.len() > 2 {
                format!("{}.{}", parts[0], parts[1])
            } else {
                c.number.clone()
            }
        };
        let key = (c.kind.clone(), block_number);

        // Der benannte Raum entscheidet, WO aufgeloest wird. Ohne Praefix:
        // PSK-RA. Unbekanntes Praefix: Fehler, nicht Standardfall.
        let (space_name, index) = match c.namespace.as_deref() {
            None => ("PSK-RA", Some(&ra_index)),
            Some("CPSK") => ("CPSK", Some(&cpsk_index)),
            Some("QPM") => ("QPM/NRAII-RA", qpm_index.as_ref()),
            Some(other) => {
                problems.push(format!(
                    "{}:{}: unbekannter Namensraum \"{other}\" vor {} {} - \
                     deklariert sind {NAMESPACES:?}, ohne Praefix gilt PSK-RA",
                    c.file, c.line, c.kind, c.number
                ));
                continue;
            }
        };
        let Some(index) = index else {
            problems.push(format!(
                "{}:{}: {} {} zitiert {space_name}, dessen Dokument nicht im \
                 Wurzelverzeichnis liegt - Zitat nicht pruefbar",
                c.file, c.line, c.kind, c.number
            ));
            continue;
        };
        let Some(source_title) = index.get(&key) else {
            problems.push(format!(
                "{}:{}: {} {} loest in {space_name} nicht auf",
                c.file, c.line, c.kind, c.number
            ));
            continue;
        };
        if let Some(cited) = &c.inline_title {
            titled += 1;
            let cited_n = normalize(cited);
            let ok = source_title.starts_with(&cited_n)
                || cited_n.starts_with(source_title.as_str())
                || source_title == &cited_n;
            if !ok {
                problems.push(format!(
                    "{}:{}: {} {} traegt Titel \"{}\", {space_name} fuehrt \"{}\"",
                    c.file, c.line, c.kind, c.number, cited, source_title
                ));
            }
        }
    }

    // ---- Registerrueckverweise: `struktur: "N.M"`-Felder.
    //
    // Sie sind maschinenlesbar und wurden von nichts geprueft - 23 von
    // 29 waren gedriftet (meist +2, unsichtbar seit zwanzig Editionen),
    // weil diese Stufe nur Fliesstext las. Fuenfte Instanz derselben
    // Klasse (Objektzahlen, Testzahl, Kollisionszahl, Katalogeintraege,
    // Registerrueckverweise); die Loesung ist jedes Mal dieselbe:
    // pruefen, nicht pflegen.
    //
    // Der TITEL wird mitgeprueft: der Eintragsname MUSS im Blocktitel
    // stecken. Blosse Aufloesbarkeit reicht nicht - wenn eine
    // Einfuegung die alte Nummer neu besetzt, loest der gedriftete
    // Verweis wieder auf und die Verschiebung waere erneut still (im
    // Fliesstext real passiert: "Regel 9.9" ueberlebte so eine ganze
    // Edition).
    let register_backrefs = scan_register_backrefs(&[
        root.join("architecture").as_path(),
        root.join("constitution").as_path(),
    ]);
    for r in &register_backrefs {
        let key = ("Struktur".to_string(), r.number.clone());
        let Some(title) = ra_index.get(&key) else {
            problems.push(format!(
                "{}:{}: Registerrueckverweis struktur: \"{}\" ({}) loest in PSK-RA nicht auf",
                r.file, r.line, r.number, r.name
            ));
            continue;
        };
        if !title.contains(&normalize(&r.name)) {
            problems.push(format!(
                "{}:{}: struktur: \"{}\" gehoert laut Register zu {}, PSK-RA fuehrt dort \"{}\"",
                r.file, r.line, r.number, r.name, title
            ));
        }
    }
    if register_backrefs.is_empty() {
        // Nullwache: object_schemas.yaml traegt diese Felder seit I0.
        eprintln!(
            "verify-citations: FAIL — kein einziger Registerrueckverweis gefunden; Scanner kaputt."
        );
        return ExitCode::FAILURE;
    }

    eprintln!(
        "    {} Zitierungen geprueft ({} mit Titel), {} Registerrueckverweise | PSK-RA {} Bloecke, CPSK {}, QPM {}",
        citations.len(),
        titled,
        register_backrefs.len(),
        ra_index.len(),
        cpsk_index.len(),
        qpm_index
            .as_ref()
            .map(|i| i.len().to_string())
            .unwrap_or_else(|| "- (Dokument nicht im Repo)".to_string())
    );
    // Die Kollisionszahl wird gemessen, nicht behauptet - sie haengt an
    // zwei unabhaengig fortgeschriebenen Werken und ist genau die Groesse,
    // die begruendet, warum ein Zitat seinen Raum benennen muss.
    if let Some(q) = qpm_index.as_ref() {
        let collisions = ra_index.keys().filter(|k| q.contains_key(*k)).count();
        eprintln!(
            "    {collisions} Nummern tragen in PSK-RA und QPM verschiedene Bloecke - \
             ohne Praefix waere jede davon blind aufloesbar"
        );
    }
    if problems.is_empty() {
        eprintln!("verify-citations: PASS — jede Zitierung loest gegen die aktuelle Fassung auf.");
        ExitCode::SUCCESS
    } else {
        eprintln!("verify-citations: FAIL —");
        for p in &problems {
            eprintln!("    - {p}");
        }
        ExitCode::FAILURE
    }
}

/// Ein Registerrueckverweis: der Eintrag `name` beansprucht, sein
/// normativer Block sei `Struktur <number>`.
struct RegisterBackref {
    file: String,
    line: usize,
    name: String,
    number: String,
}

/// Sammelt `struktur: "N.M"`-Felder aus den YAML-Registern; der
/// zugehoerige Eintragsname ist das letzte vorangegangene `name:`-Feld.
/// Ohne Praefixspalte gilt wie im Fliesstext: PSK-RA.
fn scan_register_backrefs(dirs: &[&Path]) -> Vec<RegisterBackref> {
    let mut out = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e != "yaml").unwrap_or(true) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&p) else {
                continue;
            };
            let mut current_name: Option<String> = None;
            for (i, raw) in text.lines().enumerate() {
                let line = raw.trim();
                if let Some(rest) = line.strip_prefix("name:") {
                    current_name = Some(rest.trim().to_string());
                }
                if let Some(rest) = line.strip_prefix("struktur:") {
                    let number = rest.trim().trim_matches('"').to_string();
                    if let Some(name) = &current_name {
                        out.push(RegisterBackref {
                            file: p.display().to_string(),
                            line: i + 1,
                            name: name.clone(),
                            number,
                        });
                    }
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CORPUS: &str = "Regel 7.40 (Zwei Digests je Segment). Text. \
                          Struktur 7.44 (RunDescriptor). Mehr Text. \
                          Invariante 6.8 (Trennung von Inhalt und Aufzeichnung).";

    #[test]
    fn the_index_finds_blocks_and_normalizes_titles() {
        let idx = index_source(CORPUS);
        assert_eq!(idx.len(), 3);
        assert_eq!(
            idx.get(&("Regel".into(), "7.40".into())).unwrap(),
            "zweidigestsjesegment"
        );
    }

    #[test]
    fn umlaut_spellings_are_the_same_title() {
        assert_eq!(
            normalize("Zulässige Selbstverhärtung"),
            normalize("Zulaessige Selbstverhaertung")
        );
    }

    /// Der Fall, den die Stufe verhindert: eine Nummer, die es (nicht
    /// mehr) gibt. Positivkontrolle daneben, sonst bestuende der Test
    /// auch mit einem Index, der nie etwas findet.
    /// Die Namensraumregel, mechanisch: dasselbe (Art, Nummer) meint in
    /// zwei Werken zwei verschiedene Bloecke. Ohne Praefix gilt PSK-RA;
    /// ein Praefix waehlt den Raum; ein UNBEKANNTES Praefix ist ein
    /// Fehler und kein stiller Standardfall - sonst waere ein Tippfehler
    /// im Raumnamen von "meint PSK-RA" nicht zu unterscheiden.
    #[test]
    fn register_backrefs_are_scanned_and_the_title_check_catches_reoccupied_numbers() {
        // Der Fall, der die Erweiterung ausgeloest hat: 23 von 29
        // struktur:-Feldern waren gedriftet, und blosse Aufloesbarkeit
        // haette die neu besetzte Nummer wieder durchgewunken.
        let dir = std::env::temp_dir().join(format!("psk-backref-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("reg.yaml"),
            "objects:
  - id: OBJ-X
    name: IRBundle
    struktur: \"7.19\"
",
        )
        .unwrap();
        let refs = scan_register_backrefs(&[dir.as_path()]);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].name, "IRBundle");
        assert_eq!(refs[0].number, "7.19");

        // Titelpruefung: 7.19 existiere wieder, tritt aber unter fremdem
        // Titel auf - der Rueckverweis DARF NICHT durchgehen.
        let idx = index_source("Struktur 7.19 (CandidateCapsule). Struktur 7.21 (IRBundle).");
        let title = idx
            .get(&("Struktur".to_string(), "7.19".to_string()))
            .unwrap();
        assert!(!title.contains(&normalize("IRBundle")));
        let right = idx
            .get(&("Struktur".to_string(), "7.21".to_string()))
            .unwrap();
        assert!(right.contains(&normalize("IRBundle")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_declared_namespaces_are_exactly_two_and_unknown_is_not_a_default() {
        assert_eq!(NAMESPACES, ["QPM", "CPSK"]);
        assert!(
            !NAMESPACES.contains(&"PSK-RA"),
            "PSK-RA ist der praefixlose Standardfall"
        );
    }

    /// Die Kollision, die den Bau ausgeloest hat: Definition 15.1 ist in
    /// PSK-RA die Instruktionsmenge, in QPM/NRAII das Lokale
    /// Vierfachprimitiv. Zwei Indizes, dieselbe Nummer, zwei Titel.
    #[test]
    fn the_same_number_carries_different_titles_in_different_spaces() {
        let ra = index_source("Definition 15.1 (Instruktionsmenge). Text.");
        let qpm = index_source("Definition 15.1 (Lokales Vierfachprimitiv). Text.");
        let key = ("Definition".to_string(), "15.1".to_string());
        assert_ne!(ra.get(&key), qpm.get(&key));
        assert!(ra.contains_key(&key) && qpm.contains_key(&key));
    }

    #[test]
    fn a_stale_number_does_not_resolve_and_a_current_one_does() {
        let idx = index_source(CORPUS);
        assert!(!idx.contains_key(&("Regel".into(), "7.39".into())));
        assert!(idx.contains_key(&("Regel".into(), "7.40".into())));
        // Auch die ART zaehlt: Axiom 7.40 existiert nicht, Regel 7.40 schon.
        assert!(!idx.contains_key(&("Axiom".into(), "7.40".into())));
    }
}
