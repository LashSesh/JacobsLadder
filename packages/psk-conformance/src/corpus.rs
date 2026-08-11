//! Die Domaenenseite des Korpus: das versiegelte Korpus LESEN und das
//! Frischepraedikat des Verzeichnisankers auswerten.
//!
//! Identifikation, Falsifikator und Integrator liegen seit der
//! Taktumverdrahtung (Regel 24.4 (Der Golden Run laeuft unter tick)) in
//! M24 (`psk_adversarial::corpus`, siehe dortigen Modulkopf): die
//! Challenge-Phase wickelt sie als Arbeit ab, und Definition 14.2 (Phasen-Modul-Bindung)
//! ordnet der Challenge-Phase genau M24 zu. Hier
//! bleibt, was Domaenensache ist - Dateipfade, Zeilenform, Praedikat-
//! auswertung -, dieselbe Trennung wie bei `ir_assembly` (Lader hier,
//! Zusammenbau in M23).

use std::collections::BTreeMap;
use std::path::Path;

use psk_types::{Digest, PskError};

pub use psk_adversarial::{
    falsifier_countermodels, identify_contradictions, integrator_obstruction, open_obligation_for,
    Contradiction, Geltung, Requirement,
};

/// Eine deklarierte Quelle des Korpus: der SourceRef, unter dem der
/// Abhaengigkeitsquotient sie fuehrt, ihre Herkunft und ihr Pfad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusSource {
    pub id: String,
    pub origin: String,
    pub path: String,
}

/// Das gelesene Manifest: die Quellen und die domaenengelieferte
/// Zuordnung, welcher Archetyp aus welcher Quelle liest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorpusManifest {
    pub sources: Vec<CorpusSource>,
    /// Archetypname -> die Quellen, die er befragt. Domaenengeliefert
    /// wie LensSpec und GateSet: WELCHE Rolle WELCHES Dokument liest,
    /// ist eine Aussage ueber diese Domaene.
    pub archetype_sources: BTreeMap<String, Vec<String>>,
}

/// Liest das Korpusmanifest (`requirements.yaml`).
///
/// Seit v1.0.45 ist die Datei ein Manifest ueber mehrere Quellen statt
/// einer einzelnen Anforderungsliste - siehe ihren eigenen Kopf und
/// Regel 32.6 (Referenzauftrag) ("gemeinsame Quellen quotientieren").
pub fn load_manifest(corpus_root: &Path) -> Result<CorpusManifest, PskError> {
    let text = std::fs::read_to_string(corpus_root.join("requirements.yaml"))
        .map_err(|_| PskError::UntypedInput)?;

    let mut sources: Vec<CorpusSource> = Vec::new();
    let mut archetype_sources: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut section = "";
    let mut cur: BTreeMap<&str, String> = BTreeMap::new();

    let flush = |cur: &mut BTreeMap<&str, String>, out: &mut Vec<CorpusSource>| {
        if let (Some(id), Some(origin), Some(path)) =
            (cur.get("id"), cur.get("origin"), cur.get("path"))
        {
            out.push(CorpusSource {
                id: id.clone(),
                origin: origin.clone(),
                path: path.clone(),
            });
        }
        cur.clear();
    };

    for raw in text.lines() {
        let line = raw.trim();
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if line == "sources:" {
            flush(&mut cur, &mut sources);
            section = "sources";
            continue;
        }
        if line == "archetype_sources:" {
            flush(&mut cur, &mut sources);
            section = "archetypes";
            continue;
        }
        match section {
            "sources" => {
                if let Some(rest) = line.strip_prefix("- id: ") {
                    flush(&mut cur, &mut sources);
                    cur.insert("id", rest.trim().to_string());
                } else {
                    for key in ["origin", "path"] {
                        if let Some(v) = line.strip_prefix(&format!("{key}: ")) {
                            cur.insert(key, v.trim().trim_matches('"').to_string());
                        }
                    }
                }
            }
            "archetypes" => {
                if let Some((name, list)) = line.split_once(": [") {
                    let ids: Vec<String> = list
                        .trim_end_matches(']')
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                    if !ids.is_empty() {
                        archetype_sources.insert(name.trim().to_string(), ids);
                    }
                }
            }
            _ => {}
        }
    }
    flush(&mut cur, &mut sources);

    // Nullbefund ueber nichtleerer Datei: der Parser greift daneben.
    if sources.is_empty() || archetype_sources.is_empty() {
        return Err(PskError::UntypedInput);
    }
    // Eine Zuordnung auf eine nicht deklarierte Quelle waere ein
    // SourceRef ohne Dokument - ein erfundener Unabhaengigkeitsbeleg.
    let declared: std::collections::BTreeSet<&str> =
        sources.iter().map(|s| s.id.as_str()).collect();
    for ids in archetype_sources.values() {
        if ids.iter().any(|i| !declared.contains(i.as_str())) {
            return Err(PskError::UntypedInput);
        }
    }
    Ok(CorpusManifest {
        sources,
        archetype_sources,
    })
}

/// Liest das Korpus ueber ALLE im Manifest deklarierten Quellen.
///
/// Bewusst zeilenweise wie die verify-*-Werkzeuge: der Lauf soll an
/// einer Korpusaenderung scheitern, nicht sie wegabstrahieren. Jede
/// Anforderung traegt die Quelle, aus der sie stammt - ohne sie waere
/// jede Rangfolge quellenblind.
pub fn load_requirements(corpus_root: &Path) -> Result<Vec<Requirement>, PskError> {
    let manifest = load_manifest(corpus_root)?;
    let mut out = Vec::new();
    for source in &manifest.sources {
        let text = std::fs::read_to_string(corpus_root.join(&source.path))
            .map_err(|_| PskError::UntypedInput)?;
        let before = out.len();
        parse_requirements_into(&text, &source.id, &mut out);
        if out.len() == before {
            // Eine deklarierte Quelle ohne Anforderung ist kein leerer
            // Erfolg, sondern ein Lesefehler.
            return Err(PskError::UntypedInput);
        }
    }
    if out.is_empty() {
        return Err(PskError::UntypedInput);
    }
    Ok(out)
}

fn parse_requirements_into(text: &str, source: &str, out: &mut Vec<Requirement>) {
    let mut cur: BTreeMap<&str, String> = BTreeMap::new();
    let flush = |cur: &mut BTreeMap<&str, String>, out: &mut Vec<Requirement>| {
        if let (Some(id), Some(sev), Some(art), Some(prec), Some(st)) = (
            cur.get("id"),
            cur.get("severity"),
            cur.get("artifact"),
            cur.get("precedence"),
            cur.get("statement"),
        ) {
            if let Ok(p) = prec.parse::<u32>() {
                out.push(Requirement {
                    id: id.clone(),
                    severity: sev.clone(),
                    artifact: art.clone(),
                    precedence: p,
                    statement: st.clone(),
                    source: source.to_string(),
                });
            }
        }
        cur.clear();
    };
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("- id: ") {
            flush(&mut cur, out);
            cur.insert("id", rest.trim().to_string());
        } else {
            for key in ["severity", "artifact", "precedence", "statement"] {
                if let Some(v) = line.strip_prefix(&format!("{key}: ")) {
                    cur.insert(key, v.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    flush(&mut cur, out);
}

/// Das Frischepraedikat eines ueber ein Verzeichnis versiegelten Ankers.
///
/// Regel "Ein Frischepraedikat muss verletzbar sein": es MUSS mindestens
/// eine Beobachtung benennen, unter der es faellt - "fuer einen ueber ein
/// Verzeichnis versiegelten Anker ist das die Veraenderung genau dieses
/// Verzeichnisses". Deshalb bindet es den Verzeichnisdigest zum
/// Versiegelungszeitpunkt, statt "always" zu sagen.
///
/// Der KERN wertet es nicht aus - `psk_anchor::is_fresh` liest
/// ausschliesslich `expires_at_tau_i`, und das ist die deklarierte
/// Ordnung, weil PredicateExpr domaenengeliefert ist. Die Auswertung
/// gehoert der Domaene, also hierher.
pub fn directory_freshness_predicate(corpus_digest: Digest) -> String {
    format!("corpus_digest == {corpus_digest}")
}

/// Wertet das obige Praedikat gegen eine spaetere Beobachtung aus.
/// `true` heisst frisch, `false` heisst: das Verzeichnis hat sich seit dem
/// Versiegeln veraendert.
pub fn freshness_predicate_holds(predicate: &str, observed_digest: Digest) -> bool {
    predicate
        .strip_prefix("corpus_digest == ")
        .map(|declared| declared == observed_digest.to_string())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regel "Ein Frischepraedikat muss verletzbar sein", mechanisch: das
    /// Praedikat MUSS unter einer benennbaren Beobachtung fallen. Die
    /// Gegenprobe ist der eigentliche Test - ohne sie bestuende er auch
    /// fuer ein stets wahres Praedikat.
    #[test]
    fn the_freshness_predicate_actually_falls_when_the_directory_changes() {
        let sealed = Digest::sha256(b"corpus-at-seal-time");
        let p = directory_freshness_predicate(sealed);
        assert!(
            freshness_predicate_holds(&p, sealed),
            "unveraendert: frisch"
        );
        assert!(
            !freshness_predicate_holds(&p, Digest::sha256(b"corpus-after-patch")),
            "veraendert: MUSS fallen - sonst ist der Reanchor-Pfad unerreichbar"
        );
        assert!(!p.contains("always") && !p.contains("true"));
    }

    /// Der Lader und die abgesenkte Identifikation greifen ineinander:
    /// das ECHTE Korpus der Referenzdomaene, jetzt ueber drei Quellen.
    ///
    /// **GEMESSEN, nicht entworfen** - die Zahlen fallen aus dem Korpus,
    /// und jede einzelne ist benennbar. Fuenf MUST-Anforderungen ueber
    /// `golden-run-patch.txt`, vier davon im Konflikt:
    ///
    /// 1. SPEC-PATCH-001 gegen SPEC-PATCH-002 - dieselbe Quelle,
    ///    verschiedener Rang: die Praezedenz entscheidet.
    /// 2. SPEC-PATCH-001 gegen OPS-PATCH-001 - ueber Quellen.
    /// 3. SPEC-PATCH-002 gegen OPS-PATCH-001 - ueber Quellen.
    /// 4. CODE-SCOPE-001 gegen OPS-MIRROR-001 - ueber Quellen.
    ///
    /// Bis v1.0.45 waren es zwei, einer offen. Der Zuwachs ist kein
    /// Defekt, sondern das, wofuer die Domaene gebaut wurde: mit einer
    /// Quelle gibt es nichts zu quotientieren und wenig zu widerlegen.
    #[test]
    fn the_real_corpus_yields_four_contradictions_three_of_them_across_sources() {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel");
        }
        let reqs = load_requirements(&dir.join("domains/jacobs-ladder-reference/corpus"))
            .expect("Korpus lesbar");

        // Der Lader traegt die Herkunft mit - ohne sie waere jede
        // Rangfolge quellenblind.
        let quellen: std::collections::BTreeSet<&str> =
            reqs.iter().map(|r| r.source.as_str()).collect();
        assert_eq!(
            quellen.len(),
            3,
            "drei Quelldokumente verschiedener Herkunft: {quellen:?}"
        );

        let found = identify_contradictions(&reqs).expect("Identifikation");
        assert_eq!(found.len(), 4, "{found:?}");
        assert_eq!(
            found.iter().filter(|c| !c.is_open()).count(),
            1,
            "genau der quelleninterne Fall loest sich auf"
        );
        assert_eq!(
            found.iter().filter(|c| c.crosses_sources()).count(),
            3,
            "die drei uebrigen laufen ueber Quellgrenzen"
        );

        // Und die Kontrollmenge greift weiterhin: `trace.jsonl` und
        // `anchor.json` erzeugen keinen Widerspruch. Ohne diese Zeile
        // bestuende eine Identifikation, die ALLES meldet, unbemerkt.
        assert!(
            found.iter().all(|c| c.artifact == "golden-run-patch.txt"),
            "nur das umstrittene Artefakt streitet: {found:?}"
        );
    }
}
