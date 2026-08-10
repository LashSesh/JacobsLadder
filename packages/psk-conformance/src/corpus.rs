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

/// Liest das Korpus. Bewusst zeilenweise wie die verify-*-Werkzeuge: der
/// Lauf soll an einer Korpusaenderung scheitern, nicht sie
/// wegabstrahieren.
pub fn load_requirements(corpus_root: &Path) -> Result<Vec<Requirement>, PskError> {
    let text = std::fs::read_to_string(corpus_root.join("requirements.yaml"))
        .map_err(|_| PskError::UntypedInput)?;
    let mut out = Vec::new();
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
                });
            }
        }
        cur.clear();
    };
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("- id: ") {
            flush(&mut cur, &mut out);
            cur.insert("id", rest.trim().to_string());
        } else {
            for key in ["severity", "artifact", "precedence", "statement"] {
                if let Some(v) = line.strip_prefix(&format!("{key}: ")) {
                    cur.insert(key, v.trim().trim_matches('"').to_string());
                }
            }
        }
    }
    flush(&mut cur, &mut out);

    if out.is_empty() {
        // Nullbefund ueber nichtleerer Datei: der Parser greift daneben.
        return Err(PskError::UntypedInput);
    }
    Ok(out)
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
    /// das ECHTE Korpus der Referenzdomaene ergibt weiterhin genau zwei
    /// Widersprueche, einen davon offen. Dieselbe Zahl haelt der Golden-
    /// Run-Test - hier steht sie direkt an der Naht Lader->M24.
    #[test]
    fn the_real_corpus_still_yields_two_contradictions_one_open() {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel");
        }
        let reqs = load_requirements(&dir.join("domains/jacobs-ladder-reference/corpus"))
            .expect("Korpus lesbar");
        let found = identify_contradictions(&reqs).expect("Identifikation");
        assert_eq!(found.len(), 2);
        assert_eq!(found.iter().filter(|c| c.is_open()).count(), 1);
    }
}
