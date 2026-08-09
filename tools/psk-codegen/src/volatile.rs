//! Codegen fuer architecture/volatile_fields.yaml (Definition 6.5, Volatile
//! Felder und Identitaetsprojektion; Anhang Listing B.4, v1.0.6).
//!
//! Jeder `path`-Eintrag hat die Form "TYP.seg1[.seg2...]", wobei das
//! letzte Segment auf "*" enden darf (Praefixvergleich). `TYP` ist reine
//! Dokumentation (z.B. "DualTime" oder "ThoughtBody") - CanonValue-Baeume
//! tragen keine Typinformation, daher matcht die Identitaetsprojektion
//! ausschliesslich auf die Pfadsegmente NACH dem Typhinweis, an
//! beliebiger Stelle im Baum (nicht auf den Typ selbst verankert):
//! "DualTime.tau_e" entfernt jedes Feld "tau_e", unabhaengig davon, ob
//! sein umschliessendes Objekt tatsaechlich eine DualTime ist;
//! "ThoughtBody.claim.text" entfernt jedes Feld "text", dessen
//! unmittelbares Elternfeld "claim" heisst. Zwei Gruende (volatile,
//! non_canonical), ein Mechanismus: beide werden von pi_vol identisch
//! entfernt (v1.0.6 Fehlerkorrektur Punkt 8: "Es existiert kein zweiter
//! Ausschlusspfad neben diesem Register").

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct VolatileFieldsDoc {
    pub volatile: Vec<PathEntry>,
    #[serde(default)]
    pub non_canonical: Vec<PathEntry>,
    #[serde(default)]
    pub not_removed: Vec<PathEntry>,
    pub enforcement: Enforcement,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PathEntry {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct Enforcement {
    #[allow(dead_code)]
    pub gate_input_forbidden: Vec<String>,
    pub error_on_violation: String,
}

pub fn load_volatile_fields(root: &Path) -> VolatileFieldsDoc {
    crate::load_yaml(root, "architecture/volatile_fields.yaml")
}

/// Zerlegt "TYP.seg1.seg2" in die Segmente NACH dem (verworfenen)
/// Typhinweis: ["seg1", "seg2"].
fn path_segments(path: &str) -> Vec<String> {
    let mut parts: Vec<&str> = path.split('.').collect();
    if parts.len() < 2 {
        panic!("psk-codegen: volatile_fields.yaml Pfad '{path}' hat keine Form TYP.feld[.feld...]");
    }
    parts.remove(0); // Typhinweis verwerfen
    parts.into_iter().map(str::to_string).collect()
}

fn emit_pattern_array(out: &mut String, const_name: &str, entries: &[PathEntry]) {
    out.push_str(&format!(
        "pub const {const_name}: [VolatileFieldPattern; {}] = [\n",
        entries.len()
    ));
    for e in entries {
        let mut segs = path_segments(&e.path);
        let last = segs
            .pop()
            .expect("mindestens ein Segment nach dem Typhinweis");
        let prefix = last.ends_with('*');
        let last_trimmed = last.trim_end_matches('*').to_string();
        segs.push(last_trimmed);
        let seg_list = segs
            .iter()
            .map(|s| format!("\"{s}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!(
            "    VolatileFieldPattern {{ source: \"{}\", path: &[{seg_list}], prefix: {prefix} }},\n",
            e.path
        ));
    }
    out.push_str("];\n\n");
}

/// Erzeugt `VolatileFieldPattern`, `VOLATILE_FIELDS`, `NON_CANONICAL_FIELDS`,
/// `NOT_REMOVED` und die Fehlercode-Konstante aus
/// architecture/volatile_fields.yaml.
pub fn generate_volatile_fields(doc: &VolatileFieldsDoc) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/volatile_fields.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten.\n");
    out.push_str("// Quelle: Definition 6.5 (Volatile Felder und Identitaetsprojektion),\n");
    out.push_str("// Anhang Listing B.4.\n\n");

    out.push_str("#[derive(Debug, Clone, Copy)]\n");
    out.push_str("pub struct VolatileFieldPattern {\n");
    out.push_str("    /// Der volle Registereintrag, nur zur Fehlersuche/Dokumentation.\n");
    out.push_str("    pub source: &'static str,\n");
    out.push_str("    /// Pfadsegmente NACH dem (verworfenen) Typhinweis - z.B. [\"tau_e\"]\n");
    out.push_str("    /// oder [\"claim\", \"text\"]. Ein Feld matcht, wenn seine eigene\n");
    out.push_str("    /// Position im Baum mit diesem Suffix uebereinstimmt.\n");
    out.push_str("    pub path: &'static [&'static str],\n");
    out.push_str("    /// true, wenn das Register das letzte Segment mit \"*\" abgeschlossen\n");
    out.push_str("    /// hat (Praefixvergleich, z.B. \"view_*\"); sonst exakter Vergleich.\n");
    out.push_str("    pub prefix: bool,\n");
    out.push_str("}\n\n");

    emit_pattern_array(&mut out, "VOLATILE_FIELDS", &doc.volatile);
    emit_pattern_array(&mut out, "NON_CANONICAL_FIELDS", &doc.non_canonical);
    emit_pattern_array(&mut out, "NOT_REMOVED", &doc.not_removed);

    out.push_str(&format!(
        "/// Definition 6.7/Invariante 6.8: ein Verstoss (ein von pi_vol\n/// entferntes Feld oder record_digest als Gate-Eingabe, oder eine\n/// Objekt-ID-Abweichung bei gleichem RunDescriptor und gleichen\n/// Eingaben) erzeugt {}.\npub const VOLATILE_VIOLATION_ERROR: &str = \"{}\";\n",
        doc.enforcement.error_on_violation, doc.enforcement.error_on_violation
    ));

    out
}
