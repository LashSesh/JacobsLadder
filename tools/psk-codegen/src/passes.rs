//! Codegen fuer architecture/pass_registry.yaml (Kapitel 11).
//!
//! Erzeugt die geschlossene Passfolge C1..C11 (Definition 11.1), die vier
//! Emissionsklassen (Definition 11.17) und die sieben Vorbedingungen von
//! EXECUTABLE. Alles drei sind geschlossene Mengen; sie werden aus dem
//! Register erzeugt, damit sie nicht per Hand erweitert oder umbenannt
//! werden koennen.

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct PassRegistry {
    pub passes: Vec<PassEntry>,
    pub monotonicity: String,
    pub determinism: String,
    pub emission_classes: Vec<String>,
    pub executable_requires: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PassEntry {
    pub id: String,
    pub name: String,
    pub modules: Vec<String>,
    pub errors: Vec<String>,
}

pub fn load_pass_registry(root: &Path) -> PassRegistry {
    crate::load_yaml(root, "architecture/pass_registry.yaml")
}

fn emission_variant(raw: &str) -> String {
    let mut c = raw.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
        None => String::new(),
    }
}

/// Erzeugt `PassId`, `EmissionClass` und `EXECUTABLE_REQUIRES`.
pub fn generate_passes(reg: &PassRegistry) -> String {
    assert_eq!(
        reg.passes.len(),
        11,
        "psk-codegen: Definition 11.1 kennt genau 11 Paesse C1..C11"
    );
    assert_eq!(
        reg.emission_classes.len(),
        4,
        "psk-codegen: Definition 11.17 kennt genau vier Emissionsklassen"
    );

    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/pass_registry.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Definition 11.1 (Passfolge),\n");
    out.push_str("// Definition 11.17 (Emissionsklassen).\n\n");

    // ---- PassId ----
    out.push_str("/// Die geschlossene Passfolge C1 -> C2 -> ... -> C11 (Definition 11.1).\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("pub enum PassId {\n");
    for p in &reg.passes {
        out.push_str(&format!(
            "    /// {} ({}), Module {}, Fehlerklassen {}.\n",
            p.id,
            p.name,
            p.modules.join("+"),
            p.errors.join(", ")
        ));
        out.push_str(&format!("    {},\n", p.id));
    }
    out.push_str("}\n\n");

    out.push_str("impl PassId {\n");
    out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
    for p in &reg.passes {
        out.push_str(&format!("            PassId::{} => \"{}\",\n", p.id, p.id));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str("    pub const fn name(self) -> &'static str {\n        match self {\n");
    for p in &reg.passes {
        out.push_str(&format!(
            "            PassId::{} => \"{}\",\n",
            p.id, p.name
        ));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str("    /// Die Module, die diesen Pass ausfuehren (Definition 11.1).\n");
    out.push_str(
        "    pub const fn modules(self) -> &'static [&'static str] {\n        match self {\n",
    );
    for p in &reg.passes {
        let list = p
            .modules
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("            PassId::{} => &[{}],\n", p.id, list));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str("    /// Die Fehlerklassen, die dieser Pass erzeugen kann.\n");
    out.push_str(
        "    pub const fn error_classes(self) -> &'static [&'static str] {\n        match self {\n",
    );
    for p in &reg.passes {
        let list = p
            .errors
            .iter()
            .map(|e| format!("\"{e}\""))
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(&format!("            PassId::{} => &[{}],\n", p.id, list));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str(&format!(
        "    /// Alle {} Paesse in der normativen Reihenfolge.\n    pub const ALL: [PassId; {}] = [\n",
        reg.passes.len(),
        reg.passes.len()
    ));
    for p in &reg.passes {
        out.push_str(&format!("        PassId::{},\n", p.id));
    }
    out.push_str("    ];\n\n");

    out.push_str("    /// Nullbasierte Position in der Passfolge. Die Ordnung ist\n");
    out.push_str("    /// normativ (Definition 11.1) und Grundlage der Monotonie.\n");
    out.push_str("    pub const fn index(self) -> usize {\n        match self {\n");
    for (i, p) in reg.passes.iter().enumerate() {
        out.push_str(&format!("            PassId::{} => {},\n", p.id, i));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str("    /// Der unmittelbar folgende Pass, oder None nach C11.\n");
    out.push_str("    pub fn next(self) -> Option<PassId> {\n");
    out.push_str("        PassId::ALL.get(self.index() + 1).copied()\n    }\n");
    out.push_str("}\n\n");

    // ---- EmissionClass ----
    out.push_str("/// Definition 11.17: Emission liegt in genau diesen vier Klassen.\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("pub enum EmissionClass {\n");
    for e in &reg.emission_classes {
        out.push_str(&format!("    {},\n", emission_variant(e)));
    }
    out.push_str("}\n\n");

    out.push_str("impl EmissionClass {\n");
    out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
    for e in &reg.emission_classes {
        out.push_str(&format!(
            "            EmissionClass::{} => \"{}\",\n",
            emission_variant(e),
            e
        ));
    }
    out.push_str("        }\n    }\n\n");
    out.push_str("    pub fn from_id(id: &str) -> Option<EmissionClass> {\n        match id {\n");
    for e in &reg.emission_classes {
        out.push_str(&format!(
            "            \"{}\" => Some(EmissionClass::{}),\n",
            e,
            emission_variant(e)
        ));
    }
    out.push_str("            _ => None,\n        }\n    }\n\n");
    out.push_str(&format!(
        "    pub const ALL: [EmissionClass; {}] = [\n",
        reg.emission_classes.len()
    ));
    for e in &reg.emission_classes {
        out.push_str(&format!(
            "        EmissionClass::{},\n",
            emission_variant(e)
        ));
    }
    out.push_str("    ];\n}\n\n");

    // ---- EXECUTABLE_REQUIRES ----
    out.push_str("/// Definition 11.17: die vollstaendigen Vorbedingungen von\n");
    out.push_str("/// EXECUTABLE. Fehlt auch nur eine, DARF NICHT EXECUTABLE\n");
    out.push_str("/// emittiert werden.\n");
    out.push_str(&format!(
        "pub const EXECUTABLE_REQUIRES: [&str; {}] = [\n",
        reg.executable_requires.len()
    ));
    for r in &reg.executable_requires {
        out.push_str(&format!("    \"{r}\",\n"));
    }
    out.push_str("];\n\n");

    out.push_str(&format!(
        "/// Registervermerk zur Passmonotonie (Vertrag 11.2).\npub const MONOTONICITY: &str = \"{}\";\n\n",
        reg.monotonicity
    ));
    out.push_str(&format!(
        "/// Registervermerk zum Passdeterminismus (Invariante 11.3).\npub const DETERMINISM: &str = \"{}\";\n",
        reg.determinism
    ));

    out
}
