//! Liest die normativen Register aus `architecture/` und `constitution/`
//! zur Bauzeit und erzeugt daraus Rust-Quelltext. Diese Bibliothek ist der
//! einzige Ort, an dem YAML-Register in Code uebersetzt werden; jeder
//! Aufrufer (ein `build.rs` je Paket) bezieht seine Typen ausschliesslich
//! ueber diese Funktionen. Damit kann kein Paket eigenstaendig von den
//! Registern abweichen (Regel 1.5, Registerprimat).

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;

mod objects;
pub use objects::{
    generate_object_structs, generate_sort_id_enum, load_object_schemas, load_sort_registry,
    ObjectEntry, ObjectSchemas, SortEntry, SortRegistry,
};

mod topology;
pub use topology::{generate_m13_topology, load_m13_topology, M13Topology};

// ---------------------------------------------------------------- Register-Schemas

#[derive(Debug, Deserialize)]
pub struct ModuleMap {
    pub modules: Vec<ModuleEntry>,
    #[allow(dead_code)]
    pub forbidden_edges: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ModuleEntry {
    pub id: String,
    pub name: String,
    pub layer: String,
    pub package: String,
    #[serde(default)]
    pub caps: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PortRegistry {
    pub ports: Vec<PortEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PortEntry {
    pub id: String,
    pub from: String,
    pub to: String,
    pub payload: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub errors: Option<Vec<String>>,
    #[serde(default)]
    pub sync: Option<bool>,
    #[serde(default)]
    pub readonly: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ErrorCatalog {
    pub canonical: Vec<ErrorEntry>,
    pub architecture_extension: Vec<ErrorEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ErrorEntry {
    pub code: String,
    pub name: String,
    pub domain: String,
}

// ---------------------------------------------------------------- Laden

/// Findet die Wurzel des Cargo-Workspace, ausgehend von einem beliebigen
/// Unterverzeichnis, indem nach der obersten Cargo.toml mit `[workspace]`
/// gesucht wird.
pub fn workspace_root(start: &Path) -> PathBuf {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join("Cargo.toml");
        if candidate.is_file() {
            if let Ok(text) = fs::read_to_string(&candidate) {
                if text.contains("[workspace]") {
                    return dir;
                }
            }
        }
        if !dir.pop() {
            panic!(
                "psk-codegen: keine Workspace-Cargo.toml oberhalb von {:?} gefunden",
                start
            );
        }
    }
}

pub(crate) fn load_yaml<T: for<'de> Deserialize<'de>>(root: &Path, rel: &str) -> T {
    let path = root.join(rel);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("psk-codegen: kann {:?} nicht lesen: {e}", path));
    serde_yaml::from_str(&text)
        .unwrap_or_else(|e| panic!("psk-codegen: kann {:?} nicht parsen: {e}", path))
}

pub fn load_module_map(root: &Path) -> ModuleMap {
    load_yaml(root, "architecture/module_map.yaml")
}

pub fn load_port_registry(root: &Path) -> PortRegistry {
    load_yaml(root, "architecture/port_registry.yaml")
}

pub fn load_error_catalog(root: &Path) -> ErrorCatalog {
    load_yaml(root, "constitution/error_catalog.yaml")
}

/// Alle Registerdateien, die als `cargo:rerun-if-changed` deklariert werden
/// sollen, damit generierter Code nie stillschweigend veraltet.
pub fn tracked_register_files(root: &Path) -> Vec<PathBuf> {
    [
        "architecture/module_map.yaml",
        "architecture/port_registry.yaml",
        "constitution/error_catalog.yaml",
        "architecture/sort_registry.yaml",
        "architecture/object_schemas.yaml",
        "architecture/m13_topology.yaml",
    ]
    .iter()
    .map(|p| root.join(p))
    .collect()
}

// ---------------------------------------------------------------- Bezeichner

fn snake_to_pascal(s: &str) -> String {
    s.split('_')
        .filter(|part| !part.is_empty())
        .map(|part| {
            let mut c = part.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

// ---------------------------------------------------------------- Codegen: ModuleId

/// Erzeugt `enum ModuleId` mit genau den 28 Modulen aus Definition 3.1 /
/// module_map.yaml. Variantennamen sind die dort gefuehrten PascalCase-
/// Modulnamen; `.id()` liefert die kanonische Kennung "M00".."M27".
pub fn generate_module_id_enum(map: &ModuleMap) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/module_map.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Definition 3.1 (Modulmenge).\n\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("pub enum ModuleId {\n");
    for m in &map.modules {
        out.push_str(&format!(
            "    /// {} ({}), Schicht {}, Paket `{}`.\n",
            m.id, m.name, m.layer, m.package
        ));
        out.push_str(&format!("    {},\n", m.name));
    }
    out.push_str("}\n\n");

    out.push_str("impl ModuleId {\n");
    out.push_str("    /// Kanonische Kennung, z.B. \"M05\".\n");
    out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
    for m in &map.modules {
        out.push_str(&format!(
            "            ModuleId::{} => \"{}\",\n",
            m.name, m.id
        ));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str("    /// Paketname laut architecture/module_map.yaml.\n");
    out.push_str("    pub const fn package(self) -> &'static str {\n        match self {\n");
    for m in &map.modules {
        out.push_str(&format!(
            "            ModuleId::{} => \"{}\",\n",
            m.name, m.package
        ));
    }
    out.push_str("        }\n    }\n\n");
    out.push_str(
        "    /// Umkehrung von `.id()`, z.B. \"M19\" -> Some(ModuleId::TraceReplayResidueStore).\n",
    );
    out.push_str("    pub fn from_id(id: &str) -> Option<ModuleId> {\n        match id {\n");
    for m in &map.modules {
        out.push_str(&format!(
            "            \"{}\" => Some(ModuleId::{}),\n",
            m.id, m.name
        ));
    }
    out.push_str("            _ => None,\n        }\n    }\n");
    out.push_str("}\n\n");

    out.push_str("/// Drahtform: die kanonische Kennung selbst (\"M00\".. \"M27\").\n");
    out.push_str("impl serde::Serialize for ModuleId {\n");
    out.push_str(
        "    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {\n",
    );
    out.push_str("        s.serialize_str(self.id())\n    }\n}\n\n");
    out.push_str("impl<'de> serde::Deserialize<'de> for ModuleId {\n");
    out.push_str(
        "    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {\n",
    );
    out.push_str("        let s = String::deserialize(d)?;\n");
    out.push_str("        ModuleId::from_id(&s).ok_or_else(|| serde::de::Error::custom(format!(\"unbekannte ModuleId: {s}\")))\n");
    out.push_str("    }\n}\n");
    out
}

// ---------------------------------------------------------------- Codegen: PortId

/// Erzeugt `enum PortId` mit genau den 42 Ports aus architecture/port_registry.yaml
/// (Invariante 4.5, Portabschluss). Variantennamen sind die Port-IDs selbst.
pub fn generate_port_id_enum(reg: &PortRegistry) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/port_registry.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Invariante 4.5 (Portabschluss).\n\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("pub enum PortId {\n");
    for p in &reg.ports {
        out.push_str(&format!("    /// {} -> {}: {}\n", p.from, p.to, p.payload));
        out.push_str(&format!("    {},\n", p.id));
    }
    out.push_str("}\n\n");

    out.push_str("impl PortId {\n");
    out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
    for p in &reg.ports {
        out.push_str(&format!("            PortId::{} => \"{}\",\n", p.id, p.id));
    }
    out.push_str("        }\n    }\n\n");
    out.push_str("    /// Umkehrung von `.id()`, z.B. \"P07\" -> Some(PortId::P07).\n");
    out.push_str("    pub fn from_id(id: &str) -> Option<PortId> {\n        match id {\n");
    for p in &reg.ports {
        out.push_str(&format!(
            "            \"{}\" => Some(PortId::{}),\n",
            p.id, p.id
        ));
    }
    out.push_str("            _ => None,\n        }\n    }\n");
    out.push_str("}\n\n");

    out.push_str("/// Drahtform: die kanonische Kennung selbst (\"P00\".. \"P41\").\n");
    out.push_str("impl serde::Serialize for PortId {\n");
    out.push_str(
        "    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {\n",
    );
    out.push_str("        s.serialize_str(self.id())\n    }\n}\n\n");
    out.push_str("impl<'de> serde::Deserialize<'de> for PortId {\n");
    out.push_str(
        "    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {\n",
    );
    out.push_str("        let s = String::deserialize(d)?;\n");
    out.push_str("        PortId::from_id(&s).ok_or_else(|| serde::de::Error::custom(format!(\"unbekannte PortId: {s}\")))\n");
    out.push_str("    }\n}\n");
    out
}

// ---------------------------------------------------------------- Codegen: PskError

/// Erzeugt `enum PskError` aus constitution/error_catalog.yaml (kanonisch +
/// Architekturerweiterung). `.code()` liefert den stabilen Fehlercode
/// (Invariante 29.4, Codestabilitaet).
pub fn generate_error_enum(cat: &ErrorCatalog) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus constitution/error_catalog.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Codes sind stabil (Invariante 29.4).\n\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("pub enum PskError {\n");
    for e in cat
        .canonical
        .iter()
        .chain(cat.architecture_extension.iter())
    {
        let variant = snake_to_pascal(&e.name);
        out.push_str(&format!("    /// {} (Domaene {})\n", e.code, e.domain));
        out.push_str(&format!("    {},\n", variant));
    }
    out.push_str("}\n\n");

    out.push_str("impl PskError {\n");
    out.push_str("    pub const fn code(self) -> &'static str {\n        match self {\n");
    for e in cat
        .canonical
        .iter()
        .chain(cat.architecture_extension.iter())
    {
        let variant = snake_to_pascal(&e.name);
        out.push_str(&format!(
            "            PskError::{} => \"{}\",\n",
            variant, e.code
        ));
    }
    out.push_str("        }\n    }\n\n");

    out.push_str("    pub const fn domain(self) -> &'static str {\n        match self {\n");
    for e in cat
        .canonical
        .iter()
        .chain(cat.architecture_extension.iter())
    {
        let variant = snake_to_pascal(&e.name);
        out.push_str(&format!(
            "            PskError::{} => \"{}\",\n",
            variant, e.domain
        ));
    }
    out.push_str("        }\n    }\n");
    out.push_str("}\n\n");

    out.push_str("impl std::fmt::Display for PskError {\n");
    out.push_str("    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {\n");
    out.push_str("        write!(f, \"{}\", self.code())\n    }\n}\n\n");
    out.push_str("impl std::error::Error for PskError {}\n");
    out
}

// ---------------------------------------------------------------- Codegen: payload marker types

/// Erzeugt fuer jeden in port_registry.yaml auftretenden Nutzlastnamen einen
/// leeren Markertyp. Diese Typen tragen bis WP02 (Core Types, Phase I1)
/// keine Felder; sie machen lediglich jede Portgrenze in I0 typisiert statt
/// unspezifiziert. Reale Felder folgen den Strukturen aus Kapitel 7.
pub fn generate_payload_markers(reg: &PortRegistry) -> String {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for p in &reg.ports {
        for raw in p.payload.split(',') {
            let cleaned: String = raw.trim().chars().filter(|c| c.is_alphanumeric()).collect();
            if !cleaned.is_empty() {
                names.insert(cleaned);
            }
        }
    }
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/port_registry.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Platzhalter bis WP02 (Core Types, I1) die\n");
    out.push_str("// realen Felder aus Kapitel 7 nachtraegt.\n\n");
    for n in &names {
        out.push_str(&format!(
            "#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]\npub struct {n};\n"
        ));
    }
    out
}

// ---------------------------------------------------------------- Codegen: Portstubs je Paket

/// Erzeugt typisierte, unimplementierte Funktionssignaturen fuer jeden Port,
/// an dem ein Modul des angegebenen Pakets Erzeuger oder Verbraucher ist.
/// Ports mit Platzhalter-Endpunkt ("*") werden nur auf der konkreten Seite
/// erzeugt; die andere Seite ist erst mit realer Modul-Logik sinnvoll
/// modellierbar (Scheduler/Trace-Dispatch, Phase I5) und wird hier
/// bewusst ausgelassen statt geraten.
fn payload_type_expr(payload: &str) -> String {
    let names: Vec<String> = payload
        .split(',')
        .map(|raw| {
            raw.trim()
                .chars()
                .filter(|c| c.is_alphanumeric())
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .collect();
    match names.as_slice() {
        [one] => format!("payloads::{one}"),
        many => format!(
            "({})",
            many.iter()
                .map(|n| format!("payloads::{n}"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

pub fn generate_port_stubs_for_package(
    map: &ModuleMap,
    reg: &PortRegistry,
    package: &str,
) -> String {
    let owned: BTreeSet<&str> = map
        .modules
        .iter()
        .filter(|m| m.package == package)
        .map(|m| m.id.as_str())
        .collect();

    let mut body = String::new();
    let mut emitted = 0usize;
    for p in &reg.ports {
        let produces = owned.contains(p.from.as_str());
        let consumes = owned.contains(p.to.as_str());
        if !produces && !consumes {
            continue;
        }
        let err_code = p
            .errors
            .as_ref()
            .and_then(|e| e.first())
            .cloned()
            .unwrap_or_else(|| "keiner deklariert".to_string());
        let payload_ty = payload_type_expr(&p.payload);

        if produces {
            emitted += 1;
            body.push_str(&format!(
                "/// Port {}: {} -> {} (Nutzlast: {}, Fehler: {}).\n",
                p.id, p.from, p.to, p.payload, err_code
            ));
            body.push_str(&format!(
                "/// Erzeugerseite. Referenz: architecture/port_registry.yaml#{}.\n",
                p.id
            ));
            body.push_str(&format!(
                "pub fn send_{}(_payload: {payload_ty}) -> Result<Msg, PskError> {{\n",
                p.id.to_lowercase()
            ));
            body.push_str(&format!("    const _PORT: PortId = PortId::{};\n", p.id));
            body.push_str(
                "    unimplemented!(\"Portlogik folgt in einer spaeteren Phase\")\n}\n\n",
            );
        }
        if consumes {
            emitted += 1;
            body.push_str(&format!(
                "/// Port {}: {} -> {} (Nutzlast: {}, Fehler: {}).\n",
                p.id, p.from, p.to, p.payload, err_code
            ));
            body.push_str(&format!(
                "/// Verbraucherseite. Referenz: architecture/port_registry.yaml#{}.\n",
                p.id
            ));
            body.push_str(&format!(
                "pub fn recv_{}(_msg: Msg) -> Result<{payload_ty}, PskError> {{\n",
                p.id.to_lowercase()
            ));
            body.push_str(&format!("    const _PORT: PortId = PortId::{};\n", p.id));
            body.push_str(
                "    unimplemented!(\"Portlogik folgt in einer spaeteren Phase\")\n}\n\n",
            );
        }
    }

    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/port_registry.yaml\n");
    out.push_str("// und architecture/module_map.yaml. Nicht von Hand bearbeiten.\n");
    out.push_str("//\n");
    out.push_str("// Phase I0 (Regel 32.1, WP00): typisierte, leere Modulgrenzen. Jede\n");
    out.push_str("// Funktion hier ist die spezifizierte Portgrenze, nicht eine Attrappe;\n");
    out.push_str("// ihr Koerper wird erst realisiert, wenn das jeweilige Modul an der Reihe\n");
    out.push_str("// ist (Regel 32.2, Reihenfolgezwang).\n\n");
    if emitted == 0 {
        out.push_str("// Kein Modul dieses Pakets ist Erzeuger oder Verbraucher an einem\n");
        out.push_str("// konkreten (nicht-Wildcard-) Port. Das ist bei Paketen ohne eigenes\n");
        out.push_str("// Portregister-Modul (psk-conformance, psk-cli) erwartet.\n");
    } else {
        out.push_str("use psk_types::{payloads, Msg, PortId, PskError};\n\n");
        out.push_str(&body);
    }
    out
}
