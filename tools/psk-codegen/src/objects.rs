//! Codegen fuer architecture/sort_registry.yaml (SortId) und
//! architecture/object_schemas.yaml (die kanonischen Objektstrukturen -
//! Anzahl bewusst hier nicht genannt, siehe `OBJECT_COUNT` unten: die
//! Zahl driftete bereits dreimal aus handgepflegten Kommentaren, siehe
//! object_registry.yaml-Laenge statt Literal) plus die referenzierten, im
//! Werk nicht selbst strukturell definierten Vokabulartypen. Ein
//! Feldtyp, der keine der bekannten Primitiven ist und kein
//! nested_struct-Verweis, wird als opaker String-Newtype erzeugt statt
//! eine im Text nicht gegebene innere Struktur zu erfinden.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

// ---------------------------------------------------------------- Sorten

#[derive(Debug, Deserialize)]
pub struct SortRegistry {
    pub sorts: Vec<SortEntry>,
    #[serde(default)]
    pub port_matrix: Vec<Vec<String>>,
    #[serde(default)]
    pub closed_vocabularies: Vec<ClosedVocabulary>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SortEntry {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub cell_class: String,
}

/// Eine geschlossene Wertemenge (z.B. RealityStatus, FactStatus, OpId).
/// Ohne diesen Eintrag wuerde der Typname in object_schemas.yaml auf einen
/// freien String-Newtype abgebildet - eine geschlossene Menge DARF aber
/// nicht erweiterbar sein.
///
/// Genau eines von `values` und `values_from` MUSS gesetzt sein.
/// `values_from` verweist auf das Register, das die Menge bereits fuehrt,
/// statt sie ein zweites Mal aufzuschreiben.
#[derive(Debug, Deserialize, Clone)]
pub struct ClosedVocabulary {
    pub id: String,
    pub source: String,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default)]
    pub values_from: Option<ValuesFrom>,
}

/// Verweis auf die Wertemenge in einem anderen Register.
/// `path` hat die Form "feld[].unterfeld" (Liste von Abbildungen) oder
/// "feld[].N" (Liste von Listen, N-tes Element, nullbasiert).
#[derive(Debug, Deserialize, Clone)]
pub struct ValuesFrom {
    pub register: String,
    pub path: String,
}

/// Loest `values_from` gegen die bereits geladenen Register auf. Panikt
/// laut, wenn der Verweis ins Leere geht: ein stillschweigend leeres Enum
/// waere schlimmer als ein Buildabbruch.
fn resolve_values(v: &ClosedVocabulary, root: &Path) -> Vec<String> {
    let Some(from) = &v.values_from else {
        assert!(
            !v.values.is_empty(),
            "closed_vocabulary {} hat weder values noch values_from",
            v.id
        );
        return v.values.clone();
    };
    assert!(
        v.values.is_empty(),
        "closed_vocabulary {} hat values UND values_from - genau eines ist zulaessig",
        v.id
    );

    let doc: serde_yaml::Value =
        crate::load_yaml(root, &format!("architecture/{}.yaml", from.register));
    let (field, item_path) = from
        .path
        .split_once("[].")
        .unwrap_or_else(|| panic!("closed_vocabulary {}: path ohne '[].'", v.id));
    let list = doc
        .get(field)
        .and_then(|x| x.as_sequence())
        .unwrap_or_else(|| panic!("closed_vocabulary {}: {field} ist keine Liste", v.id));

    let values: Vec<String> = list
        .iter()
        .map(|item| {
            let picked = match item_path.parse::<usize>() {
                Ok(i) => item.as_sequence().and_then(|s| s.get(i)),
                Err(_) => item.get(item_path),
            };
            picked
                .and_then(|x| x.as_str())
                .unwrap_or_else(|| {
                    panic!(
                        "closed_vocabulary {}: {item_path} fehlt in einem Eintrag",
                        v.id
                    )
                })
                .to_string()
        })
        .collect();

    // Wiederholungen sind zulaessig (die Portmatrix nennt Relationen
    // mehrfach); die Wertemenge selbst bleibt eine Menge.
    let mut seen = BTreeSet::new();
    let unique: Vec<String> = values
        .into_iter()
        .filter(|x| seen.insert(x.clone()))
        .collect();
    assert!(
        !unique.is_empty(),
        "closed_vocabulary {}: values_from lieferte keine Werte",
        v.id
    );
    unique
}

pub fn load_sort_registry(root: &Path) -> SortRegistry {
    crate::load_yaml(root, "architecture/sort_registry.yaml")
}

/// Erzeugt fuer jede geschlossene Wertemenge ein eigenes Enum mit
/// `.id()`, `from_id()` und `ALL`. Der Aufrufer reicht dieselbe Liste an
/// `generate_object_structs` weiter, damit dort kein zweiter,
/// konkurrierender Typ gleichen Namens entsteht.
pub fn generate_closed_vocabularies(reg: &SortRegistry, root: &Path) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/sort_registry.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Geschlossene Wertemengen des Werkes.\n\n");
    for entry in &reg.closed_vocabularies {
        let resolved = resolve_values(entry, root);
        let v = ClosedVocabulary {
            values: resolved,
            values_from: None,
            ..entry.clone()
        };
        out.push_str(&format!("/// {} - {}\n", v.id, v.source));
        if let Some(from) = &entry.values_from {
            out.push_str(&format!(
                "/// Werte aus architecture/{}.yaml#{} - dort und nur dort gefuehrt.\n",
                from.register, from.path
            ));
        }
        if let Some(note) = &v.note {
            for line in note.lines() {
                out.push_str(&format!("/// {}\n", line.trim()));
            }
        }
        out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
        out.push_str(&format!("pub enum {} {{\n", v.id));
        for val in &v.values {
            out.push_str(&format!("    {},\n", sanitize_ident(val)));
        }
        out.push_str("}\n\n");

        out.push_str(&format!("impl {} {{\n", v.id));
        out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
        for val in &v.values {
            out.push_str(&format!(
                "            {}::{} => \"{}\",\n",
                v.id,
                sanitize_ident(val),
                val
            ));
        }
        out.push_str("        }\n    }\n\n");
        out.push_str(&format!(
            "    pub fn from_id(id: &str) -> Option<{}> {{\n        match id {{\n",
            v.id
        ));
        for val in &v.values {
            out.push_str(&format!(
                "            \"{}\" => Some({}::{}),\n",
                val,
                v.id,
                sanitize_ident(val)
            ));
        }
        out.push_str("            _ => None,\n        }\n    }\n\n");
        out.push_str(&format!(
            "    pub const ALL: [{}; {}] = [\n",
            v.id,
            v.values.len()
        ));
        for val in &v.values {
            out.push_str(&format!("        {}::{},\n", v.id, sanitize_ident(val)));
        }
        out.push_str("    ];\n}\n\n");

        out.push_str(&format!(
            "/// Drahtform: der Registerwert selbst.\nimpl serde::Serialize for {} {{\n",
            v.id
        ));
        out.push_str(
            "    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {\n",
        );
        out.push_str("        s.serialize_str(self.id())\n    }\n}\n\n");
        out.push_str(&format!(
            "impl<'de> serde::Deserialize<'de> for {} {{\n",
            v.id
        ));
        out.push_str(
            "    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {\n",
        );
        out.push_str("        let s = String::deserialize(d)?;\n");
        out.push_str(&format!(
            "        {}::from_id(&s).ok_or_else(|| serde::de::Error::custom(format!(\"unbekannter {}-Wert: {{s}}\")))\n",
            v.id, v.id
        ));
        out.push_str("    }\n}\n\n");
    }
    out
}

/// Erzeugt `enum SortId` mit den 19 Sorten (Invariante 5.2). Variantennamen
/// sind die `name`-Werte des Registers (bereits PascalCase); `.id()`
/// liefert die kanonische Kennung "S-IDT" etc.
pub fn generate_sort_id_enum(reg: &SortRegistry) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/sort_registry.yaml.\n");
    out.push_str(
        "// Nicht von Hand bearbeiten. Quelle: Invariante 5.2 (Sortenabschluss, |T|=19).\n\n",
    );
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("pub enum SortId {\n");
    for s in &reg.sorts {
        out.push_str(&format!(
            "    /// {} ({}), Owner {}, Zellklasse {}.\n",
            s.id, s.name, s.owner, s.cell_class
        ));
        out.push_str(&format!("    {},\n", s.name));
    }
    out.push_str("}\n\n");
    out.push_str("impl SortId {\n");
    out.push_str("    pub const fn id(self) -> &'static str {\n        match self {\n");
    for s in &reg.sorts {
        out.push_str(&format!(
            "            SortId::{} => \"{}\",\n",
            s.name, s.id
        ));
    }
    out.push_str("        }\n    }\n\n");
    out.push_str("    /// Umkehrung von `.id()`, z.B. \"S-IDT\" -> Some(SortId::Identity).\n");
    out.push_str("    pub fn from_id(id: &str) -> Option<SortId> {\n        match id {\n");
    for s in &reg.sorts {
        out.push_str(&format!(
            "            \"{}\" => Some(SortId::{}),\n",
            s.id, s.name
        ));
    }
    out.push_str("            _ => None,\n");
    out.push_str("        }\n    }\n\n");
    out.push_str(
        "    /// Zellklasse laut architecture/sort_registry.yaml (Regel 9.10, Platzierungsregel).\n",
    );
    out.push_str("    pub const fn cell_class(self) -> SortCellClass {\n        match self {\n");
    for s in &reg.sorts {
        let variant = match s.cell_class.as_str() {
            "center" => "Center",
            "bridge" => "Bridge",
            "boundary" => "Boundary",
            "cell_bound" => "CellBound",
            other => panic!("psk-codegen: unbekannte Zellklasse '{other}' in sort_registry.yaml"),
        };
        out.push_str(&format!(
            "            SortId::{} => SortCellClass::{},\n",
            s.name, variant
        ));
    }
    out.push_str("        }\n    }\n");
    out.push_str("}\n\n");

    out.push_str("/// Drahtform: die kanonische Kennung selbst (\"S-IDT\" etc.).\n");
    out.push_str("impl serde::Serialize for SortId {\n");
    out.push_str(
        "    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {\n",
    );
    out.push_str("        s.serialize_str(self.id())\n    }\n}\n\n");
    out.push_str("impl<'de> serde::Deserialize<'de> for SortId {\n");
    out.push_str(
        "    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {\n",
    );
    out.push_str("        let s = String::deserialize(d)?;\n");
    out.push_str("        SortId::from_id(&s).ok_or_else(|| serde::de::Error::custom(format!(\"unbekannte SortId: {s}\")))\n");
    out.push_str("    }\n}\n\n");

    out.push_str("/// Vier Gruppen aus Regel 9.10 (Platzierungsregel): drei feste Zellklassen\n");
    out.push_str(
        "/// plus \"zellgebunden\" (die Zelle des bereits geprueften Knotens, nicht frei\n",
    );
    out.push_str("/// waehlbar - siehe Regel 9.10 Punkt 4).\n");
    out.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str(
        "pub enum SortCellClass {\n    Center,\n    Bridge,\n    Boundary,\n    CellBound,\n}\n",
    );
    out
}

// ---------------------------------------------------------------- Objektschemas

#[derive(Debug, Deserialize)]
pub struct ObjectSchemas {
    pub objects: Vec<ObjectEntry>,
    /// Strukturen, die von MEHREREN Objekten referenziert werden (z.B.
    /// Scaled, Matrix - Struktur 7.27). Anders als `nested_structs` (je
    /// Objekt, dort auch erzeugt) wird jede hier genau einmal erzeugt und
    /// per Name referenziert; zwei Objekte, die dieselbe Struktur je
    /// eigenstaendig als nested_struct fuehren wuerden, kollidierten sonst.
    #[serde(default)]
    pub shared_structs: BTreeMap<String, Vec<FieldEntry>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ObjectEntry {
    pub id: String,
    pub name: String,
    pub fields: Vec<FieldEntry>,
    #[serde(default)]
    pub nested_structs: BTreeMap<String, Vec<FieldEntry>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct FieldEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(default)]
    pub nested_struct: Option<String>,
}

pub fn load_object_schemas(root: &Path) -> ObjectSchemas {
    crate::load_yaml(root, "architecture/object_schemas.yaml")
}

fn pascal_case(s: &str) -> String {
    s.split(|c: char| !c.is_alphanumeric())
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}

// Rust-Schluesselwoerter (strict + reserviert, Editions 2015-2021) — als
// Bezeichner nur ueber das r#-Praefix zulaessig.
const RUST_KEYWORDS: &[&str] = &[
    "as", "break", "const", "continue", "crate", "else", "enum", "extern", "false", "fn", "for",
    "if", "impl", "in", "let", "loop", "match", "mod", "move", "mut", "pub", "ref", "return",
    "self", "Self", "static", "struct", "super", "trait", "true", "type", "unsafe", "use", "where",
    "while", "async", "await", "dyn", "abstract", "become", "box", "do", "final", "macro",
    "override", "priv", "typeof", "unsized", "virtual", "yield", "try", "union",
];

fn escape_keyword(ident: &str) -> String {
    if RUST_KEYWORDS.contains(&ident) {
        format!("r#{ident}")
    } else {
        ident.to_string()
    }
}

/// Enum-Variantenname aus einem Quelltoken wie "SPLIT_PENDING", "PASS" oder
/// "internal": auf PascalCase normalisiert (jedes Wortsegment: erster
/// Buchstabe gross, Rest klein), damit weder SCREAMING_SNAKE_CASE noch
/// snake_case einen non_camel_case_types-Lint ausloest. Alle Quelltoken in
/// diesem Korpus sind konsistent ALL_CAPS(_WITH_UNDERSCORE) oder
/// all_lowercase(_with_underscore); keine Mischschreibung geht dabei verloren.
fn sanitize_ident(tok: &str) -> String {
    let t = tok.trim();
    let name: String = t
        .split(|c: char| !c.is_alphanumeric())
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect();
    let name = if name
        .chars()
        .next()
        .map(|c| c.is_ascii_digit())
        .unwrap_or(false)
    {
        format!("V{name}")
    } else {
        name
    };
    escape_keyword(&name)
}

// Diese Konstanten sind fuer den Zielort dieses Codegens geschrieben: das
// generierte Modul liegt als `pub mod objects { ... }` in psk-types selbst,
// direkt hinter dem SortId- und dem handgeschriebenen ObjectId-Code (siehe
// packages/psk-types/src/lib.rs). "crate::" adressiert daher psk-types'
// Wurzel; SortId/ObjectId sind ohne Praefix im selben Modul sichtbar.
const KNOWN_SCALARS: &[(&str, &str)] = &[
    ("Digest", "crate::Digest"),
    ("ObjectId", "crate::ObjectId"),
    ("DualTime", "crate::DualTime"),
    ("SortId", "SortId"),
    ("ModuleId", "crate::ModuleId"),
    ("PortId", "crate::PortId"),
    ("RunId", "crate::RunId"),
    ("Signature", "crate::Signature"),
    ("TraceRef", "crate::TraceRef"),
    // Die 21 Fehlercodes sind bereits als geschlossenes `PskError` aus
    // constitution/error_catalog.yaml generiert (Invariante 29.4,
    // Codestabilitaet). Ohne diesen Eintrag entstuende daneben ein freier
    // Zeichenketten-Newtype `ErrorCode` mit demselben Inhalt - zwei Stellen
    // fuer eine Menge.
    ("ErrorCode", "crate::PskError"),
    ("bool", "bool"),
    ("string", "String"),
    ("uint64", "u64"),
    // v1.0.26: RunDescriptor.ratchet_max_rounds (Regel 12.7) ist das
    // erste und bisher einzige uint32 des Werks.
    ("uint32", "u32"),
    // Struktur 7.27 (Scaled/Matrix): "integer" ohne "u"-Praefix, anders als
    // "uint64" andernorts - vorzeichenbehaftet gelesen, da nicht als
    // nichtnegativ bezeichnet (anders als bei `scale`, das laut Kommentar
    // "scale >= 0" ist, aber denselben Bezeichner "integer" traegt; die
    // Nichtnegativitaet von scale ist damit eine Wertebereichs-, keine
    // Typvorgabe und wird als Invariante geprueft, nicht im Typ erzwungen).
    ("integer", "i64"),
    ("bytes32", "[u8; 32]"),
    ("bytes", "Vec<u8>"),
];

/// Ergebnis der Typuebersetzung: der Rust-Typausdruck plus alle dabei neu
/// entdeckten opaken Vokabulartypen (werden vom Aufrufer gesammelt).
struct TypeGen<'a> {
    /// Praefix fuer generierte Feld-Enum-Namen (der umschliessende Struct-
    /// Name), damit z.B. CandidateCapsule.status und EvidenceObject.status
    /// nicht denselben "StatusKind"-Namen beanspruchen.
    owner: &'a str,
    /// Namen aller bereits (oder noch) generierten Structs — Top-Level-
    /// Objekte und ihre nested_structs. Ein Feldtyp, der auf einen dieser
    /// Namen verweist (z.B. IRBundle.graph.nodes: [IRNode]), referenziert
    /// die bestehende Struktur, statt faelschlich einen zweiten,
    /// gleichnamigen opaken Vokabulartyp zu erzeugen.
    known_structs: &'a BTreeSet<String>,
    vocabulary: &'a mut BTreeSet<String>,
    enums: &'a mut Vec<(String, String)>,
}

impl TypeGen<'_> {
    fn resolve(&mut self, field_name: &str, ty: &str, nested_struct: Option<&str>) -> String {
        if let Some(n) = nested_struct {
            // Die Listenklammer gilt auch fuer nested_structs: ein Feld
            // `{type: "[Step]", nested_struct: Step}` ist eine Liste von
            // Step, kein einzelnes Step. Vor dieser Korrektur ging die
            // Listeneigenschaft still verloren - ValidationPlan.steps
            // (Struktur 21.5) trug genau einen Schritt statt aller.
            let t = ty.trim();
            return if t.starts_with('[') && t.ends_with(']') {
                format!("Vec<{n}>")
            } else {
                n.to_string()
            };
        }
        let t = ty.trim();

        if let Some((_, rust)) = KNOWN_SCALARS.iter().find(|(k, _)| *k == t) {
            return rust.to_string();
        }

        // Literaler Schema-Tag, z.B. "psk.runtime-manifest/1.0".
        if t.contains('/') && t.contains('.') && !t.contains('|') && !t.starts_with('[') {
            return "String".to_string();
        }

        // "[[T]]" — verschachteltes Array.
        if let Some(inner) = t.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            let inner_ty = self.resolve(field_name, inner, None);
            return format!("Vec<Vec<{inner_ty}>>");
        }

        // "[T]" oder "[T, U]" (feste kleine Tupel als Array).
        if let Some(inner) = t.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            let items: Vec<&str> = inner.split(',').map(str::trim).collect();
            if items.len() > 1 {
                let first = self.resolve(field_name, items[0], None);
                let same = items.iter().all(|i| i.trim() == items[0].trim());
                if same {
                    return format!("[{first}; {}]", items.len());
                }
                let parts: Vec<String> = items
                    .iter()
                    .map(|i| self.resolve(field_name, i, None))
                    .collect();
                return format!("({})", parts.join(", "));
            }
            let inner_ty = self.resolve(field_name, items[0], None);
            return format!("Vec<{inner_ty}>");
        }

        // "map<K,V>".
        if let Some(inner) = t.strip_prefix("map<").and_then(|s| s.strip_suffix('>')) {
            let parts: Vec<&str> = inner.splitn(2, ',').map(str::trim).collect();
            if parts.len() == 2 {
                let k = self.resolve(field_name, parts[0], None);
                let v = self.resolve(field_name, parts[1], None);
                return format!("std::collections::BTreeMap<{k}, {v}>");
            }
        }

        // "A | B | C" — Enum. Rein numerische Alternativen ("1 | 2") werden
        // als kleine Ganzzahl behandelt, nicht als Bezeichner-Enum.
        if t.contains('|') {
            let alts: Vec<&str> = t.split('|').map(str::trim).collect();
            if alts.iter().all(|a| a.parse::<i64>().is_ok()) {
                return "u8".to_string();
            }

            // Eine Alternative kann selbst ein Typverweis sein statt eines
            // weiteren literalen Tags - z.B. "RollbackSpec |
            // NO_ROLLBACK_JUSTIFIED" (EffectToken.rollback, Struktur 7.33).
            // Erkennbar an gemischter Gross-/Kleinschreibung ohne
            // Unterstrich (anders als "PASS" oder "NO_ROLLBACK_JUSTIFIED").
            // Vor dieser Korrektur erzeugte eine solche Alternative nur
            // einen weiteren INHALTSLOSEN Tag (z.B. Variante "Rollbackspec"
            // ohne Nutzlast) - der eigentliche Wert (die Rollback-
            // Beschreibung) war damit unerreichbar, obwohl das Feld ihn
            // laut Registerkommentar tragen soll.
            let is_type_ref = |a: &str| {
                a.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && a.chars().any(|c| c.is_ascii_lowercase())
            };
            if let Some(type_ref) = alts.iter().find(|a| is_type_ref(a)) {
                let enum_name = format!("{}{}Kind", self.owner, pascal_case(field_name));
                let inner_ty = self.resolve(field_name, type_ref, None);
                let payload_variant = sanitize_ident(type_ref);
                let mut e = format!(
                    "#[derive(Debug, Clone, PartialEq)]\npub enum {enum_name} {{\n    {payload_variant}({inner_ty}),\n"
                );
                for a in alts.iter().filter(|a| *a != type_ref) {
                    e.push_str(&format!("    {},\n", sanitize_ident(a)));
                }
                e.push_str("}\n\n");
                // Handgeschriebene Serde-Impls statt derive: die
                // literalen Alternativen sind auf der Drahtform eigene
                // Zeichenketten (z.B. "NO_ROLLBACK_JUSTIFIED"), keine
                // getaggte Variante - dieselbe Drahtform, die ein opaker
                // Vokabulartyp fuer sich allein haette.
                e.push_str(&format!(
                    "impl serde::Serialize for {enum_name} {{\n    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {{\n        match self {{\n            {enum_name}::{payload_variant}(v) => v.serialize(s),\n"
                ));
                for a in alts.iter().filter(|a| *a != type_ref) {
                    e.push_str(&format!(
                        "            {enum_name}::{} => s.serialize_str(\"{}\"),\n",
                        sanitize_ident(a),
                        a
                    ));
                }
                e.push_str("        }\n    }\n}\n\n");
                e.push_str(&format!(
                    "impl<'de> serde::Deserialize<'de> for {enum_name} {{\n    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {{\n        let s = String::deserialize(d)?;\n        Ok(match s.as_str() {{\n"
                ));
                for a in alts.iter().filter(|a| *a != type_ref) {
                    e.push_str(&format!(
                        "            \"{a}\" => {enum_name}::{},\n",
                        sanitize_ident(a)
                    ));
                }
                e.push_str(&format!(
                    "            _ => {enum_name}::{payload_variant}({inner_ty}(s)),\n        }})\n    }}\n}}\n"
                ));
                self.enums.push((enum_name.clone(), e));
                return enum_name;
            }

            // Owner-Praefix macht den Namen eindeutig ueber alle Objekte
            // hinweg (mehrere Objekte haben z.B. je ein Feld "status" mit
            // unterschiedlichen Alternativen).
            let enum_name = format!("{}{}Kind", self.owner, pascal_case(field_name));
            let mut e = format!(
                "#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]\npub enum {enum_name} {{\n"
            );
            for a in &alts {
                e.push_str(&format!(
                    "    #[serde(rename = \"{}\")]\n    {},\n",
                    a,
                    sanitize_ident(a)
                ));
            }
            e.push_str("}\n");
            self.enums.push((enum_name.clone(), e));
            return enum_name;
        }

        // Verweist der Bezeichner auf ein bereits (oder anderswo im selben
        // Lauf) generiertes Struct — z.B. IRBundle.graph.nodes: [IRNode] —
        // dann dieses referenzieren statt einen kollidierenden
        // gleichnamigen Vokabulartyp zu erzeugen.
        let bare = pascal_case(t);
        if self.known_structs.contains(t) || self.known_structs.contains(&bare) {
            return bare;
        }

        // Bare Bezeichner ohne eigene Struktur im Werk (z.B. AdapterId,
        // ScopeExpr, BudgetSpec) — opaker Vokabulartyp, keine erfundene
        // innere Struktur.
        self.vocabulary.insert(bare.clone());
        bare
    }
}

fn generate_struct(
    name: &str,
    fields: &[FieldEntry],
    known_structs: &BTreeSet<String>,
    vocabulary: &mut BTreeSet<String>,
    enums: &mut Vec<(String, String)>,
) -> String {
    let mut out = format!(
        "#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]\npub struct {name} {{\n"
    );
    for f in fields {
        let mut gen = TypeGen {
            owner: name,
            known_structs,
            vocabulary,
            enums,
        };
        let mut ty = gen.resolve(&f.name, &f.ty, f.nested_struct.as_deref());
        if f.optional {
            ty = format!("Option<{ty}>");
            // Fehlender Schluessel <-> None (nicht null <-> None): ein aus
            // Can()'schem kanonischem JSON dekodiertes Objekt, dessen
            // optionales Feld fehlt, muss nach ir_encode(ir_decode(x))
            // wieder ohne diesen Schluessel serialisieren (Round-Trip-
            // Pflicht, Algorithmus 10.3).
            out.push_str("    #[serde(skip_serializing_if = \"Option::is_none\", default)]\n");
        }
        let field_name = escape_keyword(&f.name);
        out.push_str(&format!("    pub {field_name}: {ty},\n"));
    }
    out.push_str("}\n");
    out
}

/// Erzeugt alle kanonischen Objektstrukturen (inkl. ihrer nested_structs)
/// sowie am Ende die gesammelten opaken Vokabulartypen und Feld-Enums.
///
/// `closed_vocabularies` sind die Namen der in sort_registry.yaml
/// gefuehrten geschlossenen Wertemengen (RealityStatus, FactStatus). Sie
/// werden hier wie bereits bekannte Typen behandelt, damit kein zweiter,
/// erweiterbarer String-Newtype gleichen Namens entsteht - ihr Enum
/// erzeugt `generate_closed_vocabularies`.
pub fn generate_object_structs(
    schemas: &ObjectSchemas,
    closed_vocabularies: &BTreeSet<String>,
) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/object_schemas.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Struktur 7.1-7.45, 21.5, 22.5.\n");
    out.push_str("// Feldnamen I_C/I_A/I_M/I_t sind woertlich aus Regel 6.10 (siehe #![allow(non_snake_case)] am Modulkopf).\n\n");
    out.push_str(&format!(
        "/// Anzahl der kanonischen Objektstrukturen, direkt aus object_schemas.yaml's\n\
         /// tatsaechlicher Registerlaenge abgeleitet (nie von Hand pflegen - siehe\n\
         /// Modulkopf: diese Zahl driftete bereits dreimal in Prosa-Kommentaren).\n\
         pub const OBJECT_COUNT: usize = {};\n\n",
        schemas.objects.len()
    ));

    let mut known_structs: BTreeSet<String> = closed_vocabularies.clone();
    for obj in &schemas.objects {
        known_structs.insert(obj.name.clone());
        for nested_name in obj.nested_structs.keys() {
            known_structs.insert(nested_name.clone());
        }
    }
    for shared_name in schemas.shared_structs.keys() {
        known_structs.insert(shared_name.clone());
    }

    let mut vocabulary: BTreeSet<String> = BTreeSet::new();
    let mut enums: Vec<(String, String)> = Vec::new();

    out.push_str(
        "// ---- Geteilte Strukturen (mehrfach referenziert, je genau einmal erzeugt) ----\n\n",
    );
    for (shared_name, shared_fields) in &schemas.shared_structs {
        out.push_str(&generate_struct(
            shared_name,
            shared_fields,
            &known_structs,
            &mut vocabulary,
            &mut enums,
        ));
        out.push('\n');
    }

    for obj in &schemas.objects {
        out.push_str(&format!("/// {} ({})\n", obj.name, obj.id));
        out.push_str(&generate_struct(
            &obj.name,
            &obj.fields,
            &known_structs,
            &mut vocabulary,
            &mut enums,
        ));
        out.push('\n');
        for (nested_name, nested_fields) in &obj.nested_structs {
            out.push_str(&format!("/// Verschachtelt in {}.\n", obj.name));
            out.push_str(&generate_struct(
                nested_name,
                nested_fields,
                &known_structs,
                &mut vocabulary,
                &mut enums,
            ));
            out.push('\n');
        }
    }

    out.push_str("// ---- Feld-Enums (aus \"A | B | C\"-Alternativen, Name eindeutig je Struct.Feld) ----\n\n");
    for (_, code) in &enums {
        out.push_str(code);
        out.push('\n');
    }

    out.push_str("// ---- Opake Vokabulartypen: im Werk referenziert, aber nirgends mit\n");
    out.push_str("// einer eigenen Struktur X.Y definiert. Kein erfundener Feldinhalt.\n\n");
    for v in &vocabulary {
        out.push_str(&format!(
            "#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Default, serde::Serialize, serde::Deserialize)]\n#[serde(transparent)]\npub struct {v}(pub String);\n"
        ));
    }
    out
}

#[cfg(test)]
mod list_field_regression_tests {
    //! Generischer Test gegen die Fehlerklasse, die `ValidationPlan.steps`
    //! (v1.0.7) still brach: `nested_struct` kurzschloss vor der
    //! Listenbehandlung in `TypeGen::resolve`, sodass ein Feld mit
    //! `{type: "[Step]", nested_struct: Step}` als `steps: Step` statt
    //! `steps: Vec<Step>` generiert wurde - ein Objekt mit mehr als einem
    //! Schritt verlor stillschweigend alle bis auf den letzten.
    //!
    //! Statt den Fehler an einer Stelle (ein Rust-Fixture mit >= 2
    //! Elementen) erneut zu pruefen, prueft dieser Test JEDES Feld in
    //! JEDEM Objekt, jedem nested_struct und jedem shared_struct, dessen
    //! Registertyp mit "[" beginnt (die Array-Notation aus dem
    //! Header-Kommentar von object_schemas.yaml): der generierte Rust-Typ
    //! MUSS `Vec<...>` (bzw. `Option<Vec<...>>` bei optional) sein. Ein
    //! kuenftiges Listenfeld, das denselben Fehler wiederholt, faellt hier
    //! auf, ohne dass jemand mit mehr als einem Element testen muss.

    use super::*;

    /// Sucht `pub struct {name} { ... }` im generierten Code und liefert
    /// fuer jeden Feldnamen darin dessen Typtext (ohne `pub `, ohne
    /// abschliessendes Komma). Nur eine einfache Zeilenparse - die
    /// generierten Structs sind flach, ohne verschachtelte Klammern in
    /// Feldtypen ausser `Vec<...>`/`Option<...>`, die hier gerade geprueft
    /// werden.
    fn field_types_of(generated: &str, struct_name: &str) -> BTreeMap<String, String> {
        let marker = format!("pub struct {struct_name} {{");
        let start = generated.find(&marker).unwrap_or_else(|| {
            panic!("generierter Code enthaelt keine 'pub struct {struct_name}'")
        });
        let body_start = start + marker.len();
        let body_end = generated[body_start..]
            .find("\n}")
            .map(|i| body_start + i)
            .unwrap_or_else(|| {
                panic!("keine schliessende Klammer fuer struct {struct_name} gefunden")
            });
        let body = &generated[body_start..body_end];

        let mut fields = BTreeMap::new();
        for line in body.lines() {
            let line = line
                .trim()
                .trim_start_matches("#[serde(skip_serializing_if = \"Option::is_none\", default)]")
                .trim();
            let Some(rest) = line.strip_prefix("pub ") else {
                continue;
            };
            let Some((name, ty)) = rest.trim_end_matches(',').split_once(':') else {
                continue;
            };
            let name = name.trim().trim_start_matches("r#");
            fields.insert(name.to_string(), ty.trim().to_string());
        }
        fields
    }

    /// Prueft alle Listenfelder einer Feldliste (Objekt, nested_struct oder
    /// shared_struct) gegen den generierten Code.
    fn check_fields_are_vecs(struct_name: &str, schema_fields: &[FieldEntry], generated: &str) {
        let generated_types = field_types_of(generated, struct_name);
        for f in schema_fields {
            let ty = f.ty.trim();
            // "[T]" ist eine Liste; "[T, U]" ist ein festes kleines Tupel
            // (eigene Behandlung in TypeGen::resolve, generiert [T; N]) -
            // beide beginnen mit '[', nur die erste Form gehoert hierher.
            let is_homogeneous_list =
                ty.starts_with('[') && ty.ends_with(']') && !ty[1..ty.len() - 1].contains(',');
            if !is_homogeneous_list {
                continue;
            }
            let generated_ty = generated_types.get(&f.name).unwrap_or_else(|| {
                panic!(
                    "{struct_name}.{}: im generierten Code nicht gefunden",
                    f.name
                )
            });
            let expected_prefix = if f.optional { "Option<Vec<" } else { "Vec<" };
            assert!(
                generated_ty.starts_with(expected_prefix),
                "{struct_name}.{} ist im Register als Liste ({ty}) deklariert, \
                 generierter Typ ist aber '{generated_ty}' statt '{expected_prefix}...'",
                f.name
            );
        }
    }

    #[test]
    fn every_registered_list_field_generates_a_vec() {
        let root = crate::workspace_root(&std::env::current_dir().unwrap());
        let schemas = load_object_schemas(&root);
        let sort_registry = load_sort_registry(&root);
        let closed_vocab = crate::closed_vocabulary_names(&sort_registry);
        let generated = generate_object_structs(&schemas, &closed_vocab);

        let mut checked = 0usize;
        for obj in &schemas.objects {
            checked += obj
                .fields
                .iter()
                .filter(|f| f.ty.trim().starts_with('['))
                .count();
            check_fields_are_vecs(&obj.name, &obj.fields, &generated);
            for (name, fields) in &obj.nested_structs {
                checked += fields
                    .iter()
                    .filter(|f| f.ty.trim().starts_with('['))
                    .count();
                check_fields_are_vecs(name, fields, &generated);
            }
        }
        for (name, fields) in &schemas.shared_structs {
            checked += fields
                .iter()
                .filter(|f| f.ty.trim().starts_with('['))
                .count();
            check_fields_are_vecs(name, fields, &generated);
        }

        // Ein Test, der nichts prueft, weil sich die Registerform geaendert
        // hat, waere schlimmer als ein rotes Ergebnis - deshalb eine
        // Untergrenze statt eines blossen "lief durch".
        assert!(
            checked >= 20,
            "nur {checked} Listenfelder geprueft - Registerpfad vermutlich veraendert"
        );
    }
}
