//! Codegen fuer architecture/sort_registry.yaml (SortId) und
//! architecture/object_schemas.yaml (die 25 kanonischen Objektstrukturen
//! plus die referenzierten, im Werk nicht selbst strukturell definierten
//! Vokabulartypen). Ein Feldtyp, der keine der bekannten Primitiven ist
//! und kein nested_struct-Verweis, wird als opaker String-Newtype erzeugt
//! statt eine im Text nicht gegebene innere Struktur zu erfinden.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

// ---------------------------------------------------------------- Sorten

#[derive(Debug, Deserialize)]
pub struct SortRegistry {
    pub sorts: Vec<SortEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SortEntry {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub cell_class: String,
}

pub fn load_sort_registry(root: &Path) -> SortRegistry {
    crate::load_yaml(root, "architecture/sort_registry.yaml")
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
        "    /// Zellklasse laut architecture/sort_registry.yaml (Regel 9.9, Platzierungsregel).\n",
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

    out.push_str("/// Vier Gruppen aus Regel 9.9 (Platzierungsregel): drei feste Zellklassen\n");
    out.push_str(
        "/// plus \"zellgebunden\" (die Zelle des bereits geprueften Knotens, nicht frei\n",
    );
    out.push_str("/// waehlbar - siehe Regel 9.9 Punkt 4).\n");
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
    ("bool", "bool"),
    ("string", "String"),
    ("uint64", "u64"),
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
            return n.to_string();
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

/// Erzeugt alle 25 kanonischen Objektstrukturen (inkl. ihrer nested_structs)
/// sowie am Ende die gesammelten opaken Vokabulartypen und Feld-Enums.
pub fn generate_object_structs(schemas: &ObjectSchemas) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus architecture/object_schemas.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Struktur 7.1-7.38, 21.5, 22.5.\n");
    out.push_str("// Feldnamen I_C/I_A/I_M/I_t sind woertlich aus Regel 6.7 (siehe #![allow(non_snake_case)] am Modulkopf).\n\n");

    let mut known_structs: BTreeSet<String> = BTreeSet::new();
    for obj in &schemas.objects {
        known_structs.insert(obj.name.clone());
        for nested_name in obj.nested_structs.keys() {
            known_structs.insert(nested_name.clone());
        }
    }

    let mut vocabulary: BTreeSet<String> = BTreeSet::new();
    let mut enums: Vec<(String, String)> = Vec::new();

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
