//! Can() nach Algorithmus 6.1: parse YAML/JSON, kanonisiere, serialisiere
//! kompakt. Definition 6.5 (Objekt-ID), Definition 6.6 (Kollektionsdigest).
//!
//! ## Geltungsbereich (bewusste Abgrenzung, nicht stillschweigend verkuerzt)
//!
//! Can() ist formatagnostisch: es kennt YAML/JSON-Werte, aber keine
//! Feldsemantik. Zwei der in Vertrag 6.3 genannten verbotenen Formen sind
//! daher NICHT hier, sondern in der Schemapruefung (M03/SchemaValidator,
//! JSON-Schema `format`) zu Hause, weil sie Feldbedeutung voraussetzen, die
//! ein generischer Kanonisierer nicht hat:
//! - "Zeitzonen-lose Zeitstempel" — ob ein String ueberhaupt ein Zeitstempel
//!   ist (und ob ihm ein "Z"-Suffix fehlt, Struktur 6.10 tau_e), ist eine
//!   Schemafrage, keine generische YAML/JSON-Eigenschaft.
//! - "Sprachtags ohne BCP-47-Form" — ebenso schemaabhaengig.
//!
//! Was Can() selbst durchsetzt: gueltiges UTF-8, keine NaN/Infinity, keine
//! Gleitkommazahl ohne exakte Dezimaldarstellung, NFC-Normalisierung aller
//! Strings, rekursive Schluesselsortierung nach Codepoint, erhaltene
//! Array-Reihenfolge, kompakte Serialisierung ohne Whitespace.
//!
//! Zur Gleitkomma-Exaktheit: Vertrag 6.3 ("Verbotene Serialisierungsformen")
//! verbietet "Gleitkommazahlen ohne exakte Dezimaldarstellung" normativ und
//! fordert PSK-E102 dafuer — fail-closed ist hier Normverhalten, keine
//! Implementierungsentscheidung. Nur der Fall mit Bruchteil exakt null wird
//! als Ganzzahl anerkannt ("ganzzahlig wo exakt", Algorithmus 6.1); jede
//! sonstige Gleitkommazahl erzeugt PSK-E102, unabhaengig davon, ob sie bei
//! anderer Betrachtung "exakt genug" erscheinen mag.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use psk_types::{Digest, PskError};
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Media {
    Yaml,
    Json,
}

/// Kanonisierter Wertbaum. Objektschluessel sind ueber BTreeMap<String,_>
/// automatisch nach Byte-/Codepointreihenfolge sortiert (UTF-8 erhaelt
/// Codepointordnung bei byteweisem Vergleich). Array-Reihenfolge bleibt in
/// Vec erhalten (Invariante 6.2: identitaetsbildend, nicht sortieren).
#[derive(Debug, Clone, PartialEq)]
pub enum CanonValue {
    Null,
    Bool(bool),
    Int(i128),
    String(String),
    Array(Vec<CanonValue>),
    Object(BTreeMap<String, CanonValue>),
}

/// Ergebnis von Can(): kompakt serialisierte kanonische Bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBytes(pub Vec<u8>);

impl CanonicalBytes {
    /// H(Can(f)) — die Digest-Haelfte von Definition 6.5/6.6/Regel 6.7.
    pub fn digest(&self) -> Digest {
        Digest::sha256(&self.0)
    }
}

/// Can(bytes, media) -> CanonicalBytes, Algorithmus 6.1.
pub fn can(bytes: &[u8], media: Media) -> Result<CanonicalBytes, PskError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PskError::CanonicalizationFailed)?;
    let raw = parse(text, media)?;
    let normalized = normalize(raw)?;
    let json = serialize_compact(&normalized);
    Ok(CanonicalBytes(json.into_bytes()))
}

fn parse(text: &str, media: Media) -> Result<RawValue, PskError> {
    match media {
        Media::Json => serde_json::from_str(text).map_err(|_| PskError::CanonicalizationFailed),
        Media::Yaml => {
            let v: serde_yaml::Value =
                serde_yaml::from_str(text).map_err(|_| PskError::CanonicalizationFailed)?;
            yaml_to_raw(v)
        }
    }
}

/// Zwischenform vor der Normalisierung: unterscheidet Ganzzahl/Gleitkomma,
/// damit normalize() ueber "ganzzahlig wo exakt" (Algorithmus 6.1) und die
/// Gleitkomma-Ablehnung (Vertrag 6.3) entscheiden kann, statt dass der
/// Parser das bereits verdeckt vorwegnimmt.
enum RawValue {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    String(String),
    Array(Vec<RawValue>),
    Object(Vec<(String, RawValue)>),
}

impl<'de> serde::Deserialize<'de> for RawValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = RawValue;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON value")
            }
            fn visit_unit<E>(self) -> Result<RawValue, E> {
                Ok(RawValue::Null)
            }
            fn visit_bool<E>(self, v: bool) -> Result<RawValue, E> {
                Ok(RawValue::Bool(v))
            }
            fn visit_i64<E>(self, v: i64) -> Result<RawValue, E> {
                Ok(RawValue::Int(v as i128))
            }
            fn visit_u64<E>(self, v: u64) -> Result<RawValue, E> {
                Ok(RawValue::Int(v as i128))
            }
            fn visit_f64<E>(self, v: f64) -> Result<RawValue, E> {
                Ok(RawValue::Float(v))
            }
            fn visit_str<E>(self, v: &str) -> Result<RawValue, E> {
                Ok(RawValue::String(v.to_string()))
            }
            fn visit_string<E>(self, v: String) -> Result<RawValue, E> {
                Ok(RawValue::String(v))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<RawValue, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some(v) = seq.next_element()? {
                    out.push(v);
                }
                Ok(RawValue::Array(out))
            }
            fn visit_map<A>(self, mut map: A) -> Result<RawValue, A::Error>
            where
                A: serde::de::MapAccess<'de>,
            {
                let mut out = Vec::new();
                while let Some((k, v)) = map.next_entry::<String, RawValue>()? {
                    out.push((k, v));
                }
                Ok(RawValue::Object(out))
            }
        }
        deserializer.deserialize_any(V)
    }
}

fn yaml_to_raw(v: serde_yaml::Value) -> Result<RawValue, PskError> {
    match v {
        serde_yaml::Value::Null => Ok(RawValue::Null),
        serde_yaml::Value::Bool(b) => Ok(RawValue::Bool(b)),
        serde_yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(RawValue::Int(i as i128))
            } else if let Some(u) = n.as_u64() {
                Ok(RawValue::Int(u as i128))
            } else if let Some(f) = n.as_f64() {
                Ok(RawValue::Float(f))
            } else {
                Err(PskError::CanonicalizationFailed)
            }
        }
        serde_yaml::Value::String(s) => Ok(RawValue::String(s)),
        serde_yaml::Value::Sequence(seq) => Ok(RawValue::Array(
            seq.into_iter().map(yaml_to_raw).collect::<Result<_, _>>()?,
        )),
        serde_yaml::Value::Mapping(map) => {
            let mut out = Vec::with_capacity(map.len());
            for (k, v) in map {
                let key = match k {
                    serde_yaml::Value::String(s) => s,
                    _non_string_key => return Err(PskError::CanonicalizationFailed),
                };
                out.push((key, yaml_to_raw(v)?));
            }
            Ok(RawValue::Object(out))
        }
        serde_yaml::Value::Tagged(t) => yaml_to_raw(t.value),
    }
}

/// normalize_scalars + sort_object_keys_recursive (Algorithmus 6.1).
fn normalize(v: RawValue) -> Result<CanonValue, PskError> {
    match v {
        RawValue::Null => Ok(CanonValue::Null),
        RawValue::Bool(b) => Ok(CanonValue::Bool(b)),
        RawValue::Int(i) => Ok(CanonValue::Int(i)),
        RawValue::Float(f) => {
            if !f.is_finite() {
                // NaN/Infinity — Vertrag 6.3, PSK-E102.
                return Err(PskError::CanonicalizationFailed);
            }
            if f.fract() == 0.0 && f.abs() < 1.0e18 {
                // "ganzzahlig wo exakt" — Algorithmus 6.1.
                Ok(CanonValue::Int(f as i128))
            } else {
                // Gleitkommazahl ohne bewiesene exakte Dezimaldarstellung —
                // Vertrag 6.3, PSK-E102 (siehe Modulkommentar: bewusst
                // fail-closed statt einer ungeprueften Naeherung).
                Err(PskError::CanonicalizationFailed)
            }
        }
        RawValue::String(s) => {
            // Vertrag 6.3: Unicode wird in NFC normalisiert.
            let nfc: String = s.nfc().collect();
            Ok(CanonValue::String(nfc))
        }
        RawValue::Array(arr) => {
            let items = arr
                .into_iter()
                .map(normalize)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(CanonValue::Array(items))
        }
        RawValue::Object(obj) => {
            let mut map = BTreeMap::new();
            for (k, v) in obj {
                let key: String = k.nfc().collect();
                map.insert(key, normalize(v)?);
            }
            Ok(CanonValue::Object(map))
        }
    }
}

/// json_compact_serialize (Algorithmus 6.1): Trennzeichen "," und ":", kein
/// Whitespace. Objektschluessel sind durch BTreeMap bereits sortiert;
/// Array-Reihenfolge bleibt exakt wie im Quellbaum.
fn serialize_compact(v: &CanonValue) -> String {
    let mut out = String::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &CanonValue, out: &mut String) {
    match v {
        CanonValue::Null => out.push_str("null"),
        CanonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        CanonValue::Int(i) => {
            let _ = write!(out, "{i}");
        }
        CanonValue::String(s) => write_json_string(s, out),
        CanonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        CanonValue::Object(map) => {
            out.push('{');
            for (i, (k, v)) in map.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_json_string(k, out);
                out.push(':');
                write_value(v, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Definition 6.5 (Objekt-ID): id(o) = psk:s:H(Can(o)).
pub fn object_id(sort: &str, canonical: &CanonicalBytes) -> String {
    format!("psk:{sort}:{}", canonical.digest())
}

/// Definition 6.6 (Kollektionsdigest): I = H(concat_k(name(f_k) || 0x00 ||
/// H(Can(f_k)) || LF)). `files` MUSS bereits in der normativen Reihenfolge
/// vorliegen (ordnungssemantische Liste, Definition 10.5) — diese Funktion
/// sortiert nicht um.
pub fn collection_digest(files: &[(&str, &CanonicalBytes)]) -> Digest {
    let mut buf = Vec::new();
    for (name, canon) in files {
        buf.extend_from_slice(name.as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(canon.digest().to_string().as_bytes());
        buf.push(b'\n');
    }
    Digest::sha256(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idempotent_can_of_can() {
        let src = br#"{"b": 2, "a": [3,1,2], "c": {"z": 1, "y": 2}}"#;
        let once = can(src, Media::Json).unwrap();
        let twice = can(&once.0, Media::Json).unwrap();
        assert_eq!(once, twice, "Can(Can(x)) muss Can(x) sein (Invariante 6.2)");
    }

    #[test]
    fn object_keys_sorted_array_order_preserved() {
        let src = br#"{"b": 1, "a": 2}"#;
        let out = can(src, Media::Json).unwrap();
        assert_eq!(String::from_utf8(out.0).unwrap(), r#"{"a":2,"b":1}"#);

        let src = br#"[3,1,2]"#;
        let out = can(src, Media::Json).unwrap();
        assert_eq!(String::from_utf8(out.0).unwrap(), "[3,1,2]");
    }

    #[test]
    fn yaml_and_json_of_equivalent_content_match() {
        let yaml = b"a: 1\nb: [1, 2, 3]\n";
        let json = br#"{"a": 1, "b": [1,2,3]}"#;
        assert_eq!(
            can(yaml, Media::Yaml).unwrap(),
            can(json, Media::Json).unwrap()
        );
    }

    #[test]
    fn exact_integer_float_normalizes_to_int() {
        let src = br#"{"n": 5.0}"#;
        let out = can(src, Media::Json).unwrap();
        assert_eq!(String::from_utf8(out.0).unwrap(), r#"{"n":5}"#);
    }

    #[test]
    fn non_integer_float_rejected() {
        let src = br#"{"n": 0.1}"#;
        assert!(can(src, Media::Json).is_err());
    }

    #[test]
    fn nan_and_infinity_rejected() {
        assert!(can(b"n: .nan\n", Media::Yaml).is_err());
        assert!(can(b"n: .inf\n", Media::Yaml).is_err());
    }

    #[test]
    fn comments_and_key_order_are_not_identity_forming() {
        let a = b"# comment\nb: 1\na: 2\n";
        let b = b"a: 2 # trailing\nb: 1\n";
        assert_eq!(can(a, Media::Yaml).unwrap(), can(b, Media::Yaml).unwrap());
    }

    #[test]
    fn array_order_is_identity_forming() {
        let a = can(br#"[1,2,3]"#, Media::Json).unwrap();
        let b = can(br#"[3,2,1]"#, Media::Json).unwrap();
        assert_ne!(
            a, b,
            "Invariante 6.2: Arrayreihenfolge ist identitaetsbildend"
        );
    }

    #[test]
    fn invalid_utf8_rejected() {
        let bytes = [0xFF, 0xFE, 0x00];
        assert!(can(&bytes, Media::Json).is_err());
    }

    #[test]
    fn collection_digest_is_order_sensitive() {
        let a = can(br#"{"x":1}"#, Media::Json).unwrap();
        let b = can(br#"{"y":2}"#, Media::Json).unwrap();
        let d1 = collection_digest(&[("a.yaml", &a), ("b.yaml", &b)]);
        let d2 = collection_digest(&[("b.yaml", &b), ("a.yaml", &a)]);
        assert_ne!(d1, d2);
    }

    #[test]
    fn object_id_format() {
        let v = can(br#"{"a":1}"#, Media::Json).unwrap();
        let id = object_id("S-IDT", &v);
        assert!(id.starts_with("psk:S-IDT:"));
        assert_eq!(id.len(), "psk:S-IDT:".len() + 64);
    }
}
