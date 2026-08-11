//! Can() nach Algorithmus 6.1: parse YAML/JSON, kanonisiere, serialisiere
//! kompakt. Definition 6.6 (Objekt-ID), Definition 6.9 (Kollektionsdigest).
//!
//! ## Geltungsbereich (bewusste Abgrenzung, nicht stillschweigend verkuerzt)
//!
//! Can() ist formatagnostisch: es kennt YAML/JSON-Werte, aber keine
//! Feldsemantik. Zwei der in Vertrag 6.3 genannten verbotenen Formen sind
//! daher NICHT hier, sondern in der Schemapruefung (M03/SchemaValidator,
//! JSON-Schema `format`) zu Hause, weil sie Feldbedeutung voraussetzen, die
//! ein generischer Kanonisierer nicht hat:
//! - "Zeitzonen-lose Zeitstempel" — ob ein String ueberhaupt ein Zeitstempel
//!   ist (und ob ihm ein "Z"-Suffix fehlt, Struktur 6.13 tau_e), ist eine
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
//!
//! ## Zwei getrennte Digestpfade (v1.0.5, Definition 6.5-6.8)
//!
//! Can() allein bildet `record_digest(o) = H(Can(o))` (Definition 6.7) -
//! ueber das VOLLSTAENDIGE Objekt einschliesslich seiner volatilen Felder
//! (z.B. DualTime.tau_e, die Wanduhr). Das ist absichtlich NICHT die
//! Objekt-ID: Definition 6.6 verlangt `id(o) = psk:s:H(Can(pi_vol(o)))`,
//! wobei `pi_vol` (Definition 6.5, `identity_projection()` unten) die in
//! architecture/volatile_fields.yaml gefuehrten Felder vorher rekursiv
//! entfernt. Ohne diese Trennung ginge z.B. die Wanduhr in die Objekt-ID
//! ein, und zwei inhaltsgleiche Laeufe erhielten verschiedene IDs -
//! Invariante 6.8 verbietet genau das ("gleiche Eingaben + gleicher
//! RunDescriptor => gleiche Objekt-ID; abweichende record_digests sind
//! zulaessig und kein Replaydefekt"). Verstoss erzeugt PSK-E015.

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
///
/// ## Warum das Feld privat ist
///
/// Wer `CanonicalBytes` direkt bilden kann, faelscht kanonische Bytes -
/// und damit JEDEN Digest darueber: `digest()`, `record_digest`,
/// `collection_digest`, ueber sie I_A, I_C und die
/// Zweitschichtidentitaeten. Die Kanonisierung waere dann eine
/// Behauptung des Aufrufers statt ein Ergebnis der Kanonisierung
/// (Algorithmus 6.1 (Can)).
///
/// Bis v1.0.12 war das Feld oeffentlich, und die Begruendung lautete,
/// dass es ausserhalb dieses Moduls niemand direkt konstruiert -
/// nachgemessen und zutreffend, aber folgenlos, und folgenlos ist nicht
/// dasselbe wie unmoeglich. Dieselbe Klasse wie das Loch, das
/// `GateReport` hatte, bevor `GateAuthorization` es schloss: dort war
/// die Autoritaet erfindbar, hier die Kanonizitaet. Sichtbar geworden
/// ist es an der NRAII-Seite, wo eine zweite Kanonisierung der von
/// QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)
/// benannte Verstoss waere - der Defekt selbst liegt aber hier.
///
/// Konstruieren duerfen nur die beiden Kanonisierungspfade dieses
/// Moduls, [`can`] (Definition 6.6 (Objekt-ID)) und
/// [`identity_projection`] (Definition 6.7 (Recorddigest)). Von
/// aussen ist der Weg verschlossen:
///
/// ```compile_fail,E0423
/// let _ = psk_canon::CanonicalBytes(vec![1, 2, 3]);
/// ```
///
/// Lesend bleibt alles offen - [`CanonicalBytes::as_bytes`] gibt die
/// Bytes heraus. Verschlossen ist das HEREINGEBEN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalBytes(Vec<u8>);

impl CanonicalBytes {
    /// H(Can(f)) — die Digest-Haelfte von Definition 6.6/6.7/6.9/Regel 6.10.
    pub fn digest(&self) -> Digest {
        Digest::sha256(&self.0)
    }

    /// Die kanonischen Bytes, lesend.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Die kanonischen Bytes, uebernommen.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Can(bytes, media) -> CanonicalBytes, Algorithmus 6.1. Kanonisiert das
/// VOLLSTAENDIGE Objekt (keine Feldentfernung) - Grundlage von
/// record_digest (Definition 6.7) und der Kollektionsdigests fuer
/// Registerdateien (Definition 6.9), die keine volatilen Felder tragen.
/// Fuer die Objekt-ID kanonischer Kapitel-7-Objekte NICHT direkt verwenden
/// - siehe `identity_projection()`.
pub fn can(bytes: &[u8], media: Media) -> Result<CanonicalBytes, PskError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PskError::CanonicalizationFailed)?;
    let raw = parse(text, media)?;
    let normalized = normalize(raw)?;
    let json = serialize_compact(&normalized);
    Ok(CanonicalBytes(json.into_bytes()))
}

include!(concat!(env!("OUT_DIR"), "/volatile_fields.rs"));

/// Prueft, ob `path` (die Kette der Objektschluessel von der Wurzel bis
/// zum aktuellen Feld, einschliesslich) mit dem Suffix eines Musters
/// uebereinstimmt - siehe Modulkopf von volatile_fields.rs. Ein
/// einsegmentiges Muster wie "tau_e" matcht daher an jeder Tiefe; ein
/// mehrsegmentiges wie ["claim","text"] verlangt uebereinstimmende
/// unmittelbare Elternschaft.
fn path_matches(path: &[String], pattern: &VolatileFieldPattern) -> bool {
    let n = pattern.path.len();
    if path.len() < n {
        return false;
    }
    let suffix = &path[path.len() - n..];
    let parents_match = suffix
        .iter()
        .zip(pattern.path.iter())
        .take(n - 1)
        .all(|(actual, expected)| actual == expected);
    if !parents_match {
        return false;
    }
    let last = suffix[n - 1].as_str();
    let last_pattern = pattern.path[n - 1];
    if pattern.prefix {
        last.starts_with(last_pattern)
    } else {
        last == last_pattern
    }
}

fn field_is_excluded(path: &[String]) -> bool {
    VOLATILE_FIELDS
        .iter()
        .chain(NON_CANONICAL_FIELDS.iter())
        .any(|p| path_matches(path, p))
}

/// pi_vol (Definition 6.5): entfernt die in architecture/volatile_fields.yaml
/// gefuehrten Felder (beide Gruppen: volatile UND non_canonical, v1.0.6
/// Fehlerkorrektur Punkt 8 - ein Mechanismus fuer beide) rekursiv aus einem
/// bereits normalisierten Wertbaum.
fn strip_volatile(v: &mut CanonValue) {
    let mut path = Vec::new();
    strip_volatile_at(v, &mut path);
}

fn strip_volatile_at(v: &mut CanonValue, path: &mut Vec<String>) {
    match v {
        CanonValue::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                path.push(k.clone());
                if field_is_excluded(path) {
                    map.remove(&k);
                } else if let Some(val) = map.get_mut(&k) {
                    strip_volatile_at(val, path);
                }
                path.pop();
            }
        }
        CanonValue::Array(items) => {
            for item in items.iter_mut() {
                strip_volatile_at(item, path);
            }
        }
        CanonValue::Null | CanonValue::Bool(_) | CanonValue::Int(_) | CanonValue::String(_) => {}
    }
}

/// Can(pi_vol(o)) — die Identitaetsprojektion aus Definition 6.5, Grundlage
/// der Objekt-ID (Definition 6.6: id(o) = psk:s:H(Can(pi_vol(o)))). Entfernt
/// volatile Felder VOR der Kanonisierung, nicht danach: Can() selbst bleibt
/// dadurch weiterhin formatagnostisch und feldunwissend (siehe Modulkopf).
pub fn identity_projection(bytes: &[u8], media: Media) -> Result<CanonicalBytes, PskError> {
    let text = std::str::from_utf8(bytes).map_err(|_| PskError::CanonicalizationFailed)?;
    let raw = parse(text, media)?;
    let mut normalized = normalize(raw)?;
    strip_volatile(&mut normalized);
    let json = serialize_compact(&normalized);
    Ok(CanonicalBytes(json.into_bytes()))
}

/// record_digest(o) = H(Can(o)) (Definition 6.7): sichert die Integritaet
/// der vollstaendig gespeicherten Bytes einschliesslich der volatilen
/// Felder. NICHT identitaetsbildend und NIE Eingabe einer Gate-Entscheidung
/// (Invariante 6.8) - nur `object_id()` ueber `identity_projection()` DARF
/// das.
pub fn record_digest(bytes: &[u8], media: Media) -> Result<Digest, PskError> {
    Ok(can(bytes, media)?.digest())
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

/// Definition 6.6 (Objekt-ID): id(o) = psk:s:H(Can(pi_vol(o))). Der
/// Aufrufer MUSS `canonical` ueber `identity_projection()` gebildet haben,
/// NICHT ueber `can()` — sonst ginge ein volatiles Feld (z.B.
/// DualTime.tau_e) faelschlich in die ID ein (Definition 6.5, Invariante
/// 6.8). Diese Funktion selbst formatiert nur; sie kann nicht erzwingen,
/// mit welchen Bytes sie aufgerufen wird.
pub fn object_id(sort: &str, canonical: &CanonicalBytes) -> String {
    format!("psk:{sort}:{}", canonical.digest())
}

/// Definition 6.9 (Kollektionsdigest): I = H(concat_k(name(f_k) || 0x00 ||
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
        let v = identity_projection(br#"{"a":1}"#, Media::Json).unwrap();
        let id = object_id("S-IDT", &v);
        assert!(id.starts_with("psk:S-IDT:"));
        assert_eq!(id.len(), "psk:S-IDT:".len() + 64);
    }

    #[test]
    fn identity_projection_strips_tau_e_clock_ref_uncertainty_ns() {
        // Definition 6.5: DualTime.tau_e/clock_ref/uncertainty_ns sind
        // volatil. Zwei "Laeufe", die sich NUR in der Wanduhr
        // unterscheiden, muessen dieselbe Identitaetsprojektion ergeben.
        let run_a = br#"{"time":{"tau_i":7,"tau_e":"2026-01-01T00:00:00Z","clock_ref":"host-a","uncertainty_ns":500}}"#;
        let run_b = br#"{"time":{"tau_i":7,"tau_e":"2027-06-15T12:30:00Z","clock_ref":"host-b","uncertainty_ns":999}}"#;
        let id_a = identity_projection(run_a, Media::Json).unwrap();
        let id_b = identity_projection(run_b, Media::Json).unwrap();
        assert_eq!(
            id_a, id_b,
            "Invariante 6.8: gleiche tau_i, verschiedene Wanduhr => gleiche Identitaetsprojektion"
        );
        assert_eq!(
            String::from_utf8(id_a.0).unwrap(),
            r#"{"time":{"tau_i":7}}"#
        );
    }

    #[test]
    fn record_digest_differs_while_object_id_matches() {
        // Kern von Invariante 6.8: "abweichende record_digests sind
        // zulaessig und kein Replaydefekt", solange die Objekt-ID (ueber
        // pi_vol) uebereinstimmt.
        let run_a = br#"{"time":{"tau_i":1,"tau_e":"2026-01-01T00:00:00Z"}}"#;
        let run_b = br#"{"time":{"tau_i":1,"tau_e":"2099-12-31T23:59:59Z"}}"#;

        let oid_a = object_id("S-IDT", &identity_projection(run_a, Media::Json).unwrap());
        let oid_b = object_id("S-IDT", &identity_projection(run_b, Media::Json).unwrap());
        assert_eq!(oid_a, oid_b, "Objekt-ID darf nicht von tau_e abhaengen");

        let rd_a = record_digest(run_a, Media::Json).unwrap();
        let rd_b = record_digest(run_b, Media::Json).unwrap();
        assert_ne!(
            rd_a, rd_b,
            "record_digest DARF sich unterscheiden (Definition 6.7) - das ist kein Defekt"
        );
    }

    #[test]
    fn tau_i_is_never_stripped() {
        // Definition 6.5, letzter Satz: "tau_i ist DARF NICHT volatil".
        let src = br#"{"tau_i": 42}"#;
        let out = identity_projection(src, Media::Json).unwrap();
        assert_eq!(String::from_utf8(out.0).unwrap(), r#"{"tau_i":42}"#);
    }

    #[test]
    fn not_removed_register_entries_never_match_an_exclusion_pattern() {
        // Regressionswaechter: architecture/volatile_fields.yaml fuehrt
        // tau_i explizit unter not_removed. Wuerde irgendein
        // volatile/non_canonical-Muster tau_i faelschlich treffen, waere
        // das ein Widerspruch im generierten Code selbst.
        for entry in NOT_REMOVED {
            let mut path: Vec<String> = entry.path.iter().map(|s| s.to_string()).collect();
            // Ein einzelnes Segment wie "tau_i" matcht an jeder Tiefe -
            // ein einelementiger Pfad genuegt, um field_is_excluded zu pruefen.
            if path.is_empty() {
                path.push(entry.source.to_string());
            }
            assert!(
                !field_is_excluded(&path),
                "not_removed-Eintrag '{}' wird faelschlich ausgeschlossen",
                entry.source
            );
        }
    }

    #[test]
    fn violation_error_code_is_psk_e015() {
        assert_eq!(VOLATILE_VIOLATION_ERROR, "PSK-E015");
    }

    #[test]
    fn non_canonical_claim_text_is_stripped_from_identity_but_kept_in_record() {
        // Axiom 7.10: "Das Feld claim.text geht nicht in Can ein; es wird
        // von pi_vol als non_canonical entfernt und ist damit weder
        // identitaetsbildend noch Gate-Eingabe. Im record_digest bleibt es
        // enthalten." Zwei ThoughtBodies, die sich NUR im Prosatext
        // unterscheiden, sind identitaetsgleich.
        let a = br#"{"claim":{"formal":"F","text":"Ein Satz."},"lineage":"l"}"#;
        let b = br#"{"claim":{"formal":"F","text":"Ein voellig anderer Satz."},"lineage":"l"}"#;

        let id_a = identity_projection(a, Media::Json).unwrap();
        let id_b = identity_projection(b, Media::Json).unwrap();
        assert_eq!(id_a, id_b, "claim.text darf nicht identitaetsbildend sein");
        assert_eq!(
            String::from_utf8(id_a.0).unwrap(),
            r#"{"claim":{"formal":"F"},"lineage":"l"}"#
        );

        assert_ne!(
            record_digest(a, Media::Json).unwrap(),
            record_digest(b, Media::Json).unwrap(),
            "im record_digest bleibt claim.text enthalten"
        );
    }

    #[test]
    fn multi_segment_pattern_requires_matching_parent() {
        // "ThoughtBody.claim.text" trifft nur ein "text" UNTER "claim" -
        // ein gleichnamiges Feld anderswo bleibt erhalten. Sonst wuerde
        // ein einzelnes Registermuster unbeabsichtigt den halben Baum
        // leeren.
        let src = br#"{"claim":{"text":"weg"},"note":{"text":"bleibt"}}"#;
        let out = identity_projection(src, Media::Json).unwrap();
        assert_eq!(
            String::from_utf8(out.0).unwrap(),
            r#"{"claim":{},"note":{"text":"bleibt"}}"#
        );
    }

    #[test]
    fn both_exclusion_groups_share_one_mechanism() {
        // v1.0.6 Fehlerkorrektur Punkt 8: "Es existiert kein zweiter
        // Ausschlusspfad neben diesem Register." Beide Gruppen wirken in
        // derselben Projektion, nicht in getrennten Durchlaeufen.
        assert!(!VOLATILE_FIELDS.is_empty());
        assert!(!NON_CANONICAL_FIELDS.is_empty());
        let src = br#"{"tau_e":"volatil","claim":{"text":"non_canonical","formal":"bleibt"}}"#;
        let out = identity_projection(src, Media::Json).unwrap();
        assert_eq!(
            String::from_utf8(out.0).unwrap(),
            r#"{"claim":{"formal":"bleibt"}}"#
        );
    }

    #[test]
    fn wildcard_prefix_pattern_strips_view_star_fields() {
        // "*.view_*": jedes Feld mit Praefix "view_" ist volatil.
        let src = br#"{"view_frame": "a", "view_reason": "b", "kept": 1}"#;
        let out = identity_projection(src, Media::Json).unwrap();
        assert_eq!(String::from_utf8(out.0).unwrap(), r#"{"kept":1}"#);
    }

    #[test]
    fn exact_wildcard_type_hint_fields_are_stripped() {
        // "*.runtime_metrics" und "*.persona_projection": exakter
        // Feldname, beliebiger (dokumentarischer) Typkontext.
        let src = br#"{"runtime_metrics": {"cpu": 1}, "persona_projection": "x", "kept": true}"#;
        let out = identity_projection(src, Media::Json).unwrap();
        assert_eq!(String::from_utf8(out.0).unwrap(), r#"{"kept":true}"#);
    }

    #[test]
    fn strip_volatile_recurses_into_arrays_and_nested_objects() {
        let src = br#"{"items":[{"tau_e":"x","keep":1},{"tau_e":"y","keep":2}]}"#;
        let out = identity_projection(src, Media::Json).unwrap();
        assert_eq!(
            String::from_utf8(out.0).unwrap(),
            r#"{"items":[{"keep":1},{"keep":2}]}"#
        );
    }

    #[test]
    fn identity_projection_is_idempotent() {
        let src = br#"{"tau_e":"x","tau_i":1,"a":2}"#;
        let once = identity_projection(src, Media::Json).unwrap();
        let twice = identity_projection(&once.0, Media::Json).unwrap();
        assert_eq!(once, twice);
    }
}
