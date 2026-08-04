//! Nachrichtenhuelle nach Struktur 4.1 und ihre unmittelbaren Feldtypen.
//!
//! Nur Typen, die Msg selbst als Felder traegt, werden hier definiert.
//! Die 19 Sorten und kanonischen Objekte aus Kapitel 7 sind Gegenstand von
//! WP02 (Core Types, Phase I1) und werden hier bewusst nicht vorweggenommen.

use crate::{Digest, ModuleId, PortId};

/// "monoton, kollisionsfrei, prozessweit" (Struktur 4.1). Nur der
/// Speichertyp ist hier festgelegt; ein Generator (Uhr-Anbindung,
/// Crockford-Base32-Textform) ist Laufzeitverhalten und folgt mit dem
/// Modul, das msg_id tatsaechlich vergibt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ulid(pub u128);

/// "type: MessageType # request | response | event | fault" (Struktur 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MessageType {
    #[serde(rename = "request")]
    Request,
    #[serde(rename = "response")]
    Response,
    #[serde(rename = "event")]
    Event,
    #[serde(rename = "fault")]
    Fault,
}

/// "schema_id: SchemaId # namespaced + versioniert" (Struktur 4.1),
/// z.B. "psk.trace-segment/1.0".
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SchemaId(pub String);

/// Laeufer-Kennung, referenziert u.a. in RunDescriptor (Struktur 7.34) und
/// jeder Msg (Struktur 4.1). Die Norm legt den Namen fest, nicht die
/// interne Darstellung; String ist die freizuegigste, unpraejudizierte Wahl.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct RunId(pub String);

/// "Identitaet und Kalibrierstatus der verwendeten Uhr" (Struktur 6.13).
/// Form nicht normativ festgelegt; opaker Bezeichner. Volatil (Definition
/// 6.5, "DualTime.clock_ref") - geht nicht in eine Objekt-ID ein.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct ClockRef(pub String);

/// DualTime nach Struktur 6.13. Volatil sind tau_e, clock_ref und
/// uncertainty_ns (Definition 6.5); tau_i ist es ausdruecklich NICHT
/// (Kausalzaehler, je run_id deterministisch und identitaetsbildend).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DualTime {
    /// Lamport-artiger Kausalzaehler, streng monoton je run_id.
    pub tau_i: u64,
    /// UTC, RFC3339Nano, Pflicht "Z"-Suffix.
    pub tau_e: String,
    pub clock_ref: ClockRef,
    pub uncertainty_ns: u64,
}

/// Verweis auf ein TraceSegment. TraceSegment ist inhaltsadressiert
/// (segment_digest: Digest, Struktur 7.30); ein Verweis darauf ist damit
/// folgerichtig selbst ein Digest, analog zur Objekt-ID-Bildung aus
/// Definition 6.6. Diese Abbildung ist eine Implementierungsentscheidung
/// im verbleibenden Raum, kein woertliches Zitat.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct TraceRef(pub Digest);

/// "signature: Signature?" — Primitive und Schluesselhaltung sind OBL-005
/// (Security Reduction), domaenenabhaengig zu deklarieren. Nur der
/// Speichertyp (Rohbytes) ist hier festgelegt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Signature(pub Vec<u8>);

/// Msg nach Struktur 4.1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Msg {
    pub msg_id: Ulid,
    pub port_id: PortId,
    /// Feldname im Register: "type" (Rust-Schluesselwort, daher r#type).
    pub r#type: MessageType,
    pub schema_id: SchemaId,
    pub producer: ModuleId,
    pub consumer: ModuleId,
    pub run_id: RunId,
    /// Deterministische Sequenz je (run_id, port_id) — Invariante 4.3.
    pub seq: u64,
    /// SHA-256 aller kausalen Eingaben.
    pub input_digests: Vec<Digest>,
    pub created_at: DualTime,
    pub trace_parent: TraceRef,
    pub payload_digest: Digest,
    /// Kanonisch serialisiert (Vertrag 4.2). Der Sortentyp des dekodierten
    /// Inhalts folgt mit WP02; bis dahin ist payload absichtlich roh.
    pub payload: Vec<u8>,
    /// "Pflicht an Vertrauensgrenzen" (Struktur 4.1) — welche Grenzen das
    /// sind, legt Kapitel 19 fest; die Durchsetzungspflicht selbst ist
    /// Laufzeitverhalten und hier nicht modelliert.
    pub signature: Option<Signature>,
}
