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
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
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

/// Laeufer-Kennung, referenziert u.a. in RunDescriptor (Struktur 7.45) und
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
/// (segment_digest: Digest, Struktur 7.40); ein Verweis darauf ist damit
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
///
/// `Serialize`/`Deserialize` (P24a): die kanonische Drahtform fuer die
/// Nachrichtenhuelle, sobald sie eine echte Prozessgrenze ueberquert - wie
/// bei `ModuleId`/`PortId` (oben, ueber ihre kanonische String-Kennung)
/// und `ExternalReceipt`/P24 (`serde_json::to_vec`/`from_slice`, bereits
/// etabliert) keine neue Kodierung, sondern dieselbe serde_json-Form wie
/// ueberall sonst in diesem Werk.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModuleId, PortId};

    fn sample_msg() -> Msg {
        Msg {
            msg_id: Ulid(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
            port_id: PortId::P24,
            r#type: MessageType::Event,
            schema_id: SchemaId("psk.external-receipt/1.0".into()),
            producer: ModuleId::ExternalRecordIngress,
            consumer: ModuleId::ReconciliationEngine,
            run_id: RunId("golden-run".into()),
            seq: 1,
            input_digests: vec![crate::Digest::sha256(b"input")],
            created_at: DualTime {
                tau_i: 1,
                tau_e: "2026-08-05T00:00:00.000000000Z".into(),
                clock_ref: ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            trace_parent: TraceRef(crate::Digest::sha256(b"trace")),
            payload_digest: crate::Digest::sha256(b"payload"),
            payload: b"hello ipc".to_vec(),
            signature: None,
        }
    }

    #[test]
    fn msg_round_trips_through_json() {
        let original = sample_msg();
        let bytes = serde_json::to_vec(&original).expect("Msg muss serialisierbar sein");
        let parsed: Msg = serde_json::from_slice(&bytes).expect("Msg muss deserialisierbar sein");
        assert_eq!(original, parsed);
    }

    #[test]
    fn port_id_and_module_id_use_their_canonical_string_id_on_the_wire() {
        // Ueber echte Bytes, nicht `serde_json::to_value` direkt: Ulids u128
        // uebersteigt den Zahlenbereich, den `serde_json::Value` ohne das
        // Feature `arbitrary_precision` intern darstellen kann - dieselbe
        // Serialisierung ueber `to_vec`/`from_slice` (die reale Drahtform)
        // hat dieses Problem nicht, siehe `msg_round_trips_through_json`.
        let bytes = serde_json::to_vec(&sample_msg()).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["port_id"], "P24");
        assert_eq!(value["producer"], "M17");
        assert_eq!(value["consumer"], "M18");
        // r#type: Rust-Rohbezeichner-Praefix darf nicht ins Feld durchschlagen.
        assert_eq!(value["type"], "event");
    }
}
