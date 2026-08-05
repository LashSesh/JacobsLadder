//! M19 TraceReplayResidueStore, Trace-Teil (Struktur 7.38, OBJ-TRC).
//!
//! Regel 8.2 (Erzeugung), dritte Pflicht: "ein TraceSegment ueber P28
//! schreiben." Invariante 4.8 (Trace vor Wirkung): "der TraceSegment-
//! Schreibvorgang fuer delta ist in der kanonischen Ordnung strikt vor der
//! Sichtbarkeit von delta an irgendeinem Port abgeschlossen." `append`
//! gibt das versiegelte Segment erst nach vollstaendiger Kettenbildung
//! zurueck - ein Aufrufer, der es vor dem Schreiben an einen Port
//! weitergibt, kann das strukturell nicht, weil es vorher nicht existiert.
//!
//! `run_id` steht im Feldkommentar ("seq: uint64 # global monoton je
//! run_id"), ist aber KEIN Feld von TraceSegment selbst (Struktur 7.38).
//! Ein `TraceStore` ist deshalb hier je Lauf instanziiert - die Bindung an
//! run_id ist Sache des Aufrufers (M26 haelt genau einen TraceStore pro
//! offenem Lauf), nicht der Struktur.

use psk_canon::{can, Media};
use psk_types::objects::EventTypeId;
use psk_types::{Digest, DualTime, ModuleId, ObjectId, PortId, PskError, Signature};

pub use psk_types::objects::TraceSegment;

/// "Genesis = 64x\"0\"" (Struktur 7.38): der Vorgaenger des allerersten
/// Segments ist der Nulldigest, kein SHA-256 von irgendetwas.
pub const GENESIS_DIGEST: Digest = Digest::from_bytes([0u8; 32]);

/// Eingaben fuer ein neues Segment. `seq`, `prev_digest` und
/// `segment_digest` fehlen: die Kette bestimmt sie, nicht der Aufrufer.
pub struct SegmentInputs {
    pub event_type: EventTypeId,
    pub module: ModuleId,
    pub port_id: Option<PortId>,
    pub object_refs: Vec<ObjectId>,
    pub payload_digest: Digest,
    pub time: DualTime,
    pub attestation: Option<Signature>,
}

/// `segment_digest = H(Can(alle vorstehenden Feldern))` (Struktur 7.38,
/// woertlich) - anders als die pi_vol-Selbstreferenzausschluesse an
/// anderer Stelle (ObjectId aus dem VOLLEN Objekt minus `id`) ist dies ein
/// einfacher Presegment-Hash: alle Felder ausser `segment_digest` selbst,
/// keine Vokabularausnahme.
fn compute_segment_digest(without_own_digest: &TraceSegment) -> Result<Digest, PskError> {
    let mut value =
        serde_json::to_value(without_own_digest).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("segment_digest");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(can(&bytes, Media::Json)?.digest())
}

/// Der Tracespeicher eines einzelnen, gerade offenen Laufs: eine
/// hashverkettete, ausschliesslich anhaengende Segmentfolge.
#[derive(Debug, Clone, Default)]
pub struct TraceStore {
    segments: Vec<TraceSegment>,
}

impl TraceStore {
    pub fn new() -> Self {
        TraceStore {
            segments: Vec::new(),
        }
    }

    /// Haengt ein neues Segment an. `seq` ist die aktuelle Laenge (0-basiert,
    /// global monoton je Lauf), `prev_digest` der Digest des letzten
    /// Segments oder `GENESIS_DIGEST`.
    pub fn append(&mut self, inputs: SegmentInputs) -> Result<&TraceSegment, PskError> {
        let prev_digest = self
            .segments
            .last()
            .map(|s| s.segment_digest)
            .unwrap_or(GENESIS_DIGEST);
        let seq = self.segments.len() as u64;

        let draft = TraceSegment {
            schema: "psk.trace-segment/1.0".to_string(),
            seq,
            prev_digest,
            event_type: inputs.event_type,
            module: inputs.module,
            port_id: inputs.port_id,
            object_refs: inputs.object_refs,
            payload_digest: inputs.payload_digest,
            time: inputs.time,
            attestation: inputs.attestation,
            segment_digest: GENESIS_DIGEST, // Platzhalter, s.u. ersetzt
        };
        let segment_digest = compute_segment_digest(&draft)?;
        self.segments.push(TraceSegment {
            segment_digest,
            ..draft
        });
        Ok(self.segments.last().expect("gerade angehaengt"))
    }

    pub fn segments(&self) -> &[TraceSegment] {
        &self.segments
    }

    pub fn head(&self) -> Digest {
        self.segments
            .last()
            .map(|s| s.segment_digest)
            .unwrap_or(GENESIS_DIGEST)
    }
}

/// Algorithmus 22.3: `require verify_chain(M19.trace(run_id)) else
/// FAIL(PSK-E014)`. Prueft `seq` (luecken- und wiederholungsfrei ab 0),
/// die Vorgaengerkette (erstes Segment gegen `GENESIS_DIGEST`) und dass
/// jeder gespeicherte `segment_digest` tatsaechlich aus den uebrigen
/// Feldern folgt - ein Segment kann also nicht nachtraeglich veraendert
/// worden sein, ohne dass die Kette bricht.
pub fn verify_chain(segments: &[TraceSegment]) -> Result<(), PskError> {
    let mut expected_prev = GENESIS_DIGEST;
    for (i, seg) in segments.iter().enumerate() {
        if seg.seq != i as u64 {
            return Err(PskError::TraceOrResidueViolation);
        }
        if seg.prev_digest != expected_prev {
            return Err(PskError::TraceOrResidueViolation);
        }
        let recomputed = compute_segment_digest(&TraceSegment {
            segment_digest: GENESIS_DIGEST,
            ..seg.clone()
        })?;
        if recomputed != seg.segment_digest {
            return Err(PskError::TraceOrResidueViolation);
        }
        expected_prev = seg.segment_digest;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs(module: ModuleId, event: &str) -> SegmentInputs {
        SegmentInputs {
            event_type: EventTypeId(event.into()),
            module,
            port_id: None,
            object_refs: vec![],
            payload_digest: Digest::sha256(event.as_bytes()),
            time: DualTime {
                tau_i: 0,
                tau_e: "2026-08-04T00:00:00.000000000Z".into(),
                clock_ref: psk_types::ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            attestation: None,
        }
    }

    #[test]
    fn first_segment_chains_to_genesis() {
        let mut store = TraceStore::new();
        let seg = store
            .append(inputs(ModuleId::ThoughtCompiler, "created"))
            .unwrap()
            .clone();
        assert_eq!(seg.seq, 0);
        assert_eq!(seg.prev_digest, GENESIS_DIGEST);
    }

    #[test]
    fn seq_is_monotone_and_chain_links() {
        let mut store = TraceStore::new();
        store
            .append(inputs(ModuleId::ThoughtCompiler, "a"))
            .unwrap();
        let first_digest = store.head();
        store
            .append(inputs(ModuleId::ThoughtCompiler, "b"))
            .unwrap();
        assert_eq!(store.segments()[1].seq, 1);
        assert_eq!(store.segments()[1].prev_digest, first_digest);
    }

    #[test]
    fn a_valid_chain_verifies() {
        let mut store = TraceStore::new();
        for e in ["a", "b", "c"] {
            store.append(inputs(ModuleId::ThoughtCompiler, e)).unwrap();
        }
        assert_eq!(verify_chain(store.segments()), Ok(()));
    }

    #[test]
    fn an_empty_chain_verifies() {
        assert_eq!(verify_chain(&[]), Ok(()));
    }

    #[test]
    fn tampering_with_a_segment_breaks_the_chain() {
        let mut store = TraceStore::new();
        for e in ["a", "b"] {
            store.append(inputs(ModuleId::ThoughtCompiler, e)).unwrap();
        }
        let mut segments = store.segments().to_vec();
        segments[0].payload_digest = Digest::sha256(b"veraendert");
        // segment_digest[0] passt nicht mehr zu den (jetzt anderen) Feldern,
        // UND segment[1].prev_digest zeigt noch auf den alten Digest.
        assert_eq!(
            verify_chain(&segments),
            Err(PskError::TraceOrResidueViolation)
        );
    }

    #[test]
    fn reordering_segments_breaks_seq_or_prev_digest() {
        let mut store = TraceStore::new();
        for e in ["a", "b", "c"] {
            store.append(inputs(ModuleId::ThoughtCompiler, e)).unwrap();
        }
        let mut segments = store.segments().to_vec();
        segments.swap(0, 1);
        assert_eq!(
            verify_chain(&segments),
            Err(PskError::TraceOrResidueViolation)
        );
    }

    #[test]
    fn a_gap_in_seq_is_rejected() {
        let mut store = TraceStore::new();
        for e in ["a", "b"] {
            store.append(inputs(ModuleId::ThoughtCompiler, e)).unwrap();
        }
        let mut segments = store.segments().to_vec();
        segments.remove(0);
        assert_eq!(
            verify_chain(&segments),
            Err(PskError::TraceOrResidueViolation)
        );
    }

    #[test]
    fn appending_is_deterministic_given_the_same_inputs() {
        let mut a = TraceStore::new();
        let mut b = TraceStore::new();
        for store in [&mut a, &mut b] {
            store
                .append(inputs(ModuleId::ThoughtCompiler, "x"))
                .unwrap();
        }
        assert_eq!(a.head(), b.head());
    }
}
