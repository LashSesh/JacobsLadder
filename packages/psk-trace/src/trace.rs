//! M19 TraceReplayResidueStore, Trace-Teil (Struktur 7.41 (TraceSegment), OBJ-TRC).
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
//! run_id"), ist aber KEIN Feld von TraceSegment selbst (Struktur 7.41 (TraceSegment)).
//! Ein `TraceStore` ist deshalb hier je Lauf instanziiert - die Bindung an
//! run_id ist Sache des Aufrufers (M26 haelt genau einen TraceStore pro
//! offenem Lauf), nicht der Struktur.

use psk_canon::{can, identity_projection, Media};
use psk_types::objects::EventTypeId;
use psk_types::{Digest, DualTime, ModuleId, ObjectId, PortId, PskError, Signature};

pub use psk_types::objects::TraceSegment;

/// "Genesis = 64x\"0\"" (Struktur 7.41 (TraceSegment)): der Vorgaenger des allerersten
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

/// Die beiden Digests eines Segments (Struktur 7.41 (TraceSegment) / Regel 7.42 (Zwei Digests je Segment),
/// PSK-RA v1.0.20) ueber DIESELBE Feldmenge - alle Felder ausser den
/// beiden Digests selbst -, aber mit verschiedener Projektion:
///
/// - `segment_digest = H(Can(pi_vol(...)))` - identitaetsbildend, bildet
///   die Kette, geht ueber `L_t` in `I_t` ein.
/// - `segment_record_digest = H(Can(...))` - mit `tau_e`, sichert die
///   Integritaet der gespeicherten Bytes.
///
/// Regel 7.42 (Zwei Digests je Segment) nennt fuer `segment_record_digest` "dieselben Felder
/// einschliesslich tau_e" - deshalb hier eine Funktion, die beide aus
/// einem Vorbild bildet, statt zweier, die auseinanderlaufen koennten.
///
/// Befund (v1.0.19): die vorherige Fassung bildete NUR
/// `H(Can(alle vorstehenden Felder))` und zog damit `tau_e` in jeden
/// Kettendigest - gemessen ueber zwei Laeufe, die sich ausschliesslich in
/// der Wanduhr unterschieden und verschiedene Zustandsdigests erhielten.
/// PSK-RA v1.0.20 hat das an der Quelle aufgeloest (Fehlerkorrektur 24).
fn compute_segment_digests(draft: &TraceSegment) -> Result<(Digest, Digest), PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("segment_digest");
    obj.remove("segment_record_digest");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;

    let identity = identity_projection(&bytes, Media::Json)?.digest();
    let record = can(&bytes, Media::Json)?.digest();
    Ok((identity, record))
}

/// Der Tracespeicher eines einzelnen, gerade offenen Laufs: eine
/// hashverkettete, ausschliesslich anhaengende Segmentfolge.
///
/// `Serialize` (nicht `Deserialize`): der Store ist Teil von Sigma
/// (Definition 13.1, Position `Lt`) und geht damit in `I_t =
/// H(Can(Sigma_t))` ein - siehe `psk_scheduler::sigma_digest`. Die
/// Gegenrichtung fehlt bewusst: ein Tracespeicher entsteht ausschliesslich
/// durch `append` (Invariante 4.8, Kettenbildung), nie durch
/// Deserialisierung eines fremden Werts - sonst waere die Hashkette
/// umgehbar.
#[derive(Debug, Clone, Default, serde::Serialize)]
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
            segment_record_digest: GENESIS_DIGEST, // Platzhalter, s.u. ersetzt
        };
        let (segment_digest, segment_record_digest) = compute_segment_digests(&draft)?;
        self.segments.push(TraceSegment {
            segment_digest,
            segment_record_digest,
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

/// Welche der Pruefungen aus Regel 7.42 (Zwei Digests je Segment) gebrochen ist - und an welchem
/// Segment. Alle Faelle bilden auf denselben Fehlercode ab
/// (`PSK-E014 trace_or_residue_violation`, das geschlossene
/// Fehlervokabular kennt keinen zweiten fuer diesen Bereich); die
/// Unterscheidung liegt deshalb hier im Ergebnistyp, nicht in einem
/// erfundenen Code - dasselbe Muster wie `LensOutcome`/`ChargeOutcome`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainViolation {
    /// `seq` ist nicht lueckenlos ab 0 fortlaufend.
    SequenceOutOfOrder { at: u64 },
    /// Die Vorgaengerverkettung stimmt nicht (erstes Segment gegen
    /// `GENESIS_DIGEST`).
    PrevDigestMismatch { at: u64 },
    /// Kettenfortschreibung: der gespeicherte `segment_digest` folgt nicht
    /// aus den identitaetsbildenden Feldern. Bricht bei jeder inhaltlichen
    /// Aenderung - aber NICHT bei einer blossen Wanduhraenderung, die
    /// `pi_vol` ohnehin entfernt.
    SegmentDigestMismatch { at: u64 },
    /// Aufzeichnungsintegritaet: der gespeicherte `segment_record_digest`
    /// folgt nicht aus den vollstaendigen Feldern. GENAU dies bricht eine
    /// nachtraegliche Aenderung an `tau_e` - der Fall, den die
    /// Kettenpruefung seit v1.0.20 bewusst nicht mehr sieht.
    RecordDigestMismatch { at: u64 },
}

/// Algorithmus 22.5: `require verify_chain(M19.trace(run_id)) else
/// FAIL(PSK-E014)`.
///
/// Regel 7.42 (Zwei Digests je Segment): "verify_chain MUSS beides pruefen: die
/// Kettenfortschreibung ueber segment_digest und je Segment die
/// Aufzeichnungsintegritaet ueber segment_record_digest. Eine
/// nachtraegliche Aenderung an tau_e bricht damit die zweite Pruefung,
/// ohne die erste zu beruehren." Die Manipulationssicherheit geht durch
/// die Trennung also nicht verloren - sie liegt in der jeweils
/// zustaendigen der beiden Pruefungen.
pub fn verify_chain_detailed(segments: &[TraceSegment]) -> Result<(), ChainViolation> {
    let mut expected_prev = GENESIS_DIGEST;
    for (i, seg) in segments.iter().enumerate() {
        let at = i as u64;
        if seg.seq != at {
            return Err(ChainViolation::SequenceOutOfOrder { at });
        }
        if seg.prev_digest != expected_prev {
            return Err(ChainViolation::PrevDigestMismatch { at });
        }
        let (identity, record) = compute_segment_digests(&TraceSegment {
            segment_digest: GENESIS_DIGEST,
            segment_record_digest: GENESIS_DIGEST,
            ..seg.clone()
        })
        .map_err(|_| ChainViolation::SegmentDigestMismatch { at })?;

        if identity != seg.segment_digest {
            return Err(ChainViolation::SegmentDigestMismatch { at });
        }
        if record != seg.segment_record_digest {
            return Err(ChainViolation::RecordDigestMismatch { at });
        }
        expected_prev = seg.segment_digest;
    }
    Ok(())
}

/// Dieselbe Pruefung mit dem Fehlercode des geschlossenen Vokabulars -
/// die Form, die Algorithmus 22.5 woertlich nennt. Wer wissen muss,
/// WELCHE der beiden Pruefungen brach, ruft `verify_chain_detailed`.
pub fn verify_chain(segments: &[TraceSegment]) -> Result<(), PskError> {
    verify_chain_detailed(segments).map_err(|_| PskError::TraceOrResidueViolation)
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
    fn changing_the_wall_clock_breaks_the_record_check_not_the_chain() {
        // Regel 7.42 (Zwei Digests je Segment), der eigentliche Zweck der Zweiteilung: "Eine
        // nachtraegliche Aenderung an tau_e bricht damit die zweite
        // Pruefung, ohne die erste zu beruehren." Die
        // Manipulationssicherheit geht nicht verloren - sie wandert in die
        // zustaendige der beiden Pruefungen.
        let mut store = TraceStore::new();
        for e in ["a", "b"] {
            store.append(inputs(ModuleId::ThoughtCompiler, e)).unwrap();
        }
        let mut segments = store.segments().to_vec();
        segments[1].time.tau_e = "2099-12-31T23:59:59.999999999Z".to_string();

        // Die Kettenpruefung allein sieht das NICHT (tau_e ist pi_vol-frei
        // aus segment_digest heraus) ...
        let (identity, _record) = compute_segment_digests(&TraceSegment {
            segment_digest: GENESIS_DIGEST,
            segment_record_digest: GENESIS_DIGEST,
            ..segments[1].clone()
        })
        .unwrap();
        assert_eq!(
            identity, segments[1].segment_digest,
            "segment_digest DARF sich durch eine blosse Wanduhraenderung nicht aendern"
        );

        // ... aber die Aufzeichnungspruefung schon, und zwar genau dort.
        assert_eq!(
            verify_chain_detailed(&segments),
            Err(ChainViolation::RecordDigestMismatch { at: 1 })
        );
        assert_eq!(
            verify_chain(&segments),
            Err(PskError::TraceOrResidueViolation)
        );
    }

    #[test]
    fn changing_canonical_content_breaks_the_chain_check() {
        // Die Gegenprobe: eine inhaltliche Aenderung bricht die ERSTE
        // Pruefung - sonst haette die Zweiteilung die Kette entschaerft.
        let mut store = TraceStore::new();
        for e in ["a", "b"] {
            store.append(inputs(ModuleId::ThoughtCompiler, e)).unwrap();
        }
        let mut segments = store.segments().to_vec();
        segments[1].payload_digest = Digest::sha256(b"veraendert");
        assert_eq!(
            verify_chain_detailed(&segments),
            Err(ChainViolation::SegmentDigestMismatch { at: 1 })
        );
    }

    #[test]
    fn the_two_digests_of_one_segment_differ_from_each_other() {
        // Sie decken dieselben Felder ab, aber mit verschiedener
        // Projektion - waeren sie gleich, wuerde pi_vol nichts entfernen
        // und die Trennung existierte nur dem Namen nach.
        let mut store = TraceStore::new();
        store
            .append(inputs(ModuleId::ThoughtCompiler, "a"))
            .unwrap();
        let seg = &store.segments()[0];
        assert_ne!(seg.segment_digest, seg.segment_record_digest);
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
