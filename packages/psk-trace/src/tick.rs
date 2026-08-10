//! M19 TraceReplayResidueStore, Takt-Teil: `open_tick`/`seal_phase`/
//! `close_tick` aus Algorithmus 14.5 (Tick).
//!
//! Keines der drei war vor v1.0.19-Umsetzung real - nicht einmal als
//! Zitat ausserhalb des Pseudocodes selbst (anders als z.B. `dispatch()`,
//! das wenigstens `psk-scheduler`s eigener Kopfkommentar nannte). Diese
//! Datei ist deshalb greenfield, keine Realisierung einer bereits
//! entworfenen Schnittstelle.
//!
//! `TraceStore` kennt keinen eigenen "aktueller Takt"-Zustand (siehe
//! `trace.rs`s Modulkopf: "die Bindung an run_id ist Sache des Aufrufers").
//! Dieselbe Haltung gilt hier fuer den Takt: `open_tick`/`seal_phase`/
//! `close_tick` sind duenne, ehrliche Wrapper um `TraceStore::append` mit
//! festen `EventTypeId`-Werten - keine zweite, parallele Speicherform
//! neben der bereits bestehenden, hashverketteten Segmentfolge. `t`
//! (Algorithmus 14.5 (Tick)s Rueckgabewert von `open_tick`) ist hier `TickHandle`:
//! traegt `tick_no` und die wanduhrfreie Taktkennung, die
//! `seal_phase`/`close_tick` als `payload_digest` weiterreichen - siehe
//! dessen Kommentar fuer den gemessenen Grund, warum dort NICHT der
//! `segment_digest` des Eroeffnungssegments steht.

use psk_canon::{can, Media};
use psk_types::objects::EventTypeId;
use psk_types::{Digest, DualTime, ModuleId, Phase, PskError};

use crate::{SegmentInputs, TraceStore};

/// Rueckgabewert von `open_tick` (Algorithmus 14.5 (Tick)s `t`). Kein kanonisches
/// Kapitel-7-Objekt (keine ObjectId, kein Schema) - ein reiner
/// Laufzeit-Handle fuer die Dauer eines einzelnen Takts.
///
/// `tick_identity` ist H(Can(tick_no, run_descriptor_digest)) - die
/// wanduhrfreie Kennung dieses Takts, NICHT der `segment_digest` des
/// Eroeffnungssegments. Der Unterschied ist gemessen, nicht theoretisch:
/// `segment_digest` schliesst nach Struktur 7.40 das Feld `time: DualTime`
/// mit ein und traegt damit `tau_e`. Ein Handle, der ihn weiterreicht,
/// schleppt die Wanduhr in jedes Folgesegment (`seal_phase`/`close_tick`
/// setzen ihn als `payload_digest`) und von dort in jeden Digest ueber den
/// Laufzustand - genau das, was Invariante 6.14 verbietet. Die Bindung an
/// den Takt bleibt trotzdem echt: `tick_no` und der RunDescriptor-Digest
/// identifizieren ihn eindeutig, und die Kettenbindung
/// (`prev_digest`) leistet die Reihenfolgesicherung ohnehin schon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TickHandle {
    pub tick_no: u64,
    tick_identity: Digest,
}

/// `t = M19.open_tick(state.tick_no, rd)`. `rd_digest` ist
/// `RunDescriptor.digest` - der Lauf, unter dem dieser Takt steht; die
/// volle `RunDescriptor` wird hier bewusst nicht entgegengenommen (M19
/// kennt ihre Felder nicht, nur ihren bereits gebildeten Digest, siehe
/// `run.rs::open_run`).
pub fn open_tick(
    store: &mut TraceStore,
    tick_no: u64,
    rd_digest: Digest,
    time: DualTime,
) -> Result<TickHandle, PskError> {
    let tick_identity = tick_payload_digest(tick_no, rd_digest)?;
    store.append(SegmentInputs {
        event_type: EventTypeId("tick.opened".to_string()),
        module: ModuleId::Scheduler,
        port_id: None,
        object_refs: vec![],
        payload_digest: tick_identity,
        time,
        attestation: None,
    })?;
    Ok(TickHandle {
        tick_no,
        tick_identity,
    })
}

/// `M19.seal_phase(t, phase)`: schliesst eine Phase innerhalb des offenen
/// Takts `t` ab. Kein Rueckgabewert im Pseudocode - hier `Result<(),
/// PskError>`, da `append` scheitern kann (Kanonisierungsfehler).
pub fn seal_phase(
    store: &mut TraceStore,
    handle: &TickHandle,
    phase: Phase,
    time: DualTime,
) -> Result<(), PskError> {
    store.append(SegmentInputs {
        event_type: EventTypeId(format!("phase.sealed.{}", phase.label())),
        module: ModuleId::Scheduler,
        port_id: None,
        object_refs: vec![],
        payload_digest: handle.tick_identity,
        time,
        attestation: None,
    })?;
    Ok(())
}

/// `M19.close_tick(t)`: versiegelt den Takt nach allen zwoelf Phasen.
/// Nimmt `handle` nach Wert - ein bereits geschlossener Takt kann nicht
/// zweimal versiegelt werden, strukturell, nicht nur per Laufzeitpruefung.
pub fn close_tick(
    store: &mut TraceStore,
    handle: TickHandle,
    time: DualTime,
) -> Result<(), PskError> {
    store.append(SegmentInputs {
        event_type: EventTypeId("tick.closed".to_string()),
        module: ModuleId::Scheduler,
        port_id: None,
        object_refs: vec![],
        payload_digest: handle.tick_identity,
        time,
        attestation: None,
    })?;
    Ok(())
}

fn tick_payload_digest(tick_no: u64, rd_digest: Digest) -> Result<Digest, PskError> {
    let bytes = serde_json::to_vec(&serde_json::json!({
        "tick_no": tick_no,
        "run_descriptor_digest": rd_digest,
    }))
    .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(can(&bytes, Media::Json)?.digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-08T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    #[test]
    fn open_tick_appends_exactly_one_segment() {
        let mut store = TraceStore::new();
        open_tick(&mut store, 0, Digest::sha256(b"rd"), sample_time()).unwrap();
        assert_eq!(store.segments().len(), 1);
        assert_eq!(store.segments()[0].event_type.0, "tick.opened");
    }

    #[test]
    fn seal_phase_appends_one_segment_per_phase_referencing_the_tick() {
        let mut store = TraceStore::new();
        let handle = open_tick(&mut store, 0, Digest::sha256(b"rd"), sample_time()).unwrap();
        for phase in psk_types::CANONICAL_PHASES {
            seal_phase(&mut store, &handle, phase, sample_time()).unwrap();
        }
        // 1 open + 12 phases
        assert_eq!(store.segments().len(), 13);
        assert!(store.segments()[1..]
            .iter()
            .all(|s| s.event_type.0.starts_with("phase.sealed.")));
    }

    #[test]
    fn close_tick_appends_a_final_segment() {
        let mut store = TraceStore::new();
        let handle = open_tick(&mut store, 0, Digest::sha256(b"rd"), sample_time()).unwrap();
        close_tick(&mut store, handle, sample_time()).unwrap();
        assert_eq!(store.segments().len(), 2);
        assert_eq!(store.segments()[1].event_type.0, "tick.closed");
    }

    #[test]
    fn the_whole_tick_lifecycle_stays_a_verifiable_chain() {
        let mut store = TraceStore::new();
        let handle = open_tick(&mut store, 3, Digest::sha256(b"rd"), sample_time()).unwrap();
        for phase in psk_types::CANONICAL_PHASES {
            seal_phase(&mut store, &handle, phase, sample_time()).unwrap();
        }
        close_tick(&mut store, handle, sample_time()).unwrap();
        assert_eq!(crate::verify_chain(store.segments()), Ok(()));
    }

    #[test]
    fn different_tick_numbers_yield_different_opening_payloads() {
        let mut store_a = TraceStore::new();
        let mut store_b = TraceStore::new();
        let a = open_tick(&mut store_a, 0, Digest::sha256(b"rd"), sample_time()).unwrap();
        let b = open_tick(&mut store_b, 1, Digest::sha256(b"rd"), sample_time()).unwrap();
        assert_ne!(
            store_a.segments()[0].payload_digest,
            store_b.segments()[0].payload_digest
        );
        assert_ne!(a.tick_identity, b.tick_identity);
    }
}
