//! P24a: Drahtformat fuer `Msg` (Struktur 4.1) ueber eine echte
//! Prozessgrenze - laengenpraefigiertes JSON, wie beim bereits
//! etablierten ExternalReceipt/P24-Pfad (`serde_json::to_vec`/
//! `from_slice`, siehe `psk_anchor::receipt`), nur mit einem expliziten
//! Rahmen, weil eine Pipe (anders als ein einzelner `recv()`-Aufruf mit
//! bekannter Laenge) einen kontinuierlichen Bytestrom liefert, in dem
//! Nachrichtengrenzen sonst nicht wiederauffindbar waeren.
//!
//! Rahmenformat: `[4 Bytes Laenge N, big-endian u32][N Bytes JSON]`. Kein
//! neues Format - dieselbe `serde_json`-Kodierung, die `Msg` (psk-types)
//! bereits traegt, nur mit einem minimalen Streaming-Rahmen davor. Diese
//! Bibliothek dient BEIDEN Seiten der Prozessgrenze: der spawnenden Seite
//! (M26, psk-lifecycle) und den gespawnten `[[bin]]`-Adaptern
//! (effect-local-fs, observer-local-fs) - keine der beiden Seiten hat
//! eine privilegierte Kodierung.
//!
//! `MAX_FRAME_BYTES` begrenzt die Allokation aus einer gelesenen
//! Laengenangabe. Der Gegenueber ist in dieser Referenzarchitektur immer
//! ein von M26 selbst erzeugter, vertrauter Kindprozess (kein
//! netzwerkexponierter, adversarieller Peer) - die Grenze ist deshalb
//! eine Sicherheitsvorkehrung gegen einen beschaedigten Stream, keine
//! Verteidigung gegen Angriff.

use std::io::{self, Read, Write};

use psk_types::{Msg, PskError};

/// 64 MiB - grosszuegig fuer jede in dieser Referenzarchitektur
/// tatsaechlich anfallende `Msg`-Nutzlast, klein genug, um eine
/// beschaedigte Laengenangabe nicht in eine Allokation ausufern zu lassen.
pub const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

/// Schreibt `msg` als einen laengenpraefigierten JSON-Rahmen. Flusht den
/// Writer nicht selbst - Pipes/Sockets puffern unterschiedlich; das
/// Flushen ist Sache des Aufrufers, der die Verbindungssemantik kennt.
pub fn write_frame<W: Write>(w: &mut W, msg: &Msg) -> Result<(), PskError> {
    let bytes = serde_json::to_vec(msg).map_err(|_| PskError::CanonicalizationFailed)?;
    let len: u32 = bytes
        .len()
        .try_into()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    if len > MAX_FRAME_BYTES {
        return Err(PskError::CanonicalizationFailed);
    }
    w.write_all(&len.to_be_bytes())
        .map_err(|_| PskError::CanonicalizationFailed)?;
    w.write_all(&bytes)
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// Liest genau einen laengenpraefigierten JSON-Rahmen und deserialisiert
/// ihn zu `Msg`. `Ok(None)` bedeutet sauberes EOF vor jedem Byte des
/// naechsten Rahmens (Gegenseite hat den Stream geordnet geschlossen) -
/// unterschieden von einem abgeschnittenen Rahmen (Err), der einen
/// tatsaechlichen Fehler darstellt.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Msg>, PskError> {
    let mut len_bytes = [0u8; 4];
    if !read_exact_or_eof(r, &mut len_bytes)? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_FRAME_BYTES {
        return Err(PskError::CanonicalizationFailed);
    }
    let mut payload = vec![0u8; len as usize];
    r.read_exact(&mut payload)
        .map_err(|_| PskError::CanonicalizationFailed)?;
    let msg: Msg =
        serde_json::from_slice(&payload).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(Some(msg))
}

/// Wie `Read::read_exact`, aber liefert `Ok(false)` statt `Err`, wenn das
/// EOF exakt an der Grenze zwischen zwei Rahmen liegt (0 bereits gelesene
/// Bytes) - jedes andere vorzeitige EOF bleibt ein echter Fehler.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<bool, PskError> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(PskError::CanonicalizationFailed),
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(PskError::CanonicalizationFailed),
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::{
        ClockRef, Digest, DualTime, MessageType, ModuleId, PortId, RunId, SchemaId, TraceRef, Ulid,
    };
    use std::io::Cursor;

    fn sample_msg() -> Msg {
        Msg {
            msg_id: Ulid(42),
            port_id: PortId::P24,
            r#type: MessageType::Event,
            schema_id: SchemaId("psk.external-receipt/1.0".into()),
            producer: ModuleId::ExternalRecordIngress,
            consumer: ModuleId::ReconciliationEngine,
            run_id: RunId("golden-run".into()),
            seq: 1,
            input_digests: vec![Digest::sha256(b"input")],
            created_at: DualTime {
                tau_i: 1,
                tau_e: "2026-08-05T00:00:00.000000000Z".into(),
                clock_ref: ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            trace_parent: TraceRef(Digest::sha256(b"trace")),
            payload_digest: Digest::sha256(b"payload"),
            payload: b"hello ipc".to_vec(),
            signature: None,
        }
    }

    #[test]
    fn a_written_frame_reads_back_identically() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &sample_msg()).unwrap();
        let mut cursor = Cursor::new(buf);
        let read_back = read_frame(&mut cursor).unwrap();
        assert_eq!(read_back, Some(sample_msg()));
    }

    #[test]
    fn two_frames_in_sequence_read_back_in_order() {
        let mut buf = Vec::new();
        let mut first = sample_msg();
        first.seq = 1;
        let mut second = sample_msg();
        second.seq = 2;
        write_frame(&mut buf, &first).unwrap();
        write_frame(&mut buf, &second).unwrap();

        let mut cursor = Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap().seq, 1);
        assert_eq!(read_frame(&mut cursor).unwrap().unwrap().seq, 2);
    }

    #[test]
    fn clean_eof_between_frames_yields_none_not_an_error() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        assert_eq!(read_frame(&mut cursor).unwrap(), None);
    }

    #[test]
    fn a_frame_truncated_mid_payload_is_a_real_error_not_none() {
        let mut buf = Vec::new();
        write_frame(&mut buf, &sample_msg()).unwrap();
        buf.truncate(buf.len() - 3); // Laengenpraefix da, Payload abgeschnitten
        let mut cursor = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor),
            Err(PskError::CanonicalizationFailed)
        );
    }

    #[test]
    fn a_declared_length_over_the_frame_cap_is_rejected_before_allocating() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_BYTES + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        assert_eq!(
            read_frame(&mut cursor),
            Err(PskError::CanonicalizationFailed)
        );
    }
}
