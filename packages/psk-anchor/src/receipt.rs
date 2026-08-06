//! M17 ExternalRecordIngress, ExternalReceipt-Teil (Struktur 7.34, P24).
//!
//! Schnittstelle 20.5 (Adapter), `interface ObserverAdapter`: "strikt
//! getrennte Implementierung ... fn observe(scope: ScopeExpr) ->
//! ExternalReceipt ... VERBOTEN: apply(), compensate()." Der Trait gehoert
//! hier (M17/psk-anchor), nicht bei M16/psk-effect - dieselbe Trennung wie
//! bei `EffectAdapter` (psk-effect::boundary), nur umgekehrt: `psk-anchor`
//! haengt nicht von `psk-effect` ab, ein Typ hier kann `EffectAdapter`
//! also ebenso wenig implementieren wie umgekehrt.
//!
//! Vertrag 20.2 (Herkunftsbeglaubigung an der Prozessgrenze), woertlich:
//! "ExternalReceipt ueberquert bei P24 eine echte Prozessgrenze aus dem
//! Beobachterprozess. Ein versiegelter oder anderweitig typgeschuetzter
//! Rust-Typ schuetzt hier nichts, da jede Prozessgrenze Serialisierung
//! erzwingt. Die Ingress-Implementierung von P24 MUSS die Herkunft auf
//! Substratebene pruefen ... der annehmende Prozess MUSS die
//! Betriebssystemidentitaet (Benutzerkontext oder Namespace) des sendenden
//! Prozesses gegen die beim Boot festgelegte Beobachterprozess-Identitaet
//! verifizieren, bevor ein empfangenes Byte als ExternalReceipt
//! deserialisiert wird. Eine Pruefung erst nach der Deserialisierung ist
//! verspaetet ... Eine Herkunftspruefung allein durch Feldvergleich
//! innerhalb des empfangenen Objekts (observer_identity etc.) ist
//! Konvention, keine Substraterzwingung, und erfuellt diesen Vertrag
//! nicht." v1.0.13-Praezisierung, unmittelbar anschliessend: "Eine vom
//! annehmenden Prozess selbst erzeugte, exklusive Kommunikationsleitung zu
//! genau dem einen von ihm erzeugten Kindprozess (M26, proc.control) ist
//! Prozessisolation im Sinne von Vertrag Capability-Erzwingung und
//! erfuellt diesen Vertrag, unabhaengig davon, ob Sender und Empfaenger
//! dieselbe Betriebssystem-Benutzerkennung tragen." (OBL-010 haelt die
//! davon unabhaengige Regel-Einzelrechnerbetrieb-Anforderung getrennter
//! Benutzerkontexte/Namespaces separat offen, blocking ab C4.)
//!
//! Zwei Pfade realisieren Vertrag 20.2, fuer zwei verschiedene
//! Erzwingungsarten:
//!
//! - `ingress_p24` - der urspruengliche, feldbasierte Vergleich.
//!   `ProcessIdentity` ist NICHT selbst gemessen (keine echte PID/UID/
//!   Namespace-Abfrage) - sie wird als bereits von der Transportschicht
//!   ermittelter Wert entgegengenommen, genau wie `Signature` bei M21
//!   (OBL-005: domaenenabhaengige Substratmechanismen sind erklaerte,
//!   nicht hier erfundene, Groessen). Was diese Funktion TRAEGT, ist die
//!   vom Vertrag verlangte REIHENFOLGE: sie nimmt `raw: &[u8]` entgegen
//!   und ruft die Identitaetspruefung strukturell VOR jeder
//!   Deserialisierung auf - es gibt keinen Codepfad, der `raw` in ein
//!   `ExternalReceipt` verwandelt, ohne vorher `verify_process_origin`
//!   bestanden zu haben.
//! - `ingress_p24_via_exclusive_pipe` - P24a/P24b, real genutzt von
//!   `psk-conformance::golden_run`. Keine Feldwerte zu vergleichen: `raw`
//!   MUSS bereits ueber `psk_lifecycle::process::ChildProcess::request`
//!   eingetroffen sein, dessen `stdout`-Handle PRIVAT ist - kein anderer
//!   Codepfad des Kernprozesses kann Bytes einspeisen, die hier ankommen.
//!   Die Erzwingung ist damit strukturell (Rusts Sichtbarkeitsregeln),
//!   nicht eine zur Laufzeit vergleichbare Zusicherung - genau das
//!   erlaubt die v1.0.13-Praezisierung ausdruecklich ("unabhaengig davon,
//!   ob Sender und Empfaenger dieselbe Betriebssystem-Benutzerkennung
//!   tragen"). Diese Funktion deserialisiert deshalb nur noch; die
//!   Beglaubigung ist zum Zeitpunkt ihres Aufrufs bereits geschehen.

use psk_canon::{can, Media};
use psk_types::objects::{AdapterId, ExternalReceipt, ProvenanceBlock, ScopeExpr};
use psk_types::{Digest, DualTime, PskError};

/// Schnittstelle 20.5, `interface ObserverAdapter`. Absichtlich OHNE
/// `apply`/`compensate` - derselbe Grund wie `EffectAdapter`s fehlende
/// Beobachtungsmethoden (psk-effect::boundary): der Trait kann strukturell
/// nicht mehr, als das Werk erlaubt.
pub trait ObserverAdapter {
    fn id(&self) -> AdapterId;
    fn observe(&self, scope: &ScopeExpr) -> ExternalReceipt;
    fn independence_attestation(&self) -> Digest;
}

/// Die beim Boot festgelegte Beobachterprozess-Identitaet, gegen die jede
/// eingehende P24-Nachricht geprueft wird (Vertrag 20.2: "gegen die beim
/// Boot festgelegte Beobachterprozess-Identitaet").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisteredObserverIdentity(pub ProcessIdentity);

/// Betriebssystemidentitaet eines Prozesses: Benutzerkontext ODER
/// Namespace (Vertrag 20.2 nennt beide als gleichwertige Traeger). Ein
/// Substrat liefert typischerweise nur eine der beiden Formen - deshalb
/// eine Summe, keine Struktur mit beiden Pflichtfeldern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessIdentity {
    UserContext(u64),
    Namespace(u64),
}

/// Vertrag 20.2: prueft die Herkunft VOR jeder Deserialisierung. Ein
/// Feldvergleich innerhalb eines bereits deserialisierten Objekts erfuellt
/// den Vertrag ausdruecklich NICHT - deshalb nimmt diese Funktion `raw`
/// entgegen und nicht ein `ExternalReceipt`.
fn verify_process_origin(
    claimed_origin: ProcessIdentity,
    registered: RegisteredObserverIdentity,
    _raw: &[u8],
) -> Result<(), PskError> {
    if claimed_origin == registered.0 {
        Ok(())
    } else {
        Err(PskError::ActualizationWithoutReconciliation)
    }
}

/// M17, P24-Ingress: `verify_process_origin` MUSS bestehen, bevor `raw`
/// ueberhaupt geparst wird - siehe Modulkopf. Nach bestandener
/// Herkunftspruefung ist die Deserialisierung ein gewoehnlicher
/// Kapitel-7-Objektaufbau wie ueberall sonst im Werk.
pub fn ingress_p24(
    raw: &[u8],
    claimed_origin: ProcessIdentity,
    registered: RegisteredObserverIdentity,
) -> Result<ExternalReceipt, PskError> {
    verify_process_origin(claimed_origin, registered, raw)?;
    serde_json::from_slice(raw).map_err(|_| PskError::CanonicalizationFailed)
}

/// M17, P24-Ingress ueber Pipe-Exklusivitaet (v1.0.13-Praezisierung von
/// Vertrag Herkunftsbeglaubigung an der Prozessgrenze) - siehe Modulkopf
/// fuer die volle Begruendung. `raw` MUSS aus
/// `psk_lifecycle::process::ChildProcess::request`s Antwort stammen;
/// diese Funktion selbst erzwingt das nicht (das kann sie nicht - sie hat
/// nur die Bytes), sondern deserialisiert, was der Aufrufer bereits ueber
/// eine strukturell exklusive Verbindung erhalten hat. Fuer C0-C3 (OBL-010:
/// "prozessisolierte, gleichkontextige Kommunikation") ist das die
/// vollstaendige Erfuellung des Vertrags; ab C4 verlangt OBL-010
/// zusaetzlich getrennte Benutzerkontexte/Namespaces, die `spawn` bisher
/// nicht herstellt.
pub fn ingress_p24_via_exclusive_pipe(raw: &[u8]) -> Result<ExternalReceipt, PskError> {
    serde_json::from_slice(raw).map_err(|_| PskError::CanonicalizationFailed)
}

/// Eingaben fuer `observe_local_fs` (Referenzimplementierung von
/// `ObserverAdapter::observe` fuer den lokalen Dateibaum). `id` fehlt: es
/// folgt aus dem Inhalt.
pub struct ObservationInputs {
    pub observer_adapter: AdapterId,
    pub observer_identity: Digest,
    pub observed_at: DualTime,
    pub record: Vec<u8>,
    pub provenance: ProvenanceBlock,
    pub independence_attestation: Digest,
}

fn compute_receipt_identity(draft: &ExternalReceipt) -> Result<psk_types::ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = psk_canon::identity_projection(&bytes, Media::Json)?;
    psk_canon::object_id(psk_types::objects::SortId::Receipt.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// Baut ein ExternalReceipt aus einer bereits erfolgten Beobachtung.
/// `result_digest = H(Can(record))` - der Digest des rohen, unvermischten
/// Beobachtungsergebnisses (Struktur 7.34: "record: bytes # unveraendert,
/// unvermischt").
pub fn build_receipt(inputs: ObservationInputs) -> Result<ExternalReceipt, PskError> {
    let result_digest = can(&inputs.record, Media::Json).map_or_else(
        |_| Ok::<Digest, PskError>(Digest::sha256(&inputs.record)),
        |c| Ok(c.digest()),
    )?;
    let draft = ExternalReceipt {
        id: psk_types::ObjectId::new(psk_types::objects::SortId::Receipt, Digest::sha256(b"")), // Platzhalter
        observer_adapter: inputs.observer_adapter,
        observer_identity: inputs.observer_identity,
        observed_at: inputs.observed_at,
        record: inputs.record,
        provenance: inputs.provenance,
        result_digest,
        independence_attestation: inputs.independence_attestation,
    };
    let id = compute_receipt_identity(&draft)?;
    Ok(ExternalReceipt { id, ..draft })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    fn sample_receipt() -> ExternalReceipt {
        build_receipt(ObservationInputs {
            observer_adapter: AdapterId("observer-local-fs".into()),
            observer_identity: Digest::sha256(b"observer"),
            observed_at: sample_time(),
            record: b"{\"files\":[]}".to_vec(),
            provenance: ProvenanceBlock("provenance/1".into()),
            independence_attestation: Digest::sha256(b"attestation"),
        })
        .unwrap()
    }

    #[test]
    fn ingress_rejects_a_mismatched_process_origin_before_parsing() {
        let raw = b"not even valid json";
        let registered = RegisteredObserverIdentity(ProcessIdentity::UserContext(1000));
        let claimed = ProcessIdentity::UserContext(9999);
        // Waere raw tatsaechlich geparst worden, waere der Fehler
        // CanonicalizationFailed, nicht der Herkunftsfehler - dieser Test
        // beweist also, dass die Pruefung VOR dem Parsen kommt.
        assert_eq!(
            ingress_p24(raw, claimed, registered),
            Err(PskError::ActualizationWithoutReconciliation)
        );
    }

    #[test]
    fn ingress_accepts_and_parses_once_origin_matches() {
        let receipt = sample_receipt();
        let raw = serde_json::to_vec(&receipt).unwrap();
        let registered = RegisteredObserverIdentity(ProcessIdentity::UserContext(1000));
        let parsed = ingress_p24(&raw, ProcessIdentity::UserContext(1000), registered).unwrap();
        assert_eq!(parsed.id, receipt.id);
    }

    #[test]
    fn exclusive_pipe_ingress_parses_without_any_identity_comparison() {
        let receipt = sample_receipt();
        let raw = serde_json::to_vec(&receipt).unwrap();
        let parsed = ingress_p24_via_exclusive_pipe(&raw).unwrap();
        assert_eq!(parsed.id, receipt.id);
    }

    #[test]
    fn exclusive_pipe_ingress_still_fails_closed_on_malformed_bytes() {
        assert_eq!(
            ingress_p24_via_exclusive_pipe(b"not even valid json"),
            Err(PskError::CanonicalizationFailed)
        );
    }

    #[test]
    fn a_namespace_claim_does_not_match_a_user_context_registration() {
        // Beide Formen sind zulaessige TRAEGER, aber nicht austauschbar -
        // ein Namespace-Anspruch beglaubigt keinen registrierten
        // Benutzerkontext.
        let raw = b"irrelevant";
        let registered = RegisteredObserverIdentity(ProcessIdentity::UserContext(1000));
        let claimed = ProcessIdentity::Namespace(1000);
        assert_eq!(
            ingress_p24(raw, claimed, registered),
            Err(PskError::ActualizationWithoutReconciliation)
        );
    }

    #[test]
    fn result_digest_covers_the_raw_record() {
        let receipt = sample_receipt();
        assert_ne!(receipt.result_digest, Digest::sha256(b""));
    }

    #[test]
    fn receipt_construction_is_deterministic() {
        let a = sample_receipt();
        let b = sample_receipt();
        assert_eq!(a.id, b.id);
    }
}
