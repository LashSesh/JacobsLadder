//! ExternalRecord: das rohe Erzeugnis eines ObserverAdapter-Plugins
//! (Definition 27.1), das M17 unvermischt aufnimmt und ueber P06 an M05
//! weiterreicht (Regel 32.8, Kapitel 3.2 Zeile M17).
//!
//! ExternalRecord ist KEIN Kapitel-7-Objekt (object_registry.yaml fuehrt
//! nur 27 kanonische Objekte, ExternalRecord ist keines davon) und hat
//! deshalb keine Struktur-Nummer. Die Feldliste folgt woertlich Regel 32.8
//! (Anker der Referenzdomaene; Regel 32.7 ist die Feldfamilie, sechs
//! statische Archetypen - siehe psk-fields):
//! "Der AnchorSnapshot bindet Dateihashes, Git-Commit, Zeitstempel, Rechte,
//! Konfiguration und erlaubten Scope. Der Aussenrecord entsteht nach
//! Ausfuehrung durch einen unabhaengigen Adapter, der den tatsaechlichen
//! Dateisystemzustand liest."
//!
//! Dokumentbefund (gemeldet, nicht aufgeloest): Kapitel 3.2 fuehrt fuer M17
//! als ExklusivesOwnership "ExternalReceipt", nicht "ExternalRecord"; M05
//! fuehrt "ExternalRecord" nur unter Lesezugriff. Kein Modul besitzt
//! ExternalRecord im Sinne der Ownership-Tabelle. Diese Implementierung
//! liest das als: ExternalRecord entsteht ausserhalb der M00-M27-Grenze
//! (bei einem ObserverAdapter-Plugin, Definition 27.1), M17 nimmt es
//! lediglich unvermischt auf (M17-Name: "ExternalRecordIngress") und
//! reicht es weiter - Vertrag 3.4 (Ownership-Exklusivitaet) betrifft daher
//! nicht diesen Typ, weil er keiner der M00-M27-exklusiv-erzeugten
//! Objekttypen ist.

use psk_types::Digest;

/// Ein einzelner beobachteter Dateizustand ("Dateihashes").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileObservation {
    /// Pfad relativ zur beobachteten Wurzel - nie absolut, damit der
    /// Digest nicht vom Ablageort der Werkskopie abhaengt.
    pub relative_path: String,
    pub content_digest: Digest,
}

/// "Rechte": die fuer die Beobachtung tatsaechlich wirksamen
/// Zugriffsrechte, so wie der Adapter sie vorgefunden hat - kein
/// Capability-Grant, sondern ein beobachteter IST-Zustand.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObservedPermissions {
    pub read_only: bool,
}

/// Ein einzelner Eintrag einer Folgenbeobachtung (Regel 22.4 (Verschiedene Eingaben bilden kein Replaypaar)s
/// Gegenstueck auf der Beobachtungsseite: `observe()` liefert EINEN Punkt,
/// `observe_history()` liefert eine ganze Folge davon - "Historiker
/// rekonstruiert Versionen" (Regel 32.7 (Feldfamilie der Referenzdomäne)) braucht einen Gegenstand,
/// keinen Punkt). Wie `ExternalRecord` KEIN Kapitel-7-Objekt: dieselbe
/// Begruendung (Modulkopf), dieselbe Herkunft (ein ObserverAdapter-Plugin,
/// hier `observer-local-fs::observe_history`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct HistoryPoint {
    /// Die neue HEAD-Spitze nach dieser Bewegung (volle SHA).
    pub commit: String,
    /// Unix-Zeitstempel der Reflog-Zeile, wie im Log verzeichnet - keine
    /// Wanduhr des LESENDEN Laufs (die waere unter Invariante 6.14 (Replayneutralität der Wanduhr)
    /// verboten, ginge sie in einen Digest ein; hier ist sie Beobachtungs-
    /// INHALT, keine Aufzeichnungszeit).
    pub observed_at_unix: i64,
    /// Die Reflog-Aktion samt Nachricht, z.B. "commit: ..." oder
    /// "checkout: moving from ...". Traegt die Unterscheidung, die der
    /// Historiker braucht, um Versionswechsel von blossen
    /// HEAD-Bewegungen zu trennen.
    pub message: String,
}

/// `Serialize`/`Deserialize` (P24a): ExternalRecord ueberquert bei P06
/// (M17->M05) dieselbe reale Prozessgrenze wie ExternalReceipt bei P24 -
/// dieselbe serde_json-Drahtform, kein Sonderfall.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ExternalRecord {
    /// "Dateihashes".
    pub file_hashes: Vec<FileObservation>,
    /// "Git-Commit" - None, wenn die Wurzel kein Git-Repository ist.
    pub git_commit: Option<String>,
    /// "Zeitstempel": wann der Adapter den Zustand gelesen hat.
    pub observed_at: psk_types::DualTime,
    /// "Rechte".
    pub permissions: ObservedPermissions,
    /// "Konfiguration": Digest der wirksamen Adapterkonfiguration, damit
    /// zwei Laeufe mit unterschiedlicher Konfiguration nicht denselben
    /// ExternalRecord vortaeuschen.
    pub configuration_digest: Digest,
    /// "erlaubter Scope": die Wurzel, innerhalb derer der Adapter lesen
    /// durfte (nicht notwendig identisch mit der beobachteten Menge).
    pub allowed_scope: String,
}
