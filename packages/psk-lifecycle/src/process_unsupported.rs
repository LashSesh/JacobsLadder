//! M26 LifecycleSupervisor, `proc.control` - Platzhalter fuer alle
//! Plattformen ausser Windows (siehe `process_windows.rs` fuer die reale
//! Implementierung und `lib.rs`s `#[cfg(windows)]`-Modulauswahl).
//!
//! OBL-010 (architecture/obligations.yaml) deklariert die reale
//! Substraterzwingung bislang NUR fuer Windows (`resolution_platform:
//! windows`) - PSK-RA v1.0.16 nennt fuer diese Plattform "Namespaces und
//! Rechteabgabe unter Linux" als eigene, noch offene Deklaration. Bevor
//! dieses Modul existierte, liess `lib.rs`s unbedingtes `mod process;`
//! (Windows-`windows`-Crate ohne jede `#[cfg]`-Absicherung) den GESAMTEN
//! Workspace auf jeder Nicht-Windows-Plattform mit kaskadierenden
//! "cannot find crate windows"-Fehlern nicht mehr kompilieren - laut, aber
//! ohne verstaendliche Begruendung, kein bewusst gestalteter Zustand.
//! Real geprueft (nicht angenommen): `cargo check --target
//! x86_64-unknown-linux-gnu -p psk-lifecycle` schlug mit 18 Fehlern fehl,
//! bevor dieses Modul eingefuehrt wurde.
//!
//! Dieses Modul stellt dieselbe oeffentliche `ChildProcess`-Oberflaeche
//! bereit, damit `psk-conformance`/`psk-cli`/die Adapterbinaries auf jeder
//! Plattform KOMPILIEREN - `spawn` selbst verweigert sich aber explizit,
//! statt ungeschuetzt (ohne jede Substraterzwingung) einen echten
//! Kindprozess zu starten: Vertrag Capability-Erzwingung ("Eine Erzwingung
//! allein durch Programmkonvention ist nicht konform") gilt hier genauso
//! wie unter Windows. Fail-closed, keine stillschweigende Herabstufung.

use std::path::Path;

use psk_types::{Msg, PskError};

/// Kann auf dieser Plattform nie konstruiert werden - `spawn()` liefert
/// immer `Err`. Existiert nur, damit die Typoberflaeche plattformuebergreifend
/// gleich bleibt (Aufrufer muessen nicht selbst `#[cfg]`-verzweigen).
pub struct ChildProcess {
    _never_constructed: std::convert::Infallible,
}

impl ChildProcess {
    /// Verweigert sich IMMER auf dieser Plattform - siehe Modulkopf. Der
    /// Text nennt den konkreten Registereintrag (OBL-010), nicht nur "nicht
    /// unterstuetzt", damit ein Betrachter der Fehlerausgabe direkt weiss,
    /// welche Deklaration fehlt und wo sie stuende.
    pub fn spawn(
        _exe_path: &Path,
        _args: &[&str],
        _granted_write_dir: Option<&Path>,
    ) -> Result<Self, PskError> {
        eprintln!(
            "psk_lifecycle::ChildProcess::spawn: auf dieser Plattform nicht verfuegbar. \
             OBL-010 (architecture/obligations.yaml) deklariert die reale Substraterzwingung \
             bislang nur fuer Windows (resolution_platform: windows) - die davon unabhaengige \
             Plattformdeklaration (\"Namespaces und Rechteabgabe unter Linux\", PSK-RA v1.0.16) \
             ist noch offen. Faellt bewusst NICHT auf ungeschuetztes Spawnen zurueck (Vertrag \
             Capability-Erzwingung: \"Eine Erzwingung allein durch Programmkonvention ist nicht \
             konform\")."
        );
        Err(PskError::BootPreconditionFailed)
    }

    pub fn request(&mut self, _msg: &Msg) -> Result<Msg, PskError> {
        match self._never_constructed {}
    }

    pub fn id(&self) -> u32 {
        match self._never_constructed {}
    }

    pub fn shutdown(self) -> Result<(), PskError> {
        match self._never_constructed {}
    }
}
