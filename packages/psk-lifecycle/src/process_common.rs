//! Plattformunabhaengiger Teil von M26s Kindprozess-Werkzeug: reine
//! Dateisystemsuche, keine Substrat-API. IMMER kompiliert (anders als
//! `ChildProcess` selbst, siehe `process_windows.rs`/`process_unsupported.rs`
//! und `lib.rs`s Modulauswahl) - `psk-conformance`/`psk-cli` rufen diese
//! Funktion unabhaengig davon auf, ob echtes Spawnen auf der jeweiligen
//! Plattform bereits real erzwungen ist (OBL-010).

use std::path::PathBuf;

use psk_types::PskError;

/// Begrenztes Wiederholungsfenster, waehrend dem `sibling_binary_path` auf
/// das Erscheinen des gesuchten Binaries wartet, bevor es aufgibt - siehe
/// dessen Modulkopf-Ergaenzung fuer den Anlass. 60 Versuche a 500ms = 30s
/// Obergrenze, grosszuegig genug fuer einen vollstaendigen Neubuild eines
/// einzelnen Geschwister-Crates auf einem langsamen CI-Runner, ohne den
/// Normalfall (Datei bereits vorhanden, sofortiger Erfolg) zu verzoegern.
const SIBLING_WAIT_ATTEMPTS: u32 = 60;
const SIBLING_WAIT_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// Sucht ein Geschwister-Binary im selben Cargo-Ausgabeverzeichnis wie
/// das aktuell laufende Programm - der Ort, an dem Cargo ALLE Workspace-
/// Binaries desselben Profils ablegt (`target/debug/`, `target/release/`).
/// `name` ist der reine Binaryname ohne Plattformendung (".exe" wird
/// unter Windows automatisch ergaenzt). Prueft zwei Kandidaten: direkt
/// neben `current_exe()` (Produktionsfall - z.B. `psk-cli` sucht neben
/// sich selbst) und ein Verzeichnis darueber (Testfall - Testbinaries
/// liegen unter `target/<profil>/deps/`, die eigentlichen Crate-Binaries
/// ein Verzeichnis hoeher).
///
/// Wartet bis zu `SIBLING_WAIT_ATTEMPTS * SIBLING_WAIT_DELAY` (30s) auf das
/// Erscheinen der Datei, statt beim ersten Fehlschlag aufzugeben. Konkreter
/// Befund: `i8_independent_replay.rs` scheiterte in CI deterministisch mit
/// `BootPreconditionFailed`, obwohl `psk_contract::boot()` (Schritte 1-19,
/// per Tracing bestaetigt) vollstaendig durchlief - der Fehler entstand
/// spaeter, hier (siehe golden_run.rs Zeilen 460/511, `?`-durchgereicht).
/// `unit`-Job (`.github/workflows/ci.yml`) checkt frisch aus und baut den
/// GESAMTEN Workspace in EINEM `cargo test --workspace --locked`-Aufruf,
/// ohne Cache zwischen Jobs - Cargo darf ein bereits kompilierbereites
/// Testbinary (dessen eigene Kompilierzeit-Abhaengigkeiten wie `psk-cli`
/// fertig sind) ausfuehren, waehrend ein DAVON UNABHAENGIGES `[[bin]]`-Ziel
/// wie `effect-local-fs`/`observer-local-fs` (kein Kompilierzeit-Bezug von
/// `psk-cli` aus, nur eine transitive Bibliotheksabhaengigkeit ueber
/// `psk-conformance`) noch kompiliert wird - auf einem ressourcenbe-
/// schraenkten Runner (windows-latest: Standard 2 vCPU) ein reales,
/// zeitlich enges Fenster, lokal (schnellere/mehrkernige Maschine) nicht
/// reproduzierbar. Die Datei ERSCHEINT hier also typischerweise noch
/// waehrend des Wartens, statt nie zu existieren - ein Wettlauf, kein
/// dauerhaft fehlendes Artefakt.
pub fn sibling_binary_path(name: &str) -> Result<PathBuf, PskError> {
    let exe = std::env::current_exe().map_err(|_| PskError::BootPreconditionFailed)?;
    let dir = exe.parent().ok_or(PskError::BootPreconditionFailed)?;
    let filename = if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_string()
    };
    let direct = dir.join(&filename);
    let one_up = dir
        .parent()
        .ok_or(PskError::BootPreconditionFailed)?
        .join(&filename);

    for attempt in 0..SIBLING_WAIT_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(SIBLING_WAIT_DELAY);
        }
        if direct.is_file() {
            return Ok(direct);
        }
        if one_up.is_file() {
            return Ok(one_up);
        }
    }
    // TEMPORAERE Diagnose (siehe Doc-Kommentar oben) - entfernt, sobald
    // bestaetigt ist, dass dies die tatsaechliche Ursache war.
    eprintln!(
        "sibling_binary_path: DIAGNOSE - '{name}' nach {SIBLING_WAIT_ATTEMPTS} Versuchen \
         (insgesamt {:?}) nicht gefunden. Geprueft: {} (existiert={}) und {} (existiert={})",
        SIBLING_WAIT_ATTEMPTS * (SIBLING_WAIT_DELAY.as_millis() as u32),
        direct.display(),
        direct.exists(),
        one_up.display(),
        one_up.exists(),
    );
    Err(PskError::BootPreconditionFailed)
}
