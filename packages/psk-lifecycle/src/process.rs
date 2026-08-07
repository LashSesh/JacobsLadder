//! M26 LifecycleSupervisor, `proc.control` (capability_matrix.yaml: einziger
//! Halter, scope `process`) - P24a-Realisierung.
//!
//! `ChildProcess::spawn` erzeugt Effekt-/Beobachterprozess (Regel
//! Einzelrechnerbetrieb) als echte Kindprozesse mit eigenen, privaten
//! stdio-Pipes (`std::process::Command`, dasselbe Grundmuster wie I8s
//! `psk-cli --independent`, siehe dessen `cmd_golden_run_independent`).
//!
//! v1.0.13-Praezisierung von Vertrag Herkunftsbeglaubigung an der
//! Prozessgrenze: "Eine vom annehmenden Prozess selbst erzeugte,
//! exklusive Kommunikationsleitung zu genau dem einen von ihm erzeugten
//! Kindprozess ... ist Prozessisolation im Sinne von Vertrag Capability-
//! Erzwingung und erfuellt diesen Vertrag." `ChildProcess`s `stdout`-Feld
//! ist PRIVAT - der einzige Codepfad, der Bytes von diesem Kind lesen
//! kann, ist `request()` selbst. Das ist die Erzwingung: strukturell
//! (Rusts Sichtbarkeitsregeln), nicht eine zur Laufzeit pruefbare
//! Zusicherung. OBL-010 haelt die davon unabhaengige Anforderung
//! getrennter Benutzerkontexte/Namespaces separat offen (blocking ab
//! C4) - `spawn` gibt dem Kind keine gesonderte Rechte-/Namespace-
//! Trennung, C0-C3 verlangen das laut Regel auch (noch) nicht.

use std::io::{BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use psk_types::{Msg, PskError};

/// Ein einzelnes, von M26 gespawntes Kind (Effekt- oder Beobachterprozess)
/// mit exklusiv verbundenen stdio-Pipes. `stdin` ist `Option`, damit
/// `shutdown()` sie explizit vor dem Warten schliessen kann (das Kind
/// sieht dann EOF in seiner eigenen Leseschleife und beendet sich selbst,
/// siehe `effect-local-fs`/`observer-local-fs`s `main.rs`).
pub struct ChildProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: BufReader<ChildStdout>,
    exited_cleanly: bool,
}

impl ChildProcess {
    /// Spawnt `exe_path` mit `args`, stdin/stdout als exklusiv verbundene
    /// Pipes (kein Vererben von stdout an den Elternprozess - die Pipe
    /// ist die Erzwingung, siehe Modulkopf). stderr bleibt geerbt, damit
    /// Diagnosen des Kindes sichtbar sind; sie tragen keine Msg-Rahmen.
    pub fn spawn(exe_path: &Path, args: &[&str]) -> Result<Self, PskError> {
        let mut child = Command::new(exe_path)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|_| PskError::BootPreconditionFailed)?;
        let stdin = child.stdin.take().ok_or(PskError::BootPreconditionFailed)?;
        let stdout = child
            .stdout
            .take()
            .ok_or(PskError::BootPreconditionFailed)?;
        Ok(ChildProcess {
            child,
            stdin: Some(stdin),
            stdout: BufReader::new(stdout),
            exited_cleanly: false,
        })
    }

    /// Schreibt `msg` an das Kind und liest genau eine Antwort - eines der
    /// fuenf Ports, die die Prozessgrenze tatsaechlich ueberqueren (P22,
    /// P23, P37, P06, P24; siehe `architecture/port_registry.yaml`).
    /// Synchron, ein Request pro Aufruf - dieselbe einfache, deterministische
    /// Gestalt wie der Rest dieses Werks (kein async-Laufzeitsystem).
    pub fn request(&mut self, msg: &Msg) -> Result<Msg, PskError> {
        let stdin = self
            .stdin
            .as_mut()
            .ok_or(PskError::BootPreconditionFailed)?;
        psk_ipc::write_frame(stdin, msg)?;
        stdin
            .flush()
            .map_err(|_| PskError::CanonicalizationFailed)?;
        psk_ipc::read_frame(&mut self.stdout)?.ok_or(PskError::CanonicalizationFailed)
    }

    /// OS-Prozess-ID des Kindes - Diagnosewert, nicht Teil der P24b-
    /// Erzwingung selbst (die ist strukturell, siehe Modulkopf).
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Ordnungsgemaesses Herunterfahren: schliesst stdin zuerst (das Kind
    /// sieht EOF und beendet sich selbst), wartet dann auf den
    /// tatsaechlichen Prozessexit.
    pub fn shutdown(mut self) -> Result<(), PskError> {
        drop(self.stdin.take());
        let status = self
            .child
            .wait()
            .map_err(|_| PskError::BootPreconditionFailed)?;
        self.exited_cleanly = true;
        if status.success() {
            Ok(())
        } else {
            Err(PskError::BootPreconditionFailed)
        }
    }
}

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

impl Drop for ChildProcess {
    /// Sicherheitsnetz: ein nicht ordnungsgemaess heruntergefahrenes Kind
    /// (Panic, vergessenes `shutdown()`) wird beendet statt verwaist zu
    /// bleiben. `shutdown()` selbst hat bereits gewartet - `kill()` auf
    /// einen bereits beendeten Prozess ist ein ignorierbarer Fehler, kein
    /// Programmierfehler.
    fn drop(&mut self) {
        if !self.exited_cleanly {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Diese Tests spawnen ein triviales OS-Kommando als "Kind" - kein
    // echtes Msg-Protokoll, nur eine echte OS-Prozessgrenze (stdin/stdout
    // tatsaechlich verbunden), um `spawn`/`shutdown`/`id` ohne die realen
    // Adapterbinaries zu pruefen. Der eigentliche Protokolltest gegen die
    // realen Binaries liegt in `tests/spawn_and_request.rs`
    // (CARGO_BIN_EXE_*, dort verfuegbar - psk-lifecycle selbst haengt
    // bewusst nicht von den Adaptercrates ab).

    fn trivial_command() -> (&'static str, &'static [&'static str]) {
        if cfg!(windows) {
            ("cmd", &["/c", "exit 0"])
        } else {
            ("true", &[])
        }
    }

    #[test]
    fn spawning_a_real_process_yields_a_real_nonzero_pid() {
        let (exe, args) = trivial_command();
        let child = ChildProcess::spawn(Path::new(exe), args).unwrap();
        assert!(child.id() > 0);
        child.shutdown().ok();
    }

    #[test]
    fn shutdown_waits_for_real_process_exit() {
        let (exe, args) = trivial_command();
        let child = ChildProcess::spawn(Path::new(exe), args).unwrap();
        assert!(child.shutdown().is_ok());
    }
}
