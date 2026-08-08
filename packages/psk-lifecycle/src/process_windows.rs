//! M26 LifecycleSupervisor, `proc.control` (capability_matrix.yaml: einziger
//! Halter, scope `process`) - P24a-Realisierung. Windows-Implementierung -
//! siehe `process_unsupported.rs` fuer andere Plattformen und `lib.rs`s
//! `#[cfg(windows)]`-Modulauswahl. OBL-010 (architecture/obligations.yaml)
//! deklariert die reale Substraterzwingung bislang NUR fuer diese Plattform
//! (`resolution_platform: windows`) - eine Linux-Entsprechung ("Namespaces
//! und Rechteabgabe unter Linux", PSK-RA v1.0.16) bleibt eine eigene,
//! separat zu treffende Deklaration.
//!
//! `ChildProcess::spawn` erzeugt Effekt-/Beobachterprozess (Regel
//! Einzelrechnerbetrieb) als echte Kindprozesse mit eigenen, privaten
//! stdio-Pipes (dasselbe Grundmuster wie I8s `psk-cli --independent`,
//! siehe dessen `cmd_golden_run_independent`).
//!
//! v1.0.13-Praezisierung von Vertrag Herkunftsbeglaubigung an der
//! Prozessgrenze: "Eine vom annehmenden Prozess selbst erzeugte,
//! exklusive Kommunikationsleitung zu genau dem einen von ihm erzeugten
//! Kindprozess ... ist Prozessisolation im Sinne von Vertrag Capability-
//! Erzwingung und erfuellt diesen Vertrag." `ChildProcess`s `stdout`-Feld
//! ist PRIVAT - der einzige Codepfad, der Bytes von diesem Kind lesen
//! kann, ist `request()` selbst. Das ist die Erzwingung: strukturell
//! (Rusts Sichtbarkeitsregeln), nicht eine zur Laufzeit pruefbare
//! Zusicherung.
//!
//! OBL-010 (getrennte Benutzerkontexte oder Namespaces) ist SEIT HIER real
//! erzwungen, nicht mehr offen: `spawn` erzeugt das Kind angehalten
//! (`CREATE_SUSPENDED`), sperrt sein Token (`sandbox::lock_down_token` -
//! alle Privilegien entfernt, Integritaetsstufe auf Low gesenkt) WAEHREND
//! es noch angehalten ist, und laesst es erst DANACH per `ResumeThread`
//! laufen - das Kind fuehrt zu keinem Zeitpunkt auch nur eine einzige
//! Instruktion mit den vollen Rechten des Elternprozesses aus (kein
//! Zeitfenster, keine Race, siehe `sandbox.rs`s Kopfkommentar fuer die
//! Wahl von Low IL + Rechteabbau als die fuer diese Domaene erklaerte
//! Windows-Entsprechung zu `CreateProcessWithLogonW`). `granted_write_dir`
//! (falls gesetzt) erhaelt vorab dieselbe Low-IL-Kennzeichnung
//! (`sandbox::set_directory_low_integrity`) - das einzige Verzeichnis, in
//! das das sonst auf Low abgesenkte Kind noch schreiben kann.
//!
//! Bypasst bewusst `std::process::Command` fuer die Prozesserzeugung
//! selbst (dessen API bietet keinen Weg, das resultierende Kindtoken VOR
//! dem ersten Instruktionsschritt zu manipulieren) UND bewusst `std::
//! process::ChildStdin`/`ChildStdout` fuer die stdio-Enden (siehe
//! `PipeHandle`s Kopfkommentar - deren `Write`/`Read` haengt intern von
//! einer Handle-Eigenschaft ab, die per `CreatePipe` erzeugte anonyme
//! Pipes strukturell nicht haben koennen; real an einem haengenden
//! Schreibvorgang verifiziert, nicht angenommen). `std::process::Child`
//! war ohnehin nie verfuegbar (siehe `ChildProcess`s Kopfkommentar).

use std::io::{BufReader, Read, Write};
use std::path::Path;

use psk_types::{Msg, PskError};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, ERROR_BROKEN_PIPE, HANDLE, HANDLE_FLAG_INHERIT};
use windows::Win32::Security::{
    SECURITY_ATTRIBUTES, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES,
};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Console::{GetStdHandle, STD_ERROR_HANDLE};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_SUSPENDED, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};

/// Eigener, rein synchroner `Read`/`Write`-Wrapper um ein rohes Pipe-
/// `HANDLE` - ersetzt bewusst `std::process::ChildStdin`/`ChildStdout`.
/// Befund, real verifiziert (nicht aus der Dokumentation angenommen):
/// `ChildStdin::write` auf ein per `CreatePipe` erzeugtes Handle blockiert
/// UNBEGRENZT, selbst fuer wenige Bytes - ein rohes `WriteFile` auf
/// GENAU DEMSELBEN Handle kehrt sofort erfolgreich zurueck. Grund: `std`s
/// eigene Windows-Pipes entstehen intern ueber `CreateNamedPipeW` mit
/// `FILE_FLAG_OVERLAPPED` (asynchronfaehig) und `ChildStdin`/`ChildStdout`s
/// `Write`/`Read` nutzen dafuer intern ueberlappte E/A-Semantik; ein per
/// `CreatePipe` erzeugtes anonymes Pipe-Handle unterstuetzt
/// `FILE_FLAG_OVERLAPPED` grundsaetzlich NICHT (dokumentierte Win32-
/// Einschraenkung), die ueberlappte Operation kehrt deshalb nie zurueck.
/// `PipeHandle` verwendet stattdessen ausschliesslich synchrones
/// `ReadFile`/`WriteFile` (kein `OVERLAPPED`-Zeiger), passend zu dem, was
/// `CreatePipe` tatsaechlich liefert.
struct PipeHandle(HANDLE);

impl Write for PipeHandle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut written = 0u32;
        unsafe { WriteFile(self.0, Some(buf), Some(&mut written), None) }
            .map_err(|e| std::io::Error::from_raw_os_error(e.code().0))?;
        Ok(written as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(()) // Anonyme Pipes puffern nicht anwendungsseitig - jedes
               // `write` ist bereits im Kernel angekommen.
    }
}

impl Read for PipeHandle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut read = 0u32;
        match unsafe { ReadFile(self.0, Some(buf), Some(&mut read), None) } {
            Ok(()) => Ok(read as usize),
            // Die schreibende Seite hat geschlossen - EOF, kein Fehler
            // (dasselbe Signal, das `shutdown()`s Gegenstelle erwartet).
            // `e.code()` ist ein volles HRESULT (0x8007xxxx-Praefix fuer
            // Win32-Fehler) - Vergleich gegen den blossen Win32-Code
            // (109) OHNE `HRESULT::from_win32` schlaegt IMMER fehl (real
            // beobachtet: EOF kam als Err statt Ok(0) durch).
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_BROKEN_PIPE.0) => {
                Ok(0)
            }
            Err(e) => Err(std::io::Error::from_raw_os_error(e.code().0)),
        }
    }
}

impl Drop for PipeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// Ein einzelnes, von M26 gespawntes Kind (Effekt- oder Beobachterprozess)
/// mit exklusiv verbundenen stdio-Pipes. `stdin` ist `Option`, damit
/// `shutdown()` sie explizit vor dem Warten schliessen kann (das Kind
/// sieht dann EOF in seiner eigenen Leseschleife und beendet sich selbst,
/// siehe `effect-local-fs`/`observer-local-fs`s `main.rs`).
///
/// Haelt den rohen Prozess-`HANDLE` selbst (statt `std::process::Child`):
/// `Child` besitzt in stabilem Rust keinen oeffentlichen Weg, aus einem
/// bereits per `CreateProcessW` erzeugten Handle konstruiert zu werden -
/// `id`/`shutdown`/`Drop` bilden `GetProcessId`/`WaitForSingleObject`+
/// `GetExitCodeProcess`/`TerminateProcess` deshalb direkt nach, statt
/// eines nicht verfuegbaren `Child`-Umwegs.
pub struct ChildProcess {
    process: HANDLE,
    pid: u32,
    stdin: Option<PipeHandle>,
    stdout: BufReader<PipeHandle>,
    exited_cleanly: bool,
}

/// Windows erlaubt keine eingebauten Anfuehrungszeichen in Pfaden (Datei-
/// systembeschraenkung) - die einzige verbleibende Quotierungssonderheit
/// ist ein Backslash unmittelbar vor dem schliessenden Anfuehrungszeichen,
/// der sonst als Escape gelesen wuerde. Bewusst KEIN allgemeiner argv-
/// Quotierer: `spawn`s einzige Aufrufer geben ausschliesslich einzelne
/// Dateisystempfade als Argumente weiter (siehe golden_run.rs, tests/
/// spawn_and_request.rs), nie mehrteilige oder anderweitig konstruierte
/// Kommandozeilen.
fn quote_path_arg(s: &str) -> String {
    if !s.contains(' ') && !s.contains('\t') {
        return s.to_string();
    }
    let mut escaped = s.to_string();
    if escaped.ends_with('\\') {
        escaped.push('\\');
    }
    format!("\"{escaped}\"")
}

fn to_wide_null(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// RAII fuer die im Elternprozess verbleibenden Enden der beiden Pipes -
/// bei jedem Fehlschlag zwischen `CreatePipe` und dem erfolgreichen
/// Uebergang der kindseitigen Enden in den Kindprozess muessen ALLE vier
/// Handles wieder geschlossen werden, nicht nur die, die zufaellig im
/// Erfolgspfad ohnehin geschlossen wuerden.
struct PipeEnd(HANDLE);

impl Drop for PipeEnd {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

/// Serialisiert `ChildProcess::spawn` - siehe dessen Kopfkommentar.
/// `pub(crate)`, damit `sandbox::tests` denselben Riegel fuer seinen
/// eigenen, unabhaengigen Testhilfsprozess mitbenutzen kann (siehe dortigen
/// Kommentar - realer Interferenzherd, an mehreren Testlaeufen verifiziert).
pub(crate) static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

impl ChildProcess {
    /// Spawnt `exe_path` mit `args`, stdin/stdout als exklusiv verbundene
    /// Pipes (kein Vererben von stdout an den Elternprozess - die Pipe ist
    /// die Erzwingung, siehe Modulkopf). stderr bleibt geerbt, damit
    /// Diagnosen des Kindes sichtbar sind; sie tragen keine Msg-Rahmen.
    ///
    /// `granted_write_dir`: das einzige Verzeichnis, das dieses (sonst auf
    /// Low IL abgesenkte) Kind beschreiben koennen soll - `Some(sandbox_
    /// root)` fuer `effect-local-fs`, `None` fuer `observer-local-fs`
    /// (reine Lesezugriffe, von der Standard-MIC-Richtlinie nicht
    /// blockiert) und fuer Testprozesse ohne eigenen Schreibbedarf.
    ///
    /// Serialisiert ueber `SPAWN_LOCK`: M26 spawnt in der echten Pipeline
    /// (golden_run.rs) ohnehin nie zwei Kinder gleichzeitig aus zwei
    /// Threads (Effekt- und Beobachterprozess folgen dort sequenziell
    /// aufeinander) - die Sperre kostet dort nichts. Real noetig geworden
    /// als Testinfrastruktur-Haertung: `cargo test`s parallele
    /// Testausfuehrung liess mehrere `spawn`-Aufrufe aus verschiedenen
    /// Threads gleichzeitig laufen und brachte dabei wiederholt einen
    /// haengenden Kindprozess hervor (an mehreren Testlaeufen verifiziert,
    /// nicht nur vermutet) - die explizite Handle-Liste oben schliesst die
    /// dokumentierte Vererbungsfalle, behebt dieses konkrete Haengen aber
    /// NICHT vollstaendig; die Sperre tut es zuverlaessig und kostet in
    /// der echten, sequenziellen Nutzung nichts.
    pub fn spawn(
        exe_path: &Path,
        args: &[&str],
        granted_write_dir: Option<&Path>,
    ) -> Result<Self, PskError> {
        let _guard = SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(dir) = granted_write_dir {
            crate::sandbox::set_directory_low_integrity(dir)?;
        }

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: true.into(),
        };

        let mut stdin_read = HANDLE::default();
        let mut stdin_write = HANDLE::default();
        unsafe { CreatePipe(&mut stdin_read, &mut stdin_write, Some(&sa), 0) }
            .map_err(|_| PskError::BootPreconditionFailed)?;
        let stdin_read = PipeEnd(stdin_read);
        let stdin_write = PipeEnd(stdin_write);

        let mut stdout_read = HANDLE::default();
        let mut stdout_write = HANDLE::default();
        unsafe { CreatePipe(&mut stdout_read, &mut stdout_write, Some(&sa), 0) }
            .map_err(|_| PskError::BootPreconditionFailed)?;
        let stdout_read = PipeEnd(stdout_read);
        let stdout_write = PipeEnd(stdout_write);

        // Elterneigene Enden nicht vererbbar - Standardmuster fuer
        // CreatePipe-basierte Kind-stdio (sonst haelt der Elternprozess
        // nach dem Spawn selbst noch eine ueberzaehlige Kopie der
        // KINDSEITIGEN Handles, was spaeteres EOF-Erkennen bricht, siehe
        // `shutdown()`).
        unsafe { windows::Win32::Foundation::SetHandleInformation(stdin_write.0, HANDLE_FLAG_INHERIT.0, windows::Win32::Foundation::HANDLE_FLAGS(0)) }
            .map_err(|_| PskError::BootPreconditionFailed)?;
        unsafe { windows::Win32::Foundation::SetHandleInformation(stdout_read.0, HANDLE_FLAG_INHERIT.0, windows::Win32::Foundation::HANDLE_FLAGS(0)) }
            .map_err(|_| PskError::BootPreconditionFailed)?;

        let stderr_handle = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
            .map_err(|_| PskError::BootPreconditionFailed)?;

        let mut startup_info_ex = STARTUPINFOEXW::default();
        startup_info_ex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        startup_info_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup_info_ex.StartupInfo.hStdInput = stdin_read.0;
        startup_info_ex.StartupInfo.hStdOutput = stdout_write.0;
        startup_info_ex.StartupInfo.hStdError = stderr_handle;

        // `bInheritHandles=true` unten vererbt sonst JEDES vererbbare
        // Handle des GESAMTEN Elternprozesses, nicht nur die drei hier
        // gemeinten (dokumentierte Win32-Falle) - unter Nebenlaeufigkeit
        // (mehrere Threads spawnen gleichzeitig) reisst das fremde Pipe-
        // Enden in dieses Kind hinein, die dann verhindern, dass die
        // GEWOLLTE Gegenseite je EOF sieht. Real beobachtet, nicht nur
        // befuerchtet: derselbe Test, der einzeln zuverlaessig durchlief,
        // hing nebenlaeufig mit dem gesamten Testsuite-Lauf (ein FREMDES
        // Kind hielt nachweislich ein zusaetzliches Handle). Explizite
        // Handle-Liste (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) ist Microsofts
        // eigene, dokumentierte Behebung dafuer - nur die drei genannten
        // Handles werden vererbt, unabhaengig davon, was sonst im Prozess
        // gerade vererbbar ist.
        let mut inherit_handles = [stdin_read.0, stdout_write.0, stderr_handle];
        let mut attr_list_size: usize = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut attr_list_size);
        }
        // `Vec<u8>` ist NICHT auf die von `PROC_THREAD_ATTRIBUTE_LIST`
        // (interne Zeigerfelder) verlangten 8 Byte ausgerichtet garantiert -
        // dieselbe Klasse Fehler wie bei `TOKEN_MANDATORY_LABEL` (siehe
        // sandbox.rs), hier vorab vermieden statt erst an einem Fehlschlag
        // gefunden: `Vec<usize>` (aufgerundet) ist auf 64-Bit-Windows immer
        // 8-Byte-ausgerichtet.
        let mut attr_list_buffer =
            vec![0usize; attr_list_size.div_ceil(std::mem::size_of::<usize>())];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buffer.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(attr_list), 1, None, &mut attr_list_size) }
            .map_err(|_| PskError::BootPreconditionFailed)?;
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(inherit_handles.as_mut_ptr().cast()),
                std::mem::size_of_val(&inherit_handles),
                None,
                None,
            )
        }
        .map_err(|_| PskError::BootPreconditionFailed)?;
        startup_info_ex.lpAttributeList = attr_list;

        let mut command_line = quote_path_arg(&exe_path.to_string_lossy());
        for arg in args {
            command_line.push(' ');
            command_line.push_str(&quote_path_arg(arg));
        }
        let mut command_line_wide = to_wide_null(&command_line);

        let mut process_info = PROCESS_INFORMATION::default();
        let create_result = unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(command_line_wide.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR::null(),
                &startup_info_ex.StartupInfo,
                &mut process_info,
            )
        };
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
        }
        create_result.map_err(|_| PskError::BootPreconditionFailed)?;
        let process_handle = process_info.hProcess;
        let thread_handle = process_info.hThread;

        // Ab hier ist das Kind angehalten (CREATE_SUSPENDED) - Token
        // sperren, BEVOR auch nur eine Instruktion laeuft (siehe
        // Modulkopf). Ein Fehlschlag hier MUSS den (bereits erzeugten,
        // aber noch nie gelaufenen) Prozess beenden statt ihn
        // unabgesperrt weiterlaufen zu lassen - fail-closed, keine
        // stillschweigende Herabstufung auf "unsandboxed".
        let lockdown_result = (|| -> Result<(), PskError> {
            let mut token = HANDLE::default();
            unsafe {
                OpenProcessToken(
                    process_handle,
                    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT,
                    &mut token,
                )
            }
            .map_err(|_| PskError::BootPreconditionFailed)?;
            let result = crate::sandbox::lock_down_token(token);
            unsafe {
                let _ = CloseHandle(token);
            }
            result
        })();
        if let Err(e) = lockdown_result {
            unsafe {
                let _ = TerminateProcess(process_handle, 1);
                let _ = CloseHandle(thread_handle);
                let _ = CloseHandle(process_handle);
            }
            return Err(e);
        }

        unsafe {
            ResumeThread(thread_handle);
            let _ = CloseHandle(thread_handle);
        }

        // Die kindseitigen Pipe-Enden hat CreateProcessW in den Kindprozess
        // vererbt (eigene Kopien) - der Elternprozess braucht seine
        // urspruenglichen Handles darauf nicht mehr; PipeEnds Drop
        // schliesst sie beim Verlassen dieses Gueltigkeitsbereichs
        // automatisch (`stdin_read`, `stdout_write`).
        //
        // Elterneigene Enden gehen in `PipeHandle` ueber (siehe dessen
        // Kopfkommentar fuer den Grund, warum NICHT `ChildStdin`/
        // `ChildStdout`) - `mem::forget` verhindert, dass `PipeEnd`s
        // eigenes Drop dasselbe Handle ein zweites Mal schliesst.
        let stdin = PipeHandle(stdin_write.0);
        let stdout = PipeHandle(stdout_read.0);
        std::mem::forget(stdin_write);
        std::mem::forget(stdout_read);

        Ok(ChildProcess {
            process: process_handle,
            pid: process_info.dwProcessId,
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
        self.pid
    }

    /// Wartet auf den tatsaechlichen Prozessexit und liefert `true`, wenn
    /// der Exitcode 0 war - `WaitForSingleObject`+`GetExitCodeProcess`
    /// direkt, da `self.process` ein rohes `HANDLE` ist (siehe Struct-
    /// Kommentar, kein `std::process::Child` verfuegbar).
    fn wait_for_exit(&self) -> Result<bool, PskError> {
        unsafe {
            if WaitForSingleObject(self.process, INFINITE) != windows::Win32::Foundation::WAIT_OBJECT_0 {
                return Err(PskError::BootPreconditionFailed);
            }
            let mut code = 0u32;
            GetExitCodeProcess(self.process, &mut code)
                .map_err(|_| PskError::BootPreconditionFailed)?;
            Ok(code == 0)
        }
    }

    /// Ordnungsgemaesses Herunterfahren: schliesst stdin zuerst (das Kind
    /// sieht EOF und beendet sich selbst), wartet dann auf den
    /// tatsaechlichen Prozessexit.
    pub fn shutdown(mut self) -> Result<(), PskError> {
        drop(self.stdin.take());
        let success = self.wait_for_exit()?;
        self.exited_cleanly = true;
        if success {
            Ok(())
        } else {
            Err(PskError::BootPreconditionFailed)
        }
    }
}

impl Drop for ChildProcess {
    /// Sicherheitsnetz: ein nicht ordnungsgemaess heruntergefahrenes Kind
    /// (Panic, vergessenes `shutdown()`) wird beendet statt verwaist zu
    /// bleiben. `shutdown()` selbst hat bereits gewartet - `TerminateProcess`
    /// auf einen bereits beendeten Prozess ist ein ignorierbarer Fehler,
    /// kein Programmierfehler. Schliesst am Ende in jedem Fall das
    /// Prozess-Handle selbst (`self.process`) - sonst leckt es.
    fn drop(&mut self) {
        if !self.exited_cleanly {
            unsafe {
                let _ = TerminateProcess(self.process, 1);
            }
            let _ = self.wait_for_exit();
        }
        unsafe {
            let _ = CloseHandle(self.process);
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
        ("cmd", &["/c", "exit 0"])
    }

    #[test]
    fn spawning_a_real_process_yields_a_real_nonzero_pid() {
        let (exe, args) = trivial_command();
        let child = ChildProcess::spawn(Path::new(exe), args, None).unwrap();
        assert!(child.id() > 0);
        child.shutdown().ok();
    }

    #[test]
    fn shutdown_waits_for_real_process_exit() {
        let (exe, args) = trivial_command();
        let child = ChildProcess::spawn(Path::new(exe), args, None).unwrap();
        assert!(child.shutdown().is_ok());
    }

    // Beweist die rohe Pipe-Verdrahtung selbst, unabhaengig von psk_ipcs
    // Rahmenprotokoll und von effect-local-fs' eigener Logik: `sort.exe`
    // (echtes externes Programm, kein von diesem Werk kontrollierter Code)
    // liest alles von stdin und schreibt es (fuer eine einzelne Zeile
    // unveraendert) nach stdout, sobald es EOF sieht. Regressionswache
    // gegen genau den Fehler, der `PipeHandle` noetig gemacht hat (siehe
    // dessen Kopfkommentar) - mit `ChildStdin`/`ChildStdout` haengt
    // dieser Test unbegrenzt im ersten Schreibvorgang.
    #[test]
    fn a_real_external_process_echoes_through_the_raw_pipes() {
        use std::io::{Read, Write};
        // Voller Pfad, nicht PATH-Suche: dieses Dev-/CI-Environment hat
        // Git-Bash-Werkzeuge (u.a. ein GNU `sort.exe`, das sich anders
        // verhaelt) vor System32 im PATH - real beobachtet, kein
        // Vorsorgeabstrakt (`where sort` zeigt `Git\usr\bin\sort.exe` vor
        // `System32\sort.exe`).
        let sort_exe = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into())
            + "\\System32\\sort.exe";
        let mut child = ChildProcess::spawn(Path::new(&sort_exe), &[], None).unwrap();
        {
            let stdin = child.stdin.as_mut().unwrap();
            stdin.write_all(b"hello-pipe\r\n").unwrap();
            stdin.flush().unwrap();
        }
        drop(child.stdin.take());
        let mut out = String::new();
        child.stdout.read_to_string(&mut out).unwrap();
        assert_eq!(out.trim(), "hello-pipe");
    }
}
