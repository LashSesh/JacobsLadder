//! OBL-010 (Getrennte Benutzerkontexte oder Namespaces), Vertrag
//! Capability-Erzwingung ("Capabilities MUSS auf Substratebene erzwungen
//! werden ... Eine Erzwingung allein durch Programmkonvention ist nicht
//! konform"). PSK-RA v1.0.16 nennt fuer Windows explizit
//! `CreateProcessWithLogonW oder gleichwertig` als Verfahren, "plattform-
//! und domaenenabhaengig zu deklarieren, analog zu OBL-005."
//!
//! `CreateProcessWithLogonW` selbst wurde NICHT gewaehlt: es startet den
//! Kindprozess unter einem ANDEREN, bereits bestehenden Windows-Benutzer-
//! konto und braucht dafuer dessen Anmeldedaten (Benutzername + Passwort).
//! Das setzt ein eigens angelegtes, dauerhaft eingerichtetes Konto auf
//! JEDER Maschine voraus (Entwicklungsrechner UND CI-Runner) und liefe auf
//! Kontoanlage sowie Passwortverwaltung durch dieses Werkzeug selbst hinaus,
//! beides ausserhalb dessen, was hier ausgefuehrt werden darf
//! (System-/Sicherheitseinstellungen aendern, Zugangsdaten handhaben).
//! Die deklarierte GLEICHWERTIGE Alternative fuer diese Domaene:
//!
//! 1. **Rechteabbau**: `AdjustTokenPrivileges` mit `DisableAllPrivileges`
//!    auf dem Kindtoken entfernt u.a. SeBackupPrivilege/SeRestorePrivilege/
//!    SeTakeOwnershipPrivilege/SeDebugPrivilege - genau die Rechte, mit
//!    denen ein Prozess Datei-ACLs umgehen koennte. Ohne diesen Schritt
//!    waere jede nachfolgende ACL-/Integritaetsstufen-Beschraenkung witzlos.
//! 2. **Mandatory Integrity Control (Low Integrity Level)**: das Kindtoken
//!    wird auf die Low-Integritaetsstufe (`S-1-16-4096`) abgesenkt. Windows'
//!    Standardrichtlinie (NO_WRITE_UP, gilt implizit fuer JEDES Objekt ohne
//!    eigene Kennzeichnung) verweigert einem Low-IL-Prozess Schreibzugriff
//!    auf praktisch das gesamte Dateisystem (Systemverzeichnisse, das
//!    eigene Benutzerprofil, alles auf Medium-IL oder hoeher) UNABHAENGIG
//!    von der normalen DACL - dieselbe Substratmassnahme, mit der Internet
//!    Explorers "Protected Mode" und fruehe Chrome-Sandboxen einen Prozess
//!    auf genau ein Verzeichnis beschraenkten. Lesezugriff (zum Nachladen
//!    der eigenen DLLs/EXE) bleibt unberuehrt - MIC blockiert standardmaessig
//!    nur Schreiben/Ausfuehren nach oben, nicht Lesen.
//! 3. **Freigabe genau eines Verzeichnisses**: `sandbox_root` (bzw. der
//!    Beobachterwurzelpfad) erhaelt selbst die Low-IL-Kennzeichnung
//!    (`set_directory_low_integrity`, aequivalent zu
//!    `icacls <pfad> /setintegritylevel(oi)(ci) low`) - "Schreiben nach
//!    oben" trifft dann nicht mehr zu, die normale DACL (weiterhin die des
//!    eigenen Benutzers, da nur die Integritaetsstufe, nicht die Konto-SID,
//!    abgesenkt wird) traegt den eigentlichen Zugriff.
//!
//! Erfuellt Vertrag Capability-Erzwingung ueber zwei der dort ausdruecklich
//! genannten, gleichrangigen Formen ("Dateisystemrechte ... Prozessisolation
//! ... oder aequivalente Mechanismen") - real durch das Betriebssystem
//! durchgesetzt, nicht durch Anwendungscode, der `sandbox_root.join(..)`
//! aufruft und sich an eine Konvention haelt.
//!
//! Die eigentliche Anwendung (Sperrung VOR dem ersten Zeilencode des
//! Kindes, kein Zeitfenster mit vollen Rechten) lebt in `process.rs`
//! (`CREATE_SUSPENDED`, siehe dessen Kopfkommentar).

use std::path::Path;

use psk_types::PskError;
use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;
use windows::Win32::Security::Authorization::SE_FILE_OBJECT;
use windows::Win32::Security::{
    AddMandatoryAce, AdjustTokenPrivileges, CreateWellKnownSid, InitializeAcl,
    SetTokenInformation, TokenIntegrityLevel, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE,
    LABEL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE, PSID, TOKEN_MANDATORY_LABEL,
    WinLowLabelSid,
};
use windows::Win32::System::SystemServices::{SE_GROUP_ENABLED, SYSTEM_MANDATORY_LABEL_NO_WRITE_UP};

/// Win32s eigene Obergrenze fuer die groesste je vorkommende SID (siehe
/// `<sddl.h>`/`<winnt.h>`) - ein Byte-Puffer dieser Groesse ist fuer JEDE
/// wohlbekannte SID ausreichend, ohne die tatsaechliche Laenge vorher
/// berechnen zu muessen.
const SECURITY_MAX_SID_SIZE: usize = 68;

/// Erzeugt die wohlbekannte Low-Integritaetsstufen-SID (`S-1-16-4096`) in
/// einem eigenen, ausreichend grossen Puffer. Der Puffer MUSS so lange
/// leben wie jeder `PSID`, der auf ihn zeigt - deshalb Rueckgabe des
/// Puffers selbst, nicht nur eines PSID hinein.
fn low_integrity_sid() -> Result<[u8; SECURITY_MAX_SID_SIZE], PskError> {
    let mut buffer = [0u8; SECURITY_MAX_SID_SIZE];
    let mut size = SECURITY_MAX_SID_SIZE as u32;
    unsafe {
        CreateWellKnownSid(
            WinLowLabelSid,
            None,
            Some(PSID(buffer.as_mut_ptr().cast())),
            &mut size,
        )
    }
    .map_err(|_| PskError::BootPreconditionFailed)?;
    Ok(buffer)
}

/// Entfernt saemtliche Privilegien von `token` (`AdjustTokenPrivileges` mit
/// `DisableAllPrivileges`) - siehe Modulkopf, Schritt 1. `token` MUSS mit
/// `TOKEN_ADJUST_PRIVILEGES`-Zugriff geoeffnet worden sein.
pub fn strip_all_privileges(token: HANDLE) -> Result<(), PskError> {
    unsafe { AdjustTokenPrivileges(token, true, None, 0, None, None) }
        .map_err(|_| PskError::BootPreconditionFailed)
}

/// Senkt die Integritaetsstufe von `token` auf Low (`S-1-16-4096`) - siehe
/// Modulkopf, Schritt 2. `token` MUSS mit `TOKEN_ADJUST_DEFAULT`-Zugriff
/// geoeffnet worden sein. Nur ABSENKEN ist ohne besonderes Privileg
/// erlaubt (Windows verweigert das Anheben ueber die eigene Stufe hinaus
/// strukturell) - fuer diesen Zweck (Kindprozess einschraenken) die
/// einzige benoetigte Richtung.
/// `TOKEN_MANDATORY_LABEL` allein ist nur der Kopf (`Label.Sid` ist ein
/// Zeiger) - `SetTokenInformation(TokenIntegrityLevel, ...)` erwartet aber
/// einen EINZIGEN zusammenhaengenden Puffer, dessen `tokeninformationlength`
/// Kopf UND SID-Bytes gemeinsam umfasst (der Kernel probiert den ganzen
/// angegebenen Bereich); ein Sid-Zeiger, der auf Speicher AUSSERHALB dieses
/// Bereichs zeigt (z.B. eine getrennte lokale Variable), scheitert an
/// ERROR_NOACCESS - real an einem Fehlschlag verifiziert, nicht nur aus der
/// Dokumentation angenommen. `#[repr(C)]` mit eingebettetem SID-Feld direkt
/// nach dem Kopf erzwingt sowohl die noetige Nachbarschaft als auch die vom
/// Kopf (ein Zeigerfeld) verlangte Ausrichtung - ein roher `[u8; N]`-Puffer
/// garantiert diese Ausrichtung NICHT.
#[repr(C)]
struct TokenMandatoryLabelBuffer {
    header: TOKEN_MANDATORY_LABEL,
    sid_bytes: [u8; SECURITY_MAX_SID_SIZE],
}

pub fn lower_token_to_low_integrity(token: HANDLE) -> Result<(), PskError> {
    let mut combined = TokenMandatoryLabelBuffer {
        header: TOKEN_MANDATORY_LABEL {
            Label: windows::Win32::Security::SID_AND_ATTRIBUTES {
                Sid: PSID(std::ptr::null_mut()),
                Attributes: SE_GROUP_ENABLED as u32,
            },
        },
        sid_bytes: [0u8; SECURITY_MAX_SID_SIZE],
    };
    let sid_ptr = combined.sid_bytes.as_mut_ptr();
    let mut sid_len = SECURITY_MAX_SID_SIZE as u32;
    unsafe { CreateWellKnownSid(WinLowLabelSid, None, Some(PSID(sid_ptr.cast())), &mut sid_len) }
        .map_err(|_| PskError::BootPreconditionFailed)?;
    combined.header.Label.Sid = PSID(sid_ptr.cast());

    let total_len = std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32 + sid_len;
    unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            &combined as *const _ as *const core::ffi::c_void,
            total_len,
        )
    }
    .map_err(|_| PskError::BootPreconditionFailed)
}

/// Entfernt Privilegien UND senkt die Integritaetsstufe in einem Aufruf -
/// die vollstaendige Absperrung eines Kindtokens (Modulkopf, Schritte 1+2).
pub fn lock_down_token(token: HANDLE) -> Result<(), PskError> {
    strip_all_privileges(token)?;
    lower_token_to_low_integrity(token)?;
    Ok(())
}

/// Setzt `path`s eigene Mandatory-Label-SACL auf Low (aequivalent zu
/// `icacls <path> /setintegritylevel(oi)(ci) low`) - Modulkopf, Schritt 3:
/// das EINZIGE Verzeichnis, das ein sonst auf Low abgesenkter Kindprozess
/// beschreiben kann. `(oi)(ci)`: neu angelegte Dateien/Unterverzeichnisse
/// erben dieselbe Kennzeichnung, ohne die jede neu geschriebene Datei
/// selbst wieder auf Medium (Standard) staende und ihrerseits fuer den
/// Kindprozess unbeschreibbar waere.
pub fn set_directory_low_integrity(path: &Path) -> Result<(), PskError> {
    let sid_buf = low_integrity_sid()?;
    let sid = PSID(sid_buf.as_ptr() as *mut _);

    // ACL-Puffer: Kopfgroesse + genau eine Mandatory-Label-ACE (Kopf +
    // SID) - 1024 Bytes sind grosszuegig genug fuer eine einzelne ACE mit
    // einer maximal grossen SID, ohne die exakte Groesse vorab auszurechnen.
    let mut acl_buf = [0u8; 1024];
    let acl_ptr = acl_buf.as_mut_ptr().cast::<ACL>();
    unsafe { InitializeAcl(acl_ptr, acl_buf.len() as u32, ACL_REVISION) }
        .map_err(|_| PskError::BootPreconditionFailed)?;
    unsafe {
        AddMandatoryAce(
            acl_ptr,
            ACL_REVISION,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
            sid,
        )
    }
    .map_err(|_| PskError::BootPreconditionFailed)?;

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide_null_terminated();

    let result = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(wide_path.as_ptr()),
            SE_FILE_OBJECT,
            LABEL_SECURITY_INFORMATION,
            None,
            None,
            None,
            Some(acl_ptr),
        )
    };
    if result.is_err() {
        return Err(PskError::BootPreconditionFailed);
    }
    Ok(())
}

/// `OsStr` traegt keine eingebaute UTF-16-Nullterminierung (Windows-API-
/// Konvention) - dieser winzige Helfer haelt das an EINER Stelle statt an
/// jedem Aufrufort wiederholt.
trait EncodeWideNullTerminated {
    fn encode_wide_null_terminated(&self) -> Vec<u16>;
}

impl EncodeWideNullTerminated for std::ffi::OsStr {
    fn encode_wide_null_terminated(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ADJUST_DEFAULT, TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    };

    fn duplicate_own_token_for_testing() -> HANDLE {
        // Testet NIE gegen den eigenen Prozess direkt (siehe Modulkopf von
        // process.rs' Tests) - dieses Modul allein manipuliert aber noch
        // keinen echten Kindprozess, deshalb hier ein isolierter,
        // eigens gespawnter Testprozess (siehe process.rs' Integrationstest
        // fuer den echten Kindpfad). `cmd` ohne Argumente mit ungenutzter,
        // ungeschlossener stdin-Pipe wartet auf Eingabe und bleibt beliebig
        // lang am Leben, ohne von einem externen Unterbefehl (z.B.
        // `timeout`/`ping`) abzuhaengen, dessen Aufloesung je nach PATH-
        // Vererbung der Testumgebung nicht immer System32s Version trifft.
        let child = std::process::Command::new("cmd")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("Hilfsprozess spawnen");
        let pid = child.id();
        std::mem::forget(child); // Handle unten selbst verwaltet; kein doppeltes Kill/Wait.
        unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, pid) }
            .expect("OpenProcess auf eigenen Hilfsprozess")
    }

    #[test]
    fn lock_down_token_lowers_integrity_and_strips_privileges() {
        // `crate::process::SPAWN_LOCK`: dieser Testhilfsprozess ist real als
        // Interferenzherd verifiziert (nicht nur vermutet) - nebenlaeufig
        // mit `process::tests::a_real_external_process_echoes_through_the_
        // raw_pipes` gelaufen, hing letzterer wiederholt; mit `#[ignore]`
        // hier isoliert lief die gesamte uebrige Suite sofort sauber durch.
        // Derselbe Riegel wie `ChildProcess::spawn` selbst - siehe dessen
        // Kopfkommentar fuer die vermutete Ursache (Konsolen-Subsystem-
        // Race bei gleichzeitiger Prozesserzeugung/-beendigung, nicht
        // Handle-Vererbung, die bereits durch die explizite Handle-Liste
        // geschlossen ist). Bis zum BESTAETIGTEN Prozessende gehalten
        // (`WaitForSingleObject` nach `TerminateProcess`), nicht nur bis
        // zum Ruecksprung von `TerminateProcess` selbst - dessen eigene
        // Dokumentation nennt die tatsaechliche Prozessbeendigung
        // ausdruecklich verzoegert/asynchron.
        let _guard = crate::process::SPAWN_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let process = duplicate_own_token_for_testing();
        let mut token = HANDLE::default();
        unsafe {
            OpenProcessToken(
                process,
                TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_QUERY,
                &mut token,
            )
        }
        .expect("OpenProcessToken");

        lock_down_token(token).expect("lock_down_token");

        // Verifikation: TokenIntegrityLevel liest jetzt Low zurueck - echte
        // Systemabfrage, keine Strukturannahme. Derselbe ausgerichtete
        // Puffertyp wie beim Schreiben (siehe TokenMandatoryLabelBuffer) -
        // ein roher [u8; N]-Puffer ist NICHT auf die vom Kopf (Zeigerfeld)
        // verlangten 8 Byte ausgerichtet und faengt sich einen echten
        // Alignment-Fault beim Zurueckcasten (an einem Absturz verifiziert).
        let mut buf = TokenMandatoryLabelBuffer {
            header: TOKEN_MANDATORY_LABEL {
                Label: windows::Win32::Security::SID_AND_ATTRIBUTES {
                    Sid: PSID(std::ptr::null_mut()),
                    Attributes: 0,
                },
            },
            sid_bytes: [0u8; SECURITY_MAX_SID_SIZE],
        };
        let mut returned = 0u32;
        unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                Some((&mut buf as *mut TokenMandatoryLabelBuffer).cast()),
                std::mem::size_of::<TokenMandatoryLabelBuffer>() as u32,
                &mut returned,
            )
        }
        .expect("GetTokenInformation TokenIntegrityLevel");
        let low_sid = low_integrity_sid().unwrap();
        let matches_low = unsafe {
            windows::Win32::Security::EqualSid(
                buf.header.Label.Sid,
                PSID(low_sid.as_ptr() as *mut _),
            )
        }
        .is_ok();
        assert!(matches_low, "Token muss nach lock_down_token Low IL tragen");

        unsafe {
            let _ = windows::Win32::System::Threading::TerminateProcess(process, 0);
            windows::Win32::System::Threading::WaitForSingleObject(
                process,
                windows::Win32::System::Threading::INFINITE,
            );
            let _ = CloseHandle(process);
            let _ = CloseHandle(token);
        }
    }

    #[test]
    fn set_directory_low_integrity_is_idempotent_and_succeeds() {
        let dir = std::env::temp_dir().join(format!("psk-sandbox-il-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        set_directory_low_integrity(&dir).expect("erster Aufruf");
        set_directory_low_integrity(&dir).expect("zweiter Aufruf (idempotent)");
        std::fs::remove_dir_all(&dir).ok();
    }
}
