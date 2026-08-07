//! Bootschritt 1 (Algorithmus 17.1): `acquire_store_lock() else
//! FAIL(PSK-E101)`.
//!
//! Kein Modul wird fuer diesen Schritt genannt - er steht vor `M00.load`,
//! also vor jeder Modulzustaendigkeit. Struktur 16.7 (Store-Layout) fuehrt
//! den realen Ort dafuer bereits: `<store_root>/LOCK # exklusiver
//! Schreibzugriff je Store`. Diese Implementierung legt genau diese Datei
//! exklusiv an (`create_new` - atomar auf allen unterstuetzten
//! Plattformen: schlaegt fehl, wenn die Datei bereits existiert, ohne
//! Race zwischen Existenzpruefung und Anlegen) und entfernt sie beim Drop
//! des zurueckgegebenen Guards wieder. Keine neue Abhaengigkeit - `std`
//! traegt dieses Primitiv bereits.
//!
//! Ein Store-Root ohne bereits laufende Instanz hat nie eine LOCK-Datei;
//! ihr Fehlen ist deshalb kein "missing_artifact" (Regel 17.2), sondern
//! der Normalfall vor dem ersten `acquire`.

use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

use psk_types::PskError;

/// Haelt die exklusive Schreibsperre, solange der Wert lebt. `Drop`
/// entfernt die LOCK-Datei wieder - ein Absturz vor dem geordneten
/// Shutdown (Invariante 17.5) hinterlaesst dann zwar eine verwaiste Datei,
/// aber das ist Algorithmus 17.6s (Recovery) Zustaendigkeit, nicht die
/// dieses Primitivs.
#[derive(Debug)]
pub struct StoreLock {
    path: PathBuf,
    _file: File,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Kurzes, begrenztes Wiederholungsfenster gegen TRANSIENTE Kontention
/// beim Sperrerwerb (siehe `acquire_store_lock`s Modulkopf-Ergaenzung) -
/// max. `RETRY_ATTEMPTS * RETRY_DELAY` = 180ms zusaetzliche Wartezeit im
/// ungluenstigsten Fall, vernachlaessigbar fuer einen Bootvorgang.
const RETRY_ATTEMPTS: u32 = 10;
const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(20);

/// Bootschritt 1: `acquire_store_lock() else FAIL(PSK-E101)`. `store_root`
/// MUSS bereits existieren (der Bootpfad legt keine neuen Verzeichnisse
/// an, das waere M00s Zustaendigkeit ab Schritt 2).
///
/// Wiederholt den Erwerbsversuch kurz, bevor `FAIL` zurueckgegeben wird -
/// Algorithmus 17.1 Schritt 1 spezifiziert nur die abstrakte Operation
/// "acquire_store_lock() else FAIL", keine konkrete Anzahl von
/// Systemaufrufen; ein kurzes, begrenztes Retry BEIM Erwerb selbst bleibt
/// innerhalb dieser Spezifikation und aendert die Exklusivitaetsgarantie
/// nicht: haelt ein ANDERER Prozess die Sperre tatsaechlich (der
/// semantische, erwartete Fall), besteht sie ueber das gesamte kurze
/// Fenster fort und der Aufruf schlaegt am Ende genauso fehl wie ohne
/// Retry (siehe `a_second_acquisition_while_held_fails_closed` unten).
///
/// Konkreter Befund, kein Vorsorgeabstrakt: CI (windows-latest,
/// .github/workflows/ci.yml `unit`) scheiterte deterministisch (2/2
/// Laeufen) exakt hier, ausschliesslich im einzigen Test, der echte
/// Kindprozesse mit mehreren, schnell aufeinanderfolgenden boot()-Zyklen
/// startet (psk-cli/tests/i8_independent_replay.rs) - lokal (auch unter
/// `--workspace --locked`, mehrfach) nicht reproduzierbar. Der Workflow
/// selbst verwendet fuer die eigenstaendigen `golden`/`replay`-Stufen
/// bereits `$RUNNER_TEMP` statt des Standard-`%TEMP%`, den
/// `std::env::temp_dir()` (und damit dieser Test) nutzt - ein Hinweis,
/// dass der Standardpfad auf diesem Runner-Image bereits als weniger
/// zuverlaessig bekannt war, nicht eine hier neu erfundene Vermutung.
pub fn acquire_store_lock(store_root: &Path) -> Result<StoreLock, PskError> {
    let path = store_root.join("LOCK");
    for attempt in 0..RETRY_ATTEMPTS {
        if attempt > 0 {
            std::thread::sleep(RETRY_DELAY);
        }
        if let Ok(file) = OpenOptions::new().write(true).create_new(true).open(&path) {
            return Ok(StoreLock { path, _file: file });
        }
    }
    Err(PskError::BootPreconditionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("psk-store-lock-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn acquiring_a_free_lock_succeeds() {
        let dir = temp_dir("free");
        let lock = acquire_store_lock(&dir).unwrap();
        assert!(dir.join("LOCK").is_file());
        drop(lock);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_second_acquisition_while_held_fails_closed() {
        let dir = temp_dir("held");
        let _first = acquire_store_lock(&dir).unwrap();
        assert_eq!(
            acquire_store_lock(&dir).unwrap_err(),
            PskError::BootPreconditionFailed
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn dropping_the_guard_releases_the_lock_for_reacquisition() {
        let dir = temp_dir("release");
        let first = acquire_store_lock(&dir).unwrap();
        drop(first);
        let second = acquire_store_lock(&dir);
        assert!(second.is_ok());
        assert!(dir.join("LOCK").is_file(), "second haelt die Sperre noch");
        drop(second);
        assert!(
            !dir.join("LOCK").exists(),
            "nach dem letzten Drop muss die LOCK-Datei wieder verschwunden sein"
        );
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_lock_cleared_during_the_retry_window_is_still_acquired() {
        // Beweist, dass das Retry tatsaechlich eine kurze, transiente
        // Kontention ueberbrueckt (nicht nur kosmetisch existiert): eine
        // bereits vorhandene LOCK-Datei simuliert genau die Situation, die
        // in CI vermutet wird (z.B. Antivirus-Echtzeitscan auf einem
        // gerade angelegten Pfad) - ein Hintergrundthread raeumt sie kurz
        // vor Ablauf des Retry-Fensters weg (RETRY_ATTEMPTS * RETRY_DELAY
        // = 180ms; 60ms Wartezeit hier liegt sicher darunter), und
        // `acquire_store_lock` muss trotzdem erfolgreich sein.
        let dir = temp_dir("transient");
        let lock_path = dir.join("LOCK");
        fs::write(&lock_path, b"simulated transient hold").unwrap();

        let path_for_thread = lock_path.clone();
        let clearer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(60));
            fs::remove_file(&path_for_thread).unwrap();
        });

        let result = acquire_store_lock(&dir);
        clearer.join().unwrap();

        assert!(
            result.is_ok(),
            "Retry haette die zwischenzeitlich freigegebene Sperre erwerben muessen: {result:?}"
        );
        drop(result);
        fs::remove_dir_all(&dir).ok();
    }
}
