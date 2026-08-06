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

/// Bootschritt 1: `acquire_store_lock() else FAIL(PSK-E101)`. `store_root`
/// MUSS bereits existieren (der Bootpfad legt keine neuen Verzeichnisse
/// an, das waere M00s Zustaendigkeit ab Schritt 2).
pub fn acquire_store_lock(store_root: &Path) -> Result<StoreLock, PskError> {
    let path = store_root.join("LOCK");
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| PskError::BootPreconditionFailed)?;
    Ok(StoreLock { path, _file: file })
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
}
