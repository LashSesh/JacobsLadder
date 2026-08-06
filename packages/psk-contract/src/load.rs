//! M00 ConstitutionLoader, Bootschritt 2 (Algorithmus 17.1): `image =
//! M00.load(bundle_path) // constitution.lock.json zuerst`.
//!
//! `tools/verify-bundle::check_constitution_bundle` fuehrt bereits die
//! reale Pruefung, die die Schritte 4-6 brauchen (M01.canonicalize_all +
//! M01.collection_digest + der Vergleich gegen den versiegelten Wert -
//! siehe dessen eigenen Modulkopf). M00.load() liest dieselbe Datei fuer
//! denselben Zweck; diese Funktion ruft die bereits gebaute Pruefung
//! direkt auf, statt sie ein zweites Mal zu schreiben (derselbe Grund, aus
//! dem `psk-conformance` und `psk-cli` sie schon wiederverwenden statt
//! duplizieren).
//!
//! `image.lock.constitution_id` (Schritt 6) ist NICHT
//! `declared_ancestor_constitution_id` (die `aa10aa5a...`-Kennung, OBL-009,
//! Status "unreachable" - widerspruechliche Digestmengen zwischen Kapitel
//! 44.1 und Kapitel F). Es ist der SELBST BERECHNETE, im Bundle
//! versiegelte Wert - exakt `BundleCheck::stored_constitution_id`, gegen
//! `BundleCheck::computed_constitution_id` verglichen ueber
//! `BundleCheck::matches()`. `declared_ancestor_constitution_id` wird von
//! `check_constitution_bundle` gar nicht erst in `BundleCheck`
//! uebernommen - es kann an dieser Stelle folglich nicht versehentlich
//! verglichen werden.

use std::path::{Path, PathBuf};

use psk_types::PskError;

/// Bootschritt 2s Ergebnis. `bundle_root` wird durchgereicht, weil Schritt
/// 3/10/11 (M02/M03-Konzern, architecture-seitig) denselben Wurzelpfad
/// brauchen, nicht weil `BundleImage` selbst mehr als die Konstitution
/// laedt - "constitution.lock.json zuerst" (Schritt 2s eigener Kommentar)
/// heisst woertlich: nur die Konstitution, hier.
pub struct BundleImage {
    pub bundle_root: PathBuf,
    pub constitution_check: verify_bundle::BundleCheck,
}

/// M00: laedt das Bundle. `bundle_root` ist die Workspace-Wurzel
/// (enthaelt `constitution/`) - derselbe Wurzelbegriff wie bei
/// `verify_architecture::check_architecture_bundle`.
pub fn load(bundle_root: &Path) -> Result<BundleImage, PskError> {
    let constitution_dir = bundle_root.join("constitution");
    let constitution_check = verify_bundle::check_constitution_bundle(&constitution_dir)
        .map_err(|_| PskError::BootPreconditionFailed)?;
    Ok(BundleImage {
        bundle_root: bundle_root.to_path_buf(),
        constitution_check,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        loop {
            if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
                return dir;
            }
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
    }

    #[test]
    fn loading_the_real_workspace_bundle_reads_the_sealed_constitution() {
        let image = load(&workspace_root()).unwrap();
        assert!(image.constitution_check.sealed());
        assert_eq!(image.constitution_check.total_normative_files, 22);
    }

    #[test]
    fn loading_a_bundle_without_a_constitution_directory_fails_closed() {
        let dir = std::env::temp_dir().join(format!("psk-load-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // `BundleImage` traegt `verify_bundle::BundleCheck` (kein Debug/PartialEq
        // - siehe dessen Modulkopf), deshalb hier `matches!` statt `assert_eq!`.
        assert!(matches!(load(&dir), Err(PskError::BootPreconditionFailed)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
