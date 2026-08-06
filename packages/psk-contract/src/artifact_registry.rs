//! M02 ArtifactRegistry, Bootschritt 3 (Algorithmus 17.1):
//! `M02.resolve_artifact_registry(image)`.
//!
//! Diese eine Funktion deckt zugleich den architekturseitigen Anteil von
//! Schritt 7 (`M03.register_schemas(canon); M03.validate_all(canon)`) und
//! die Schritte 10/11 (`aid = M01.collection_digest(canon.
//! architecture_registers)`; `require aid == image.lock.architecture_id`)
//! ab: `tools/verify-architecture::check_architecture_bundle` validiert
//! bereits alle 18 Architekturregister strukturell gegen ihre Schemas UND
//! bildet I_A ueber dieselben 18 Register plus ihre 18 Schemas, im selben
//! Durchlauf (siehe dessen Modulkopf). Drei Algorithmusschritte, eine
//! bereits reale, bereits getestete Pruefung - `boot()` liest hier
//! dieselben Felder dreifach aus, statt die Pruefung dreifach
//! aufzurufen.
//!
//! M03 (SchemaValidator) selbst ist laut module_map.yaml `package:
//! psk-types` - die konstitutionsseitigen 5 Objektschemas (Struktur 7.x)
//! werden dort durch den generierten Rust-Typ selbst erzwungen
//! (Compilezeit-Formzwang), nicht durch einen zusaetzlichen Laufzeitpass
//! hier. Diese Funktion realisiert deshalb genau M02, nicht ein
//! zusaetzliches M03-Modul, das die Architektur laut Register gar nicht
//! vorsieht.

use std::path::Path;

use psk_types::PskError;

use crate::load::BundleImage;

pub struct ArtifactRegistry {
    pub architecture_check: verify_architecture::ArchitectureCheck,
}

/// M02: loest die Artefaktregistrierung gegen `image.bundle_root` auf.
pub fn resolve_artifact_registry(image: &BundleImage) -> Result<ArtifactRegistry, PskError> {
    resolve_artifact_registry_at(&image.bundle_root)
}

/// Wie `resolve_artifact_registry`, aber direkt gegen einen Wurzelpfad -
/// fuer Tests, die keinen vollen `BundleImage` aufbauen wollen.
pub fn resolve_artifact_registry_at(bundle_root: &Path) -> Result<ArtifactRegistry, PskError> {
    let architecture_check = verify_architecture::check_architecture_bundle(bundle_root)
        .map_err(|_| PskError::BootPreconditionFailed)?;
    Ok(ArtifactRegistry { architecture_check })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> std::path::PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        loop {
            if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
                return dir;
            }
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
    }

    #[test]
    fn resolving_the_real_workspace_registers_all_18_files_schema_conformant() {
        let registry = resolve_artifact_registry_at(&workspace_root()).unwrap();
        assert!(registry.architecture_check.schema_conformant());
        assert!(registry.architecture_check.sealed());
        assert_eq!(registry.architecture_check.total_expected, 36);
    }

    #[test]
    fn resolving_a_bundle_without_an_architecture_directory_fails_closed() {
        let dir = std::env::temp_dir().join(format!("psk-artreg-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(
            resolve_artifact_registry_at(&dir),
            Err(PskError::BootPreconditionFailed)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
