//! M21 CertificateReleaseEngine, Bootschritt 18 (Algorithmus 17.1):
//! `compute_release_and_operational_posture()`.
//!
//! Definition 31.3 (Releaseposture): "Release in { REJECTED, QUARANTINED,
//! CONFORMANT_LIMITED, CONFORMANT_REFERENCE, EXTERNALLY_VALIDATED }."
//! Regel 31.1 nennt zwoelf blockierende Bedingungen, Vertrag 31.4 das
//! `verified`-Praedikat (sieben Pflichtberichte MUESSEN gemeinsam vorliegen
//! und gemeinsam verifiziert sein: Maschinenzertifikat, Replaymanifest,
//! Negativtestbericht, Residuenbericht, Capability Audit, Refinementbericht,
//! Bundlemanifest). Das ist die VOLLE Release-Pruefung - dieselbe, die
//! `evaluate_release_gate`/`issue_certificate` (certify.rs) bereits am
//! tatsaechlichen Releasepunkt durchfuehren, mit echten Laufresultaten als
//! Eingabe.
//!
//! Zur BOOTZEIT (Algorithmus 17.1 Schritt 18) liegt davon strukturell nur
//! ein Teil vor: kein Lauf hat stattgefunden, also existieren weder
//! Replaymanifest noch Negativtestbericht noch Capability Audit noch
//! Refinementbericht noch SBOM. Was am Boot tatsaechlich pruefbar ist, sind
//! die Bootartefakte selbst - dieselben, die G-BOOT (Schritte 1-13)
//! bereits einzeln feststellt. `compute_release_and_operational_posture`
//! bildet deshalb eine EHRLICH BOOT-SKALIERTE Teilmenge von Regel 31.1 auf
//! Definition 31.3 ab:
//!
//! - Ein versiegelter, aber nicht deckungsgleicher Digest (constitution_
//!   oder architecture_digest_mismatch) => REJECTED (Regel 17.2:
//!   digest_mismatch:fail - ein FAIL-Fall, keine Bootzeit-Grauzone).
//! - Ein fehlendes/unversiegeltes Artefakt oder eine nicht gebundene
//!   Identitaet (manifest_invalid) => QUARANTINED (Regel 17.2:
//!   missing_artifact:quarantine).
//! - Sind Konstitution und Architektur versiegelt, deckungsgleich und
//!   schemakonform, und ist die Identitaet gebunden, aber das volle
//!   `verified`-Praedikat (Vertrag 31.4) liegt noch nicht vor (am Boot
//!   IMMER der Fall - siehe oben) => CONFORMANT_LIMITED. Das ist keine
//!   Herabstufung, sondern die einzige am Boot ehrliche positive Posture.
//! - CONFORMANT_REFERENCE (Vertrag 31.4 `verified`) und EXTERNALLY_VALIDATED
//!   (C5, unabhaengige Reproduktion) verlangen Evidenz, die es vor einem
//!   tatsaechlichen Lauf nicht geben kann - diese Funktion gibt sie nur
//!   zurueck, wenn der Aufrufer sie explizit als bereits erbracht meldet
//!   (`full_release_verified`/`externally_reproduced`), was `boot()` selbst
//!   nie tut. Der spaetere, vollstaendige Releasepfad bleibt
//!   `evaluate_release_gate`/`issue_certificate` vorbehalten.

use psk_types::objects::Releaseposture;

/// Eingaben aus den bereits real durchgefuehrten Bootpruefungen (M00/M02/
/// M04) - keines dieser Felder wird hier gemessen, alle kommen vom
/// Aufrufer, der die eigentliche Pruefung schon durchgefuehrt hat
/// (derselbe Grund wie bei `AdditionalAcceptance` in certify.rs).
#[derive(Debug, Clone, Copy, Default)]
pub struct PostureInputs {
    /// constitution.lock.json traegt bereits eine constitution_id.
    pub constitution_sealed: bool,
    /// Der selbst berechnete Digest stimmt mit dem versiegelten ueberein.
    pub constitution_matches: bool,
    /// architecture.lock.json traegt bereits eine architecture_id.
    pub architecture_sealed: bool,
    /// Der selbst berechnete Digest stimmt mit dem versiegelten ueberein.
    pub architecture_matches: bool,
    /// Alle 18 Architekturregister sind strukturell schemakonform.
    pub architecture_schema_conformant: bool,
    /// M04.bind()/check_profile_binding() sind erfolgreich durchgelaufen.
    pub identity_bound: bool,
    /// Vertrag 31.4 `verified`: alle sieben Pflichtberichte liegen
    /// gemeinsam vor und sind gemeinsam verifiziert. Bei `boot()` immer
    /// `false` - siehe Modulkopf.
    pub full_release_verified: bool,
    /// C5: unabhaengige Instanz hat reproduziert. Bei `boot()` immer
    /// `false` - siehe Modulkopf.
    pub externally_reproduced: bool,
}

/// M21: leitet die Releaseposture (Definition 31.3) aus den Bootbefunden
/// ab. Totale, monotone Funktion - siehe Modulkopf fuer die Zuordnung.
pub fn compute_release_and_operational_posture(inputs: PostureInputs) -> Releaseposture {
    if inputs.constitution_sealed && !inputs.constitution_matches {
        return Releaseposture::Rejected; // constitution_digest_mismatch
    }
    if inputs.architecture_sealed && !inputs.architecture_matches {
        return Releaseposture::Rejected; // architecture_digest_mismatch
    }
    if inputs.architecture_sealed && !inputs.architecture_schema_conformant {
        return Releaseposture::Rejected; // schema_failure
    }
    if !inputs.constitution_sealed || !inputs.architecture_sealed || !inputs.identity_bound {
        return Releaseposture::Quarantined; // manifest_invalid
    }
    if inputs.externally_reproduced && inputs.full_release_verified {
        return Releaseposture::ExternallyValidated;
    }
    if inputs.full_release_verified {
        return Releaseposture::ConformantReference;
    }
    Releaseposture::ConformantLimited
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_boot_checks_pass() -> PostureInputs {
        PostureInputs {
            constitution_sealed: true,
            constitution_matches: true,
            architecture_sealed: true,
            architecture_matches: true,
            architecture_schema_conformant: true,
            identity_bound: true,
            full_release_verified: false,
            externally_reproduced: false,
        }
    }

    #[test]
    fn a_fully_consistent_boot_is_conformant_limited_not_rejected() {
        // Der ehrliche positive Bootbefund - kein Lauf hat stattgefunden,
        // also kann Vertrag 31.4 (verified) noch nicht erfuellt sein.
        assert_eq!(
            compute_release_and_operational_posture(all_boot_checks_pass()),
            Releaseposture::ConformantLimited
        );
    }

    #[test]
    fn a_sealed_but_mismatched_constitution_digest_is_rejected() {
        let inputs = PostureInputs {
            constitution_matches: false,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::Rejected
        );
    }

    #[test]
    fn a_sealed_but_mismatched_architecture_digest_is_rejected() {
        let inputs = PostureInputs {
            architecture_matches: false,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::Rejected
        );
    }

    #[test]
    fn a_schema_failure_is_rejected() {
        let inputs = PostureInputs {
            architecture_schema_conformant: false,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::Rejected
        );
    }

    #[test]
    fn an_unsealed_constitution_is_quarantined_not_rejected() {
        // Regel 17.2: missing_artifact -> quarantine, nicht fail - noch
        // kein Digest-Widerspruch, nur ein fehlendes Artefakt.
        let inputs = PostureInputs {
            constitution_sealed: false,
            constitution_matches: false,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::Quarantined
        );
    }

    #[test]
    fn an_unbound_identity_is_quarantined() {
        let inputs = PostureInputs {
            identity_bound: false,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::Quarantined
        );
    }

    #[test]
    fn full_release_verification_reaches_conformant_reference() {
        let inputs = PostureInputs {
            full_release_verified: true,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::ConformantReference
        );
    }

    #[test]
    fn external_reproduction_on_top_of_verified_reaches_externally_validated() {
        let inputs = PostureInputs {
            full_release_verified: true,
            externally_reproduced: true,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::ExternallyValidated
        );
    }

    #[test]
    fn external_reproduction_alone_without_verified_is_not_enough() {
        // Vertrag 31.4 zuerst, C5 baut DARAUF auf, ersetzt es nicht.
        let inputs = PostureInputs {
            externally_reproduced: true,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::ConformantLimited
        );
    }

    #[test]
    fn rejection_takes_priority_over_quarantine_conditions() {
        // Ein Digest-Mismatch ist ein FAIL-Fall (Regel 17.2); er darf nicht
        // durch eine gleichzeitig fehlende Identitaetsbindung zu einem
        // blossen QUARANTINED abgeschwaecht werden.
        let inputs = PostureInputs {
            constitution_matches: false,
            identity_bound: false,
            ..all_boot_checks_pass()
        };
        assert_eq!(
            compute_release_and_operational_posture(inputs),
            Releaseposture::Rejected
        );
    }
}
