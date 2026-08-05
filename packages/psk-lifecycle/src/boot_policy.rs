//! M26 LifecycleSupervisor, Bootpolitik (Regel 17.2).
//!
//! Woertlich: "default: fail_closed; undecidable: hold; missing_artifact:
//! quarantine; digest_mismatch: fail." Vier benannte Situationen, vier
//! feste Reaktionen - keine davon ist eine Wahl der Implementierung.
//!
//! Invariante 17.3 (Keine undokumentierten Defaults): "Alle fuer
//! Identitaet, Replay, Sicherheit, Governance und Emission relevanten
//! Werte MUSS aus aufloesbaren Artefakten stammen. Ein verdeckter Default
//! ist ein Konformitaetsdefekt und erzeugt PSK-E101." Deshalb hat
//! `BootSituation` keinen `Default`-Impl und `decide` keinen Catch-all-
//! Zweig, der etwas anderes als `Default` annimmt, ohne dass die
//! Situation ausdruecklich als `Default` benannt wird.

use psk_types::PskError;

/// Die vier in Regel 17.2 benannten Situationen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSituation {
    /// Keine der drei anderen Situationen liegt vor.
    Default,
    /// Ein Bootschritt konnte kein Ergebnis feststellen (z.B. ein Gate mit
    /// `decision: HOLD`).
    Undecidable,
    /// Ein fuer den Boot benoetigtes Artefakt fehlt.
    MissingArtifact,
    /// Ein erwarteter Digest (constitution_id, architecture_id, ...)
    /// stimmt nicht mit dem versiegelten Wert ueberein.
    DigestMismatch,
}

/// Die vier Reaktionen aus Regel 17.2, als konkretes Ergebnis statt nur
/// eines Namens: `Fail`/`FailClosed` tragen den Fehlercode, den Boot-
/// Schritt 6/11 bei einem Digest-Mismatch ausdruecklich nennen
/// (PSK-E103), Undecidable/MissingArtifact ihre jeweils eigene Reaktion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootOutcome {
    FailClosed,
    Hold,
    Quarantine,
    Fail(PskError),
}

/// Regel 17.2 als totale Funktion - jede der vier Situationen hat genau
/// eine Reaktion, keine Ausnahme.
pub fn decide(situation: BootSituation) -> BootOutcome {
    match situation {
        BootSituation::Default => BootOutcome::FailClosed,
        BootSituation::Undecidable => BootOutcome::Hold,
        BootSituation::MissingArtifact => BootOutcome::Quarantine,
        // "require cid == image.lock.constitution_id else FAIL(PSK-E103)"
        // (Bootschritt 6, wortgleich Schritt 11 fuer architecture_id).
        BootSituation::DigestMismatch => BootOutcome::Fail(PskError::IdentityDigestMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_four_situations_match_regel_17_2_literally() {
        assert_eq!(decide(BootSituation::Default), BootOutcome::FailClosed);
        assert_eq!(decide(BootSituation::Undecidable), BootOutcome::Hold);
        assert_eq!(
            decide(BootSituation::MissingArtifact),
            BootOutcome::Quarantine
        );
        assert_eq!(
            decide(BootSituation::DigestMismatch),
            BootOutcome::Fail(PskError::IdentityDigestMismatch)
        );
    }

    #[test]
    fn decision_is_a_pure_deterministic_function() {
        assert_eq!(
            decide(BootSituation::Undecidable),
            decide(BootSituation::Undecidable)
        );
    }
}
