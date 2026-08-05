//! Definition 9.12 (360-Grad-Closure), Definition 9.13 (720-Grad-Closure),
//! Invariante 9.16 (Keine Halbschliessung).
//!
//! ```text
//! Close360(x) = 1 <=> pi(Phi(x)) = pi(x)  and  Seam(Phi,x) = 1
//! Close720(x) = 1 <=> Phi^2(x) ==can x  and  Hol(Phi^2) = I  and  Replay(Phi^2) ==can x
//! ```
//!
//! Phi (Linsenanwendung, M09/SpectralLensRouter), pi (Projektion), Seam
//! (M10/M11) und Replay (M19/Trace-Replay-Residue-Store) selbst zu
//! berechnen liegt ausserhalb dieses Moduls und ausserhalb des fuer I2
//! vereinbarten Umfangs; hier wird ausschliesslich die in Definition
//! 9.12/9.13 gegebene Verknuepfungsformel ueber bereits vorliegende Evidenz
//! ausgewertet - das ist woertliche Umsetzung der Definition, nicht eine
//! Annaeherung an sie.

use psk_types::Digest;

/// Evidenz fuer Definition 9.12: die bereits andernorts (M09/M10)
/// berechneten Groessen pi(Phi(x)), pi(x) und Seam(Phi,x).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close360Evidence {
    /// pi(Phi(x)) - Projektion des gelinsten Bildes.
    pub projected_lensed: Digest,
    /// pi(x) - Projektion des Urbildes.
    pub projected_source: Digest,
    /// Seam(Phi, x) == 1.
    pub seam_ok: bool,
}

/// Definition 9.12 woertlich: pi(Phi(x)) = pi(x) und Seam(Phi,x) = 1.
pub fn close360(e: &Close360Evidence) -> bool {
    e.projected_lensed == e.projected_source && e.seam_ok
}

/// Evidenz fuer Definition 9.13: die bereits andernorts (M09/M19)
/// berechneten Groessen Phi^2(x) ==can x, Hol(Phi^2) = I und
/// Replay(Phi^2) ==can x.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Close720Evidence {
    /// Phi^2(x) ==can x.
    pub double_lensed_canon_eq: bool,
    /// Hol(Phi^2) == I (Identitaetstransport, Definition 9.14).
    pub holonomy_is_identity: bool,
    /// Replay(Phi^2) ==can x.
    pub replay_canon_eq: bool,
}

/// Definition 9.13 woertlich: alle drei Bedingungen zugleich.
pub fn close720(e: &Close720Evidence) -> bool {
    e.double_lensed_canon_eq && e.holonomy_is_identity && e.replay_canon_eq
}

/// Vertrag 9.15 (Semantische Rueckkehr): eine geschlossene Atlasroute ist
/// semantisch geschlossen, wenn Can(Hol_gamma(E)) = Can(E) gilt, oder die
/// Abweichung als zulaessiger Wicklungssektor, deklarierter Nachfolger oder
/// sichtbares Residuum klassifiziert ist. `UnclassifiedDeviation` ist keine
/// dieser vier Alternativen - eine Abweichung, die in keine der drei
/// benannten Ausweichklassen faellt, bleibt semantisch offen; genau dafuer
/// braucht `semantically_closed` einen Fall, der `false` liefert.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnClassification {
    ExactCanonicalReturn,
    PermissibleWindingSector,
    DeclaredSuccessor,
    VisibleResidue,
    UnclassifiedDeviation,
}

/// Vertrag 9.15: semantisch geschlossen, sofern eine der drei benannten
/// Ausweichklassen zutrifft oder der Exaktfall Can(Hol)=Can(E) vorliegt;
/// eine unklassifizierte Abweichung ist es nicht.
pub fn semantically_closed(classification: ReturnClassification) -> bool {
    matches!(
        classification,
        ReturnClassification::ExactCanonicalReturn
            | ReturnClassification::PermissibleWindingSector
            | ReturnClassification::DeclaredSuccessor
            | ReturnClassification::VisibleResidue
    )
}

/// Ergebnis einer Closure-Auswertung (Portnutzlast P18, M11 -> M12:
/// "ClosureReport", architecture/port_registry.yaml#P18).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClosureReport {
    pub close360: bool,
    pub close720: bool,
    /// Invariante 9.16 (Keine Halbschliessung): Close360(x)=1 impliziert
    /// NICHT Close720(x)=1. Emissionsklasse EXECUTABLE erfordert
    /// Close720=1 - unabhaengig vom Wert von close360. Dieses Feld macht
    /// genau das exekutierbar: es ist buchstaeblich gleich `close720`,
    /// nie aus `close360` ableitbar.
    pub executable_eligible: bool,
}

/// Wertet Close360 und Close720 aus der jeweiligen Evidenz aus (Definition
/// 9.12/9.13) und bildet daraus den ClosureReport (Invariante 9.16:
/// `executable_eligible` haengt ausschliesslich von `close720` ab).
pub fn evaluate(c360: &Close360Evidence, c720: &Close720Evidence) -> ClosureReport {
    let close360 = close360(c360);
    let close720 = close720(c720);
    ClosureReport {
        close360,
        close720,
        executable_eligible: close720,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(seed: &[u8]) -> Digest {
        Digest::sha256(seed)
    }

    #[test]
    fn close360_holds_when_projection_matches_and_seam_ok() {
        let d = digest(b"same");
        let e = Close360Evidence {
            projected_lensed: d,
            projected_source: d,
            seam_ok: true,
        };
        assert!(close360(&e));
    }

    #[test]
    fn close360_fails_when_projection_diverges() {
        let e = Close360Evidence {
            projected_lensed: digest(b"a"),
            projected_source: digest(b"b"),
            seam_ok: true,
        };
        assert!(!close360(&e));
    }

    #[test]
    fn close360_fails_when_seam_not_ok_even_if_projection_matches() {
        let d = digest(b"same");
        let e = Close360Evidence {
            projected_lensed: d,
            projected_source: d,
            seam_ok: false,
        };
        assert!(!close360(&e));
    }

    #[test]
    fn close720_requires_all_three_conditions() {
        let full = Close720Evidence {
            double_lensed_canon_eq: true,
            holonomy_is_identity: true,
            replay_canon_eq: true,
        };
        assert!(close720(&full));

        let missing_holonomy = Close720Evidence {
            holonomy_is_identity: false,
            ..full
        };
        assert!(!close720(&missing_holonomy));

        let missing_replay = Close720Evidence {
            replay_canon_eq: false,
            ..full
        };
        assert!(!close720(&missing_replay));

        let missing_canon = Close720Evidence {
            double_lensed_canon_eq: false,
            ..full
        };
        assert!(!close720(&missing_canon));
    }

    #[test]
    fn invariante_9_16_no_half_closure() {
        // Close360 = 1, aber Close720 = 0: executable_eligible MUSS false
        // bleiben - Close360 allein darf niemals Identitaetsschluss
        // begruenden (Invariante 9.16).
        let d = digest(b"same");
        let c360 = Close360Evidence {
            projected_lensed: d,
            projected_source: d,
            seam_ok: true,
        };
        let c720 = Close720Evidence {
            double_lensed_canon_eq: true,
            holonomy_is_identity: false,
            replay_canon_eq: true,
        };
        let report = evaluate(&c360, &c720);
        assert!(report.close360);
        assert!(!report.close720);
        assert!(!report.executable_eligible);
    }

    #[test]
    fn full_closure_makes_executable_eligible() {
        let d = digest(b"same");
        let c360 = Close360Evidence {
            projected_lensed: d,
            projected_source: d,
            seam_ok: true,
        };
        let c720 = Close720Evidence {
            double_lensed_canon_eq: true,
            holonomy_is_identity: true,
            replay_canon_eq: true,
        };
        let report = evaluate(&c360, &c720);
        assert!(report.close360);
        assert!(report.close720);
        assert!(report.executable_eligible);
    }

    #[test]
    fn semantic_return_accepts_the_named_vertrag_9_15_classes_only() {
        assert!(semantically_closed(
            ReturnClassification::ExactCanonicalReturn
        ));
        assert!(semantically_closed(
            ReturnClassification::PermissibleWindingSector
        ));
        assert!(semantically_closed(ReturnClassification::DeclaredSuccessor));
        assert!(semantically_closed(ReturnClassification::VisibleResidue));
        assert!(!semantically_closed(
            ReturnClassification::UnclassifiedDeviation
        ));
    }
}
