//! Definition 14.1 (Kanonische Taktfolge): "Observe -> Normalize -> Type ->
//! Anchor -> Project -> Compile -> Challenge -> Verify -> Execute ->
//! Observe -> Reconcile -> Archive. Ein Tick durchlaeuft die Phasen in
//! exakt dieser Reihenfolge."
//!
//! Kein Registerursprung (kein YAML fuehrt die Taktfolge; sie steht nur als
//! Fliesstext in Kapitel 14) - deshalb handgeschrieben statt generiert,
//! genau wie `digest`/`m13_address`/`msg`/`object_id` in diesem Paket.
//! Liegt hier statt in psk-scheduler (M25), weil sowohl psk-trace (M19,
//! `seal_phase`) als auch psk-scheduler (M25, `dispatch`/`tick`) denselben
//! Phasenbegriff brauchen und psk-scheduler von psk-trace abhaengt - ein
//! Typ, den beide lesen, muss unterhalb beider liegen.
//!
//! Die zweite Observe-Phase heisst hier `Observe2`: Rust-Enums kennen keine
//! doppelten Varianten, das Werk selbst schreibt sie als "Observe (2)".

/// Definition 14.1s zwoelf Phasen, in der dort festgelegten Reihenfolge.
/// `Ord` sortiert nach Deklarationsreihenfolge - dieselbe Reihenfolge, in
/// der `tick()` sie durchlaeuft.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    Observe,
    Normalize,
    Type,
    Anchor,
    Project,
    Compile,
    Challenge,
    Verify,
    Execute,
    Observe2,
    Reconcile,
    Archive,
}

impl Phase {
    /// Kurzbezeichner fuer Traceeintraege (`EventTypeId`) und Diagnosen -
    /// stabil, klein geschrieben, ASCII.
    pub const fn label(self) -> &'static str {
        match self {
            Phase::Observe => "observe",
            Phase::Normalize => "normalize",
            Phase::Type => "type",
            Phase::Anchor => "anchor",
            Phase::Project => "project",
            Phase::Compile => "compile",
            Phase::Challenge => "challenge",
            Phase::Verify => "verify",
            Phase::Execute => "execute",
            Phase::Observe2 => "observe_2",
            Phase::Reconcile => "reconcile",
            Phase::Archive => "archive",
        }
    }
}

/// Definition 14.1, als feste Reihenfolge. `tick()` iteriert genau darueber
/// ("for phase in CANONICAL_PHASES: // feste Reihenfolge", Algorithmus 14.4).
pub const CANONICAL_PHASES: [Phase; 12] = [
    Phase::Observe,
    Phase::Normalize,
    Phase::Type,
    Phase::Anchor,
    Phase::Project,
    Phase::Compile,
    Phase::Challenge,
    Phase::Verify,
    Phase::Execute,
    Phase::Observe2,
    Phase::Reconcile,
    Phase::Archive,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn twelve_phases_in_the_defined_order() {
        assert_eq!(CANONICAL_PHASES.len(), 12);
        assert_eq!(CANONICAL_PHASES[0], Phase::Observe);
        assert_eq!(CANONICAL_PHASES[8], Phase::Execute);
        assert_eq!(CANONICAL_PHASES[9], Phase::Observe2);
        assert_eq!(CANONICAL_PHASES[11], Phase::Archive);
    }

    #[test]
    fn phases_sort_in_declaration_order() {
        let mut shuffled = vec![Phase::Archive, Phase::Observe, Phase::Execute];
        shuffled.sort();
        assert_eq!(
            shuffled,
            vec![Phase::Observe, Phase::Execute, Phase::Archive]
        );
    }

    #[test]
    fn labels_are_distinct() {
        let labels: std::collections::BTreeSet<&str> =
            CANONICAL_PHASES.iter().map(|p| p.label()).collect();
        assert_eq!(labels.len(), 12);
    }
}
