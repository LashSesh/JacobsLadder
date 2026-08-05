//! M25 Scheduler, Prioritaetsordnung (Regel 14.5).
//!
//! Woertlich: "Innerhalb einer Phase gilt die absteigende Ordnung:
//! 1. offene UNKNOWN_EFFECT-Zustaende und offene Reconciliation;
//! 2. ablaufende EffectToken (kleinstes expires_at_tau_i zuerst);
//! 3. blocking Witnesses und blocking Residuen;
//! 4. deklarierte externe Gefahren gemaess RiskClass;
//! 5. bestehende Kapseln im Ratchet;
//! 6. neue spekulative Branches.
//!
//! Bei Gleichrang entscheidet die aufsteigende ObjectId in lexikographischer
//! Bytereihenfolge. Damit ist die Ordnung total und replaystabil."
//!
//! Algorithmus 14.4 (Tick): "queue = M25.select(phase, state) //
//! deterministische Auswahl". `state` (Sigma, Definition 13.1) ist der
//! gesamte Laufzustand - `select` hier nimmt statt dessen direkt die
//! bereits identifizierten anstehenden Elemente entgegen (welche Elemente
//! in einer Phase ueberhaupt anstehen, ist Sache der Phase-Dispatchlogik,
//! nicht der Prioritaetsordnung selbst).

use psk_types::ObjectId;

/// Die sechs Raenge aus Regel 14.5, in der im Text genannten Reihenfolge.
/// `Ord` sortiert nach Deklarationsreihenfolge - Rang 1 ist der kleinste
/// Diskriminant und damit (aufsteigend sortiert) der erste.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityTier {
    UnknownEffectOrOpenReconciliation,
    ExpiringEffectToken,
    BlockingWitnessOrResidue,
    DeclaredExternalDanger,
    RatchetingCapsule,
    SpeculativeBranch,
}

/// Ein fuer eine Phase anstehendes Element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulableItem {
    pub id: ObjectId,
    pub tier: PriorityTier,
    /// Nur fuer `ExpiringEffectToken` bedeutsam (Kriterium 2: "kleinstes
    /// zuerst"); bei jedem anderen Rang `None` und ohne Einfluss auf die
    /// Ordnung, weil Elemente unterschiedlicher Raenge bereits durch `tier`
    /// entschieden sind.
    pub expires_at_tau_i: Option<u64>,
}

/// Regel 14.5 als totale Ordnung: `tier` aufsteigend, dann
/// `expires_at_tau_i` aufsteigend (nur innerhalb `ExpiringEffectToken`
/// ueberhaupt vorhanden), dann die ObjectId in ihrer Bytedarstellung
/// (`to_string()` liefert "psk:<sorte>:<digest>" - lexikographisch auf
/// dieser Zeichenkette ist dieselbe Ordnung wie auf den zugrundeliegenden
/// Bytes, weil Sorte und Digest je fester Laenge und Hexziffern sind).
pub fn select(mut items: Vec<SchedulableItem>) -> Vec<SchedulableItem> {
    items.sort_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then_with(|| a.expires_at_tau_i.cmp(&b.expires_at_tau_i))
            .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::SortId;
    use psk_types::Digest;

    fn item(tier: PriorityTier, seed: &[u8], expires: Option<u64>) -> SchedulableItem {
        SchedulableItem {
            id: ObjectId::new(SortId::Context, Digest::sha256(seed)),
            tier,
            expires_at_tau_i: expires,
        }
    }

    #[test]
    fn higher_tiers_come_first() {
        let out = select(vec![
            item(PriorityTier::SpeculativeBranch, b"a", None),
            item(PriorityTier::UnknownEffectOrOpenReconciliation, b"b", None),
            item(PriorityTier::RatchetingCapsule, b"c", None),
        ]);
        let tiers: Vec<_> = out.iter().map(|i| i.tier).collect();
        assert_eq!(
            tiers,
            vec![
                PriorityTier::UnknownEffectOrOpenReconciliation,
                PriorityTier::RatchetingCapsule,
                PriorityTier::SpeculativeBranch,
            ]
        );
    }

    #[test]
    fn within_expiring_tokens_smallest_expiry_first() {
        let out = select(vec![
            item(PriorityTier::ExpiringEffectToken, b"a", Some(100)),
            item(PriorityTier::ExpiringEffectToken, b"b", Some(10)),
            item(PriorityTier::ExpiringEffectToken, b"c", Some(50)),
        ]);
        let expiries: Vec<_> = out.iter().map(|i| i.expires_at_tau_i).collect();
        assert_eq!(expiries, vec![Some(10), Some(50), Some(100)]);
    }

    #[test]
    fn ties_break_on_ascending_object_id() {
        let a = item(PriorityTier::RatchetingCapsule, b"zzz", None);
        let b = item(PriorityTier::RatchetingCapsule, b"aaa", None);
        let expect_first = if a.id.to_string() < b.id.to_string() {
            a.id
        } else {
            b.id
        };
        let out = select(vec![a, b]);
        assert_eq!(out[0].id, expect_first);
    }

    #[test]
    fn a_lower_tier_never_jumps_an_expiring_token_regardless_of_expiry() {
        // Rang 1 vor Rang 2: unabhaengig davon, wie knapp das Token ablaeuft.
        let out = select(vec![
            item(PriorityTier::ExpiringEffectToken, b"a", Some(1)),
            item(PriorityTier::UnknownEffectOrOpenReconciliation, b"b", None),
        ]);
        assert_eq!(out[0].tier, PriorityTier::UnknownEffectOrOpenReconciliation);
    }

    #[test]
    fn ordering_is_total_and_replay_stable() {
        let items = vec![
            item(PriorityTier::SpeculativeBranch, b"a", None),
            item(PriorityTier::DeclaredExternalDanger, b"b", None),
            item(PriorityTier::BlockingWitnessOrResidue, b"c", None),
        ];
        let once = select(items.clone());
        let twice = select(items);
        assert_eq!(once, twice);
    }

    #[test]
    fn empty_queue_is_fine() {
        assert!(select(vec![]).is_empty());
    }
}
