//! Der **Historiker** ("rekonstruiert Versionen", Regel 32.7 (Feldfamilie der Referenzdomäne)) hat hier sein
//! Verhalten - dasselbe Muster wie Falsifikator und Integrator
//! (`psk_adversarial::corpus`): eine reine Funktion ueber bereits
//! deponierte Sigma-Werte, kein eigener Zugriff auf die Aussenwelt. Das
//! LESEN bleibt M17s Sache (`observer_local_fs::observe_history`,
//! `psk_scheduler::RunProgram::version_history`); der Historiker
//! interpretiert nur, was dort schon steht.
//!
//! Warum das eine eigene Funktion braucht, statt die Folgenbeobachtung
//! direkt zu melden: ein Reflog fuehrt JEDE HEAD-Bewegung
//! (`clone`, `checkout`, `fetch`, `commit`, ...), nicht nur die, die eine
//! neue Version erzeugen. `checkout` bewegt die Spitze, ohne Inhalt zu
//! aendern; nur `commit`-Eintraege tun das. Ohne diese Trennung waere ein
//! Branchwechsel dieselbe "Version" wie ein Fassungswechsel des Korpus.

use psk_anchor::HistoryPoint;

/// Reflog-Aktionen, die eine tatsaechlich neue Version erzeugen. Bewusst
/// eng: `commit` (und seine Sonderform `commit (amend)`, die git im
/// selben Praefix fuehrt) ist die einzige Aktion, die den beobachteten
/// Baum inhaltlich veraendert. `merge`, `pull`, `rebase` bewegen HEAD
/// ueber einen NEUEN Commit ebenfalls - git schreibt sie im Reflog aber
/// bereits als `commit` bzw. mit eigenem Praefix; diese Funktion faengt
/// nur, was `commit` genannt wird, und meldet den Rest nicht als
/// Version, statt zu raten.
fn is_version_change(message: &str) -> bool {
    message.starts_with("commit")
}

/// Der Historiker: filtert die rohe Folgenbeobachtung auf tatsaechliche
/// Versionswechsel, aeltester zuerst (Reihenfolge der Eingabe bleibt
/// erhalten - der Historiker sortiert nicht um, er waehlt aus).
pub fn reconstructed_versions(history: &[HistoryPoint]) -> Vec<HistoryPoint> {
    history
        .iter()
        .filter(|p| is_version_change(&p.message))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn point(commit: &str, message: &str) -> HistoryPoint {
        HistoryPoint {
            commit: commit.to_string(),
            observed_at_unix: 0,
            message: message.to_string(),
        }
    }

    #[test]
    fn commits_are_versions_checkouts_and_clones_are_not() {
        let history = vec![
            point("a", "clone: from https://example.invalid/repo.git"),
            point("b", "checkout: moving from main to feature"),
            point("c", "commit: first real change"),
            point("d", "checkout: moving from feature to main"),
            point("e", "commit: second real change"),
        ];
        let versions = reconstructed_versions(&history);
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].commit, "c");
        assert_eq!(versions[1].commit, "e");
    }

    #[test]
    fn an_amended_commit_still_counts_as_a_version() {
        let history = vec![point("a", "commit (amend): fix a typo")];
        assert_eq!(reconstructed_versions(&history).len(), 1);
    }

    #[test]
    fn an_empty_sequence_yields_an_empty_reconstruction_not_an_error() {
        assert_eq!(reconstructed_versions(&[]), Vec::new());
    }

    #[test]
    fn order_is_preserved_not_resorted() {
        let history = vec![
            point("z", "commit: third by commit content, first in the list"),
            point("a", "commit: first by commit content, second in the list"),
        ];
        let versions = reconstructed_versions(&history);
        assert_eq!(versions[0].commit, "z");
        assert_eq!(versions[1].commit, "a");
    }

    /// Reale Reflog-Zeilen dieses Repos (siehe `.git/logs/HEAD`), nicht
    /// erfunden - derselbe Anspruch wie ueberall sonst im Werk, wo eine
    /// Domaene beobachtet statt behauptet wird.
    #[test]
    fn a_real_looking_reflog_message_is_recognized() {
        let history = vec![point(
            "6198dae168632e99940c25ad9d67f7e090588fba",
            "commit: v1.0.47: capsulate reads its own argument, and the corpus explains why it still agrees",
        )];
        assert_eq!(reconstructed_versions(&history).len(), 1);
    }
}
