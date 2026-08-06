//! M15 EffectTokenService, Bootschritt 17 (Algorithmus 17.1):
//! `register_only_versioned_operators_and_capabilities()`.
//!
//! Struktur 7.1 (RuntimeManifest) fuehrt genau diese beiden Felder:
//! `operator_versions: map<OpId,SemVer>`, `adapter_versions:
//! map<AdapterId,SemVer>`. Der Funktionsname liest sich als Vorbedingung,
//! nicht als Aufzaehlung: "only_versioned" heisst, von den 23
//! geschlossenen OpId-Werten (Definition 12.1) und den frei benannten
//! AdapterId-Adaptern wird NUR registriert, was der Aufrufer bereits mit
//! einer echten SemVer versehen hat. Ein Operator ohne Version wird nicht
//! mit einem erfundenen Default versehen (Invariante 17.3 - "Kein
//! undokumentierter Default" - waere sonst verletzt), sondern bleibt
//! schlicht unregistriert. Die reale Pruefung dieser Funktion ist deshalb
//! nicht "sind alle 23 da", sondern "ist jede gemeldete Version auch
//! wirklich eine, und ist jede OpId/AdapterId hoechstens einmal gemeldet" -
//! eine leere oder wiederholte Version waere eine verdeckte
//! Falschbehauptung von Versioniertheit.

use std::collections::BTreeMap;

use psk_types::objects::{AdapterId, OpId, SemVer};
use psk_types::PskError;

/// Ergebnis von `register_only_versioned_operators_and_capabilities` -
/// dieselben beiden Kartentypen wie `RuntimeManifest.operator_versions`/
/// `.adapter_versions` (Struktur 7.1), damit der Aufrufer sie direkt in
/// ein RuntimeManifest uebernehmen kann, ohne sie ein zweites Mal zu bauen.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OperatorRegistration {
    pub operator_versions: BTreeMap<OpId, SemVer>,
    pub adapter_versions: BTreeMap<AdapterId, SemVer>,
}

fn is_real_version(v: &SemVer) -> bool {
    !v.0.trim().is_empty()
}

/// M15: registriert nur versionierte Operatoren/Adapter. `operators`/
/// `adapters` sind die vom Aufrufer bereits als "in diesem Build
/// vorhanden" identifizierten Paare - welche der 23 OpId-Werte ein
/// gegebener Build tatsaechlich realisiert, ist eine Build-Tatsache, keine
/// aus einem Register ableitbare Berechnung (derselbe Grund, aus dem
/// `psk_gate::evaluate_gate`s `ConditionOutcome` vom Aufrufer kommt, siehe
/// dessen Modulkopf).
///
/// Scheitert (PSK-E101, Bootvorbedingung verletzt) bei einer leeren
/// Versionszeichenkette oder einer doppelt gemeldeten OpId/AdapterId -
/// beides waere eine verdeckte Falschbehauptung von Versioniertheit, kein
/// gueltiger Registrierungszustand.
pub fn register_only_versioned_operators_and_capabilities(
    operators: &[(OpId, SemVer)],
    adapters: &[(AdapterId, SemVer)],
) -> Result<OperatorRegistration, PskError> {
    let mut operator_versions = BTreeMap::new();
    for (op, version) in operators {
        if !is_real_version(version) {
            return Err(PskError::BootPreconditionFailed);
        }
        if operator_versions.insert(*op, version.clone()).is_some() {
            return Err(PskError::BootPreconditionFailed);
        }
    }

    let mut adapter_versions = BTreeMap::new();
    for (adapter, version) in adapters {
        if !is_real_version(version) {
            return Err(PskError::BootPreconditionFailed);
        }
        if adapter_versions
            .insert(adapter.clone(), version.clone())
            .is_some()
        {
            return Err(PskError::BootPreconditionFailed);
        }
    }

    Ok(OperatorRegistration {
        operator_versions,
        adapter_versions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> SemVer {
        SemVer(s.to_string())
    }

    #[test]
    fn registers_real_versioned_operators_and_adapters() {
        let result = register_only_versioned_operators_and_capabilities(
            &[(OpId::Canon, v("1.0.0")), (OpId::Gate, v("1.0.0"))],
            &[(AdapterId("observer-local-fs".into()), v("1.0.0"))],
        )
        .unwrap();
        assert_eq!(result.operator_versions.len(), 2);
        assert_eq!(result.adapter_versions.len(), 1);
        assert_eq!(
            result.operator_versions.get(&OpId::Canon),
            Some(&v("1.0.0"))
        );
    }

    #[test]
    fn empty_operator_list_is_a_valid_empty_registration() {
        let result = register_only_versioned_operators_and_capabilities(&[], &[]).unwrap();
        assert!(result.operator_versions.is_empty());
        assert!(result.adapter_versions.is_empty());
    }

    #[test]
    fn an_empty_version_string_is_rejected_not_defaulted() {
        // Invariante 17.3: kein verdeckter Default fuer eine fehlende Version.
        assert_eq!(
            register_only_versioned_operators_and_capabilities(&[(OpId::Canon, v(""))], &[]),
            Err(PskError::BootPreconditionFailed)
        );
    }

    #[test]
    fn a_whitespace_only_version_string_is_rejected() {
        assert_eq!(
            register_only_versioned_operators_and_capabilities(&[(OpId::Canon, v("   "))], &[]),
            Err(PskError::BootPreconditionFailed)
        );
    }

    #[test]
    fn a_duplicate_operator_id_is_rejected() {
        assert_eq!(
            register_only_versioned_operators_and_capabilities(
                &[(OpId::Canon, v("1.0.0")), (OpId::Canon, v("2.0.0"))],
                &[]
            ),
            Err(PskError::BootPreconditionFailed)
        );
    }

    #[test]
    fn a_duplicate_adapter_id_is_rejected() {
        assert_eq!(
            register_only_versioned_operators_and_capabilities(
                &[],
                &[
                    (AdapterId("observer-local-fs".into()), v("1.0.0")),
                    (AdapterId("observer-local-fs".into()), v("1.0.1")),
                ]
            ),
            Err(PskError::BootPreconditionFailed)
        );
    }

    #[test]
    fn all_23_opids_can_be_registered_at_once() {
        let operators: Vec<(OpId, SemVer)> = OpId::ALL.iter().map(|op| (*op, v("1.0.0"))).collect();
        let result = register_only_versioned_operators_and_capabilities(&operators, &[]).unwrap();
        assert_eq!(result.operator_versions.len(), 23);
    }
}
