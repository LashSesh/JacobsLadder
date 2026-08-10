//! Die Domaenenseite des IRBundle-Zusammenbaus: das Domaenenprofil und
//! die versiegelten Register LADEN. Der Bau selbst (Knoten, Kanten,
//! Sondierungsvermerke) liegt seit der Taktumverdrahtung (Regel 24.4 (Der Golden Run läuft unter tick)
//! (Der Golden Run laeuft unter tick)) in M23 (`psk_ir::builders`, siehe
//! dortigen Modulkopf): die Compile-Phase wickelt ihn als Arbeit ab.
//!
//! ## Warum die Lader hier liegen und nicht in psk-ir
//!
//! Regel 10.9 (Herkunft der Kantenbedingungen) macht die Kantenbedingungen domaenengeliefert; Vertrag 27.2 (Domänengelieferte opake Eingaben)
//! sagt, der Kern reicht sie "nur typisiert weiter". Wer das
//! Domaenenprofil LIEST, ist also die Domaene - und die Referenzdomaene
//! ist dieser Konformanzlauf. psk-ir kennt deshalb weder den Dateipfad
//! noch das YAML-Format; es bekommt die geladenen Werte typisiert, und
//! seit der Taktumverdrahtung bekommt es sie aus dem Laufzustand Sigma,
//! in den dieser Lauf sie DEPONIERT.
//!
//! Dasselbe gilt fuer die Sorten-Port-Matrix: sie steht in
//! architecture/sort_registry.yaml und wird von hier gelesen, statt in
//! psk-ir noch einmal als Rust-Tabelle zu existieren. Eine zweite Wahrheit
//! neben dem Register ist genau die Driftklasse, die dieses Projekt schon
//! bei den Objektzahlen und beim Katalog getroffen hat.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use psk_ir::{EdgeConditionDeclarations, EdgeConditions};
use psk_types::objects::{PredicateExpr, RelationSortId, SortId};
use psk_types::{ModuleId, PskError};

pub use psk_ir::{build_node, edge, edge_census, NodeEnvelope};

/// Liest die Portmatrix aus dem versiegelten Register.
pub fn load_port_matrix(
    workspace_root: &Path,
) -> Result<Vec<(SortId, SortId, RelationSortId)>, PskError> {
    let text = std::fs::read_to_string(workspace_root.join("architecture/sort_registry.yaml"))
        .map_err(|_| PskError::UntypedInput)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|_| PskError::UntypedInput)?;
    let rows = doc
        .get("port_matrix")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?;

    let mut out = Vec::new();
    for row in rows {
        let cells = row.as_sequence().ok_or(PskError::UntypedInput)?;
        if cells.len() != 3 {
            return Err(PskError::UntypedInput);
        }
        let s = cells[0].as_str().ok_or(PskError::UntypedInput)?;
        let t = cells[1].as_str().ok_or(PskError::UntypedInput)?;
        let r = cells[2].as_str().ok_or(PskError::UntypedInput)?;
        out.push((
            SortId::from_id(s).ok_or(PskError::UntypedInput)?,
            SortId::from_id(t).ok_or(PskError::UntypedInput)?,
            RelationSortId::from_id(r).ok_or(PskError::UntypedInput)?,
        ));
    }
    Ok(out)
}

/// Die Normdaten, die Regel 9.8 (Richtungskonsistenz einer Zelle) zum
/// Pruefen braucht: Sorteneigner, Modulschichten, gemeinsame
/// Passtraegerschaften. Alle drei aus den versiegelten Registern gelesen,
/// nicht als Rust-Tabelle dupliziert - dieselbe Begruendung wie bei
/// `load_port_matrix` im Modulkopf.
pub struct ClosureNorms {
    pub sort_owner: BTreeMap<SortId, ModuleId>,
    pub module_layer: BTreeMap<ModuleId, u8>,
    pub shared_pass_carriers: BTreeSet<(ModuleId, ModuleId)>,
}

/// Liest Sorteneigner (sort_registry.yaml), Modulschichten
/// (module_map.yaml) und Passtraegerpaare (pass_registry.yaml).
pub fn load_closure_norms(workspace_root: &Path) -> Result<ClosureNorms, PskError> {
    // Modul -> Schicht. module_map.yaml: {id: M12, ..., layer: L5, ...}.
    let text = std::fs::read_to_string(workspace_root.join("architecture/module_map.yaml"))
        .map_err(|_| PskError::UntypedInput)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|_| PskError::UntypedInput)?;
    let mut module_layer = BTreeMap::new();
    for row in doc
        .get("modules")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?
    {
        let module = row
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(ModuleId::from_id)
            .ok_or(PskError::UntypedInput)?;
        let layer = row
            .get("layer")
            .and_then(|v| v.as_str())
            .and_then(|l| l.strip_prefix('L'))
            .and_then(|n| n.parse::<u8>().ok())
            .ok_or(PskError::UntypedInput)?;
        module_layer.insert(module, layer);
    }
    if module_layer.len() != 28 {
        // Definition 3.1 (Modulmenge): |M| = 28, abgeschlossen.
        return Err(PskError::UntypedInput);
    }

    // Sorte -> Eigner. sort_registry.yaml: {id: S-WIT, ..., owner: M12, ...}.
    let text = std::fs::read_to_string(workspace_root.join("architecture/sort_registry.yaml"))
        .map_err(|_| PskError::UntypedInput)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|_| PskError::UntypedInput)?;
    let mut sort_owner = BTreeMap::new();
    for row in doc
        .get("sorts")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?
    {
        let sort = row
            .get("id")
            .and_then(|v| v.as_str())
            .and_then(SortId::from_id)
            .ok_or(PskError::UntypedInput)?;
        let owner = row
            .get("owner")
            .and_then(|v| v.as_str())
            .and_then(ModuleId::from_id)
            .ok_or(PskError::UntypedInput)?;
        sort_owner.insert(sort, owner);
    }

    // Passtraegerpaare. pass_registry.yaml: {id: C9, modules: [M11, M22], ...}.
    let text = std::fs::read_to_string(workspace_root.join("architecture/pass_registry.yaml"))
        .map_err(|_| PskError::UntypedInput)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|_| PskError::UntypedInput)?;
    let mut shared_pass_carriers = BTreeSet::new();
    for row in doc
        .get("passes")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?
    {
        let carriers: Vec<ModuleId> = row
            .get("modules")
            .and_then(|v| v.as_sequence())
            .ok_or(PskError::UntypedInput)?
            .iter()
            .filter_map(|m| m.as_str().and_then(ModuleId::from_id))
            .collect();
        for a in &carriers {
            for b in &carriers {
                if a != b {
                    shared_pass_carriers.insert((*a, *b));
                }
            }
        }
    }

    Ok(ClosureNorms {
        sort_owner,
        module_layer,
        shared_pass_carriers,
    })
}

/// Laedt das Domaenenprofil der Referenzdomaene (Regel 10.9 (Herkunft der Kantenbedingungen)).
///
/// Bewusst ausserhalb von architecture/: laege es dort, waeren die
/// Praedikate der Domaene Teil von I_A und damit Teil der Identitaet des
/// Kerns - siehe den Kopfkommentar der Datei selbst.
pub fn load_reference_domain_profile(
    workspace_root: &Path,
) -> Result<EdgeConditionDeclarations, PskError> {
    let path = workspace_root.join("domains/jacobs-ladder-reference/domain_profile.yaml");
    let text = std::fs::read_to_string(&path).map_err(|_| PskError::UntypedInput)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|_| PskError::UntypedInput)?;
    let rows = doc
        .get("edge_conditions")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?;

    let list = |v: &serde_yaml::Value, key: &str| -> Result<Vec<PredicateExpr>, PskError> {
        v.get(key)
            .and_then(|x| x.as_sequence())
            .ok_or(PskError::UntypedInput)?
            .iter()
            .map(|e| {
                e.as_str()
                    .map(|s| PredicateExpr(s.to_string()))
                    .ok_or(PskError::UntypedInput)
            })
            .collect()
    };

    let mut declarations = EdgeConditionDeclarations::default();
    for row in rows {
        let relation = row
            .get("relation_sort")
            .and_then(|v| v.as_str())
            .ok_or(PskError::UntypedInput)?;
        // Eine unbekannte Relationssorte ist ein Fehler, keine Auslassung:
        // sie stuende in keiner Zeile der Portmatrix und koennte nie eine
        // Kante tragen.
        let relation = RelationSortId::from_id(relation).ok_or(PskError::UntypedInput)?;
        // `declare` erzwingt Invariante 10.7 (Kantenvollstaendigkeit), nichtleer, und Regel 10.9 (Herkunft der Kantenbedingungen)
        // (kein stets wahres Praedikat) - hier wird nichts nachgeprueft,
        // was M23 schon prueft.
        declarations.declare(
            relation,
            EdgeConditions {
                preconditions: list(row, "preconditions")?,
                postconditions: list(row, "postconditions")?,
            },
        )?;
    }
    Ok(declarations)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> std::path::PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel");
        }
        dir
    }

    #[test]
    fn the_port_matrix_is_read_from_the_sealed_register() {
        let matrix = load_port_matrix(&root()).expect("Portmatrix lesbar");
        assert_eq!(
            matrix.len(),
            23,
            "Regel 10.6 (Sorten-Port-Matrix) fuehrt 23 zulaessige Tripel"
        );
        assert!(matrix.contains(&(SortId::Anchor, SortId::Context, RelationSortId::Grounds)));
    }

    #[test]
    fn the_reference_domain_declares_only_what_it_uses() {
        let d = load_reference_domain_profile(&root()).expect("Profil lesbar");
        let declared: Vec<_> = d.declared().collect();
        assert!(
            !declared.is_empty(),
            "ein leeres Profil waere kein Profil, sondern ein Ladefehler"
        );
        assert!(
            declared.len() < 23,
            "die Referenzdomaene deklariert bewusst NICHT alle 23 - ein volles \
             Profil waere hier das Warnsignal, nicht das Ziel"
        );
        assert_eq!(d.undeclared().len(), 23 - declared.len());
    }

    #[test]
    fn a_profile_with_an_always_true_predicate_is_refused_at_load_time() {
        // Regel 10.9 (Herkunft der Kantenbedingungen) mechanisch: das Muster des T-IR-001-Fixtures darf
        // nicht durch den Lader kommen.
        let dir = std::env::temp_dir().join(format!("psk-profile-{}", std::process::id()));
        let profile_dir = dir.join("domains/jacobs-ladder-reference");
        std::fs::create_dir_all(&profile_dir).expect("mkdir");
        std::fs::write(
            profile_dir.join("domain_profile.yaml"),
            "schema: psk.domain-profile/1.0\nedge_conditions:\n  - relation_sort: grounds\n    \
             preconditions: [\"true\"]\n    postconditions: [\"etwas Echtes\"]\n",
        )
        .expect("write");
        assert!(
            load_reference_domain_profile(&dir).is_err(),
            "ein stets wahres Praedikat MUSS beim Laden scheitern"
        );

        // Positivkontrolle: derselbe Lader nimmt ein echtes Praedikat an,
        // sonst pruefte der Test nur, dass er ueberhaupt scheitert.
        std::fs::write(
            profile_dir.join("domain_profile.yaml"),
            "schema: psk.domain-profile/1.0\nedge_conditions:\n  - relation_sort: grounds\n    \
             preconditions: [\"anchor.observations ist nicht leer\"]\n    postconditions: \
             [\"thought erbt den Horizont\"]\n",
        )
        .expect("write");
        assert!(load_reference_domain_profile(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
