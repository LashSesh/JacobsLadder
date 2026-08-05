//! `psk refinement verify` (Struktur 27.6): zwei Verfeinerungssicherheits-
//! pruefungen (Kapitel 27 CPSK / Kapitel 23.3 PSK-RA).
//!
//! (1) architecture/refinement_map.yaml: jede konkrete Transition MUSS auf
//! eine abstrakte abgebildet sein (Vertrag 23.4, I-ARCH-013, T-REF-001).
//! Setzt Can() (WP01) fuer echte Werte voraus; bei 0 konkreten Transitionen
//! (I0) ist die Pruefung vakuos aber ausfuehrbar.
//!
//! (2) constitution/state_machines.yaml: FSM-THOUGHT und FSM-FIELD MUESSEN
//! C_PSK Anhang D wortgetreu spiegeln (PSK-RA v1.0.2, Vertrag 13.7/13.13,
//! Fehlerkorrektur v1.0.2 Punkt 3) — exakt 8 bzw. 7 Kern-Transitionen, keine
//! mehr, keine weniger. Die zwei bekannten Peripherie-Erweiterungen
//! (RA-EXT-THOUGHT-01, RA-EXT-FIELD-01, Struktur 13.9/13.14) MUESSEN unter
//! `ra_extensions` gefuehrt werden, nicht im Kernregister.
//!
//! Bibliotheksteil - siehe verify-bundle/src/lib.rs's Modulkopf fuer die
//! Motivation (dieselbe Pruefung auch aus `psk-conformance`/`psk-cli`
//! aufrufbar).

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RefinementMap {
    pub coverage: Coverage,
    pub unmapped_is_blocking: bool,
}

#[derive(Debug, Deserialize)]
pub struct Coverage {
    pub concrete_transitions: u64,
    pub mapped: u64,
    pub unmapped: u64,
    pub complete: bool,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Transition {
    from: String,
    to: String,
    operator: String,
    #[serde(default)]
    gate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CoreMachine {
    transitions: Vec<Transition>,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ExtensionEdge {
    id: String,
    from: String,
    to: String,
    operator: String,
    #[serde(default)]
    gate: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StateMachines {
    thought: CoreMachine,
    field: CoreMachine,
    ra_extensions: RaExtensions,
}

#[derive(Debug, Deserialize)]
struct RaExtensions {
    thought: Vec<ExtensionEdge>,
    field: Vec<ExtensionEdge>,
}

fn t(from: &str, to: &str, operator: &str, gate: Option<&str>) -> Transition {
    Transition {
        from: from.into(),
        to: to.into(),
        operator: operator.into(),
        gate: gate.map(String::from),
    }
}

/// C_PSK Anhang D, wortgetreu (PSK-RA v1.0.2 Automat 13.6, Vertrag 13.7).
fn cpsk_thought_core() -> BTreeSet<Transition> {
    [
        t(
            "SPECIFIED",
            "POSSIBLE",
            "classify_coherent",
            Some("G-REALITY-COHERENT"),
        ),
        t("POSSIBLE", "SIMULATED", "simulate", Some("G-SIMULATION")),
        t(
            "POSSIBLE",
            "SELECTED",
            "select_candidate",
            Some("G-SELECTION"),
        ),
        t("SELECTED", "ATTEMPTED", "execute_effect", Some("G-EFFECT")),
        t(
            "ATTEMPTED",
            "OBSERVED",
            "bind_external_record",
            Some("G-OBSERVATION"),
        ),
        t(
            "OBSERVED",
            "ACTUALIZED",
            "reconcile",
            Some("G-ACTUALIZATION"),
        ),
        t("*", "RESIDUE", "route_residue", Some("G-RESIDUE")),
        t("*", "RETRACTED", "retract", Some("G-RETRACTION")),
    ]
    .into_iter()
    .collect()
}

/// C_PSK Anhang D, wortgetreu (PSK-RA v1.0.2 Automat 13.12, Vertrag 13.13).
fn cpsk_field_core() -> BTreeSet<Transition> {
    [
        t("PROPOSED", "ACTIVE", "activate", Some("G-MORPH")),
        t("ACTIVE", "QUIESCENT", "quiesce", None),
        t("ACTIVE", "SPLIT_PENDING", "propose_split", Some("G-MORPH")),
        t("ACTIVE", "MERGE_PENDING", "propose_merge", Some("G-MORPH")),
        t("ACTIVE", "FOLDED", "fold", Some("G-MORPH")),
        t("QUIESCENT", "RETIRED", "retire", None),
        t("*", "EXCISED", "excise", Some("G-EXCISION")),
    ]
    .into_iter()
    .collect()
}

fn expected_extension(id: &str, from: &str, to: &str, operator: &str, gate: &str) -> ExtensionEdge {
    ExtensionEdge {
        id: id.into(),
        from: from.into(),
        to: to.into(),
        operator: operator.into(),
        gate: Some(gate.into()),
    }
}

/// Prueft FSM-THOUGHT/FSM-FIELD gegen C_PSK Anhang D. `root` ist die
/// Workspace-Wurzel (enthaelt `constitution/`).
pub fn check_core_fidelity(root: &Path) -> Result<(), String> {
    let path = root.join("constitution/state_machines.yaml");
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("kann {} nicht lesen: {e}", path.display()))?;
    let doc: StateMachines =
        serde_yaml::from_str(&text).map_err(|e| format!("{} nicht lesbar: {e}", path.display()))?;

    let thought_actual: BTreeSet<Transition> = doc.thought.transitions.into_iter().collect();
    let thought_expected = cpsk_thought_core();
    if thought_actual != thought_expected {
        let extra: Vec<_> = thought_actual.difference(&thought_expected).collect();
        let missing: Vec<_> = thought_expected.difference(&thought_actual).collect();
        return Err(format!(
            "FSM-THOUGHT weicht von C_PSK Anhang D ab (Vertrag 13.7). Zusaetzlich: {extra:?}. Fehlend: {missing:?}."
        ));
    }

    let field_actual: BTreeSet<Transition> = doc.field.transitions.into_iter().collect();
    let field_expected = cpsk_field_core();
    if field_actual != field_expected {
        let extra: Vec<_> = field_actual.difference(&field_expected).collect();
        let missing: Vec<_> = field_expected.difference(&field_actual).collect();
        return Err(format!(
            "FSM-FIELD weicht von C_PSK Anhang D ab (Vertrag 13.13). Zusaetzlich: {extra:?}. Fehlend: {missing:?}."
        ));
    }

    let thought_ext: BTreeSet<ExtensionEdge> = doc.ra_extensions.thought.into_iter().collect();
    let thought_ext_expected: BTreeSet<ExtensionEdge> = [expected_extension(
        "RA-EXT-THOUGHT-01",
        "SIMULATED",
        "SELECTED",
        "select_candidate",
        "G-SELECTION",
    )]
    .into_iter()
    .collect();
    if thought_ext != thought_ext_expected {
        return Err(format!(
            "ra_extensions.thought weicht von Struktur 13.9 ab: {thought_ext:?}"
        ));
    }

    let field_ext: BTreeSet<ExtensionEdge> = doc.ra_extensions.field.into_iter().collect();
    let field_ext_expected: BTreeSet<ExtensionEdge> = [expected_extension(
        "RA-EXT-FIELD-01",
        "QUIESCENT",
        "ACTIVE",
        "reactivate",
        "G-MORPH",
    )]
    .into_iter()
    .collect();
    if field_ext != field_ext_expected {
        return Err(format!(
            "ra_extensions.field weicht von Struktur 13.14 ab: {field_ext:?}"
        ));
    }

    Ok(())
}

/// Liest architecture/refinement_map.yaml und prueft die Kohaerenz seiner
/// coverage-Felder (Vertrag 23.4, T-REF-001).
pub fn read_refinement_map(root: &Path) -> Result<RefinementMap, String> {
    let path = root.join("architecture/refinement_map.yaml");
    let text = fs::read_to_string(&path)
        .map_err(|e| format!("kann {} nicht lesen: {e}", path.display()))?;
    serde_yaml::from_str(&text).map_err(|e| format!("{} nicht lesbar: {e}", path.display()))
}

impl RefinementMap {
    /// "complete" heisst nicht nur "0 unabgebildet", sondern "es gibt etwas,
    /// das vollstaendig abgebildet wurde". Bei 0 konkreten Transitionen (I0:
    /// noch kein Code) ist 0 unmapped nur vakuos wahr, nicht abgeschlossen.
    pub fn expected_complete(&self) -> bool {
        self.coverage.concrete_transitions > 0 && self.coverage.unmapped == 0
    }

    pub fn internally_consistent(&self) -> bool {
        self.coverage.mapped + self.coverage.unmapped == self.coverage.concrete_transitions
            && self.coverage.complete == self.expected_complete()
    }

    /// T-REF-001: eine unabgebildete konkrete Transition blockiert, wenn
    /// `unmapped_is_blocking` gesetzt ist (Vertrag 23.4, I-ARCH-013).
    pub fn blocks_on_unmapped(&self) -> bool {
        self.unmapped_is_blocking && self.coverage.unmapped > 0
    }
}
