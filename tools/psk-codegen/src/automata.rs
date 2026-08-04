//! Codegen fuer constitution/state_machines.yaml (WP03, Teil "Automaten";
//! Kapitel 13, Vertrag 23.4).
//!
//! Die sieben Automaten - runtime, object, thought, effect, field, capsule,
//! token - werden als Zustandsenums plus Transitionstabellen erzeugt. Der
//! Kern (`machines`) und die gesondert gefuehrte Peripherie
//! (`ra_extensions`, Prinzip 4.3 C_PSK) bleiben dabei getrennt: eine
//! RA-Erweiterung ist nur wirksam, wenn ein DomainProfile sie ausdruecklich
//! einschaltet, und wird deshalb in eine eigene Tabelle erzeugt statt in
//! die Kerntabelle gemischt.
//!
//! `forbidden` ist keine zweite Transitionsquelle, sondern eine Zusicherung
//! ueber die erste: keine deklarierte Transition - auch keine, die aus
//! einem `"*"`-Platzhalter entsteht - darf eine verbotene Kante
//! verwirklichen. Der Generator erzeugt dafuer einen Test.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct StateMachinesDoc {
    /// Die Namen der Kernautomaten, in Registerreihenfolge.
    pub machines: Vec<String>,
    #[serde(default)]
    pub ra_extensions: BTreeMap<String, Vec<ExtensionEntry>>,
    #[serde(flatten)]
    rest: BTreeMap<String, serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Machine {
    pub initial: String,
    pub states: Vec<String>,
    pub transitions: Vec<TransitionEntry>,
    #[serde(default)]
    pub forbidden: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TransitionEntry {
    pub from: String,
    pub to: String,
    pub operator: String,
    #[serde(default)]
    pub gate: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ExtensionEntry {
    pub id: String,
    pub from: String,
    pub to: String,
    pub operator: String,
    #[serde(default)]
    pub gate: Option<String>,
}

impl StateMachinesDoc {
    pub fn machine(&self, name: &str) -> Machine {
        let v = self.rest.get(name).unwrap_or_else(|| {
            panic!("psk-codegen: Automat '{name}' fehlt in state_machines.yaml")
        });
        serde_yaml::from_value(v.clone())
            .unwrap_or_else(|e| panic!("psk-codegen: Automat '{name}' nicht lesbar: {e}"))
    }
}

pub fn load_state_machines(root: &Path) -> StateMachinesDoc {
    crate::load_yaml(root, "constitution/state_machines.yaml")
}

/// "BOOTING" -> "Booting", "UNKNOWN_EFFECT" -> "UnknownEffect",
/// "SPLIT_PENDING" -> "SplitPending". Alle Zustandsnamen im Register sind
/// ALL_CAPS(_WITH_UNDERSCORE); keine Mischschreibung geht verloren.
fn state_variant(raw: &str) -> String {
    raw.split('_')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let mut c = p.chars();
            match c.next() {
                Some(f) => f.to_uppercase().collect::<String>() + &c.as_str().to_lowercase(),
                None => String::new(),
            }
        })
        .collect()
}

/// "A->B" aus dem `forbidden`-Feld in seine beiden Zustaende zerlegen.
fn split_forbidden(entry: &str) -> (String, String) {
    let (a, b) = entry
        .split_once("->")
        .unwrap_or_else(|| panic!("psk-codegen: forbidden-Eintrag '{entry}' hat keine Form A->B"));
    (a.trim().to_string(), b.trim().to_string())
}

fn quoted_opt(v: &Option<String>) -> String {
    match v {
        Some(s) => format!("Some(\"{s}\")"),
        None => "None".to_string(),
    }
}

fn emit_machine(out: &mut String, name: &str, m: &Machine, exts: &[ExtensionEntry]) {
    let known: BTreeSet<&str> = m.states.iter().map(String::as_str).collect();
    let check = |s: &str, what: &str| {
        assert!(
            known.contains(s),
            "psk-codegen: Automat '{name}': {what} '{s}' steht nicht in states"
        );
    };
    for t in &m.transitions {
        if t.from != "*" {
            check(&t.from, "transition.from");
        }
        check(&t.to, "transition.to");
    }
    for e in exts {
        check(&e.from, "ra_extension.from");
        check(&e.to, "ra_extension.to");
    }
    check(&m.initial, "initial");

    out.push_str(&format!(
        "/// Automat `{name}` aus constitution/state_machines.yaml.\npub mod {name} {{\n"
    ));
    out.push_str("    use super::{StepOutcome, TransitionError};\n\n");

    // ---- State ----
    out.push_str("    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]\n");
    out.push_str("    pub enum State {\n");
    for s in &m.states {
        out.push_str(&format!("        {},\n", state_variant(s)));
    }
    out.push_str("    }\n\n");

    out.push_str("    impl State {\n");
    out.push_str("        pub const fn id(self) -> &'static str {\n            match self {\n");
    for s in &m.states {
        out.push_str(&format!(
            "                State::{} => \"{}\",\n",
            state_variant(s),
            s
        ));
    }
    out.push_str("            }\n        }\n\n");
    out.push_str("        pub fn from_id(id: &str) -> Option<State> {\n            match id {\n");
    for s in &m.states {
        out.push_str(&format!(
            "                \"{}\" => Some(State::{}),\n",
            s,
            state_variant(s)
        ));
    }
    out.push_str("                _ => None,\n            }\n        }\n\n");
    out.push_str(&format!(
        "        pub const ALL: [State; {}] = [\n",
        m.states.len()
    ));
    for s in &m.states {
        out.push_str(&format!("            State::{},\n", state_variant(s)));
    }
    out.push_str("        ];\n    }\n\n");

    out.push_str(&format!(
        "    /// `initial` laut Register.\n    pub const INITIAL: State = State::{};\n\n",
        state_variant(&m.initial)
    ));

    // ---- Transition ----
    out.push_str("    /// Eine deklarierte Transition. `from == None` entspricht dem\n");
    out.push_str("    /// Registerplatzhalter \"*\" (aus jedem Zustand).\n");
    out.push_str("    #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("    pub struct Transition {\n");
    out.push_str("        pub from: Option<State>,\n");
    out.push_str("        pub to: State,\n");
    out.push_str("        pub operator: &'static str,\n");
    out.push_str("        pub gate: Option<&'static str>,\n");
    out.push_str("    }\n\n");

    out.push_str(&format!(
        "    /// Die {} Kerntransitionen, in Registerreihenfolge.\n    pub const TRANSITIONS: [Transition; {}] = [\n",
        m.transitions.len(),
        m.transitions.len()
    ));
    for t in &m.transitions {
        let from = if t.from == "*" {
            "None".to_string()
        } else {
            format!("Some(State::{})", state_variant(&t.from))
        };
        out.push_str(&format!(
            "        Transition {{ from: {}, to: State::{}, operator: \"{}\", gate: {} }},\n",
            from,
            state_variant(&t.to),
            t.operator,
            quoted_opt(&t.gate)
        ));
    }
    out.push_str("    ];\n\n");

    // ---- RA-Erweiterungen ----
    out.push_str("    /// Gesondert gefuehrte Peripherie-Erweiterungen (Prinzip 4.3\n");
    out.push_str("    /// C_PSK). NICHT Teil des Kerns: nur wirksam, wenn ein\n");
    out.push_str("    /// DomainProfile die jeweilige ID ausdruecklich einschaltet.\n");
    out.push_str("    #[derive(Debug, Clone, Copy, PartialEq, Eq)]\n");
    out.push_str("    pub struct Extension {\n");
    out.push_str("        pub id: &'static str,\n");
    out.push_str("        pub from: State,\n");
    out.push_str("        pub to: State,\n");
    out.push_str("        pub operator: &'static str,\n");
    out.push_str("        pub gate: Option<&'static str>,\n");
    out.push_str("    }\n\n");
    out.push_str(&format!(
        "    pub const RA_EXTENSIONS: [Extension; {}] = [\n",
        exts.len()
    ));
    for e in exts {
        out.push_str(&format!(
            "        Extension {{ id: \"{}\", from: State::{}, to: State::{}, operator: \"{}\", gate: {} }},\n",
            e.id,
            state_variant(&e.from),
            state_variant(&e.to),
            e.operator,
            quoted_opt(&e.gate)
        ));
    }
    out.push_str("    ];\n\n");

    // ---- forbidden ----
    let forbidden: Vec<(String, String)> = m.forbidden.iter().map(|f| split_forbidden(f)).collect();
    for (a, b) in &forbidden {
        check(a, "forbidden.from");
        check(b, "forbidden.to");
    }
    out.push_str("    /// `forbidden` laut Register: Kanten, die kein Weg dieses\n");
    out.push_str("    /// Automaten verwirklichen darf.\n");
    out.push_str(&format!(
        "    pub const FORBIDDEN: [(State, State); {}] = [\n",
        forbidden.len()
    ));
    for (a, b) in &forbidden {
        out.push_str(&format!(
            "        (State::{}, State::{}),\n",
            state_variant(a),
            state_variant(b)
        ));
    }
    out.push_str("    ];\n\n");

    // ---- step ----
    out.push_str(
        r#"    /// Sucht die Transition zu (`from`, `operator`) und meldet, ob sie
    /// unmittelbar zulaessig ist oder zuerst ein Gate verlangt.
    ///
    /// Eine exakte `from`-Angabe hat Vorrang vor dem Platzhalter "*";
    /// `enabled_extensions` schaltet einzelne RA-EXT-IDs zu (leer = reiner
    /// Kern). Eine im Register als `forbidden` gefuehrte Kante wird auch
    /// dann abgelehnt, wenn eine Transition sie formal anbieten wuerde.
    pub fn step(
        from: State,
        operator: &str,
        enabled_extensions: &[&str],
    ) -> Result<StepOutcome<State>, TransitionError<State>> {
        let exact = TRANSITIONS
            .iter()
            .find(|t| t.from == Some(from) && t.operator == operator);
        let wildcard = TRANSITIONS
            .iter()
            .find(|t| t.from.is_none() && t.operator == operator);
        let ext = RA_EXTENSIONS.iter().find(|e| {
            e.from == from && e.operator == operator && enabled_extensions.contains(&e.id)
        });

        let (to, gate) = match (exact.or(wildcard), ext) {
            (Some(t), _) => (t.to, t.gate),
            (None, Some(e)) => (e.to, e.gate),
            (None, None) => {
                return Err(TransitionError::NoSuchTransition {
                    from,
                    operator: operator.to_string(),
                })
            }
        };

        if FORBIDDEN.iter().any(|(a, b)| *a == from && *b == to) {
            return Err(TransitionError::ForbiddenEdge { from, to });
        }

        Ok(match gate {
            None => StepOutcome::Allowed { to },
            Some(g) => StepOutcome::RequiresGate { to, gate: g },
        })
    }
"#,
    );

    out.push_str("}\n\n");
}

/// Erzeugt die sieben Automaten aus constitution/state_machines.yaml.
pub fn generate_automata(doc: &StateMachinesDoc) -> String {
    let mut out = String::new();
    out.push_str("// GENERIERT von tools/psk-codegen aus constitution/state_machines.yaml.\n");
    out.push_str("// Nicht von Hand bearbeiten. Quelle: Kapitel 13 (Automaten),\n");
    out.push_str("// Vertrag 23.4 (Maschinencheckbare Verfeinerung).\n\n");

    out.push_str(
        r#"/// Ergebnis eines Transitionsversuchs. Ein Gate wird hier NICHT
/// ausgewertet: die Gate-Entscheidung ist Sache von M14
/// (Authority/Consequence Gate) und existiert erst mit WP11. Diese
/// Aufzaehlung haelt die Anforderung sichtbar, statt sie zu unterschlagen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepOutcome<S> {
    Allowed { to: S },
    RequiresGate { to: S, gate: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionError<S> {
    /// Kein deklarierter Uebergang fuer (from, operator).
    NoSuchTransition { from: S, operator: String },
    /// Die Kante steht im `forbidden`-Feld des Registers.
    ForbiddenEdge { from: S, to: S },
}

impl<S: std::fmt::Debug> std::fmt::Display for TransitionError<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransitionError::NoSuchTransition { from, operator } => write!(
                f,
                "keine deklarierte Transition von {from:?} mit Operator '{operator}'"
            ),
            TransitionError::ForbiddenEdge { from, to } => {
                write!(f, "verbotene Kante {from:?}->{to:?}")
            }
        }
    }
}

impl<S: std::fmt::Debug> std::error::Error for TransitionError<S> {}

"#,
    );

    for name in &doc.machines {
        let m = doc.machine(name);
        let exts = doc.ra_extensions.get(name).cloned().unwrap_or_default();
        emit_machine(&mut out, name, &m, &exts);
    }

    // Registergetreuer Selbsttest: keine deklarierte Transition - auch
    // keine aus einem "*"-Platzhalter - darf eine verbotene Kante
    // verwirklichen.
    out.push_str("#[cfg(test)]\nmod generated_tests {\n");
    for name in &doc.machines {
        out.push_str(&format!(
            r#"    #[test]
    fn {name}_no_declared_transition_realizes_a_forbidden_edge() {{
        use super::{name}::*;
        for (a, b) in FORBIDDEN {{
            for t in TRANSITIONS {{
                let matches_from = match t.from {{
                    Some(f) => f == a,
                    None => true,
                }};
                assert!(
                    !(matches_from && t.to == b),
                    "Automat {name}: Transition {{:?}} verwirklicht die verbotene Kante {{:?}}->{{:?}}",
                    t, a, b
                );
            }}
        }}
    }}

    #[test]
    fn {name}_initial_state_is_declared() {{
        use super::{name}::*;
        assert!(State::ALL.contains(&INITIAL));
    }}

    #[test]
    fn {name}_transition_lookup_is_unambiguous() {{
        use super::{name}::*;
        // Zu jedem (from, operator) darf hoechstens ein Ziel gehoeren,
        // sonst waere `step` nicht deterministisch (Invariante 11.3).
        for a in State::ALL {{
            let mut seen: Vec<(&str, State)> = Vec::new();
            for t in TRANSITIONS {{
                let applies = match t.from {{
                    Some(f) => f == a,
                    None => true,
                }};
                if !applies {{
                    continue;
                }}
                if let Some((_, other)) = seen.iter().find(|(op, _)| *op == t.operator) {{
                    // Ein exakter Eintrag darf einen "*"-Eintrag verdecken;
                    // zwei exakte Eintraege duerfen sich nicht widersprechen.
                    assert_eq!(
                        *other, t.to,
                        "Automat {name}: (from={{:?}}, operator={{}}) hat mehrdeutige Ziele",
                        a, t.operator
                    );
                }} else {{
                    seen.push((t.operator, t.to));
                }}
            }}
        }}
    }}

"#
        ));
    }
    out.push_str("}\n");

    out
}

/// Erzeugt architecture/refinement_map.yaml aus derselben Quelle wie die
/// Automaten. Vertrag 23.4 verlangt eine explizite, maschinenlesbare
/// Abbildung jeder konkreten Transition in den abstrakten Automaten;
/// da der konkrete Code aus genau diesem Register erzeugt wird, ist die
/// Abbildung die Identitaet - und kann per Konstruktion nicht driften.
pub fn generate_refinement_map(doc: &StateMachinesDoc) -> String {
    let mut mappings = String::new();
    let mut count = 0usize;

    for name in &doc.machines {
        let m = doc.machine(name);
        for t in &m.transitions {
            count += 1;
            let gate = match &t.gate {
                Some(g) => g.clone(),
                None => "null".to_string(),
            };
            // "*" ist ein YAML-Sonderzeichen am Wortanfang und wird
            // deshalb gequotet ausgegeben.
            let from = if t.from == "*" { "\"*\"" } else { &t.from };
            mappings.push_str(&format!(
                "  - concrete: {{machine: {name}, from: {from}, to: {}, operator: {}}}\n    abstract: {{machine: {name}, from: {from}, to: {}, gate: {gate}}}\n",
                t.to, t.operator, t.to
            ));
        }
    }

    format!(
        r#"schema: psk.refinement-map/1.0
# GENERIERT von tools/psk-codegen aus constitution/state_machines.yaml.
# Nicht von Hand bearbeiten.
#
# Vertrag 23.4: Die Referenzimplementierung MUSS fuer jeden konkreten
# Zustandsautomaten eine explizite, maschinenlesbare Abbildung in den
# abstrakten Automaten aus Kapitel 13 dokumentieren. Unabgebildete
# Transitionen sind blocking (I-ARCH-013, PO-REF-001, R-RA-010, T-REF-001).
#
# Der konkrete Automat wird von demselben Generator aus derselben
# Registerquelle erzeugt wie diese Abbildung. Die Abbildung ist deshalb die
# Identitaet, und eine Abweichung zwischen konkret und abstrakt ist
# konstruktiv ausgeschlossen statt nur nachtraeglich geprueft.
#
# Die RA-Erweiterungen (ra_extensions) sind NICHT enthalten: sie sind
# gesondert gefuehrte Peripherie (Prinzip 4.3 C_PSK) und nur wirksam, wenn
# ein DomainProfile sie einschaltet. Sie sind keine Kerntransitionen und
# damit nicht Gegenstand der Kernabbildung.
#
# Kein "module"-Feld: die in Phase I0 skizzierte Eintragsform sah eines vor,
# doch Kapitel 13 ordnet den Automaten keine Module zu, und zwei von ihnen
# (object, effect) laufen ausdruecklich ueber mehrere Module hinweg -
# FSM-OBJECT ist der Hauptautomat der gesamten Passfolge, FSM-EFFECT reicht
# von M15 ueber M16 bis M18. Ein einzelnes Owner-Modul waere dort erfunden.
# Vertrag 23.4 verlangt die Abbildung der TRANSITIONEN, keine
# Modulzuordnung; das Feld entfaellt daher, statt geraten zu werden.

abstract_machines: [{machines}]
abstract_source: constitution/state_machines.yaml

simulation_direction: forward          # Definition 23.3, konservative Verfeinerung
preserved_by_abstraction_map: [gate, closure, trace, replay, identity, residue]

mappings:
{mappings}
coverage:
  concrete_transitions: {count}
  mapped: {count}
  unmapped: 0
  complete: true
unmapped_is_blocking: true
"#,
        machines = doc.machines.join(", "),
        mappings = mappings,
        count = count,
    )
}
