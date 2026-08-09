//! M23: den IRBundle-Kandidaten zusammenbauen (Definition 14.2, Compile:
//! "IRBundle als Kandidat vorhanden").
//!
//! ## Regel 10.9 ist der Kern dieser Datei
//!
//! "preconditions und postconditions sind vom Typ PredicateExpr und damit
//! domaenengeliefert. Der Kern DARF NICHT sie berechnen, aus
//! Passvertraegen ableiten oder mit einer generischen Erfuellung besetzen;
//! ein PredicateExpr, das stets wahr ist, erfuellt die Invariante
//! Kantenvollstaendigkeit nur der Form nach und ist ein
//! Konformitaetsdefekt."
//!
//! Deshalb NIMMT diese Datei die Bedingungen entgegen
//! (`EdgeConditionDeclarations`) und liest sie nirgends selbst ein. Wer
//! das Domaenenprofil laedt, ist die Domaene - hier kommt es bereits
//! typisiert an. Vertrag 27.2: "im Kern nur typisiert weitergereicht."
//!
//! "Fehlt fuer eine Relationssorte eine Deklaration, so entsteht keine
//! Kante dieser Sorte: der Zusammenbau MUSS sie auslassen und ein
//! ResidueRecord des Typs scope erzeugen, wie bei der nicht anwendbaren
//! Spektrallinse." Genau das tut `assemble_ir_bundle` - und zwar ueber
//! `RelationSortId::ALL`, also erschoepfend ueber alle 23, nicht nur ueber
//! die, an die jemand gedacht hat.
//!
//! ## Regel 10.8: eine Objektreferenz ist keine IR-Kante
//!
//! Beim Bau dieser Datei fiel auf, dass drei Objektschemata Pflicht-
//! Referenzfelder fuehren, deren Sortenpaar die Portmatrix nicht kennt:
//! `RealityClassification.thought_ref` (S-CTX/S-HOR),
//! `FieldIdentity.dependency_profile_ref` (S-FLD/S-DEP) und
//! `ReconciliationReport.attempt_ref` (S-EFF/S-RCN). Das sah nach einer
//! unvollstaendigen Matrix aus. Es ist keine.
//!
//! Regel 10.8 (v1.0.25) stellt die Trennung fest: ein Referenzfeld ist
//! Bestandteil der kanonischen Form seines Objekts, geht in dessen Digest
//! ein und traegt "weder eigene Identitaet noch Bedingungen noch
//! Gate-Bezug"; eine IREdge ist ein eigenstaendiges Objekt (OBJ-IRE) mit
//! eigener id, preconditions, postconditions und optionalem gate_ref.
//! "Die Sorten-Port-Matrix regelt ausschliesslich IREdge. Ein
//! Referenzfeld DARF bestehen, ohne dass die Matrix ein entsprechendes
//! Tripel fuehrt ... Ein fehlendes Tripel ist deshalb kein Befund gegen
//! ein Objektschema."
//!
//! Fuer diese Datei heisst das: `EdgeCandidate` vorzulegen ist eine
//! Entscheidung des Aufrufers UEBER KANTEN, nicht ein Abbild der
//! Referenzfelder. Dass ein Objekt auf ein anderes zeigt, macht daraus
//! keine Kante - und dass die Matrix ein Paar nicht fuehrt, macht das
//! Referenzfeld nicht falsch.
//!
//! ## Was der Zusammenbau NICHT tut
//!
//! Er erfindet keine Kante, deren Verknuepfung kein Objekt festhaelt. Eine
//! Kante entsteht nur, wenn der Aufrufer sie als `EdgeCandidate` vorlegt -
//! belegt durch ein reales Referenzfeld (z.B. `FieldProjection.field_ref`).
//! Ob dieses Feld existiert, weiss der Aufrufer; ob die Relation deklariert
//! und portzulaessig ist, entscheidet diese Datei.
//!
//! Er setzt `emission_class` nicht auf EXECUTABLE. `executable_requires`
//! (architecture/pass_registry.yaml) verlangt unter anderem
//! `all_18_cells_closed` und `close720` - beides Ergebnisse von Pass C9,
//! der NACH dem Zusammenbau laeuft (seit v1.0.34 rechnet
//! `psk_topology::close_all_18` real; der Golden Run misst die sieben
//! Bedingungen einzeln in `ExecutableCheck`). Zum Zeitpunkt des
//! Zusammenbaus sind sie unausgewertet, nicht erfuellt - der Kandidat
//! traegt HOLD, Definition 11.17: "HOLD bezeichnet unvollstaendige, aber
//! nicht verworfene Kandidaten."

use std::collections::BTreeMap;

use psk_types::objects::{
    Graph, IRBundle, IRBundleEmissionClassKind, IREdge, IREdgeDirectionKind, IRNode,
    ObligationExpr, PredicateExpr, RelationSortId, ResidueRecord, ResidueRecordSeverityKind,
    ResidueRecordStateKind, ResidueRecordTypeKind, ScopeExpr, SemVer, SortId,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId, PskError, TraceRef};

/// Die Vor- und Nachbedingungen einer Relationssorte, wie die Domaene sie
/// deklariert. Reiner Transporttyp - der Kern fuellt ihn nie selbst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeConditions {
    pub preconditions: Vec<PredicateExpr>,
    pub postconditions: Vec<PredicateExpr>,
}

/// Das, was Regel 10.9 "das DomainProfile deklariert je RelationSortId"
/// nennt - im Kern nur als Abbildung, ohne Wissen darueber, woher sie kam.
#[derive(Debug, Clone, Default)]
pub struct EdgeConditionDeclarations {
    by_relation: BTreeMap<RelationSortId, EdgeConditions>,
}

/// Ein PredicateExpr, das stets wahr ist - Regel 10.9 nennt das
/// ausdruecklich einen Konformitaetsdefekt, nicht bloss schlechten Stil.
///
/// Die Liste ist bewusst klein und woertlich: sie faengt genau das Muster,
/// das das T-IR-001-Fixture verwendet (`PredicateExpr("true")`), und
/// behauptet nicht, Tautologien allgemein erkennen zu koennen. Was sie
/// nicht faengt, faengt sie nicht - ein Praedikatenprueferwaere der Kern,
/// der die Bedingungen bewertet, und genau das verbietet Regel 10.9.
fn is_trivially_true(p: &PredicateExpr) -> bool {
    let normalized = p.0.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "" | "true" | "1" | "wahr" | "always" | "immer" | "any" | "*"
    )
}

impl EdgeConditionDeclarations {
    /// Nimmt eine Deklaration entgegen und weist die beiden Formen zurueck,
    /// die Regel 10.9 verbietet: leere Bedingungen (Invariante 10.7,
    /// "implizite Erlaubnis existiert nicht") und stets wahre Praedikate.
    pub fn declare(
        &mut self,
        relation: RelationSortId,
        conditions: EdgeConditions,
    ) -> Result<(), PskError> {
        if conditions.preconditions.is_empty() || conditions.postconditions.is_empty() {
            return Err(PskError::UntypedInput);
        }
        let trivial = conditions
            .preconditions
            .iter()
            .chain(conditions.postconditions.iter())
            .any(is_trivially_true);
        if trivial {
            return Err(PskError::UntypedInput);
        }
        self.by_relation.insert(relation, conditions);
        Ok(())
    }

    pub fn get(&self, relation: RelationSortId) -> Option<&EdgeConditions> {
        self.by_relation.get(&relation)
    }

    pub fn declared(&self) -> impl Iterator<Item = RelationSortId> + '_ {
        self.by_relation.keys().copied()
    }

    /// Die Relationssorten ohne Deklaration - erschoepfend ueber alle 23
    /// aus `RelationSortId::ALL`, nicht ueber eine hier gepflegte Liste.
    pub fn undeclared(&self) -> Vec<RelationSortId> {
        RelationSortId::ALL
            .iter()
            .copied()
            .filter(|r| !self.by_relation.contains_key(r))
            .collect()
    }
}

/// Eine vom Aufrufer belegte Verknuepfung zwischen zwei bereits gebauten
/// IR-Knoten. `evidence_field` benennt das Objektfeld, das die
/// Verknuepfung festhaelt (z.B. "FieldProjection.field_ref") - ohne ein
/// solches Feld gibt es keine Kante, nur eine Behauptung.
#[derive(Debug, Clone)]
pub struct EdgeCandidate {
    pub source: ObjectId,
    pub target: ObjectId,
    pub relation: RelationSortId,
    pub evidence_field: &'static str,
    pub trace_ref: TraceRef,
}

/// Warum eine Kante nicht entstand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeOmission {
    /// Regel 10.9: keine Deklaration im Domaenenprofil.
    Undeclared(RelationSortId),
    /// Regel 10.6: das Sortenpaar steht nicht in der Portmatrix.
    NotInPortMatrix {
        relation: RelationSortId,
        source: SortId,
        target: SortId,
    },
    /// Ein Endpunkt wurde nicht als Knoten gebaut (z.B. weil seine Sorte
    /// zellgebunden ist und keine Traegerzelle feststeht, Regel 9.14
    /// Punkt 4).
    EndpointMissing {
        relation: RelationSortId,
        missing: ObjectId,
    },
}

/// Was der Zusammenbau hervorgebracht hat - Kandidat samt der Residuen,
/// die seine Luecken benennen.
#[derive(Debug, Clone)]
pub struct AssemblyOutcome {
    pub bundle: IRBundle,
    /// Regel 10.9s ResidueRecord(scope) je nicht gebauter Relationssorte.
    pub residues: Vec<ResidueRecord>,
    /// Jede einzelne Auslassung mit Grund - fuer den Bericht, damit ein
    /// duenner Graph seinen Grund mitbringt statt nur seine Duenne.
    pub omissions: Vec<EdgeOmission>,
}

/// Eingaben des Zusammenbaus. Alles daran ist bereits anderswo entstanden;
/// diese Funktion erzeugt kein einziges inhaltliches Feld selbst.
pub struct AssemblyInputs<'a> {
    pub version: SemVer,
    pub constitution_id: Digest,
    pub nodes: Vec<IRNode>,
    pub edge_candidates: Vec<EdgeCandidate>,
    pub declarations: &'a EdgeConditionDeclarations,
    /// (source_sort, target_sort, relation) - die Portmatrix, vom
    /// Aufrufer aus architecture/sort_registry.yaml gereicht. M23 haelt
    /// keine eigene Kopie: eine zweite Wahrheit neben dem Register waere
    /// genau die Driftklasse, die dieses Projekt schon mehrfach getroffen hat.
    pub port_matrix: &'a [(SortId, SortId, RelationSortId)],
    pub anchor_refs: Vec<ObjectId>,
    pub field_projections: Vec<ObjectId>,
    pub dependencies: ObjectId,
    pub witnesses: Vec<ObjectId>,
    pub residues: Vec<ObjectId>,
    pub gate_reports: Vec<ObjectId>,
    pub trace_ref: TraceRef,
    pub opened_at: DualTime,
    pub scope: ScopeExpr,
}

fn scope_residue(
    relation: RelationSortId,
    scope: &ScopeExpr,
    opened_at: &DualTime,
    reason: String,
) -> Result<ResidueRecord, PskError> {
    let draft = ResidueRecord {
        schema: "psk.residue/1.0".to_string(),
        id: ObjectId::new(SortId::Residue, Digest::sha256(b"")), // Platzhalter
        r#type: ResidueRecordTypeKind::Scope,
        origin_module: ModuleId::IRCodec,
        origin_object: ObjectId::new(SortId::Residue, Digest::sha256(relation.id().as_bytes())),
        scope: scope.clone(),
        severity: ResidueRecordSeverityKind::NonBlocking,
        open_obligation: ObligationExpr(reason),
        allowed_followups: Vec::new(),
        opened_at: opened_at.clone(),
        closed_by: None,
        state: ResidueRecordStateKind::Open,
    };
    let mut value = serde_json::to_value(&draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let canonical = psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?;
    let id_str = psk_canon::object_id(SortId::Residue.id(), &canonical);
    let id: ObjectId = id_str
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(ResidueRecord { id, ..draft })
}

/// Baut den IRBundle-Kandidaten (Definition 10.2, OBJ-IRB).
pub fn assemble_ir_bundle(inputs: AssemblyInputs<'_>) -> Result<AssemblyOutcome, PskError> {
    // ObjectId traegt kein Ord (Definition 6.6 gibt ihm keine Ordnung);
    // die kanonische Zeichenkette ist der Schluessel.
    let sort_of: BTreeMap<String, SortId> = inputs
        .nodes
        .iter()
        .map(|n| (n.id.to_string(), n.sort))
        .collect();
    let has_node = |id: &ObjectId| sort_of.contains_key(&id.to_string());

    let mut edges: Vec<IREdge> = Vec::new();
    let mut omissions: Vec<EdgeOmission> = Vec::new();

    for candidate in &inputs.edge_candidates {
        // 1. Beide Endpunkte MUESSEN als Knoten existieren.
        for endpoint in [candidate.source, candidate.target] {
            if !has_node(&endpoint) {
                omissions.push(EdgeOmission::EndpointMissing {
                    relation: candidate.relation,
                    missing: endpoint,
                });
            }
        }
        if !has_node(&candidate.source) || !has_node(&candidate.target) {
            continue;
        }

        // 2. Regel 10.6: das Sortentripel MUSS in der Portmatrix stehen.
        let (s, t) = (
            sort_of[&candidate.source.to_string()],
            sort_of[&candidate.target.to_string()],
        );
        let permitted = inputs
            .port_matrix
            .iter()
            .any(|(ps, pt, pr)| *ps == s && *pt == t && *pr == candidate.relation);
        if !permitted {
            omissions.push(EdgeOmission::NotInPortMatrix {
                relation: candidate.relation,
                source: s,
                target: t,
            });
            continue;
        }

        // 3. Regel 10.9: ohne Deklaration keine Kante.
        let Some(conditions) = inputs.declarations.get(candidate.relation) else {
            omissions.push(EdgeOmission::Undeclared(candidate.relation));
            continue;
        };

        edges.push(IREdge {
            id: ObjectId::new(
                SortId::Trace,
                Digest::sha256(
                    format!(
                        "{}|{}|{}",
                        candidate.source,
                        candidate.target,
                        candidate.relation.id()
                    )
                    .as_bytes(),
                ),
            ),
            source: candidate.source,
            target: candidate.target,
            relation_sort: candidate.relation,
            direction: IREdgeDirectionKind::Forward,
            preconditions: conditions.preconditions.clone(),
            postconditions: conditions.postconditions.clone(),
            gate_ref: None,
            dependency_refs: vec![inputs.dependencies],
            trace_ref: candidate.trace_ref,
        });
    }

    // Regel 10.9: je undeklarierter Relationssorte ein ResidueRecord(scope).
    let mut residues = Vec::new();
    for relation in inputs.declarations.undeclared() {
        residues.push(scope_residue(
            relation,
            &inputs.scope,
            &inputs.opened_at,
            format!(
                "Regel 10.9: das Domaenenprofil deklariert fuer die Relationssorte {} keine Vor- \
                 und Nachbedingungen; es entsteht keine Kante dieser Sorte",
                relation.id()
            ),
        )?);
    }

    let bundle = IRBundle {
        schema: "psk.ir/1.0".to_string(),
        version: inputs.version,
        constitution_id: inputs.constitution_id,
        anchor_refs: inputs.anchor_refs,
        graph: Graph {
            nodes: inputs.nodes,
            edges,
        },
        field_projections: inputs.field_projections,
        dependencies: inputs.dependencies,
        witnesses: inputs.witnesses,
        residues: inputs.residues,
        gate_reports: inputs.gate_reports,
        trace_ref: inputs.trace_ref,
        // C10-Ausgaben (Vertrag 11.16: jeder Effektvertrag MUSS vor der
        // Emission an einen bestandenen GateReport gebunden werden). Die
        // Verify-Phase liegt NACH Compile; ein Kandidat, der sie schon
        // truege, behauptete Pruefungen, die nicht stattfanden.
        capabilities: Vec::new(),
        effect_contracts: Vec::new(),
        emission_class: IRBundleEmissionClassKind::Hold,
        digest: Digest::sha256(b""), // Platzhalter, unten ersetzt
    };

    // Vertrag 11.18: "Der Pass schreibt ... den vollstaendigen
    // IRBundle-Digest." Ueber ir_encode, also kanonisch und mit derselben
    // Sortierung, die der Round-Trip prueft.
    let digest = crate::ir_encode(&bundle).map(|bytes| Digest::sha256(&bytes))?;

    Ok(AssemblyOutcome {
        bundle: IRBundle { digest, ..bundle },
        residues,
        omissions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cond(pre: &str, post: &str) -> EdgeConditions {
        EdgeConditions {
            preconditions: vec![PredicateExpr(pre.into())],
            postconditions: vec![PredicateExpr(post.into())],
        }
    }

    #[test]
    fn a_trivially_true_predicate_is_refused() {
        // Regel 10.9 nennt das einen Konformitaetsdefekt. Der Kern kann
        // Praedikate nicht bewerten - aber DIESE eine Form muss er
        // zurueckweisen, sonst ist die Regel nicht durchgesetzt.
        let mut d = EdgeConditionDeclarations::default();
        for bad in ["true", "TRUE", " wahr ", "1", ""] {
            assert!(
                d.declare(RelationSortId::Grounds, cond(bad, "etwas Echtes"))
                    .is_err(),
                "{bad:?} MUSS als stets wahr zurueckgewiesen werden"
            );
        }
        // Positivkontrolle: ein echtes Praedikat geht durch, sonst wuerde
        // der Test auch bestehen, wenn `declare` alles ablehnte.
        assert!(d
            .declare(
                RelationSortId::Grounds,
                cond(
                    "anchor.observations ist nicht leer",
                    "thought erbt den Horizont"
                )
            )
            .is_ok());
    }

    /// Befund aus dem FC2-Bau, jetzt abgesichert: das T-IR-001-Fixture
    /// verwendet `PredicateExpr("true")` - exakt das Muster, das Regel
    /// 10.9 verbietet. Das Fixture bleibt (es prueft den Codec, nicht die
    /// Kantensemantik), aber es steht nicht laenger unkommentiert daneben:
    /// sein eigener Wert wird hier gegen den Produktionsweg gehalten und
    /// MUSS abgelehnt werden.
    ///
    /// Beide Stellen teilen eine Konstante. Wer das Fixture aendert,
    /// aendert die Eingabe dieses Tests mit - er kann nicht dadurch
    /// veralten, dass jemand woanders "true" durch etwas anderes ersetzt.
    #[test]
    fn the_t_ir_001_fixture_predicate_is_refused_by_the_production_path() {
        let fixture = PredicateExpr(crate::codec::T_IR_001_FIXTURE_PREDICATE.to_string());
        let mut d = EdgeConditionDeclarations::default();

        assert!(
            d.declare(
                RelationSortId::Grounds,
                EdgeConditions {
                    preconditions: vec![fixture.clone()],
                    postconditions: vec![PredicateExpr("etwas Echtes".into())],
                }
            )
            .is_err(),
            "das Fixturepraedikat {:?} MUSS im Produktionsweg scheitern",
            fixture.0
        );
        assert!(
            d.declare(
                RelationSortId::Grounds,
                EdgeConditions {
                    preconditions: vec![PredicateExpr("etwas Echtes".into())],
                    postconditions: vec![fixture.clone()],
                }
            )
            .is_err(),
            "auch als Nachbedingung MUSS es scheitern"
        );

        // Positivkontrolle: derselbe Aufruf mit echten Praedikaten geht
        // durch. Ohne sie bestuende der Test auch, wenn `declare` alles
        // ablehnte - und bewiese dann nichts ueber das Fixture.
        assert!(d
            .declare(
                RelationSortId::Grounds,
                cond(
                    "anchor.observations ist nicht leer",
                    "thought erbt den Horizont"
                )
            )
            .is_ok());
    }

    #[test]
    fn an_empty_condition_list_is_refused() {
        // Invariante 10.7: "Eine Kante ohne Bedingungen ist nicht
        // zulaessig; implizite Erlaubnis existiert nicht."
        let mut d = EdgeConditionDeclarations::default();
        assert!(d
            .declare(
                RelationSortId::Grounds,
                EdgeConditions {
                    preconditions: vec![],
                    postconditions: vec![PredicateExpr("echt".into())],
                }
            )
            .is_err());
        assert!(d
            .declare(
                RelationSortId::Grounds,
                EdgeConditions {
                    preconditions: vec![PredicateExpr("echt".into())],
                    postconditions: vec![],
                }
            )
            .is_err());
    }

    #[test]
    fn undeclared_is_exhaustive_over_all_twenty_three_relation_sorts() {
        // Der Punkt: die Auslassungsliste kommt aus RelationSortId::ALL,
        // nicht aus einer hier gepflegten Aufzaehlung. Eine neue Zeile in
        // der Portmatrix taucht damit automatisch auf.
        let empty = EdgeConditionDeclarations::default();
        assert_eq!(empty.undeclared().len(), 23);

        let mut one = EdgeConditionDeclarations::default();
        one.declare(RelationSortId::Grounds, cond("a", "b"))
            .unwrap();
        assert_eq!(one.undeclared().len(), 22);
        assert!(!one.undeclared().contains(&RelationSortId::Grounds));
    }
}
