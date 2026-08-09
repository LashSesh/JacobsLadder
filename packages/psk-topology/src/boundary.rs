//! Schnittstelle 9.26 (M22-Ports): `close_cell`, `close_all_18`, `descend`,
//! `holonomy`.
//!
//! ## Die benannten Blocker sind gefallen - der Reihe nach
//!
//! Dieses Modul fuehrte die vier Ports lange als dokumentierte Grenzen
//! (`unimplemented!`), jeweils mit benanntem Blocker. Ein Audit hat die
//! Blocker einzeln nachgemessen; keiner bestand mehr, und die letzten
//! Entscheidungen traf v1.0.34:
//!
//! - `close_cell`/`close_all_18` nannten M12, M19 und "die Auswertung der
//!   Sorten-Port-Matrix gegen einen konkreten Graphen". M12 (psk-witness)
//!   und M19 (psk-trace) rechnen seit ihren Work Packages real; die
//!   Matrixauswertung ist seit dem FC2-Bau verdrahtet (`load_port_matrix`
//!   und Regel 10.6 in `assemble_ir_bundle`), und der konkrete Graph
//!   entsteht in jedem Golden Run. Was fehlte, waren drei normative
//!   Entscheidungen - v1.0.34 traf sie: Regel 9.8 (Richtungskonsistenz
//!   einer Zelle), Regel 9.9 (Leere Zelle schliesst vakuum, aber nicht
//!   stillschweigend), Struktur 9.10 (CellReport).
//! - `descend` nannte `RuntimeManifest.max_depth` als Blocker - das Feld
//!   existiert seit v1.0.32; der Stubtext hier war schlicht nicht
//!   nachgezogen (dieselbe Fehlerklasse, die den Audit-Anlass
//!   compile_ir_bundle betraf). Der zunaechst offene Eintrittspunkt im
//!   Feinchart ist seit v1.0.35 durch Regel 9.20 geregelt - dieselbe
//!   Platzierungsregel, keine eigene; der Erfolgszweig rechnet, siehe
//!   `descend`.
//! - `holonomy` nannte "Phi/Transport aus M09 - kein Register definiert
//!   deren Berechnung". Das war eine echte Dokumentluecke (zehn
//!   Verwendungen, keine Definition); v1.0.34 schliesst sie: Definition
//!   9.17 (Chartwechsel) gibt T als reinen, umkehrbaren Rahmenwechsel mit
//!   T_ii = I, Definition 9.19 gibt Phi als T_gamma der geschlossenen
//!   Route, und Regel 9.21 leitet Phi = I bei max_depth = 0 daraus AB,
//!   statt es anzunehmen - mit Ausweispflicht als trivial geschlossen.
//!
//! ## Was der CellReport traegt
//!
//! Seit v1.0.35 traegt Struktur 9.10 alle Ausweispflichten selbst; die
//! beiden Befunde der v1.0.34-Bauform sind an der Quelle geschlossen:
//!
//! - Regel 9.21: "Der CellReport MUSS diesen Fall als trivial
//!   geschlossen ausweisen" - der v1.0.34-Dokumentbefund (die Feldliste
//!   konnte das nicht tragen) ist in v1.0.35 an der Quelle geschlossen:
//!   `closure_mode` steht jetzt in der Struktur, und Regel 9.11 (Vakuum
//!   ist kein Beleg) macht das Fuehren beider Ausweisfelder zur Pflicht.
//! - Die Auflage aus der Abnahme des Blocker-Audits: "aufloesbar" ueber
//!   leerer Witnessliste ist vakuum-wahr und MUSS als vakuum ausgewiesen
//!   werden, nicht als geprueft. Seit v1.0.35 traegt Struktur 9.10 das
//!   selbst: `refs_resolution: checked | vacuous_empty` und
//!   `closure_mode: substantive | trivial | vacuous` - die v1.0.34-
//!   Bauform dieses Moduls, jetzt registerseitig.
//!
//! `ProbeNote` ist seit v1.0.35 in Struktur 9.10 definiert (node,
//! computed_k, reached_k, probe_steps) - die fruehere Minimaldefinition
//! dieses Moduls ist durch die registerseitige ersetzt.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use psk_types::objects::{Graph, RelationSortId, SortId};
use psk_types::{
    parse_m13_address, CellId, CellKind, M13AddressError, M13NodeId, ModuleId, ObjectId, PskError,
    TraceRef,
};

/// IRGraph aus Schnittstelle 9.26 - der Graph-Teil eines IRBundle
/// (Struktur 7.21, OBJ-IRB).
pub type IRGraph = Graph;

/// Struktur 9.10: `occupancy: occupied | empty` - "leer schliesst vakuum,
/// wird aber ausgewiesen" (Regel 9.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Occupancy {
    Occupied,
    Empty,
}

/// Struktur 9.10 (v1.0.35): `refs_resolution: checked | vacuous_empty` -
/// "ueber leerer Verweisliste ist 'aufloesbar' vakuum wahr und KEIN
/// Beleg" (Regel 9.11: Vakuum ist kein Beleg).
///
/// Die Struktur kennt keinen Fehlwert, und das ist konsequent: ein
/// Verweis, der im eigenen Buendel nicht aufloest, ist kein
/// berichtbarer Zellzustand, sondern ein defekter Graph - er haette den
/// Zusammenbau nie verlassen duerfen. `close_cell` liefert dafuer
/// PSK-E011, wie bei einer unparsebaren Adresse.
///
/// Massgeblich fuer checked/vacuous ist die WITNESSLISTE: der
/// Traceverweis ist an jedem Knoten pflichtig und wird immer geprueft,
/// aber seine Pruefung allein stuft nicht auf "checked" hoch - genau das
/// waere die Mehrbehauptung, die Regel 9.11 verbietet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefsResolution {
    /// Mindestens ein Witnessverweis vorhanden und real aufgeloest;
    /// Traceverweise ebenfalls geprueft.
    Checked,
    /// Keine Witnessverweise vorhanden (leere Zelle oder Knoten ohne
    /// Verweise): vakuum wahr, ausgewiesen, kein Beleg.
    VacuousEmpty,
}

/// Struktur 9.10 (v1.0.35): `closure_mode: substantive | trivial |
/// vacuous`. Regel 9.21 (Triviale Route ist eine Route): bei
/// `max_depth = 0` gilt Phi = I aus T_ii = I - hergeleitet, nicht
/// angenommen; der Fall MUSS als trivial ausgewiesen werden und "DARF
/// NICHT als Beleg fuer Transportkorrektheit gelten". Regel 9.11 dehnt
/// dieselbe Pflicht auf vacuous aus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosureMode {
    /// Reale Transportauswertung ueber mehrere Charts. Kein Referenzlauf
    /// erreicht diesen Fall bisher (max_depth = 0 ueberall).
    Substantive,
    /// Route ohne Transport (Regel 9.21): belegte Zelle bei
    /// max_depth = 0.
    Trivial,
    /// Zelle ohne Knoten (Regel 9.9).
    Vacuous,
}

/// Struktur 9.10 (v1.0.35) definiert ProbeNote jetzt selbst: node,
/// computed_k ("k = H(Can(node)) mod 6, vor Sondierung"), reached_k
/// ("tatsaechlich belegte Zelle"), probe_steps ("0 heisst
/// konfliktfrei"). Dass 0 eine BEDEUTUNG hat, heisst: vermerkt wird
/// jede Platzierung, nicht nur der Konfliktfall - "Sondierung wird
/// vermerkt, nicht verworfen".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeNote {
    pub node: ObjectId,
    /// k = H(Can(node)) mod 6, vor Sondierung.
    pub computed_k: u32,
    /// Tatsaechlich belegte Zelle.
    pub reached_k: u32,
    /// 0 heisst konfliktfrei.
    pub probe_steps: u32,
}

/// Struktur 9.10 (CellReport), feldgetreu seit v1.0.35 - occupancy,
/// closure_mode und refs_resolution sind die Ausweisfelder, deren
/// Fuehrung Regel 9.11 zur Pflicht macht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellReport {
    pub cell: CellId,
    pub occupancy: Occupancy,
    pub closure_mode: ClosureMode,
    pub nodes_typed: bool,
    pub edges_port_compatible: bool,
    pub direction_consistent: bool,
    pub refs_resolution: RefsResolution,
    pub differences_residualized: bool,
    pub probe_notes: Vec<ProbeNote>,
}

impl CellReport {
    /// Vertrag 9.7: geschlossen, wenn alle Bedingungen gelten. Eine
    /// leere Zelle schliesst vakuum (Regel 9.9) - ihre Bedingungen sind
    /// ueber der leeren Menge wahr und stehen so in den Feldern; die
    /// Verweisaufloesung kennt keinen Fehlwert (defekte Verweise sind
    /// PSK-E011, nie ein Bericht).
    pub fn closed(&self) -> bool {
        self.nodes_typed
            && self.edges_port_compatible
            && self.direction_consistent
            && self.differences_residualized
    }

    /// Regel 9.9/9.11: vakuum geschlossen - zaehlt, wird aber beziffert.
    pub fn vacuum_closed(&self) -> bool {
        self.closure_mode == ClosureMode::Vacuous && self.closed()
    }
}

/// Was Vertrag 9.7 zum Pruefen braucht und der Graph allein nicht
/// hergibt. Der Aufrufer fuellt es aus dem IRBundle (W, R, T) und den
/// versiegelten Registern - Kernmuster wie `EdgeContext` und
/// `load_port_matrix`: hier kommt alles typisiert an, nichts wird selbst
/// eingelesen.
#[derive(Debug, Clone)]
pub struct ClosureContext<'a> {
    /// IRBundle.witnesses (W) - Aufloesungsuniversum der Witnessverweise.
    pub witnesses: &'a [ObjectId],
    /// IRBundle.residues (R) - Aufloesungsuniversum der Residuenverweise.
    pub residues: &'a [ObjectId],
    /// IRBundle.trace_ref (T) - der Trace, auf den Knotenverweise zeigen
    /// muessen.
    pub bundle_trace: &'a TraceRef,
    /// Die Sorten-Port-Matrix aus architecture/sort_registry.yaml
    /// (Regel 10.6), vom Aufrufer gereicht.
    pub port_matrix: &'a [(SortId, SortId, RelationSortId)],
    /// Sorte -> Eignermodul (architecture/sort_registry.yaml).
    pub sort_owner: &'a BTreeMap<SortId, ModuleId>,
    /// Modul -> Schicht L0..L7 als Zahl (architecture/module_map.yaml).
    pub module_layer: &'a BTreeMap<ModuleId, u8>,
    /// Modulpaare, die laut pass_registry.yaml gemeinsame Traeger
    /// derselben Passe sind (Regel 9.8: "gemeinsame Passtraegerschaft").
    pub shared_pass_carriers: &'a BTreeSet<(ModuleId, ModuleId)>,
    /// Sondierungsvermerke aus der realen Platzierung des Laufs
    /// (`PlacementOutcome::probed_k` je Knoten). Die Platzierung ist eine
    /// reine Funktion (Regel 9.14), aber die Vermerke stammen aus dem
    /// Lauf, der platziert hat - nicht aus einer Nachrechnung.
    pub probes: &'a [(ObjectId, Vec<u8>)],
    /// RuntimeManifest.max_depth - entscheidet den ClosureMode
    /// (Regel 9.21).
    pub max_depth: u32,
}

/// Definition 2.7 (Zulaessige Rueckfluesse): die fuenf benannten
/// Rueckflusskanaele, gegen die Regel 9.8 backward-Kanten prueft.
/// `None` als Quelle heisst "jede Schicht" (Kanal i).
const REFLUX_CHANNELS: [(Option<ModuleId>, ModuleId); 6] = [
    // (i) Residuenrueckfluss: jede Schicht -> M19.
    (None, ModuleId::TraceReplayResidueStore),
    // (ii) Reanalyserueckfluss: M18 -> M06.
    (
        Some(ModuleId::ReconciliationEngine),
        ModuleId::ThoughtCompiler,
    ),
    // (iii) Reankrierung: M18/M13 -> M05.
    (
        Some(ModuleId::ReconciliationEngine),
        ModuleId::AnchorRegistry,
    ),
    (Some(ModuleId::ValidationPlanner), ModuleId::AnchorRegistry),
    // (iv) Revisionsvorschlag: M24 -> M21.
    (
        Some(ModuleId::AdversarialKernel),
        ModuleId::CertificateReleaseEngine,
    ),
    // (v) Sondierungsrueckfluss: M13 -> M09 (P39).
    (
        Some(ModuleId::ValidationPlanner),
        ModuleId::SpectralLensRouter,
    ),
];

fn is_reflux(source: ModuleId, target: ModuleId) -> bool {
    REFLUX_CHANNELS
        .iter()
        .any(|(s, t)| *t == target && s.map(|s| s == source).unwrap_or(true))
}

/// Regel 9.8, eine Richtung: Schichtordnung (L(Ziel) >= L(Quelle)) oder
/// gemeinsame Passtraegerschaft.
fn forward_ok(ctx: &ClosureContext, source: ModuleId, target: ModuleId) -> bool {
    let ordered = match (ctx.module_layer.get(&source), ctx.module_layer.get(&target)) {
        (Some(ls), Some(lt)) => lt >= ls,
        // Ein Modul ohne Schichteintrag waere ein Registerdefekt; die
        // Ordnung ist dann nicht belegt, nicht "erfuellt".
        _ => false,
    };
    ordered
        || ctx.shared_pass_carriers.contains(&(source, target))
        || ctx.shared_pass_carriers.contains(&(target, source))
}

/// Vertrag 9.7 fuer EINE Zelle, ueber dem konkreten Graphen.
///
/// Mitglied der Zelle ist jeder Knoten, dessen `m13_address` sie als
/// aktuelle Zelle nennt; Kanten der Zelle sind die Kanten, deren beide
/// Enden Mitglieder sind (zellueberschreitende Kanten sind Nahtsache,
/// M11). Eine unparsebare Adresse ist PSK-E011 - sie haette Pass C4 nie
/// verlassen duerfen.
pub fn close_cell(
    cell: CellId,
    graph: &IRGraph,
    ctx: &ClosureContext,
) -> Result<CellReport, PskError> {
    let mut members = Vec::new();
    for node in &graph.nodes {
        let parsed = parse_m13_address(&node.m13_address.0)
            .map_err(|_: M13AddressError| PskError::NonclosingM13Seam)?;
        if parsed.cell == cell {
            members.push(node);
        }
    }

    if members.is_empty() {
        // Regel 9.9: vakuum - "ueber einer leeren Menge ist nichts
        // unabgeschlossen". Die Felder tragen die Vakuumwahrheit,
        // occupancy und closure_mode weisen sie aus (Regel 9.11).
        return Ok(CellReport {
            cell,
            occupancy: Occupancy::Empty,
            closure_mode: ClosureMode::Vacuous,
            nodes_typed: true,
            edges_port_compatible: true,
            direction_consistent: true,
            refs_resolution: RefsResolution::VacuousEmpty,
            differences_residualized: true,
            probe_notes: Vec::new(),
        });
    }

    // Belegte Zelle: bei max_depth = 0 ist jede geschlossene Route
    // trivial (Regel 9.21); eine substantielle Transportauswertung gibt
    // es erst mit mehreren Charts.
    let closure_mode = if ctx.max_depth == 0 {
        ClosureMode::Trivial
    } else {
        ClosureMode::Substantive
    };

    let member_ids: HashSet<ObjectId> = members.iter().map(|n| n.id).collect();
    let sort_of: HashMap<ObjectId, SortId> = members.iter().map(|n| (n.id, n.sort)).collect();

    // "ihre drei Knoten typisiert": jede Sorte ist ein Wert des
    // geschlossenen SortId-Enums - genau eine Primaersorte pro Knoten
    // (Invariante 5.3) ist durch Konstruktion belegt: ein untypisierter
    // Knoten waere hier nicht vom Typ IRNode.
    let nodes_typed = true;

    // Kanten der Zelle.
    let cell_edges: Vec<_> = graph
        .edges
        .iter()
        .filter(|e| member_ids.contains(&e.source) && member_ids.contains(&e.target))
        .collect();

    // "ihre drei Kanten portkompatibel": Regel 10.6 erneut ausgewertet,
    // nicht dem Zusammenbau geglaubt.
    let edges_port_compatible =
        cell_edges
            .iter()
            .all(|e| match (sort_of.get(&e.source), sort_of.get(&e.target)) {
                (Some(s), Some(t)) => ctx
                    .port_matrix
                    .iter()
                    .any(|(ms, mt, mr)| ms == s && mt == t && *mr == e.relation_sort),
                _ => false,
            });

    // Regel 9.8 (Richtungskonsistenz einer Zelle): die Zelle erbt die
    // Ordnung des Modulgraphen ueber die Sorteneigner.
    let direction_consistent = cell_edges.iter().all(|e| {
        let owners = (
            sort_of.get(&e.source).and_then(|s| ctx.sort_owner.get(s)),
            sort_of.get(&e.target).and_then(|s| ctx.sort_owner.get(s)),
        );
        let (Some(&src_owner), Some(&tgt_owner)) = owners else {
            return false;
        };
        use psk_types::objects::IREdgeDirectionKind as D;
        match e.direction {
            D::Forward => forward_ok(ctx, src_owner, tgt_owner),
            D::Backward => is_reflux(src_owner, tgt_owner),
            D::BidirectionalDeclared => {
                (forward_ok(ctx, src_owner, tgt_owner) || is_reflux(src_owner, tgt_owner))
                    && (forward_ok(ctx, tgt_owner, src_owner) || is_reflux(tgt_owner, src_owner))
            }
        }
    });

    // "Witness- und Traceverweise aufloesbar": Witnessverweise gegen
    // Buendel-W und Knotenmenge, Traceverweise gegen Buendel-T. Ein
    // Verweis, der nicht aufloest, ist KEIN Berichtszustand, sondern
    // ein defekter Graph: PSK-E011 (die Struktur kennt keinen Fehlwert,
    // siehe RefsResolution).
    let mut any_witness_ref = false;
    for node in &members {
        for w in &node.witness_refs {
            any_witness_ref = true;
            if !ctx.witnesses.contains(w) && !member_ids.contains(w) {
                return Err(PskError::NonclosingM13Seam);
            }
        }
        if node.trace_ref != *ctx.bundle_trace {
            return Err(PskError::NonclosingM13Seam);
        }
    }
    let refs_resolution = if any_witness_ref {
        RefsResolution::Checked
    } else {
        RefsResolution::VacuousEmpty
    };

    // "offene Differenzen explizit residualisiert": jeder Residuenverweis
    // eines Mitglieds loest gegen Buendel-R auf.
    let differences_residualized = members
        .iter()
        .all(|n| n.residue_refs.iter().all(|r| ctx.residues.contains(r)));

    // Struktur 9.10: JEDE Platzierung wird vermerkt ("0 heisst
    // konfliktfrei" gibt dem konfliktfreien Vermerk eine Bedeutung) -
    // aus der realen Sondierungsspur des Laufs, nie nachgerechnet.
    let probe_notes = ctx
        .probes
        .iter()
        .filter(|(id, trail)| member_ids.contains(id) && !trail.is_empty())
        .map(|(id, trail)| ProbeNote {
            node: *id,
            computed_k: u32::from(trail[0]),
            reached_k: u32::from(*trail.last().expect("nicht leer")),
            probe_steps: (trail.len() - 1) as u32,
        })
        .collect();

    Ok(CellReport {
        cell,
        occupancy: Occupancy::Occupied,
        closure_mode,
        nodes_typed,
        edges_port_compatible,
        direction_consistent,
        refs_resolution,
        differences_residualized,
        probe_notes,
    })
}

/// Pass C9 (ClosureAndGluing, M11+M22): Vertrag 9.7 ueber alle 18 Zellen
/// (Definition 9.4, |Delta| = 3*6 = 18), in kanonischer Ordnung c0..c5,
/// b0..b5, o0..o5.
pub fn close_all_18(graph: &IRGraph, ctx: &ClosureContext) -> Result<Vec<CellReport>, PskError> {
    let mut reports = Vec::with_capacity(18);
    for kind in [CellKind::Center, CellKind::Bridge, CellKind::Boundary] {
        for k in 0..6u8 {
            let cell = CellId::new(kind, k).expect("k in 0..6 ist konstruktionsbedingt gueltig");
            reports.push(close_cell(cell, graph, ctx)?);
        }
    }
    Ok(reports)
}

/// Regel 9.9, Zaehlpflicht: close_all_18 MUSS die Zahl der vakuum
/// geschlossenen Zellen berichten - "18 geschlossen, davon N vakuum",
/// nicht "18 geschlossen".
pub fn vacuum_closed_count(reports: &[CellReport]) -> usize {
    reports.iter().filter(|r| r.vacuum_closed()).count()
}

/// `all_18_cells_closed` aus pass_registry.executable_requires,
/// abgeleitet aus den 18 Berichten statt behauptet.
pub fn all_18_closed(reports: &[CellReport]) -> bool {
    reports.len() == 18 && reports.iter().all(|r| r.closed())
}

/// Skalenabstieg (Definition 9.24, Invariante 9.25, Regel 9.20).
///
/// Der v1.0.34-Dokumentbefund (Eintrittszelle normativ offen) ist in
/// v1.0.35 an der Quelle geschlossen - Regel 9.20 (Eintrittszelle eines
/// Abstiegs): "Es wird dafuer keine eigene Regel eingefuehrt: es gilt
/// dieselbe Platzierungsregel wie auf jeder anderen Skalenstufe -
/// Sortenklasse bestimmt die Zellklasse, k = H(Can(node)) mod 6,
/// Konflikte durch aufsteigende Sondierung, vermerkt in probe_notes.
/// Der Abstieg verlaengert den scale_path um genau ein Paar; die Zelle
/// darin wird platziert, nicht vererbt."
///
/// Damit ist der Abstieg eine Funktion des KNOTENS, nicht der Adresse:
/// die Platzierungsregel braucht Sorte und kanonisierten Inhalt.
/// (Schnittstelle 9.26 fuehrt weiterhin `descend(addr) -> M13Address` -
/// diese Signatur kann Regel 9.20 nicht erfuellen; kleine
/// Registerspannung, gemeldet.) Der Hash laeuft wie bei jeder
/// Platzierung ueber den Knoten MIT leerem Adressplatzhalter
/// (Zweiphasenmuster, siehe `build_node`-Aufrufer) - dieselbe Regel,
/// derselbe Hash, dieselbe Sondierung; nur der scale_path unterscheidet
/// Grob- von Feinplatzierung.
///
/// Der Verweigerungspfad bleibt vollstaendig: Ueberschreitung der
/// deklarierten Tiefe und Abstieg ohne Knotenposition sind PSK-E011 -
/// im Referenzlauf (max_depth = 0) weiterhin der einzige erreichbare
/// Ausgang.
pub fn descend(
    node: &psk_types::objects::IRNode,
    ctx: &crate::EdgeContext,
    max_depth: u32,
) -> Result<crate::PlacementOutcome, PskError> {
    let parsed = parse_m13_address(&node.m13_address.0)
        .map_err(|_: M13AddressError| PskError::NonclosingM13Seam)?;
    crate::wellformed::check_wellformed(&parsed, max_depth).map_err(|v| v.error_code())?;
    // Abstieg geschieht an einem Knoten (Definition 9.24: "Jeder Knoten
    // DARF auf feinerer Skala selbst einen M13-Chart tragen") - eine
    // Adresse ohne node_id benennt keinen.
    let Some(at_node) = parsed.node else {
        return Err(PskError::NonclosingM13Seam);
    };
    if parsed.level + 1 > max_depth {
        // Invariante 9.25 / Regel 9.13 Punkt 3: die Verweigerung.
        return Err(PskError::NonclosingM13Seam);
    }

    // Regel 9.20: dieselbe Platzierungsregel im Feinchart. `place`
    // rechnet klassenrein auf dem kanonisierten Knoten mit leerem
    // Adressplatzhalter; `ctx.occupied` ist die Belegung des FEINCHARTS.
    let mut draft = node.clone();
    draft.m13_address = psk_types::objects::M13Address(String::new());
    let fine = crate::place(&draft, ctx)?;
    let fine_parsed = parse_m13_address(&fine.address.0)
        .map_err(|_: M13AddressError| PskError::NonclosingM13Seam)?;

    // "Der Abstieg verlaengert den scale_path um genau ein Paar" - das
    // Paar ist die Grobposition, an der abgestiegen wird.
    let mut ancestors = parsed.ancestors.clone();
    ancestors.push(psk_types::ScaleAncestor {
        cell: parsed.cell,
        node: at_node,
    });
    let descended = psk_types::ParsedM13Address {
        level: parsed.level + 1,
        ancestors,
        cell: fine_parsed.cell,
        node: None,
    };
    Ok(crate::PlacementOutcome {
        address: psk_types::objects::M13Address(psk_types::format_m13_address(&descended)),
        probed_k: fine.probed_k,
    })
}

/// Definition 9.19: akkumulierte Rahmenaenderung entlang einer
/// Chartroute. Identitaet = leerer Rest (keine haengenden
/// Abstiegspaare).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transport(pub Vec<u8>);

impl Transport {
    /// Hol = I - Definition 9.17 verlangt das fuer Close720.
    pub fn is_identity(&self) -> bool {
        self.0.is_empty()
    }
}

/// Transport und Holonomie (Definition 9.18/9.19).
///
/// T_{iota_a iota_b} ist reiner Rahmenwechsel: nur die M13Address wird
/// umgeschrieben (Definition 9.18 Punkt 1), T_ii = I (Punkt 2), und jeder
/// Wechsel ist umkehrbar (Punkt 3). Entlang der Route komponiert sich das
/// als Stapel von Abstiegspaaren: ein Abstieg schiebt sein Paar, der
/// zugehoerige Aufstieg nimmt es - Punkt 3 verlangt, dass es DASSELBE
/// Paar ist. Eine Route, die anders wechselt (Sprung ueber mehr als eine
/// Skala, Aufstieg an fremder Stelle, Seitenwechsel bei gleicher Tiefe),
/// ist kein Chartwechsel, sondern ein Defekt: PSK-E011.
///
/// Bei geschlossener Route (gleiches Chart am Anfang und Ende) ist der
/// Stapel leer und Hol_gamma = I - bei max_depth = 0 gilt das aus
/// T_ii = I (Regel 9.21), der CellReport weist den Fall als trivial aus,
/// und als Beleg fuer Transportkorrektheit gilt er ausdruecklich nicht.
pub fn holonomy(route: &[psk_types::objects::M13Address]) -> Result<Transport, PskError> {
    let parsed: Vec<_> = route
        .iter()
        .map(|a| parse_m13_address(&a.0).map_err(|_: M13AddressError| PskError::NonclosingM13Seam))
        .collect::<Result<_, _>>()?;

    let mut stack: Vec<(CellId, M13NodeId)> = Vec::new();
    for pair in parsed.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        match (a.level, b.level) {
            // Gleiche Tiefe: dasselbe Chart nur bei gleicher Ahnenkette -
            // gleiche Tiefe in verschiedenen Aesten ist kein Chartwechsel,
            // sondern ein Sprung.
            (la, lb) if la == lb => {
                if a.ancestors != b.ancestors {
                    return Err(PskError::NonclosingM13Seam);
                }
                // T_ii = I: nichts zu wechseln (Definition 9.18 Punkt 2).
            }
            // Abstieg um genau eine Skala: das neue Paar MUSS die Position
            // benennen, an der der Abstieg stattfand.
            (la, lb) if lb == la + 1 => {
                let Some(descent) = b.ancestors.last() else {
                    return Err(PskError::NonclosingM13Seam);
                };
                if b.ancestors[..b.ancestors.len() - 1] != a.ancestors[..] {
                    return Err(PskError::NonclosingM13Seam);
                }
                let at_node = a.node.map(|n| n == descent.node).unwrap_or(false);
                if descent.cell != a.cell || !at_node {
                    return Err(PskError::NonclosingM13Seam);
                }
                stack.push((descent.cell, descent.node));
            }
            // Aufstieg um genau eine Skala: Umkehrbarkeit (Punkt 3) - es
            // muss DAS Paar sein, das der Abstieg geschoben hat, und die
            // Route kommt dort an, wo sie abgestiegen war.
            (la, lb) if la == lb + 1 => {
                let Some(expected) = a.ancestors.last() else {
                    return Err(PskError::NonclosingM13Seam);
                };
                if a.ancestors[..a.ancestors.len() - 1] != b.ancestors[..] {
                    return Err(PskError::NonclosingM13Seam);
                }
                let matches_stack = stack
                    .pop()
                    .map(|(c, n)| c == expected.cell && n == expected.node)
                    // Leerer Stapel: die Route beginnt tiefer und steigt
                    // auf - zulaessig, solange sie konsistent ankommt.
                    .unwrap_or(true);
                let arrives =
                    b.cell == expected.cell && b.node.map(|n| n == expected.node).unwrap_or(false);
                if !matches_stack || !arrives {
                    return Err(PskError::NonclosingM13Seam);
                }
            }
            // Sprung ueber mehr als eine Skala: kein Chartwechsel.
            _ => return Err(PskError::NonclosingM13Seam),
        }
    }

    // Der Rest des Stapels IST die akkumulierte Rahmenaenderung, kanonisch
    // als Abstiegspfad serialisiert; leer = Identitaet.
    let mut bytes = Vec::new();
    for (cell, node) in &stack {
        if !bytes.is_empty() {
            bytes.push(b'.');
        }
        bytes.extend_from_slice(format_cell(*cell).as_bytes());
        bytes.push(b'.');
        bytes.extend_from_slice(format_node(*node).as_bytes());
    }
    Ok(Transport(bytes))
}

fn format_cell(cell: CellId) -> String {
    let c = match cell.kind {
        CellKind::Center => 'c',
        CellKind::Bridge => 'b',
        CellKind::Boundary => 'o',
    };
    format!("{c}{}", cell.k)
}

fn format_node(node: M13NodeId) -> String {
    match node {
        M13NodeId::Center => "c".to_string(),
        M13NodeId::Inner(k) => format!("i{k}"),
        M13NodeId::Outer(k) => format!("o{k}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        ContextRef, FactStatus, IREdge, IREdgeDirectionKind, IRNode, Lineage, M13Address,
        PredicateExpr, RealityStatus,
    };
    use psk_types::Digest;

    fn node(sort: SortId, salt: &str, addr: &str) -> IRNode {
        let digest = Digest::sha256(salt.as_bytes());
        IRNode {
            id: ObjectId::new(sort, digest),
            sort,
            context: ContextRef("ctx".into()),
            lineage: Lineage("lin".into()),
            reality_status: RealityStatus::Coherent,
            facticity: FactStatus::Observed,
            anchor_refs: vec![],
            witness_refs: vec![],
            residue_refs: vec![],
            trace_ref: TraceRef(Digest::sha256(b"trace")),
            payload_digest: digest,
            m13_address: M13Address(addr.into()),
        }
    }

    fn ir_edge(source: &IRNode, target: &IRNode, direction: IREdgeDirectionKind) -> IREdge {
        IREdge {
            id: ObjectId::new(SortId::Trace, Digest::sha256(b"edge")),
            source: source.id,
            target: target.id,
            relation_sort: RelationSortId::Grounds,
            direction,
            preconditions: vec![PredicateExpr("anker versiegelt".into())],
            postconditions: vec![PredicateExpr("kontext gebunden".into())],
            gate_ref: None,
            dependency_refs: vec![],
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        }
    }

    /// Ein Minimalkontext mit den echten Registerwerten der beteiligten
    /// Sorten: S-ANC gehoert M05 (L2), S-CTX M06 (L3), S-EVT M19 (L7).
    /// Handgebaut, weil psk-topology die Register nicht liest (der echte
    /// Lauf laedt sie in psk-conformance - Schichtung wie EdgeContext).
    struct Fixture {
        witnesses: Vec<ObjectId>,
        residues: Vec<ObjectId>,
        trace: TraceRef,
        matrix: Vec<(SortId, SortId, RelationSortId)>,
        owner: BTreeMap<SortId, ModuleId>,
        layer: BTreeMap<ModuleId, u8>,
        carriers: BTreeSet<(ModuleId, ModuleId)>,
        probes: Vec<(ObjectId, Vec<u8>)>,
    }

    impl Fixture {
        fn new() -> Fixture {
            let mut owner = BTreeMap::new();
            owner.insert(SortId::Anchor, ModuleId::AnchorRegistry);
            owner.insert(SortId::Context, ModuleId::ThoughtCompiler);
            owner.insert(SortId::Event, ModuleId::TraceReplayResidueStore);
            let mut layer = BTreeMap::new();
            layer.insert(ModuleId::AnchorRegistry, 2);
            layer.insert(ModuleId::ThoughtCompiler, 3);
            layer.insert(ModuleId::TraceReplayResidueStore, 7);
            Fixture {
                witnesses: vec![],
                residues: vec![],
                trace: TraceRef(Digest::sha256(b"trace")),
                matrix: vec![
                    (SortId::Anchor, SortId::Context, RelationSortId::Grounds),
                    (SortId::Context, SortId::Anchor, RelationSortId::Grounds),
                    (SortId::Context, SortId::Event, RelationSortId::Grounds),
                ],
                owner,
                layer,
                carriers: BTreeSet::new(),
                probes: vec![],
            }
        }

        fn ctx(&self) -> ClosureContext<'_> {
            ClosureContext {
                witnesses: &self.witnesses,
                residues: &self.residues,
                bundle_trace: &self.trace,
                port_matrix: &self.matrix,
                sort_owner: &self.owner,
                module_layer: &self.layer,
                shared_pass_carriers: &self.carriers,
                probes: &self.probes,
                max_depth: 0,
            }
        }
    }

    fn cell(kind: CellKind, k: u8) -> CellId {
        CellId::new(kind, k).unwrap()
    }

    #[test]
    fn an_empty_graph_closes_all_18_cells_vacuously_and_says_so() {
        let f = Fixture::new();
        let graph = Graph {
            nodes: vec![],
            edges: vec![],
        };
        let reports = close_all_18(&graph, &f.ctx()).unwrap();
        assert_eq!(reports.len(), 18);
        assert!(all_18_closed(&reports));
        // Regel 9.9: vakuum zaehlt, wird aber AUSGEWIESEN.
        assert_eq!(vacuum_closed_count(&reports), 18);
        for r in &reports {
            assert_eq!(r.occupancy, Occupancy::Empty);
            assert_eq!(r.refs_resolution, RefsResolution::VacuousEmpty);
            assert_eq!(r.closure_mode, ClosureMode::Vacuous);
        }
        // Kanonische Ordnung c0..c5, b0..b5, o0..o5.
        assert_eq!(reports[0].cell, cell(CellKind::Center, 0));
        assert_eq!(reports[6].cell, cell(CellKind::Bridge, 0));
        assert_eq!(reports[17].cell, cell(CellKind::Boundary, 5));
    }

    #[test]
    fn forward_along_the_layer_order_is_consistent_and_against_it_is_not() {
        let f = Fixture::new();
        // M05 (L2) -> M06 (L3): Schichtordnung erfuellt.
        let a = node(SortId::Anchor, "a", "m13:0/c0");
        let b = node(SortId::Context, "b", "m13:0/c0");
        let up = Graph {
            edges: vec![ir_edge(&a, &b, IREdgeDirectionKind::Forward)],
            nodes: vec![a.clone(), b.clone()],
        };
        let r = close_cell(cell(CellKind::Center, 0), &up, &f.ctx()).unwrap();
        assert!(r.direction_consistent && r.closed());

        // M06 (L3) -> M05 (L2) forward: verletzt, keine gemeinsame Passe.
        let down = Graph {
            edges: vec![ir_edge(&b, &a, IREdgeDirectionKind::Forward)],
            nodes: vec![a, b],
        };
        let r = close_cell(cell(CellKind::Center, 0), &down, &f.ctx()).unwrap();
        assert!(!r.direction_consistent && !r.closed());
    }

    #[test]
    fn backward_is_only_consistent_along_a_named_reflux_channel() {
        let f = Fixture::new();
        // Kanal (i): jede Schicht -> M19 (S-EVT gehoert M19).
        let src = node(SortId::Context, "src", "m13:0/c1");
        let evt = node(SortId::Event, "evt", "m13:0/c1");
        let reflux = Graph {
            edges: vec![ir_edge(&src, &evt, IREdgeDirectionKind::Backward)],
            nodes: vec![src.clone(), evt],
        };
        let r = close_cell(cell(CellKind::Center, 1), &reflux, &f.ctx()).unwrap();
        assert!(r.direction_consistent);

        // M06 -> M05 backward: kein benannter Rueckflusskanal.
        let anchor = node(SortId::Anchor, "anc", "m13:0/c1");
        let wild = Graph {
            edges: vec![ir_edge(&src, &anchor, IREdgeDirectionKind::Backward)],
            nodes: vec![src, anchor],
        };
        let r = close_cell(cell(CellKind::Center, 1), &wild, &f.ctx()).unwrap();
        assert!(!r.direction_consistent);
    }

    #[test]
    fn witness_refs_are_vacuous_when_absent_checked_when_present_defect_when_dangling() {
        let mut f = Fixture::new();
        let plain = node(SortId::Anchor, "plain", "m13:0/b0");
        let g = Graph {
            nodes: vec![plain],
            edges: vec![],
        };
        let r = close_cell(cell(CellKind::Bridge, 0), &g, &f.ctx()).unwrap();
        // Regel 9.11: als vakuum ausweisen, nicht als geprueft - auch
        // wenn die Traceverweise real geprueft wurden.
        assert_eq!(r.refs_resolution, RefsResolution::VacuousEmpty);
        assert_eq!(r.closure_mode, ClosureMode::Trivial);

        let witness_id = ObjectId::new(SortId::Witness, Digest::sha256(b"w"));
        let mut with_ref = node(SortId::Anchor, "with", "m13:0/b0");
        with_ref.witness_refs = vec![witness_id];
        let g = Graph {
            nodes: vec![with_ref.clone()],
            edges: vec![],
        };
        // Haengender Verweis: kein Berichtszustand, sondern ein defekter
        // Graph - PSK-E011 (die Struktur kennt keinen Fehlwert).
        assert!(close_cell(cell(CellKind::Bridge, 0), &g, &f.ctx()).is_err());
        // Aufloesbar, sobald das Buendel-W ihn traegt.
        f.witnesses = vec![witness_id];
        let g = Graph {
            nodes: vec![with_ref],
            edges: vec![],
        };
        let r = close_cell(cell(CellKind::Bridge, 0), &g, &f.ctx()).unwrap();
        assert_eq!(r.refs_resolution, RefsResolution::Checked);
    }

    #[test]
    fn probe_conflicts_are_noted_and_direct_hits_are_not() {
        let mut f = Fixture::new();
        let n = node(SortId::Anchor, "n", "m13:0/o3");
        f.probes = vec![
            (n.id, vec![2, 3, 4]), // Konflikt: aufsteigend sondiert
            (
                ObjectId::new(SortId::Context, Digest::sha256(b"other")),
                vec![1, 2], // anderer Knoten, nicht Mitglied dieser Zelle
            ),
        ];
        let g = Graph {
            nodes: vec![n.clone()],
            edges: vec![],
        };
        let r = close_cell(cell(CellKind::Boundary, 3), &g, &f.ctx()).unwrap();
        assert_eq!(r.probe_notes.len(), 1);
        assert_eq!(r.probe_notes[0].node, n.id);
        assert_eq!(r.probe_notes[0].computed_k, 2);
        assert_eq!(r.probe_notes[0].reached_k, 4);
        assert_eq!(r.probe_notes[0].probe_steps, 2);

        // Auch der Direkttreffer wird vermerkt - "0 heisst konfliktfrei"
        // gibt dem konfliktfreien Vermerk seine Bedeutung.
        f.probes = vec![(n.id, vec![3])];
        let g = Graph {
            nodes: vec![n],
            edges: vec![],
        };
        let r = close_cell(cell(CellKind::Boundary, 3), &g, &f.ctx()).unwrap();
        assert_eq!(r.probe_notes.len(), 1);
        assert_eq!(r.probe_notes[0].computed_k, 3);
        assert_eq!(r.probe_notes[0].reached_k, 3);
        assert_eq!(r.probe_notes[0].probe_steps, 0);
    }

    #[test]
    fn descend_refuses_beyond_the_declared_depth_and_without_a_node() {
        let ctx = crate::EdgeContext::default();
        // Invariante 9.25: max_depth = 0 -> jeder Abstieg verweigert.
        let n = node(SortId::Context, "d", "m13:0/c2/i2");
        assert!(descend(&n, &ctx, 0).is_err());
        // Definition 9.24: Abstieg geschieht an einem KNOTEN.
        let cell_only = node(SortId::Context, "d2", "m13:0/c2");
        assert!(descend(&cell_only, &ctx, 5).is_err());
    }

    #[test]
    fn descend_places_the_fine_cell_and_extends_the_scale_path_by_one_pair() {
        // Regel 9.20: dieselbe Platzierungsregel - Sortenklasse bestimmt
        // die Zellklasse, die Zelle wird PLATZIERT, nicht vererbt.
        let ctx = crate::EdgeContext::default();
        let n = node(SortId::Context, "descender", "m13:0/c2/i2");
        let out = descend(&n, &ctx, 1).expect("Abstieg innerhalb der Tiefe");
        let parsed = parse_m13_address(&out.address.0).expect("parsebar");
        assert_eq!(parsed.level, 1);
        assert_eq!(parsed.ancestors.len(), 1);
        assert_eq!(parsed.ancestors[0].cell, cell(CellKind::Center, 2));
        assert_eq!(parsed.ancestors[0].node, M13NodeId::Inner(2));
        // S-CTX ist Zentrumssorte: die Feinzelle traegt Klasse c - und
        // ihr k stammt aus H(Can(node)), nicht aus der Grobzelle.
        assert_eq!(parsed.cell.kind, CellKind::Center);
        assert!(
            !out.probed_k.is_empty(),
            "Sondierung vermerkt, nicht verworfen"
        );

        // Determinismus: derselbe Knoten steigt in dieselbe Feinzelle.
        let again = descend(&n, &ctx, 1).expect("Abstieg wiederholbar");
        assert_eq!(out, again);

        // Und die Route grob -> fein ist fuer holonomy ein offener
        // Abstieg: der Transport ist die Rahmenaenderung "c2.i2".
        let route = [n.m13_address.clone(), again.address];
        let t = holonomy(&route).expect("zulaessiger Chartwechsel");
        assert_eq!(t.0, b"c2.i2".to_vec());
    }

    #[test]
    fn holonomy_of_a_trivial_route_is_the_identity() {
        use psk_types::objects::M13Address;
        let route = [
            M13Address("m13:0/c0/c".into()),
            M13Address("m13:0/c1/i1".into()),
            M13Address("m13:0/c0/c".into()),
        ];
        // Regel 9.21: aus T_ii = I, nicht angenommen.
        assert!(holonomy(&route).unwrap().is_identity());
    }

    #[test]
    fn holonomy_cancels_a_descent_ascent_pair_and_keeps_an_open_descent() {
        use psk_types::objects::M13Address;
        // Das Beispiel aus Definition 9.12: Abstieg bei c2/i2 in den
        // Feinchart, dort b5/o5, und zurueck an dieselbe Stelle.
        let closed = [
            M13Address("m13:0/c2/i2".into()),
            M13Address("m13:1.c2.i2/b5/o5".into()),
            M13Address("m13:0/c2/i2".into()),
        ];
        assert!(holonomy(&closed).unwrap().is_identity());

        // Offene Route: der Abstieg bleibt als Rahmenaenderung stehen.
        let open = [
            M13Address("m13:0/c2/i2".into()),
            M13Address("m13:1.c2.i2/b5/o5".into()),
        ];
        let t = holonomy(&open).unwrap();
        assert!(!t.is_identity());
        assert_eq!(t.0, b"c2.i2".to_vec());
    }

    #[test]
    fn holonomy_rejects_jumps_teleports_and_wrong_ascents() {
        use psk_types::objects::M13Address;
        // Sprung ueber zwei Skalen.
        let jump = [
            M13Address("m13:0/c0/c".into()),
            M13Address("m13:2.c0.c.c1.i1/b0/o0".into()),
        ];
        assert!(holonomy(&jump).is_err());
        // Seitenwechsel bei gleicher Tiefe (verschiedene Ahnenketten).
        let teleport = [
            M13Address("m13:1.c2.i2/b5/o5".into()),
            M13Address("m13:1.c3.i3/b5/o5".into()),
        ];
        assert!(holonomy(&teleport).is_err());
        // Aufstieg an fremder Stelle: abgestiegen bei c2/i2, angekommen
        // bei c3/i3 - Definition 9.18 Punkt 3 verlangt Umkehrbarkeit.
        let wrong = [
            M13Address("m13:0/c2/i2".into()),
            M13Address("m13:1.c2.i2/b5/o5".into()),
            M13Address("m13:0/c3/i3".into()),
        ];
        assert!(holonomy(&wrong).is_err());
    }
}
