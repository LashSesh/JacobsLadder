//! Knoten- und Kantenbau fuer den IRBundle-Zusammenbau (M23-Haelfte der
//! Compile-Phase, Definition 14.2 (Phasen-Modul-Bindung)).
//!
//! Bis zur Taktumverdrahtung (Regel 24.4 (Der Golden Run laeuft unter
//! tick)) lag dieser Bau im Konformanzpaket. Er gehoert hierher, weil die
//! Compile-Phase ihn als Arbeit abwickelt und der Zusammenbau M23s
//! Substanz ist. Die TRENNUNG von damals bleibt bestehen: wer das
//! Domaenenprofil und die Register LIEST, ist die Domaene (die Lader
//! stehen weiter im Konformanzpaket); hier steht nur, was aus bereits
//! typisierten Werten Knoten und Kanten macht.
//!
//! ## Welche Knoten entstehen - und welche nicht
//!
//! Regel 9.14 (Platzierungsregel) Punkt 4: Knoten der Sorten S-WIT, S-GAT, S-TRC, S-RES sind
//! ZELLGEBUNDEN - ihre Zelle ist "diejenige, die den geprueften Knoten
//! traegt", und die kennt nur der Gesamtgraph. `psk_topology::place`
//! verlangt sie folgerichtig als `EdgeContext.bound_cell` und schlaegt
//! ohne sie mit `NonclosingM13Seam` fehl (nachgemessen, nicht vermutet).
//! Nichts im Baum berechnet diese Traegerzelle heute. Deshalb tragen
//! GateReports und SeamReports keinen Knoten; die Kante `authorizes`
//! (S-GAT -> S-CAP) ist deklariert, aber ohne Quellknoten - sie
//! erscheint als `EdgeOmission::EndpointMissing`, nicht als Kante.

use std::collections::BTreeMap;

use psk_types::objects::{IRNode, M13Address, RelationSortId, SortId};
use psk_types::{ObjectId, PskError, TraceRef};

use crate::EdgeCandidate;

/// Der Zustand, den ein Knoten aus dem Lauf mitbringt und den er nicht
/// selbst traegt: Kontext, Lineage und Realitaetstypisierung des Laufs.
pub struct NodeEnvelope {
    pub context: psk_types::objects::ContextRef,
    pub lineage: psk_types::objects::Lineage,
    pub reality_status: psk_types::objects::RealityStatus,
    pub facticity: psk_types::objects::FactStatus,
    pub anchor_ref: ObjectId,
    pub trace_ref: TraceRef,
    /// Die Residuen, die DIESES Objekt als Ursprung fuehren. Der
    /// Aufrufer kennt den Ledger; `build_node` erfindet nichts.
    pub residue_refs: Vec<ObjectId>,
}

/// Die Residuen des Laufs, nach ihrem `origin_object` gruppiert - die
/// Rueckrichtung des Verweises, den der Ledger vorwaerts fuehrt.
pub fn residues_by_origin(
    residues: &[psk_types::objects::ResidueRecord],
) -> std::collections::HashMap<ObjectId, Vec<ObjectId>> {
    // HashMap statt BTreeMap: ObjectId ist Hash, aber nicht Ord - die
    // Ordnung des Ledgers bleibt in den Vec-Werten erhalten, und die
    // ist die einzige, auf die es ankommt.
    let mut out: std::collections::HashMap<ObjectId, Vec<ObjectId>> =
        std::collections::HashMap::new();
    for r in residues {
        out.entry(r.origin_object).or_default().push(r.id);
    }
    out
}

/// Baut einen IR-Knoten aus einem realen Laufobjekt.
///
/// `payload_digest` ist H(Can(Objekt)) ueber die identitaetsbildende
/// Projektion - dieselbe, aus der auch die ObjectId des Objekts entsteht
/// (Definition 6.6 (Objekt-ID)). Er wird berechnet, nicht uebernommen: kein
/// Laufobjekt ausser AnchorSnapshot fuehrt ein eigenes Digestfeld
/// (nachgeprueft an den generierten Strukturen).
///
/// Die Platzierung ist zweiphasig, und das ist kein Umweg: `place`
/// hasht den kanonisierten Knoten EINSCHLIESSLICH `m13_address`, also
/// muss dort beim Hashen der leere Platzhalter stehen. Alle bestehenden
/// Aufrufer machen es genauso.
pub fn build_node<T: serde::Serialize>(
    object: &T,
    id: ObjectId,
    sort: SortId,
    env: &NodeEnvelope,
    probes: &mut Vec<(ObjectId, Vec<u8>)>,
) -> Result<IRNode, PskError> {
    let bytes = serde_json::to_vec(object).map_err(|_| PskError::CanonicalizationFailed)?;
    let payload_digest = psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?.digest();

    let draft = IRNode {
        id,
        sort,
        context: env.context.clone(),
        lineage: env.lineage.clone(),
        reality_status: env.reality_status,
        facticity: env.facticity,
        anchor_refs: vec![env.anchor_ref],
        // Der Referenzlauf erzeugt kein EvidenceObject; ein erfundener
        // Witnessverweis waere ein Selbstwitness (Invariante 12.2 (Kein Selbstwitness)).
        witness_refs: Vec::new(),
        // Die Residuen, die dieses Objekt als `origin_object` fuehren.
        // Bis QPM v1.0.6 stand hier hart `Vec::new()`, und die
        // QPM-Massenklasse Residuum konnte deshalb nie von null
        // verschieden werden - obwohl der Lauf ein blockierendes
        // Residuum auf den Anker oeffnet. Das war eine Verdrahtungs-
        // luecke, keine Eigenschaft der Domaene.
        residue_refs: env.residue_refs.clone(),
        trace_ref: env.trace_ref,
        payload_digest,
        m13_address: M13Address(String::new()),
    };

    // Regel 9.14 (Platzierungsregel): reine Funktion des kanonisierten Knotens. `occupied`
    // bleibt leer - M13 hat 18 Zellen und traegt beliebig viele Knoten,
    // eine Zelle ist also nicht exklusiv. Aufsteigende Sondierung greift
    // nur, wo ein Aufrufer Exklusivitaet verlangt; dieser tut es nicht,
    // und mit ihr waeren schon die sechs Projektionen plus das
    // Abhaengigkeitsprofil nicht platzierbar (sieben Bruecken-Knoten,
    // sechs Brueckenzellen - nachgemessen).
    let placement = psk_topology::place(&draft, &psk_topology::EdgeContext::default())?;
    // Struktur 9.10 (CellReport): die Sondierungsfolge "wird hier vermerkt, nicht
    // verworfen" - bis v1.0.34 verwarf genau diese Stelle sie
    // (Fehlerkorrektur Punkt 39 auf der Registerseite, dieser Ledger auf
    // der Laufseite). close_cell filtert spaeter auf echte Konflikte.
    probes.push((id, placement.probed_k.clone()));
    Ok(IRNode {
        m13_address: placement.address,
        ..draft
    })
}

/// Eine belegte Verknuepfung: welches Objektfeld sie festhaelt, steht
/// daneben. Ohne ein solches Feld entsteht keine Kante - eine Kante, die
/// kein Objekt festhaelt, waere dieselbe Sorte Erfindung, die Regel 10.9 (Herkunft der Kantenbedingungen)
/// fuer Praedikate verbietet.
pub fn edge(
    source: ObjectId,
    target: ObjectId,
    relation: RelationSortId,
    evidence_field: &'static str,
    trace_ref: TraceRef,
) -> EdgeCandidate {
    EdgeCandidate {
        source,
        target,
        relation,
        evidence_field,
        trace_ref,
    }
}

/// Fuer den Bericht: welche Relationssorte wie oft eine Kante trug.
pub fn edge_census(bundle: &psk_types::objects::IRBundle) -> BTreeMap<String, usize> {
    let mut census = BTreeMap::new();
    for e in &bundle.graph.edges {
        *census.entry(e.relation_sort.id().to_string()).or_insert(0) += 1;
    }
    census
}
