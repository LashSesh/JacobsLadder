//! QPM-4: kanonische Signaturgrammatik, reproduzierbarer Multiview-Atlas.
//!
//! QPM Struktur 3.13 (SignatureVector) und QPM Struktur 3.19 (SignatureAtlas)
//! (SignatureAtlas) geben die Form vor; QPM Regel 3.18 (Splitbild und
//! Parallaxe) bindet den effektiven Witnessrang an den
//! Abhaengigkeitsquotienten, und QPM Regel 2.9 (Keine Ablesung auf
//! halber Rückkehr) bindet jede Ablesung an ein Siegel.
//!
//! ## Was hier gemessen wird - und was nicht
//!
//! Der Atlas traegt je deklariertem Kanal einen `SignatureVector`, und
//! jede Komponente ist eine ZAEHLUNG an realen Laufobjekten:
//!
//! | Kanal | Komponente |
//! |---|---|
//! | topology | platzierte IR-Knoten und geschlossene Zellen |
//! | trace | Siegel des Laufes (Phasensiegel und Zyklusgrenzen) |
//! | residue | Residuen des Laufes |
//! | seam | Restriktionen, die in die Verklebung eingingen |
//!
//! Die fuenf nicht deklarierten Kanaele (spectrum, phase, symmetry,
//! rank, entropy) erscheinen NICHT mit dem Wert null, sondern gar
//! nicht: QPM Struktur 2.6 (Kanal) haelt fest, dass ein nicht
//! deklarierter Kanal nicht als uebersehen gezaehlt wird. Eine Null
//! waere eine Messung, die nicht stattfand.
//!
//! **`Scaled`, nicht Fliesskomma.** Dieselbe Ueberlegung wie bei den
//! ganzzahligen Zwoelfteln in `qpm_cycle`: der Atlas wird digestet, und
//! Fliesskomma waere nicht replaystabil.
//!
//! ## Reproduzierbarkeit ist eine Eigenschaft des VERGLEICHS
//!
//! Das Stufenkriterium nennt den Atlas "reproduzierbar", und
//! QPM Struktur 3.19 (SignatureAtlas) fuehrt dafuer ein Feld
//! `reproducible: bool`. Ein
//! einzelner Lauf kann es nicht ausfuellen - genau wie die Replayklasse
//! (Definition 22.1 (Replayklassen)) ist es eine Eigenschaft zweier
//! Laeufe. `build_atlas` laesst es deshalb offen (`None`), und
//! `compare_atlases` leitet es aus dem realen Vergleich ab. Ein `bool`,
//! das aus einem Lauf entstuende, waere eine Behauptung ueber einen
//! Vergleich, der nicht stattfand - dieselbe Klasse wie
//! `close720_replay_canon_eq`.
//!
//! ## Zwei Pflichtfelder ohne Quelle in dieser Domaene (BEFUND)
//!
//! 1. `SignatureVector.calibration_ref: ObjectId` - ohne Fragezeichen,
//!    also pflichtig. Die Referenzdomaene deklariert `catalog_ref: null`
//!    (QPM-OBL-002) und fuehrt kein Kalibrierungsobjekt. Es gibt nichts,
//!    worauf der Verweis zeigen koennte.
//! 2. `SignatureAtlas.reproducible: bool` - ebenfalls ohne
//!    Fragezeichen, aber aus einem Lauf nicht bestimmbar (siehe oben).
//!
//! Beide sind hier als `Option` gefuehrt UND mit einem erklaerten
//! Grund - dieselbe Form, die Regel 7.51 (Unsignierte Ausstellung
//! unterhalb C4) fuer das leere Signaturfeld verlangt: der Nullstand
//! als erklaerter, nicht als stiller. Gemeldet, nicht ueberspielt.

use std::collections::BTreeMap;

use psk_fields::ChannelId;
use psk_types::objects::{Scaled, SourceRef};
use psk_types::{Digest, ObjectId, PskError, TraceRef};

use crate::{GoldenRunReport, QpmProfile};

/// Ein exakter Messwert: `Scaled` mit Skala 0 ist eine ganze Zahl ohne
/// Rundung. Der Umweg ueber `Scaled` statt `u64` ist die Vorgabe der
/// Struktur ("je Kanal ein Messwert, exakt").
fn exact(n: i64) -> Scaled {
    Scaled {
        schema: "psk.scaled/1.0".into(),
        numerator: n,
        scale: 0,
    }
}

/// QPM Struktur 3.13 (SignatureVector). Profil von S-WIT.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SignatureVector {
    pub id: ObjectId,
    /// Die Einzelansicht, aus der er stammt. ViewArtifact ist Profil von
    /// S-PRJ (QPM Struktur 1.4 (Sortenprofile)) - die S-PRJ-Objekte
    /// dieses Laufes sind seine FieldProjections.
    pub view_ref: ObjectId,
    pub channel_ref: ChannelId,
    /// Je Kanal ein Messwert, exakt.
    pub components: BTreeMap<String, Scaled>,
    /// BEFUND: pflichtig laut Struktur, ohne Quelle in dieser Domaene -
    /// siehe Modulkopf. `None` mit Grund statt eines erfundenen
    /// Verweises.
    pub calibration_ref: Option<ObjectId>,
    pub calibration_absent_reason: Option<String>,
    /// Grundlage des Abhaengigkeitsquotienten.
    pub provenance: Vec<SourceRef>,
    /// QPM Regel 2.9 (Keine Ablesung auf halber Rückkehr): zeigt auf
    /// ein Phasensiegel oder eine Zyklusgrenze, nicht auf eine
    /// beliebige Stelle der Kette.
    pub trace_ref: TraceRef,
}

/// QPM Struktur 3.19 (SignatureAtlas). Profil von S-WIT.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct SignatureAtlas {
    pub id: ObjectId,
    /// Die ViewArtifact-Familie - hier die S-PRJ-Objekte des Laufes.
    pub views: Vec<ObjectId>,
    /// Nur die DEKLARIERTEN Kanaele. Ein nicht deklarierter Kanal
    /// erscheint nicht mit null (QPM Struktur 2.6 (Kanal)).
    pub channels: Vec<ChannelId>,
    pub vectors: Vec<SignatureVector>,
    /// QPM Regel 3.18 (Splitbild und Parallaxe): aus dem
    /// Abhaengigkeitsquotienten, nicht aus der Zahl der Sichten.
    pub effective_witness_rank: i64,
    pub provenance: Vec<SourceRef>,
    /// BEFUND: pflichtig laut Struktur, aus EINEM Lauf nicht bestimmbar.
    /// `compare_atlases` fuellt es.
    pub reproducible: Option<bool>,
    pub reproducibility_absent_reason: Option<String>,
}

/// Die vier Zaehlungen, die dieser Lauf je deklariertem Kanal hergibt.
/// Jede liest ein reales Laufobjekt; keine ist gesetzt.
fn components_for(channel: &ChannelId, run: &GoldenRunReport) -> BTreeMap<String, Scaled> {
    let mut c = BTreeMap::new();
    match channel.0.as_str() {
        "topology" => {
            c.insert(
                "ir_nodes".to_string(),
                exact(run.ir_bundle.graph.nodes.len() as i64),
            );
            c.insert(
                "cells_closed".to_string(),
                exact(run.cell_reports.iter().filter(|r| r.closed()).count() as i64),
            );
        }
        "trace" => {
            // Nur die SIEGEL, nicht alle Segmente:
            // QPM Regel 2.9 (Keine Ablesung auf halber Rückkehr) macht
            // das Siegel zur
            // Ablesestelle, und eine Zaehlung ueber beliebige
            // Kettenglieder waere eine Messung ohne Grenze.
            c.insert("seals".to_string(), exact(seals_of(run).len() as i64));
            c.insert("ticks".to_string(), exact(run.ticks as i64));
        }
        "residue" => {
            c.insert("residues".to_string(), exact(run.residues.len() as i64));
            c.insert(
                "blocking".to_string(),
                exact(
                    run.residues
                        .iter()
                        .filter(|r| {
                            r.severity == psk_types::objects::ResidueRecordSeverityKind::Blocking
                        })
                        .count() as i64,
                ),
            );
        }
        "seam" => {
            // Die Restriktionen, die in die Verklebung eingingen: je
            // Projektion eine (siehe golden_run::deposit_program).
            c.insert(
                "restrictions".to_string(),
                exact(run.field_projections.len() as i64),
            );
            c.insert(
                "section_present".to_string(),
                exact(i64::from(run.glue.section.is_some())),
            );
        }
        // Ein Kanal ausserhalb der vier bekommt keine Komponente statt
        // einer Null - siehe Modulkopf.
        _ => {}
    }
    c
}

/// Die Siegel des Laufes: Phasensiegel und Zyklusgrenzen, in Kettenfolge.
fn seals_of(run: &GoldenRunReport) -> Vec<&psk_trace::TraceSegment> {
    run.trace_segments
        .iter()
        .filter(|s| s.event_type.0.starts_with("phase.sealed.") || s.event_type.0 == "tick.closed")
        .collect()
}

fn object_id(
    sort: psk_types::objects::SortId,
    payload: &impl serde::Serialize,
) -> Result<ObjectId, PskError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| PskError::CanonicalizationFailed)?;
    let canonical = psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?;
    Ok(ObjectId::new(sort, canonical.digest()))
}

/// Baut den Atlas ueber einem realen Lauf. Read-only in der Signatur -
/// dieselbe Form und derselbe Grund wie `observe_golden_run`.
pub fn build_atlas(
    run: &GoldenRunReport,
    profile: &QpmProfile,
) -> Result<SignatureAtlas, PskError> {
    let scope = profile.scope();
    let channels: Vec<ChannelId> = scope.declared_channels.clone();
    let views: Vec<ObjectId> = run.field_projections.iter().map(|p| p.id).collect();
    let provenance: Vec<SourceRef> = run
        .field_projections
        .iter()
        .flat_map(|p| p.source_provenance.iter().cloned())
        .collect();

    // QPM Regel 2.9 (Keine Ablesung auf halber Rückkehr): die
    // Ablesestelle ist ein Siegel. Genommen wird die
    // ZYKLUSGRENZE des letzten Takts - der Punkt, an dem der Umlauf
    // geschlossen ist und eine Ablesung nicht "auf halber Rueckkehr"
    // steht. Gibt es keine, gibt es keinen Atlas: ein Lauf ohne
    // geschlossenen Umlauf hat keine zulaessige Ablesestelle.
    let seal = run
        .trace_segments
        .iter()
        .rev()
        .find(|s| s.event_type.0 == "tick.closed")
        .ok_or(PskError::TraceOrResidueViolation)?;
    let trace_ref = TraceRef(seal.segment_digest);

    let absent = "kein Kalibrierungsobjekt in dieser Domaene: der Scope \
                  fuehrt catalog_ref: null (QPM-OBL-002)"
        .to_string();

    let mut vectors = Vec::new();
    for channel in &channels {
        let components = components_for(channel, run);
        if components.is_empty() {
            continue;
        }
        // Je Kanal EINE Sicht als Herkunft: die erste Projektion. Der
        // Lauf hat genau eine Quotientenklasse, alle sechs Projektionen
        // teilen dieselbe Ankerquelle - eine Sicht je Kanal zu waehlen
        // erhoeht den Rang nicht (QPM Regel 3.18 (Splitbild und Parallaxe)).
        let view_ref = *views.first().ok_or(PskError::UntypedInput)?;
        let body = (
            &view_ref,
            &channel.0,
            &components,
            &provenance,
            &trace_ref.0,
        );
        vectors.push(SignatureVector {
            id: object_id(psk_types::objects::SortId::Witness, &body)?,
            view_ref,
            channel_ref: channel.clone(),
            components,
            calibration_ref: None,
            calibration_absent_reason: Some(absent.clone()),
            provenance: provenance.clone(),
            trace_ref,
        });
    }

    // QPM Regel 3.18 (Splitbild und Parallaxe): der Rang kommt aus dem Abhaengigkeitsquotienten.
    let effective_witness_rank = crate::witness_rank(run).effective_rank;

    let body = (
        &views,
        &channels,
        &vectors,
        effective_witness_rank,
        &provenance,
    );
    Ok(SignatureAtlas {
        id: object_id(psk_types::objects::SortId::Witness, &body)?,
        views,
        channels,
        vectors,
        effective_witness_rank,
        provenance,
        reproducible: None,
        reproducibility_absent_reason: Some(
            "Reproduzierbarkeit ist eine Eigenschaft zweier Laeufe, nicht eines - \
             siehe compare_atlases"
                .to_string(),
        ),
    })
}

/// Der kanonische Digest eines Atlas - die Groesse, an der
/// Bitgleichheit gemessen wird.
pub fn atlas_digest(atlas: &SignatureAtlas) -> Result<Digest, PskError> {
    let bytes = serde_json::to_vec(atlas).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?.digest())
}

/// Das Ergebnis des Vergleichs zweier Atlanten - QPM-4s
/// "reproduzierbar".
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct AtlasComparison {
    pub digest_a: Digest,
    pub digest_b: Digest,
    pub reproducible: bool,
    /// Wo sie auseinanderlaufen, falls sie es tun - benannt, nicht nur
    /// gezaehlt. Ein "nicht reproduzierbar" ohne Stelle waere ein
    /// Befund ohne Gegenstand.
    pub divergences: Vec<String>,
}

/// Vergleicht zwei Atlanten und leitet `reproducible` ab. Die beiden
/// Laeufe MUESSEN denselben RunDescriptor haben - das prueft diese
/// Funktion nicht, es ist die Zusage des Aufrufers (beim Referenzlauf
/// durch R3 belegt).
pub fn compare_atlases(
    a: &SignatureAtlas,
    b: &SignatureAtlas,
) -> Result<AtlasComparison, PskError> {
    let mut divergences = Vec::new();
    if a.views != b.views {
        divergences.push(format!("views: {:?} gegen {:?}", a.views, b.views));
    }
    if a.channels != b.channels {
        divergences.push("channels weichen ab".to_string());
    }
    if a.effective_witness_rank != b.effective_witness_rank {
        divergences.push(format!(
            "effective_witness_rank: {} gegen {}",
            a.effective_witness_rank, b.effective_witness_rank
        ));
    }
    for (x, y) in a.vectors.iter().zip(b.vectors.iter()) {
        if x.trace_ref != y.trace_ref {
            divergences.push(format!(
                "Kanal {}: Ablesestelle weicht ab ({} gegen {})",
                x.channel_ref.0, x.trace_ref.0, y.trace_ref.0
            ));
        }
        if x.components != y.components {
            divergences.push(format!("Kanal {}: Komponenten weichen ab", x.channel_ref.0));
        }
    }
    if a.vectors.len() != b.vectors.len() {
        divergences.push(format!(
            "Zahl der Vektoren: {} gegen {}",
            a.vectors.len(),
            b.vectors.len()
        ));
    }

    let digest_a = atlas_digest(a)?;
    let digest_b = atlas_digest(b)?;
    Ok(AtlasComparison {
        digest_a,
        digest_b,
        // Bitgleichheit, nicht "keine gefundene Abweichung": die
        // Stellenliste oben ist die Diagnose, der Digest ist das Urteil.
        reproducible: digest_a == digest_b,
        divergences,
    })
}

/// Setzt `reproducible` aus einem realen Vergleich - der einzige
/// Schreibpfad fuer dieses Feld.
pub fn seal_reproducibility(atlas: &mut SignatureAtlas, comparison: &AtlasComparison) {
    atlas.reproducible = Some(comparison.reproducible);
    atlas.reproducibility_absent_reason = None;
}
