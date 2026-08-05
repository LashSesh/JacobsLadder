//! M27 ObservabilityProjector (Axiom 7.16, Struktur 7.1 Speicherklasse
//! `none`).
//!
//! forbidden_edge `[M27, "*"]` ("Beobachtung hat keine Schreibkante",
//! `architecture/module_map.yaml`) und die Capability-Verweigerung
//! `{holder: M27, capability: store.append, reason:
//! observation_has_no_authority}` (`architecture/capability_matrix.yaml`)
//! sagen dasselbe zweimal, aus zwei Registern. Diese Implementierung
//! haelt sich strukturell daran, so weit das ohne Crate-Trennung von M19
//! moeglich ist (M27 BRAUCHT Lesezugriff auf M19 - `store.read`, Holder
//! [M19, M27] - eine vollstaendige Abhaengigkeitsausschluss wie bei
//! psk-effect->psk-anchor waere hier falsch): `inspect_*` ruft
//! ausschliesslich `psk_trace`s Lesefunktionen auf (`TraceStore::get`,
//! `verify_chain`, `ResidueLedger::get`), nie `open`/`append`. Dieselbe
//! Konventionsgrenze wie bei M15/M16 in einem Crate, hier ueber eine
//! Crate-Grenze mit absichtlichem Lesezugriff.
//!
//! Axiom 7.16 (Persona ist Apertur): "Eine Persona DARF Stil,
//! Dialogkontinuitaet oder menschliche Lesbarkeit tragen. Sie DARF NICHT
//! Systemidentitaet, Faktberechtigung, Witnessberechtigung oder
//! Effektberechtigung erzeugen. Personaobjekte sind reine Ausgabeprofile
//! und existieren ausschliesslich in M27." Kein Register fuehrt eine
//! Feldstruktur fuer Persona (nicht unter den 28 Kapitel-7-Objekten,
//! anders als ViewArtifact/OBJ-VIW). `Persona` unten traegt deshalb nur
//! die drei im Text erlaubten Eigenschaften und keine einzige weitere -
//! die Erlaubnisgrenze ist die Feldliste selbst, wie bei `EffectAdapter`s
//! fehlenden `observe()`/`read_result()`/`confirm()` (psk-effect).

use psk_trace::{ResidueLedger, ResidueRecord, TraceStore};
use psk_types::{Digest, ObjectId, PskError};

/// Axiom 7.16: "Stil, Dialogkontinuitaet oder menschliche Lesbarkeit" -
/// nicht mehr. Es gibt hier absichtlich kein Feld fuer Identitaet, Fakt-,
/// Witness- oder Effektberechtigung; ein Aufrufer kann keines behaupten,
/// weil der Typ keines hat.
///
/// T-PERSONA-001 (`constitution/conformance_tests.yaml`:
/// "persona_claims_constitutional_authority" -> FAIL): die Feldliste
/// selbst ist der Beweis - ein erfundenes `system_identity`-Feld
/// kompiliert nicht, derselbe Stil wie `GateAuthorization`s
/// compile_fail-Doctests (psk-gate/authorization.rs).
///
/// ```compile_fail
/// let _ = psk_observe::Persona {
///     style: "x".into(),
///     dialog_continuity: true,
///     human_readable_summary: "x".into(),
///     system_identity: "constitutional-authority".to_string(),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Persona {
    pub style: String,
    pub dialog_continuity: bool,
    pub human_readable_summary: String,
}

/// Struktur 7.1 Speicherklasse `none` / object_registry.yaml:
/// "OBJ-VIW ... canonical:false ... faellt nach I-ARCH-015 aus der
/// Kanonisierung heraus." Kein `id`, kein Schema - ein ViewArtifact
/// geht nie in Can() ein und tritt nie als Gate-Eingabe auf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ViewArtifact {
    pub summary: String,
    pub source_digest: Digest,
}

/// M27: liest den Kopf der Traceskette, ohne sie zu veraendern.
/// `verify_chain` (WP04) stellt dabei sicher, dass eine kaputte Kette
/// nicht als gueltiger View erscheint - bei einer defekten Kette scheitert
/// diese Funktion, statt einen View auf zweifelhaften Daten zu bauen.
pub fn inspect_trace_head(store: &TraceStore) -> Result<ViewArtifact, PskError> {
    let segments = store.segments();
    psk_trace::verify_chain(segments)?;
    Ok(ViewArtifact {
        summary: format!("trace head, {} segments", segments.len()),
        source_digest: store.head(),
    })
}

/// M27: liest ein einzelnes Residuum, ohne es zu oeffnen oder zu
/// schliessen - reine Projektion.
pub fn inspect_residue(ledger: &ResidueLedger, id: ObjectId) -> Option<ViewArtifact> {
    let record: &ResidueRecord = ledger.get(id)?;
    Some(ViewArtifact {
        summary: format!(
            "residue {:?}/{:?} state={:?}",
            record.r#type, record.severity, record.state
        ),
        source_digest: id.digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_trace::{
        ResidueInputs, ResidueRecordSeverityKind, ResidueRecordTypeKind, SegmentInputs,
    };
    use psk_types::{DualTime, ModuleId};

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    #[test]
    fn persona_has_no_authority_bearing_fields_by_construction() {
        // Der Test IST die Feldliste: es gibt nichts jenseits von Stil,
        // Dialogkontinuitaet und Lesbarkeit zu setzen.
        let p = Persona {
            style: "knapp".into(),
            dialog_continuity: true,
            human_readable_summary: "Zusammenfassung".into(),
        };
        assert_eq!(p.style, "knapp");
    }

    #[test]
    fn inspecting_an_empty_trace_reports_genesis() {
        let store = TraceStore::new();
        let view = inspect_trace_head(&store).unwrap();
        assert_eq!(view.source_digest, psk_trace::GENESIS_DIGEST);
        assert_eq!(view.summary, "trace head, 0 segments");
    }

    #[test]
    fn inspecting_a_populated_trace_reflects_the_head() {
        let mut store = TraceStore::new();
        let seg_digest = store
            .append(SegmentInputs {
                event_type: psk_types::objects::EventTypeId("field.registered".into()),
                module: ModuleId::FieldRegistry,
                port_id: None,
                object_refs: vec![],
                payload_digest: Digest::sha256(b"payload"),
                time: sample_time(),
                attestation: None,
            })
            .unwrap()
            .segment_digest;
        let view = inspect_trace_head(&store).unwrap();
        assert_eq!(view.source_digest, seg_digest);
        assert_eq!(view.summary, "trace head, 1 segments");
    }

    #[test]
    fn inspecting_an_unknown_residue_yields_nothing() {
        let ledger = ResidueLedger::new();
        let unknown = ObjectId::new(psk_types::objects::SortId::Residue, Digest::sha256(b"x"));
        assert!(inspect_residue(&ledger, unknown).is_none());
    }

    #[test]
    fn inspecting_a_known_residue_reflects_its_state() {
        let mut ledger = ResidueLedger::new();
        let id = ledger
            .open(ResidueInputs {
                r#type: ResidueRecordTypeKind::Scope,
                origin_module: ModuleId::SpectralLensRouter,
                origin_object: ObjectId::new(
                    psk_types::objects::SortId::Projection,
                    Digest::sha256(b"o"),
                ),
                scope: psk_types::objects::ScopeExpr("scope".into()),
                severity: ResidueRecordSeverityKind::NonBlocking,
                open_obligation: psk_types::objects::ObligationExpr("obligation".into()),
                allowed_followups: vec![],
                opened_at: sample_time(),
            })
            .unwrap();
        let view = inspect_residue(&ledger, id).unwrap();
        assert_eq!(view.source_digest, id.digest);
    }
}
