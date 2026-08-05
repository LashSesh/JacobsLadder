//! M05 AnchorRegistry: ueberfuehrt einen ExternalRecord in einen
//! versiegelten AnchorSnapshot (Struktur 7.4, OBJ-ANC).
//!
//! ## Selbstreferenz bei der Identitaetsbildung
//!
//! AnchorSnapshot traegt `id: ObjectId` und `digest: Digest` als eigene
//! Felder - ein Objekt kann aber nicht ueber sein eigenes, gerade erst zu
//! bestimmendes Ergebnis hashen. Die Aufloesung folgt demselben Muster wie
//! TraceSegment.segment_digest ("H(Can(alle VORSTEHENDEN Felder))", Struktur
//! 7.36): `id` und `digest` werden ueber alle UEBRIGEN Felder gebildet,
//! danach erst eingesetzt. `sealed` ist dabei ebenfalls ausgenommen - es
//! ist ein Lebenszyklusstatus ("true nach Versiegelung"), kein Inhalt.

use std::collections::BTreeMap;

use psk_canon::{identity_projection, object_id, record_digest, Media};
use psk_types::objects::{AnchorSnapshot, AnchorUncertainty, Provenance, Validity};
use psk_types::objects::{ContextRef, Observation, ScopeExpr, SortId};
use psk_types::{Digest, DualTime, ObjectId, PskError};

/// Eingaben fuer eine Versiegelung - die Felder von AnchorSnapshot ohne die
/// drei selbstreferenziellen/statusbehafteten (id, digest, sealed).
pub struct AnchorInputs {
    pub observations: Vec<Observation>,
    pub provenance: Provenance,
    pub uncertainty: AnchorUncertainty,
    pub context: ContextRef,
    pub time: DualTime,
    pub validity: Validity,
    pub boundary: ScopeExpr,
}

/// Ein Platzhalter-ObjectId, der ausschliesslich zum Serialisieren des
/// Vorbilds dient und vor der Digestbildung wieder entfernt wird - sein
/// Inhalt ist bedeutungslos.
fn placeholder_object_id() -> ObjectId {
    ObjectId::new(SortId::Anchor, Digest::sha256(b""))
}

/// Baut das JSON-Vorbild (alle Felder ausser id/digest/sealed) und bildet
/// daraus Objekt-ID (Definition 6.6, ueber pi_vol) und record_digest
/// (Definition 6.7, ueber das vollstaendige Vorbild).
fn seal_identity(inputs: &AnchorInputs) -> Result<(ObjectId, Digest), PskError> {
    let draft = AnchorSnapshot {
        schema: "psk.anchor-snapshot/1.0".to_string(),
        id: placeholder_object_id(),
        observations: inputs.observations.clone(),
        provenance: inputs.provenance.clone(),
        uncertainty: inputs.uncertainty.clone(),
        context: inputs.context.clone(),
        time: inputs.time.clone(),
        validity: inputs.validity.clone(),
        boundary: inputs.boundary.clone(),
        digest: Digest::sha256(b""), // Platzhalter, siehe Modulkopf
        sealed: false,
    };
    let mut value = serde_json::to_value(&draft).map_err(|_| PskError::CanonicalizationFailed)?;
    let obj = value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?;
    obj.remove("id");
    obj.remove("digest");
    obj.remove("sealed");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;

    let oid_bytes = identity_projection(&bytes, Media::Json)?;
    let oid_str = object_id(SortId::Anchor.id(), &oid_bytes);
    let oid: ObjectId = oid_str
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    let rdig = record_digest(&bytes, Media::Json)?;
    Ok((oid, rdig))
}

/// Regel 32.7 / Struktur 7.4: versiegelt einen AnchorSnapshot. Nach der
/// Rueckgabe ist er unveraenderlich ("sealed: true nach Versiegelung,
/// danach unveraenderlich") - diese Funktion modelliert deshalb bewusst
/// keinen getrennten "unsealed"-Zwischenzustand mit eigenen Feldern, da der
/// Text keinen solchen beschreibt.
pub fn seal_anchor(inputs: AnchorInputs) -> Result<AnchorSnapshot, PskError> {
    let (id, digest) = seal_identity(&inputs)?;
    Ok(AnchorSnapshot {
        schema: "psk.anchor-snapshot/1.0".to_string(),
        id,
        observations: inputs.observations,
        provenance: inputs.provenance,
        uncertainty: inputs.uncertainty,
        context: inputs.context,
        time: inputs.time,
        validity: inputs.validity,
        boundary: inputs.boundary,
        digest,
        sealed: true,
    })
}

/// Vertrag 11.6 (C3): "Verletzte Ankerfrische erzeugt HOLD und
/// ReanchorRequest." Ausgewertet wird ausschliesslich das strukturierte
/// Feld `expires_at_tau_i`. `freshness_predicate` (PredicateExpr) bleibt
/// hier unausgewertet, und das ist seit v1.0.7 die deklarierte Ordnung,
/// keine Luecke: Vertrag 27.2 (Domaenengelieferte opake Eingaben) fuehrt
/// PredicateExpr ausdruecklich als einen der drei Typen, die "im Kern
/// absichtlich ohne Grammatik" sind - geliefert ueber DomainProfile oder
/// MethodPlugin, im Kern nur typisiert weitergereicht. Ein hier erfundener
/// Auswertungsmechanismus waere ein Konformitaetsdefekt, kein Fortschritt.
pub fn is_fresh(validity: &Validity, now_tau_i: u64) -> bool {
    now_tau_i < validity.expires_at_tau_i
}

/// Praeludiert `AnchorUncertainty` ohne deklarierte Parameter - Regel 32.4
/// (Erste Domaene, read-only) braucht bis zur echten Modellwahl (OBL, siehe
/// Kapitel 33) keine.
pub fn no_declared_uncertainty(model: psk_types::objects::UncertaintyModelId) -> AnchorUncertainty {
    AnchorUncertainty {
        model,
        parameters: BTreeMap::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::PredicateExpr;
    use psk_types::ClockRef;

    fn sample_inputs(tau_e: &str) -> AnchorInputs {
        AnchorInputs {
            observations: vec![Observation("obs-1".into())],
            provenance: Provenance {
                source_adapter: psk_types::objects::AdapterId("observer-local-fs".into()),
                observer_identity: Digest::sha256(b"observer-local-fs-identity"),
                method: "sha256_walk".into(),
                input_digests: vec![Digest::sha256(b"file-a"), Digest::sha256(b"file-b")],
            },
            uncertainty: no_declared_uncertainty(psk_types::objects::UncertaintyModelId(
                "none".into(),
            )),
            context: ContextRef("workspace".into()),
            time: DualTime {
                tau_i: 3,
                tau_e: tau_e.to_string(),
                clock_ref: ClockRef("host-a".into()),
                uncertainty_ns: 500,
            },
            validity: Validity {
                freshness_predicate: PredicateExpr("age_ns < 5e9 and fs_generation == g".into()),
                expires_at_tau_i: 100,
            },
            boundary: ScopeExpr("outside-workspace-root".into()),
        }
    }

    #[test]
    fn sealing_produces_a_sealed_immutable_snapshot() {
        let anchor = seal_anchor(sample_inputs("2026-01-01T00:00:00Z")).unwrap();
        assert!(anchor.sealed);
    }

    #[test]
    fn object_id_is_stable_across_wall_clock_but_digest_is_not() {
        // Invariante 6.8: gleiche Eingaben + gleicher RunDescriptor => gleiche
        // Objekt-ID, unabhaengig von der Wanduhr; record_digest DARF abweichen.
        let a = seal_anchor(sample_inputs("2026-01-01T00:00:00Z")).unwrap();
        let b = seal_anchor(sample_inputs("2099-12-31T23:59:59Z")).unwrap();
        assert_eq!(a.id, b.id, "Objekt-ID darf nicht von tau_e abhaengen");
        assert_ne!(
            a.digest, b.digest,
            "record_digest DARF abweichen (Definition 6.7) - kein Defekt"
        );
    }

    #[test]
    fn sealing_is_deterministic() {
        let a = seal_anchor(sample_inputs("2026-01-01T00:00:00Z")).unwrap();
        let b = seal_anchor(sample_inputs("2026-01-01T00:00:00Z")).unwrap();
        assert_eq!(a.id, b.id);
        assert_eq!(a.digest, b.digest);
    }

    #[test]
    fn different_content_yields_different_object_id() {
        let mut inputs_a = sample_inputs("2026-01-01T00:00:00Z");
        let mut inputs_b = sample_inputs("2026-01-01T00:00:00Z");
        inputs_a.boundary = ScopeExpr("scope-a".into());
        inputs_b.boundary = ScopeExpr("scope-b".into());
        let a = seal_anchor(inputs_a).unwrap();
        let b = seal_anchor(inputs_b).unwrap();
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn freshness_uses_expires_at_tau_i_only() {
        let validity = Validity {
            freshness_predicate: PredicateExpr("irrelevant".into()),
            expires_at_tau_i: 100,
        };
        assert!(is_fresh(&validity, 50));
        assert!(!is_fresh(&validity, 100));
        assert!(!is_fresh(&validity, 150));
    }

    #[test]
    fn object_id_has_anchor_sort_prefix() {
        let anchor = seal_anchor(sample_inputs("2026-01-01T00:00:00Z")).unwrap();
        assert_eq!(anchor.id.sort, SortId::Anchor);
        assert_eq!(anchor.id.to_string().split(':').nth(1), Some("S-ANC"));
    }
}
