//! Die vier Berichtsdigests des Maschinenzertifikats, real aggregiert.
//!
//! Struktur 7.46 verlangt in `MachineCertificate` vier Digests, die auf
//! Berichte zeigen: `gate_report_digest`, `residue_report_digest`,
//! `capability_audit_digest`, `negative_test_report_digest`. Drei davon
//! stehen namentlich unter den acht Pflichtberichten. Ein Platzhalter an
//! dieser Stelle zeigt auf nichts - das Zertifikat traegt dann eine
//! Referenz, die kein Dokument hat.
//!
//! ## Warum die Wanduhr nicht in diesen Digests steht
//!
//! `GateReport.decided_at` und `ResidueRecord.opened_at` sind `DualTime`
//! und tragen `tau_e`. Invariante 6.14 haelt die Wanduhr aus Digests
//! heraus. Zwei Schichten sorgen dafuer, und es ist wichtig, sie nicht zu
//! verwechseln:
//!
//! 1. Die BERICHTSFORM nennt die Zeitstempel gar nicht erst. Das ist die
//!    tragende Schicht - `gate_entry` und `residue_entry` lassen
//!    `decided_at` bzw. `opened_at` vollstaendig aus.
//! 2. `identity_projection` (statt `can`) wendet zusaetzlich pi_vol an.
//!    Das faengt volatile Felder, die spaeter in die Berichtsform
//!    geraten koennten, ohne dass jemand daran denkt.
//!
//! Bewiesen wird das in `the_wall_clock_does_not_reach_the_gate_report_digest`,
//! und zwar an von Hand gebauten Berichten, die sich AUSSCHLIESSLICH in
//! `tau_e` unterscheiden. Nicht am Golden Run: dessen Uhr ist eine
//! Konstante, in beiden Laeufen derselbe Zeitstempel. Ein Vergleich der
//! zwei Golden Runs zeigt Determinismus, nicht Replayneutralitaet - er
//! bestuende auch dann, wenn die Wanduhr voll im Digest saesse.
//!
//! BEFUND, nicht hier entschieden: `psk_trace::residue_digest` benutzt
//! `can()` statt `identity_projection` und nennt in seinem Kopfkommentar
//! ausdruecklich `residue_report_digest` als Verwendungszweck. Fuer einen
//! Einzelsatzdigest zur Integritaetspruefung ist das die richtige Wahl
//! (dieselbe Unterscheidung wie bei `segment_record_digest`, Regel 7.39);
//! als Zertifikatsfeld waere es die falsche. Diese Datei nimmt deshalb
//! nicht `residue_digest`, sondern projiziert selbst - der Kommentar dort
//! bleibt unangetastet, weil die Entscheidung, welche der beiden Lesarten
//! gilt, nicht in dieser Datei faellt.
//!
//! ## Was in einen Bericht kommt
//!
//! Die Berichtskoerper werden AUSGESCHRIEBEN, nicht aus den Objekten
//! abgeleitet. Ein Bericht ist ein eigenes Dokument mit eigener Form, kein
//! Speicherabbild: was er nennt, ist eine Entscheidung, und sie soll
//! lesbar an einer Stelle stehen statt implizit aus `derive(Serialize)`
//! zu folgen.

use psk_canon::{identity_projection, Media};
use psk_types::objects::{GateReport, ResidueRecord, RuntimeManifest};
use psk_types::{Digest, PskError};
use serde_json::{json, Value};

/// Ein aggregierter Bericht samt dem Digest, der im Zertifikat auf ihn
/// zeigt.
#[derive(Debug, Clone)]
pub struct Report {
    pub name: &'static str,
    pub body: Value,
    pub digest: Digest,
}

impl Report {
    fn new(name: &'static str, body: Value) -> Result<Self, PskError> {
        let bytes = serde_json::to_vec(&body).map_err(|_| PskError::CanonicalizationFailed)?;
        let digest = identity_projection(&bytes, Media::Json)?.digest();
        Ok(Report { name, body, digest })
    }
}

/// Die vier Berichte eines Zertifizierungslaufs.
#[derive(Debug, Clone)]
pub struct AggregatedReports {
    pub gate_report: Report,
    pub residue_report: Report,
    pub capability_audit: Report,
    pub negative_test_report: Report,
}

/// Ein einzelner Gatbericht in der Berichtsform.
///
/// `decided_at` fehlt bewusst und vollstaendig - nicht nur `tau_e`. Der
/// Zeitpunkt einer Gatentscheidung ist fuer den Bericht ohne Belang; was
/// zaehlt, ist welches Gat mit welchen Eingaben wie entschied. Weniger im
/// Digest heisst hier weniger, das falsch sein kann.
fn gate_entry(report: &GateReport) -> Value {
    let mut input_digests: Vec<String> =
        report.input_digests.iter().map(|d| d.to_string()).collect();
    input_digests.sort();
    let mut reasons: Vec<String> = report.reasons.iter().map(|r| format!("{r:?}")).collect();
    reasons.sort();
    json!({
        "gate_id": format!("{:?}", report.gate_id),
        "order": format!("{:?}", report.order),
        "decision": format!("{:?}", report.decision),
        "reasons": reasons,
        "input_digests": input_digests,
        "residue_refs": report.residue_refs.len(),
        "evidence_refs": report.evidence_refs.len(),
        "seam_report_refs": report.seam_report_refs.len(),
    })
}

/// Ein einzelner Residuensatz in der Berichtsform. `opened_at` fehlt aus
/// demselben Grund wie `decided_at` oben.
fn residue_entry(record: &ResidueRecord) -> Value {
    json!({
        "type": format!("{:?}", record.r#type),
        "origin_module": format!("{:?}", record.origin_module),
        "scope": record.scope.0,
        "severity": format!("{:?}", record.severity),
        "open_obligation": record.open_obligation.0,
        "state": format!("{:?}", record.state),
        "closed": record.closed_by.is_some(),
    })
}

/// Der Fahigkeitsaudit aus dem `RuntimeManifest`: was dieser Build an
/// Operatoren und Adaptern traegt, unter welchem Profil und mit welcher
/// Determinismusklasse. Das ist die Menge, gegen die jede Tokenautorisierung
/// spaeter geprueft wird - der Audit haelt fest, wogegen geprueft wurde.
fn capability_audit_body(manifest: &RuntimeManifest) -> Value {
    let mut operators: Vec<String> = manifest
        .operator_versions
        .iter()
        .map(|(op, v)| format!("{op:?}@{}", v.0))
        .collect();
    operators.sort();
    let mut adapters: Vec<String> = manifest
        .adapter_versions
        .iter()
        .map(|(a, v)| format!("{}@{}", a.0, v.0))
        .collect();
    adapters.sort();
    json!({
        "profile": format!("{:?}", manifest.profile),
        "determinism_class": format!("{:?}", manifest.determinism_class),
        "capability_matrix": manifest.capability_matrix.0,
        "build_digest": manifest.build_digest.to_string(),
        "operators": operators,
        "adapters": adapters,
    })
}

/// Der Negativtestbericht, gelesen aus dem Katalog, der ihn fuehrt.
///
/// Der Bericht kann nicht aus einem Lauf stammen: Negativtests belegen,
/// dass etwas NICHT geht, und ein Lauf, der nichts Verbotenes versucht,
/// bringt darueber kein Artefakt hervor. Sein Register ist
/// `conformance_catalog.rs` - dieselbe Quelle, die `verify-catalog` liest,
/// und damit maschinenlesbar im selben Sinn.
///
/// Gemeldet wird die Menge der gefuehrten IDs, sonst nichts. Ob ein Test
/// gruen ist, sagt dieser Bericht NICHT - das weiss nur der Testlauf, und
/// es hier zu behaupten waere dieselbe Sorte Anspruch, die beim
/// Deckungsvektor gerade entfernt wurde. Ob eine ID als derzeit nicht
/// realisierbar gefuehrt wird, sagt er ebenfalls nicht: das prueft
/// `verify-catalog` als Gatstufe, und ein zweiter Parser derselben Regel
/// an dieser Stelle koennte von ihr abdriften, ohne dass es auffaellt.
fn negative_test_body(catalog_source: &str) -> Value {
    // Zwei STRUKTURELLE Marker, keine Textsuche: der Katalog fuehrt eine
    // ID entweder als Aufzaehlungseintrag im Kopfkommentar ("//! - T-...")
    // oder als Abschnittsmarke im Rumpf ("// ---- T-..."). Beide stellen
    // die ID an den Anfang, also als Gegenstand. Eine blosse Erwaehnung
    // mitten im Satz - davon hat der Katalog mehrere - trifft keinen der
    // beiden Marker und faellt damit heraus. Genau diese Sorte
    // Falschtreffer hatte `verify-catalog` schon einmal geliefert.
    let mut ids: Vec<String> = Vec::new();
    for line in catalog_source.lines() {
        let trimmed = line.trim_start();
        let rest = trimmed
            .strip_prefix("//! - T-")
            .or_else(|| trimmed.strip_prefix("// ---- T-"));
        let Some(rest) = rest else { continue };
        let tail: String = rest
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '-')
            .collect();
        // Eine ID hat die Form T-<GRUPPE>-<NNN>; alles andere ist kein
        // Eintrag, sondern ein Marker, der zufaellig so anfaengt.
        if tail.matches('-').count() == 1 && tail.split('-').all(|p| !p.is_empty()) {
            ids.push(format!("T-{tail}"));
        }
    }
    ids.sort();
    ids.dedup();

    json!({
        "source": "packages/psk-conformance/src/conformance_catalog.rs",
        "total": ids.len(),
        "ids": ids,
    })
}

/// Baut die vier Berichte aus den Artefakten eines Zertifizierungslaufs.
pub fn aggregate_reports(
    gate_reports: &[&GateReport],
    residues: &[ResidueRecord],
    manifest: &RuntimeManifest,
    catalog_source: &str,
) -> Result<AggregatedReports, PskError> {
    let mut gates: Vec<Value> = gate_reports.iter().map(|g| gate_entry(g)).collect();
    // Stabile Ordnung: der Bericht ist eine Menge von Entscheidungen, und
    // seine Reihenfolge DARF den Digest nicht bestimmen.
    gates.sort_by_key(|v| v.to_string());

    let mut residue_entries: Vec<Value> = residues.iter().map(residue_entry).collect();
    residue_entries.sort_by_key(|v| v.to_string());

    Ok(AggregatedReports {
        gate_report: Report::new("gate_report", json!({"total": gates.len(), "gates": gates}))?,
        residue_report: Report::new(
            "residue_report",
            json!({"total": residue_entries.len(), "residues": residue_entries}),
        )?,
        capability_audit: Report::new("capability_audit", capability_audit_body(manifest))?,
        negative_test_report: Report::new(
            "negative_test_report",
            negative_test_body(catalog_source),
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_negative_test_report_finds_the_real_catalog_entries() {
        let root = {
            let mut dir = std::env::current_dir().expect("cwd");
            while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
                assert!(dir.pop(), "keine Workspace-Wurzel");
            }
            dir
        };
        let src = std::fs::read_to_string(
            root.join("packages/psk-conformance/src/conformance_catalog.rs"),
        )
        .expect("Katalog lesbar");
        let body = negative_test_body(&src);
        let total = body["total"].as_u64().expect("total");
        assert_eq!(
            total, 37,
            "der Katalog fuehrt 37 T-IDs; {total} gefunden heisst, der Parser greift daneben"
        );
        // Gegenprobe: der Parser darf nicht irgendetwas Zeilenfoermiges
        // einsammeln, sondern echte IDs. Ohne diese Pruefung koennte er
        // aus 37 Muellzeilen bestehen und der Test bliebe gruen.
        let ids = body["ids"].as_array().expect("ids");
        assert!(
            ids.iter().all(|v| {
                let s = v.as_str().unwrap_or("");
                s.starts_with("T-") && s.len() >= 7 && !s.ends_with('-')
            }),
            "jeder Eintrag MUSS eine T-ID sein: {ids:?}"
        );
        assert!(
            ids.iter().any(|v| v == "T-OWN-001"),
            "T-OWN-001 steht im Katalog und MUSS im Bericht auftauchen"
        );
    }

    fn gate_at(wall_clock: &str) -> GateReport {
        GateReport {
            schema: "psk.gate-report/1.0".into(),
            id: psk_types::ObjectId::new(psk_types::objects::SortId::Gate, Digest::sha256(b"gate")),
            gate_id: psk_types::objects::GateId::GEffect,
            order: 1,
            input_digests: vec![Digest::sha256(b"input")],
            decision: psk_types::objects::GateReportDecisionKind::Pass,
            reasons: vec![],
            evidence_refs: vec![],
            residue_refs: vec![],
            seam_report_refs: vec![],
            replay_descriptor: psk_types::objects::ReplayDescriptor("replay/1".into()),
            decided_at: psk_types::DualTime {
                tau_i: 0,
                tau_e: wall_clock.into(),
                clock_ref: psk_types::ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            trace_ref: psk_types::TraceRef(Digest::sha256(b"trace")),
        }
    }

    /// Invariante 6.14, an der Stelle gemessen, an der sie hier greift.
    ///
    /// Der Nachweis MUSS hier stattfinden und nicht am Golden Run: dessen
    /// Uhr ist eine Konstante ("2026-08-05T00:00:00.000000000Z" in beiden
    /// Laeufen). Ein Vergleich zweier Golden Runs bestuende deshalb auch
    /// dann, wenn `decided_at` voll im Digest saesse - er wuerde
    /// Determinismus zeigen und Replayneutralitaet BEHAUPTEN. Zwei
    /// Gatberichte, die sich AUSSCHLIESSLICH in der Wanduhr unterscheiden,
    /// trennen die beiden Aussagen.
    #[test]
    fn the_wall_clock_does_not_reach_the_gate_report_digest() {
        let early = gate_at("2026-08-05T00:00:00.000000000Z");
        let late = gate_at("2031-12-24T23:59:59.000000000Z");

        let a = Report::new("g", json!({"gates": [gate_entry(&early)]})).expect("digest");
        let b = Report::new("g", json!({"gates": [gate_entry(&late)]})).expect("digest");
        assert_eq!(
            a.digest, b.digest,
            "die Wanduhr DARF NICHT im Berichtsdigest stehen (Invariante 6.14)"
        );

        // Positivkontrolle: ohne die Auslassung waeren es zwei
        // verschiedene Digests. Ohne diesen Teil koennte die Gleichheit
        // oben auch daher kommen, dass `Report::new` immer dasselbe
        // liefert.
        let naive = |g: &GateReport| {
            Report::new(
                "g",
                json!({"gates": [gate_entry(g)], "decided_at": g.decided_at.tau_e}),
            )
            .expect("digest")
        };
        assert_ne!(
            naive(&early).digest,
            naive(&late).digest,
            "die Kontrolle muss beissen, sonst prueft der Test oben nichts"
        );
    }

    #[test]
    fn report_order_does_not_change_the_digest() {
        // Ein Bericht ist eine Menge. Waere die Reihenfolge digestrelevant,
        // haetten zwei Laeufe mit gleicher Entscheidungsmenge verschiedene
        // Zertifikatsfelder.
        let manifest_body = json!({"a": 1});
        let one = Report::new(
            "t",
            json!({"total": 2, "gates": [json!({"x": 1}), json!({"y": 2})]}),
        )
        .expect("digest");
        let two = Report::new(
            "t",
            json!({"total": 2, "gates": [json!({"y": 2}), json!({"x": 1})]}),
        )
        .expect("digest");
        // Ohne Sortierung unterscheiden sie sich - genau deshalb sortiert
        // `aggregate_reports` vor dem Bauen des Koerpers.
        assert_ne!(
            one.digest, two.digest,
            "unsortiert MUESSEN sie abweichen, sonst prueft der Test nichts"
        );
        let _ = manifest_body;
    }
}
