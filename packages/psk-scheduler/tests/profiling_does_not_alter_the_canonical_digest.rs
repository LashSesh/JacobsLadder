//! T-OBSV-001 (`architecture/ra_tests.yaml`: `{kind: property, run:
//! with_and_without_profiling, expect: identical_canonical_digest}`) und
//! I-ARCH-015 ("profiling_and_logging_do_not_alter_canonical_digest").
//!
//! Geprueft werden beide Schutzschichten aus `psk_scheduler::profiling`
//! getrennt voneinander, damit keine die andere verdeckt:
//!
//! 1. **strukturell** - zwei identische Laeufe, einer mit und einer ohne
//!    Profiling, erzeugen denselben kanonischen Zustand (Tracekopf,
//!    Fortschrittsmarken, Residuen). Das ist die im Register geforderte
//!    Eigenschaft.
//! 2. **registergestuetzt** - `pi_vol` entfernt ein eingebettetes
//!    `runtime_metrics`-Feld tatsaechlich vor der Identitaetsbildung,
//!    waehrend der `record_digest` abweicht (Definition 6.6 (Objekt-ID)/6.7). Ohne
//!    diesen zweiten Teil bliebe unbewiesen, dass der Feldname wirklich
//!    traegt und nicht nur zufaellig nirgends serialisiert wird.

mod common;

use psk_canon::{identity_projection, record_digest, Media};
use psk_effect::NoEffectLines;
use psk_scheduler::{tick, Profiling, Sigma};
use psk_types::objects::ProfileId;
use psk_types::{Digest, ObjectId};

/// Fuehrt denselben Takt aus: zwei Kandidaten bei Compute-Limit 1 - das
/// erste Element laeuft, das zweite faellt ins Budgetresiduum, sodass EIN
/// Takt beide Zaehler deckt (`items_dispatched`, `items_budget_skipped`).
fn run_once(profiling: &mut Profiling) -> (Digest, Vec<Option<Digest>>, Vec<ObjectId>, usize) {
    let mut sigma = Sigma::new(
        common::manifest(ProfileId::Reference),
        common::budget_with_compute(1),
    );
    common::seed_candidate(&mut sigma, "k1");
    common::seed_candidate(&mut sigma, "k2");
    let rd = common::run_descriptor();
    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        profiling,
    )
    .unwrap();

    let marks: Vec<Option<Digest>> = sigma
        .candidates
        .iter()
        .map(|c| c.canonical_digest)
        .collect();
    let residue_ids: Vec<ObjectId> = sigma.residues.all().iter().map(|r| r.id).collect();
    (
        sigma.trace.head(),
        marks,
        residue_ids,
        sigma.trace.segments().len(),
    )
}

#[test]
fn t_obsv_001_profiling_on_and_off_yield_the_identical_canonical_digest() {
    // Die im Testregister geforderte Eigenschaft selbst:
    // run: with_and_without_profiling -> expect: identical_canonical_digest.
    let mut off = Profiling::off();
    let mut on = Profiling::on();

    let (head_off, marks_off, residues_off, segments_off) = run_once(&mut off);
    let (head_on, marks_on, residues_on, segments_on) = run_once(&mut on);

    assert_eq!(
        head_off, head_on,
        "I-ARCH-015: der Tracekopf DARF sich durch Profiling nicht aendern"
    );
    assert_eq!(
        marks_off, marks_on,
        "Fortschrittsmarken muessen gleich sein"
    );
    assert_eq!(residues_off, residues_on, "Residuen muessen gleich sein");
    assert_eq!(
        segments_off, segments_on,
        "Profiling DARF kein zusaetzliches Tracesegment erzeugen"
    );
}

#[test]
fn the_profiled_run_really_did_collect_something() {
    // Gegenprobe: ohne sie waere der Test oben auch dann gruen, wenn
    // `Profiling::on()` gar nichts aufzeichnete - dann verglichen wir
    // zweimal denselben unprofilierten Lauf.
    let mut off = Profiling::off();
    let mut on = Profiling::on();
    run_once(&mut off);
    run_once(&mut on);

    assert!(
        off.runtime_metrics().is_empty(),
        "ausgeschaltet DARF nichts gesammelt werden"
    );
    assert_eq!(
        on.runtime_metrics().len(),
        12,
        "eingeschaltet MUSS jede der zwoelf Phasen eine Bilanz tragen"
    );

    // Und die Zahlen sind echt, nicht null: ein Kandidat lief, einer fiel
    // ins Budgetresiduum (Compute-Limit 1, zwei Elemente in normalize).
    let normalize_phase = on
        .runtime_metrics()
        .iter()
        .find(|m| m.phase_label == "normalize")
        .expect("die Normalize-Phase MUSS eine Bilanz haben");
    assert_eq!(normalize_phase.items_dispatched, 1);
    assert_eq!(normalize_phase.items_budget_skipped, 1);
}

#[test]
fn embedded_runtime_metrics_survive_in_the_record_digest_but_not_in_the_identity() {
    // Zweite Schutzschicht, an der ECHTEN Profilingstruktur geprueft:
    // `pi_vol` entfernt `runtime_metrics` vor der Identitaetsbildung
    // (Definition 6.5 (Volatile Felder und Identitätsprojektion)), der record_digest ueber das vollstaendige Objekt
    // behaelt es (Definition 6.7 (Recorddigest)). Genau die Trennung aus v1.0.5.
    let mut on = Profiling::on();
    run_once(&mut on);
    assert!(!on.runtime_metrics().is_empty(), "Vorbedingung");

    let with_metrics = serde_json::to_vec(&serde_json::json!({
        "schema": "psk.some-object/1.0",
        "kept": "kanonischer Inhalt",
        "runtime_metrics": on.runtime_metrics(),
    }))
    .unwrap();
    let without_metrics = serde_json::to_vec(&serde_json::json!({
        "schema": "psk.some-object/1.0",
        "kept": "kanonischer Inhalt",
    }))
    .unwrap();

    let id_with = identity_projection(&with_metrics, Media::Json).unwrap();
    let id_without = identity_projection(&without_metrics, Media::Json).unwrap();
    assert_eq!(
        id_with, id_without,
        "pi_vol MUSS runtime_metrics vor der Identitaetsbildung entfernen"
    );

    let rec_with = record_digest(&with_metrics, Media::Json).unwrap();
    let rec_without = record_digest(&without_metrics, Media::Json).unwrap();
    assert_ne!(
        rec_with, rec_without,
        "der record_digest DARF abweichen - er sichert die vollstaendigen Bytes"
    );
}

#[test]
fn profiling_data_is_not_reachable_from_sigma_at_all() {
    // Erste Schutzschicht, strukturell: `tick` nimmt `Profiling` als
    // eigenen Parameter, und nichts davon landet in `Sigma`. Der Beweis
    // ist, dass ein voll ausgefuehrter Takt den Schalter fuellt, waehrend
    // derselbe Sigma-Wert bitgleich zu dem eines unprofilierten Laufs
    // bleibt (oben geprueft) - hier zusaetzlich: der Schalter ueberlebt
    // den Aufruf als getrennter Wert, er wurde nicht in Sigma verschoben.
    let mut sigma = Sigma::new(
        common::manifest(ProfileId::Reference),
        common::budget_with_compute(1),
    );
    common::seed_candidate(&mut sigma, "k1");
    common::seed_candidate(&mut sigma, "k2");
    let rd = common::run_descriptor();
    let mut profiling = Profiling::on();
    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut profiling,
    )
    .unwrap();

    assert!(profiling.is_enabled());
    assert_eq!(profiling.runtime_metrics().len(), 12);
    // Sigmas eigene Sammlungen tragen ausschliesslich Laufzustand;
    // es gibt kein Feld, ueber das ein Messwert hierher gelangen koennte.
    let json = serde_json::to_string(&sigma).unwrap();
    assert!(
        !json.contains("runtime_metrics"),
        "kein Sigma-Feld traegt Messwerte"
    );
}
