//! `M25.select(phase, state)` (Algorithmus 14.4 (Tick)): die Ableitung der
//! Phasenarbeit aus Sigma, an den Fortschrittsmarken gemessen - was
//! ansteht, steht im Zustand; was erledigt ist, steht nicht mehr an.

mod common;

use psk_effect::NoEffectLines;
use psk_scheduler::{has_pending_work, select, tick, PendingWork, Profiling, Sigma};
use psk_types::objects::ProfileId;
use psk_types::{Phase, CANONICAL_PHASES};

/// Regel 14.5 (Prioritätsordnung) Satz 1 ("Prioritaet entsteht aus Pflichtabhaengigkeiten")
/// an der Anchor-Phase: Versiegeln (Rang 0) vor Praegung (Rang 1) vor
/// Klassifikation (Rang 2) - die Kette, die Regel 5.9 (Kandidat und Gedankenkörper) mit "Praegung
/// ebendort" in EINE Phase legt.
#[test]
fn the_anchor_queue_is_ordered_by_obligation_not_by_id() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    common::seed_bound_record(&mut sigma, b"w");
    common::seed_candidate(&mut sigma, "auftrag");
    // Kandidat bis C2 bringen, damit die Praegung ansteht.
    sigma.candidates[0].canonical_digest = Some(psk_types::Digest::sha256(b"c1"));
    sigma.candidates[0].sort = Some(psk_types::objects::SortId::Context);

    let queue = select(Phase::Anchor, &sigma);
    let kinds: Vec<&str> = queue
        .iter()
        .map(|q| match q.work {
            PendingWork::AnchorBind { .. } => "bind",
            PendingWork::MintThought { .. } => "mint",
            PendingWork::AnchorClassify { .. } => "classify",
            _ => "unerwartet",
        })
        .collect();
    assert_eq!(
        kinds,
        vec!["bind", "mint", "classify"],
        "die Pflichtabhaengigkeitskette ordnet die Phase"
    );
    let ranks: Vec<u32> = queue
        .iter()
        .map(|q| q.schedulable.obligation_rank)
        .collect();
    assert_eq!(ranks, vec![0, 1, 2]);
}

/// Regel 5.9 (Kandidat und Gedankenkörper)s Wache in der Ableitung: ohne Anker (und ohne anstehendes
/// Versiegeln) wird KEINE Praegung eingereiht - ein Kandidat ohne
/// Ankerquelle bleibt Vorform, statt beim Dispatch zu scheitern.
#[test]
fn a_candidate_without_any_anchor_source_never_derives_a_mint() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    common::seed_candidate(&mut sigma, "verwaist");
    let rd = common::run_descriptor();

    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert!(sigma.candidates[0].canonical_digest.is_some(), "C1 lief");
    assert_eq!(
        sigma.candidates[0].sort,
        Some(psk_types::objects::SortId::Context),
        "C2 lief"
    );
    assert!(
        sigma.candidates[0].minted.is_none(),
        "keine Praegung ohne Anker"
    );
    assert!(sigma.thoughts.is_empty());
    // Und der Lauf terminiert trotzdem: die Praegung STEHT NICHT AN,
    // sie scheitert nicht endlos.
    assert!(!has_pending_work(&sigma));
}

/// Die Fortschrittsmarken tragen die Terminierung: nach dem Takt, der
/// die Kette abgearbeitet hat, leitet KEINE Phase mehr Arbeit ab.
#[test]
fn after_the_chain_completes_no_phase_derives_further_work() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    common::seed_record(&mut sigma, b"w");
    common::seed_candidate(&mut sigma, "auftrag");
    let rd = common::run_descriptor();

    assert!(has_pending_work(&sigma), "vor dem Takt steht Arbeit an");
    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();

    for phase in CANONICAL_PHASES {
        assert!(
            select(phase, &sigma).is_empty(),
            "Phase {} leitet nach getaner Arbeit erneut ab",
            phase.label()
        );
    }
    assert!(!has_pending_work(&sigma));
}

/// Regel 24.4 (Der Golden Run läuft unter tick) legt Schritt 9 und 10 in EINE Phase: mit bestandenem
/// G-EFFECT und deponiertem Plan reiht die Execute-Phase Ausstellen UND
/// verkettetes Ausfuehren ein (`token: None` - die Token-ID existiert
/// beim Einreihen noch nicht, beim Dispatch schon).
#[test]
fn the_execute_phase_chains_issue_and_run_in_one_pass() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    sigma
        .gates_and_tokens
        .reports
        .push(common::passed_effect_gate());
    sigma.program.patch_plan = Some(common::patch_plan());

    let queue = select(Phase::Execute, &sigma);
    let kinds: Vec<&str> = queue
        .iter()
        .map(|q| match q.work {
            PendingWork::ExecuteIssue => "issue",
            PendingWork::ExecuteRun { token: None } => "run(verkettet)",
            PendingWork::ExecuteRun { token: Some(_) } => "run(liegend)",
            _ => "unerwartet",
        })
        .collect();
    assert_eq!(kinds, vec!["issue", "run(verkettet)"]);

    // Ohne bestandenes Gate: nichts - die Ableitung liest die
    // Vorbedingung aus dem Zustand.
    let mut ungated = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    ungated.program.patch_plan = Some(common::patch_plan());
    assert!(select(Phase::Execute, &ungated).is_empty());
}
