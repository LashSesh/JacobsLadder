//! Algorithmus 14.4 (Tick) end-to-end: `select(phase, state)` leitet die
//! Arbeit aus dem gesaeten Zustand ab, die Phasen laufen in kanonischer
//! Folge, jedes Produkt faellt nach Sigma zurueck. Plus T-REPLAY-002s
//! Negativnachweis (Regel 22.3 (Replay laeuft unter shadow)).

mod common;

use psk_effect::NoEffectLines;
use psk_scheduler::{tick, Profiling, Sigma};
use psk_types::objects::{ProfileId, SortId};

/// Regel 5.9 (Kandidat und Gedankenkoerper), Satz 3: "Der Ablauf ist
/// innerhalb eines Taktes vollstaendig: Kandidat in normalize und type,
/// Anker in anchor, Praegung ebendort." EIN Takt traegt ein deponiertes
/// Record und einen Kandidaten durch Observe -> Normalize -> Type ->
/// Anchor (Bind, Praegung, Klassifikation) - die Praegung findet den in
/// DERSELBEN Phase versiegelten Anker vor, weil Verweise beim Dispatch
/// aufloesen, nicht beim Einreihen.
#[test]
fn one_tick_carries_a_record_and_a_candidate_through_the_chain() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    common::seed_record(&mut sigma, b"workspace");
    common::seed_candidate(&mut sigma, "ein Auftrag");
    let rd = common::run_descriptor();

    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert_eq!(sigma.tick_no, 1);
    let record = &sigma.program.records[0];
    assert!(record.provenance.is_some(), "Observe hat gebunden");
    assert!(record.anchor_ref.is_some(), "Anchor hat versiegelt");
    assert_eq!(sigma.anchors.len(), 1);

    let candidate = &sigma.candidates[0];
    assert!(candidate.canonical_digest.is_some(), "C1 (normalize)");
    assert_eq!(candidate.sort, Some(SortId::Context), "C2 (type)");
    assert!(candidate.minted.is_some(), "Praegung ebendort (anchor)");
    assert_eq!(sigma.thoughts.len(), 1);
    assert_eq!(
        sigma.thoughts[0].anchor_refs,
        vec![sigma.anchors[0].id],
        "der gepraegte Koerper traegt den im selben Takt versiegelten Anker"
    );
    assert_eq!(
        sigma.reality_horizon.len(),
        1,
        "Schritt 4: die Klassifikation entsteht in derselben Anchor-Phase"
    );

    // Vertrag 27.2 (Domänengelieferte opake Eingaben) Pflicht 3: ohne Klassifikationsplugin MUSS UNKNOWN
    // entstehen - auch unter tick.
    assert_eq!(
        sigma.reality_horizon[0].reality_status,
        psk_types::objects::RealityStatus::Unknown
    );
}

/// Invariante "Keine stille Millisekunde": eine Phase ohne Arbeit wird
/// versiegelt wie jede andere - der leere Takt traegt tick.opened, zwoelf
/// phase.sealed.* und tick.closed.
#[test]
fn every_phase_is_sealed_even_when_empty() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Reference), common::budget());
    let rd = common::run_descriptor();

    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();

    let events: Vec<&str> = sigma
        .trace
        .segments()
        .iter()
        .map(|s| s.event_type.0.as_str())
        .collect();
    assert_eq!(
        events.len(),
        14,
        "tick.opened + 12x phase.sealed + tick.closed"
    );
    assert_eq!(events.first(), Some(&"tick.opened"));
    assert_eq!(events.last(), Some(&"tick.closed"));
    assert_eq!(
        events
            .iter()
            .filter(|e| e.starts_with("phase.sealed."))
            .count(),
        12
    );
    assert_eq!(sigma.tick_no, 1);
}

/// Algorithmus 14.4 (Tick): "if budget.exhausted: M19.residue(item, kind:
/// budget); continue" - das Element laeuft nicht, der Lauf schon.
#[test]
fn an_exhausted_budget_residualizes_the_item_instead_of_dispatching_it() {
    let mut sigma = Sigma::new(
        common::manifest(ProfileId::Reference),
        common::budget_with_compute(0),
    );
    common::seed_candidate(&mut sigma, "verhungert");
    let rd = common::run_descriptor();

    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert!(
        sigma.candidates[0].canonical_digest.is_none(),
        "ohne Budget DARF nichts rechnen"
    );
    let budget_residues = sigma
        .residues
        .all()
        .iter()
        .filter(|r| r.r#type == psk_types::objects::ResidueRecordTypeKind::Budget)
        .count();
    assert!(
        budget_residues >= 1,
        "die Erschoepfung MUSS residualisieren"
    );
}

/// T-REPLAY-002 / Regel 22.3 (Replay laeuft unter shadow): "Plan und
/// Token werden erzeugt, aber sofort invalidiert." Unter dem
/// Shadow-Profil stellt die Execute-Phase das Token aus und invalidiert
/// es ueber P37/`plan_changed` - die Effektleitung wird nie gesprochen.
/// Der Nachweis steckt im Aufbau: `NoEffectLines` HAT keine Leitung;
/// wuerde der Arm sie verlangen, schluege der Takt fehl statt zu
/// invalidieren.
#[test]
fn t_replay_002_shadow_invalidates_the_token_and_never_speaks_the_line() {
    let mut sigma = Sigma::new(common::manifest(ProfileId::Shadow), common::budget());
    sigma
        .gates_and_tokens
        .reports
        .push(common::passed_effect_gate());
    sigma.program.patch_plan = Some(common::patch_plan());
    let rd = common::run_descriptor();

    tick(
        &mut sigma,
        &rd,
        &mut NoEffectLines,
        common::time(),
        &mut Profiling::off(),
    )
    .unwrap();

    assert_eq!(sigma.gates_and_tokens.issued.len(), 1, "Schritt 9 lief");
    let key = &sigma.gates_and_tokens.issued[0].idempotency_key;
    assert_ne!(
        sigma.gates_and_tokens.ledger.state_of(key),
        Some(psk_effect::TokenState::Issued),
        "das Token MUSS invalidiert sein, nicht ausstehend"
    );
    assert!(
        sigma.effects.is_empty(),
        "kein EffectAttempt: der Adapter wurde nie aufgerufen"
    );

    // Und der Folgetakt leitet daraus KEINE Arbeit mehr ab - ein
    // invalidiertes Token steht nicht wieder an.
    assert!(
        !psk_scheduler::has_pending_work(&sigma),
        "nach der Invalidierung ist nichts mehr anstehend"
    );
}
