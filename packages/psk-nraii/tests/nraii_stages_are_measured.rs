//! Die Stufenmessung nach L0+L1 - gemessen an dem, was das Paket
//! HERVORBRINGT, nicht an einer Liste im Bericht.
//!
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB):
//!
//! - NRAII-0: "Zielidentitaet, Domain-Vertrag und Statusdisziplin
//!   definiert"
//! - NRAII-1: "Kanonischer Zustand, Signatur, Quotient, zustandsloser
//!   Nullanker"
//! - NRAII-2: "Reflexive Boundary, Projektorzerlegung, Residuenvertrag,
//!   nullverankerter Closure-Modus"
//! - NRAII-3: "Radiale Arme, Armtypen, Wing-Mesh, Zykluswitness"
//! - NRAII-4: "Deklarativer und rekonstruktiver Wish strikt getrennt"
//!
//! Die beiden Stufen decken sich NICHT mit den Schichten: NRAII-0 und
//! NRAII-1 fallen beide erst mit L1, weil L0 allein nur einen der vier
//! Bestandteile von NRAII-1 traegt. Genau deshalb wird schichtweise
//! gebaut und stufenweise gemessen.
//!
//! Jeder Bestandteil wird EINZELN geprueft. Ein Test, der die Stufe im
//! ganzen behauptet, waere gruen, sobald ein Teil traegt - dieselbe
//! Ueberlegung wie bei der feldweisen Nachweispflicht am Zertifikat.

use psk_nraii::{
    accept_arm, claim_is_complete, decompose, diamond_equivalent, lift,
    missing_counter_horizon_reason, residue_for_residual_part, seal_mode, witness_cycle,
    witness_seam, ArmType, AttractorMap, ClaimStatus, ContractComponent, Contraction, DiamondClass,
    DomainContract, Facet, FalsificationCheck, HorizonPair, Involution, Materialization,
    ProofHorizon, ReciprocityWitness, ResidualPart, Response, ResponseOrigin, Signed, WingMesh,
    Wish, WishDistance, WishOutcome, N0,
};
use psk_nraii::{narrow_class, reobserve};
use psk_types::{Digest, DualTime, ModuleId, ObjectId};

/// Ein Zustand des Referenzgegenstands, an dem sich die Stufen messen
/// lassen: er traegt eine kanonisierbare Form und eine Signatur.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Referenzzustand {
    art: &'static str,
    inhalt: &'static str,
}

impl Signed for Referenzzustand {
    type Sig = &'static str;
    fn signature(&self) -> &'static str {
        self.art
    }
}

fn vertrag() -> Vec<(ContractComponent, Vec<String>)> {
    ContractComponent::all()
        .into_iter()
        .map(|c| (c, vec![format!("{}: Referenzdomaene", c.label())]))
        .collect()
}

/// NRAII-0, dreiteilig gemessen: Zielidentitaet, Domain-Vertrag,
/// Statusdisziplin.
#[test]
fn nraii_zero_all_three_parts() {
    // Teil 1+2: der Vertrag bindet nur mit allen zehn Komponenten UND
    // benannter Zielidentitaet.
    let d = DomainContract::bind(&vertrag(), ClaimStatus::N, "jacobs-ladder-reference")
        .expect("Domain-Vertrag bindet");
    assert_eq!(d.target_identity(), "jacobs-ladder-reference");
    for component in ContractComponent::all() {
        assert!(!d.component(component).is_empty());
    }

    // Teil 3: die Statusdisziplin ist definiert und geschlossen.
    assert_eq!(ClaimStatus::all().len(), 5);
    assert_eq!(d.status(), ClaimStatus::N);

    println!("NRAII-0: Zielidentitaet, Domain-Vertrag (10/10), Statusdisziplin (5 Stufen)");
}

/// NRAII-1, vierteilig gemessen: kanonischer Zustand, Signatur,
/// Quotient, zustandsloser Nullanker.
#[test]
fn nraii_one_all_four_parts() {
    // Teil 1: kanonischer Zustand - und er ist die GETEILTE
    // Kanonisierung, nicht eine zweite.
    let zustand =
        psk_nraii::CanonicalState::canonicalize(br#"{"b":2,"a":1}"#, psk_canon::Media::Json)
            .expect("kanonisierbar");
    let direkt =
        psk_canon::can(br#"{"b":2,"a":1}"#, psk_canon::Media::Json).expect("kanonisierbar");
    assert_eq!(zustand.digest(), direkt.digest());

    // Teil 2: die Signatur - sie trennt, was sie trennen soll, und
    // uebersieht, was nicht klassenbildend ist.
    let a = Referenzzustand {
        art: "A",
        inhalt: "eins",
    };
    let b = Referenzzustand {
        art: "A",
        inhalt: "zwei",
    };
    let c = Referenzzustand {
        art: "B",
        inhalt: "eins",
    };
    assert_ne!(a, b);
    assert!(diamond_equivalent(&a, &b));
    assert!(!diamond_equivalent(&a, &c));

    // Teil 3: der Quotient - eine Klasse, ein gehobener Operator, und
    // die Hebung ist geprueft, nicht behauptet.
    let op = |x: &Referenzzustand| Referenzzustand {
        inhalt: "verarbeitet",
        ..x.clone()
    };
    let gehoben = lift(op, &[(a.clone(), b.clone())]).expect("quotientenvertraeglich");
    assert_eq!(gehoben.checked_pairs(), 1);
    assert_eq!(
        gehoben.apply_to_class(&DiamondClass::of(a.clone())),
        gehoben.apply_to_class(&DiamondClass::of(b))
    );

    // Teil 4: der zustandslose Nullanker - aus L0, hier als
    // Stufenbestandteil gemessen.
    assert_eq!(std::mem::size_of_val(&N0), 0);

    println!("NRAII-1: kanonischer Zustand, Signatur, Quotient, Nullanker");
}

/// NRAII-2, vierteilig gemessen: reflexive Boundary,
/// Projektorzerlegung, Residuenvertrag, nullverankerter Closure-Modus.
#[test]
fn nraii_two_all_four_parts() {
    // Teil 1: die reflexive Boundary - R mit GEPRUEFTEM R^2 = I.
    let r = Involution::check(|x: &i64| -x, &[1i64, 0, -5]).expect("R^2 = I");
    assert_eq!(r.checked_witnesses(), 3);
    // Die Selbstadjungiertheit ist erklaerter Nullstand, nicht
    // stillschweigend uebergangen.
    assert!(r.self_adjointness_unchecked().contains("kein Innenprodukt"));

    // Teil 2: die Projektorzerlegung, mit ihren drei Gesetzen.
    let split = decompose(&r, &[0i64, 1, -1, 3]);
    assert!(split.accounts_for_everything(), "B+ + B- = I");
    assert!(split.halves_are_disjoint(), "B+ B- = 0");
    assert_eq!(split.fixed().len(), 1, "die Zerlegung trennt wirklich");
    assert_eq!(split.residual().len(), 3);

    // Teil 3: der Residuenvertrag - ein PSK-RA-ResidueRecord mit allen
    // drei Pflichten aus QPM Invariante 10.10 (Residualvollständigkeit).
    let part = ResidualPart {
        origin_object: ObjectId::new(
            psk_types::objects::SortId::Context,
            Digest::sha256(b"traeger"),
        ),
        reason: "Residualraum der Involution".to_string(),
    };
    let record = residue_for_residual_part(
        &part,
        ModuleId::ClosureGlueEngine,
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-11T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("stufenmessung".into()),
            uncertainty_ns: 0,
        },
    );
    assert_eq!(record.origin_object, part.origin_object);
    assert!(record.open_obligation.0.contains("Residualraum"));

    // Und die Seam: J ist nicht automatisch R, der Zeuge sagt es.
    let w = witness_seam(&r, &|x: &i64| 10 - x, &1i64, &N0);
    assert!(!w.agree);

    // Teil 4: der nullverankerte Closure-Modus - chi ist weder psi noch
    // Sigma allein, und ohne beidseitigen Beleg nicht ausstellbar.
    let modus = seal_mode(
        br#"{"psi":1}"#,
        br#"{"sigma":2}"#,
        ReciprocityWitness {
            boundary_preserves_excitation: "Sigma haelt psi".into(),
            excitation_renews_boundary: "psi erneuert Sigma".into(),
        },
    )
    .expect("beide Richtungen belegt");
    let nur_psi = psk_nraii::CanonicalState::canonicalize(br#"{"psi":1}"#, psk_canon::Media::Json)
        .expect("kanonisierbar");
    assert_ne!(modus.digest(), nur_psi.digest());

    println!("NRAII-2: Boundary, Zerlegung, Residuenvertrag, Closure-Modus");
}

/// NRAII-3, vierteilig gemessen: radiale Arme, Armtypen, Wing-Mesh,
/// Zykluswitness.
#[test]
fn nraii_three_all_four_parts() {
    // Teil 2 zuerst, weil Teil 1 ihn braucht: die zehn Armtypen,
    // geschlossen - und neun davon mit Erzeuger auf dieser Schicht.
    assert_eq!(ArmType::all().len(), 10);
    let ohne_erzeuger: Vec<ArmType> = ArmType::all()
        .into_iter()
        .filter(|t| !t.has_producer_at_l3())
        .collect();
    assert_eq!(
        ohne_erzeuger,
        vec![ArmType::Qpm],
        "der QPMArm gehoert zu L9 - erklaerter Nullstand, kein fehlender Arm"
    );

    // Teil 1: ein angenommener Arm mit belegter Kontraktion.
    let arm = accept_arm(
        ArmType::Mirror,
        Contraction::RelativeDimensionDecreased {
            before: 8,
            after: 3,
        },
    )
    .expect("Erzeuger vorhanden");
    assert!(arm.contraction().contracts());
    assert_eq!(arm.stages().len(), 5);

    // Teil 3: das Wing-Mesh mit scope-relativer Deckung.
    let deklariert = [ArmType::Mirror, ArmType::Probe];
    let mesh = WingMesh::over(
        &deklariert,
        vec![
            arm.clone(),
            accept_arm(
                ArmType::Probe,
                Contraction::DimensionNotIncreased {
                    before: 4,
                    after: 4,
                },
            )
            .expect("Erzeuger vorhanden"),
        ],
    );
    assert!(mesh.coverage_is_complete());
    assert_eq!(
        mesh.out_of_scope().len(),
        8,
        "acht Typen ausserhalb, benannt"
    );

    // Teil 4: der Zykluswitness - mit seam_witness_ref als Pflichtfeld
    // (QPM Struktur 12.4 (Zykluswitness)).
    let r = Involution::check(|x: &i64| -x, &[1i64, 0]).expect("R^2 = I");
    let seam = witness_seam(&r, &|x: &i64| 10 - x, &1i64, &N0);
    let punkt = Digest::sha256(b"orbit");
    let zyklus = witness_cycle(&arm, punkt, punkt, &seam, None).expect("bezeugbar");
    assert!(zyklus.is_cycle());
    assert_eq!(zyklus.arm, ArmType::Mirror);
    assert_eq!(
        zyklus.seam_witness_ref,
        psk_nraii::seam_witness_id(&seam).expect("ableitbar")
    );

    println!("NRAII-3: Arme, zehn Armtypen (9 mit Erzeuger), Wing-Mesh, Zykluswitness");
}

/// L4 ist gebaut, aber NRAII-4 ist damit nicht erreicht: die Stufe
/// verlangt "Deklarativer und rekonstruktiver Wish strikt getrennt" -
/// das ist L5. Gemessen wird deshalb, was L4 HERVORBRINGT, ohne eine
/// Stufe zu beanspruchen.
///
/// Genau der Fall, den die Trennung von Schichten und Stufen vorsieht:
/// eine Schicht, die auf keine Stufe einzahlt, ist kein Fehlschlag.
#[test]
fn l4_is_built_without_claiming_a_stage() {
    // Die Attraktorkarte nennt alle fuenf Herkuenfte.
    let karte = AttractorMap::triangulate(vec![Response {
        marker: "m1".into(),
        value: "v".into(),
        origin: ResponseOrigin::Extrapolated,
    }]);
    assert_eq!(karte.by_origin().len(), 5);
    assert_eq!(karte.non_data_share(), 1);

    // Die Gegenhorizontpflicht ist pruefbar, ohne eine zweite Skala.
    let unbegruendet = HorizonPair {
        forward: vec!["bahn".into()],
        counter: vec![],
        emptiness_justification: None,
    };
    assert!(!claim_is_complete(&unbegruendet));
    assert!(missing_counter_horizon_reason(&unbegruendet).is_some());

    // Der Harness fuehrt zehn Pruefungen, der Proof-Horizon trennt
    // stabil von geschlossen.
    assert_eq!(FalsificationCheck::all().len(), 10);
    let offen = ProofHorizon {
        version: "1.0.0".into(),
        obligations: vec!["offen".into()],
    };
    assert!(!offen.is_closed());

    println!("L4 gebaut: Attraktorkarte, Gegenhorizontpflicht, Harness, Proof-Horizon");
    println!("NRAII-4 bleibt offen - die Stufe verlangt L5 (Wunschkalkuel)");
}

/// NRAII-4, gemessen: "Deklarativer und rekonstruktiver Wish strikt
/// getrennt".
///
/// Die Stufe nennt EINE Bedingung, und sie ist eine Trennung. Gemessen
/// wird deshalb beides: dass die deklarative Seite steht, dass die
/// rekonstruktive steht - und dass die eine der anderen nichts
/// zugesteht.
#[test]
fn nraii_four_the_two_wish_sides_are_strictly_separate() {
    // Deklarative Seite: ein Wish mit geprueften Gewichten und eine
    // Distanz, die ordnet.
    let wish = Wish::declare(vec![
        Facet {
            id: "a".into(),
            weight: 2,
            evidence: "a-evidenz".into(),
            gate: "N-WISH".into(),
        },
        Facet {
            id: "b".into(),
            weight: 1,
            evidence: "b-evidenz".into(),
            gate: "N-WISH".into(),
        },
    ])
    .expect("deklarierbar");
    let nah = WishDistance::measure(
        &wish,
        &[
            (
                "a".into(),
                psk_types::objects::Scaled {
                    schema: "psk.scaled/1.0".into(),
                    numerator: 100,
                    scale: 2,
                },
            ),
            (
                "b".into(),
                psk_types::objects::Scaled {
                    schema: "psk.scaled/1.0".into(),
                    numerator: 100,
                    scale: 2,
                },
            ),
        ],
    )
    .expect("messbar");
    assert_eq!(nah.as_fraction().0, 0, "die Distanz ist exakt null");

    // Rekonstruktive Seite: eine Klasse, die sich einschraenkt, ohne
    // Eindeutigkeit zu erzwingen.
    let mehrdeutig = narrow_class(vec!["h1".into(), "h2".into()], true, true);
    assert!(matches!(mehrdeutig, WishOutcome::FinitelyAmbiguous { .. }));

    // Die Trennung: die Distanz - auch die kleinstmoegliche - erzeugt
    // keine Berechtigung. Der Kreis schliesst erst bei der
    // Reobservation, und `Materialization::is_closed` verneint es.
    let materialisiert = Materialization::after_full_pass();
    assert!(!materialisiert.is_closed());
    let geschlossen =
        reobserve(materialisiert, "erneut gemessen").expect("Reobservation liegt vor");
    assert!(geschlossen.was_reobserved());

    println!("NRAII-4: deklarativer Wish, rekonstruktive Klasse, Distanz ohne Berechtigung");
}

/// Die Gegenprobe zur Stufenmessung: was NICHT erreicht ist, ist auch
/// nicht erreichbar behauptet.
///
/// NRAII-5 verlangt "Quotientenstabiler Forward/Inverse-Channel mit
/// Reobservation" und NRAII-6 die peristaltische Assimilation - L6.
/// Nichts davon existiert, und dieser Test haelt fest, dass das Paket
/// auch nichts davon exportiert.
///
/// Er hat seine Aufgabe schon zweimal erfuellt: in seinen vorigen
/// Fassungen standen NRAII-2 und NRAII-3 hier, und der Bau der
/// jeweiligen Schicht hat ihn planmaessig zu Fall gebracht.
#[test]
fn nraii_six_is_not_claimed() {
    // Die Namen, die L6 einfuehren wuerde. Zeichenketten statt echter
    // Bezuege: ein echter waere ein Kompilierfehler, und der Test soll
    // MESSEN, nicht selbst nicht bauen.
    let l6_namen = ["RawMass", "Sediment", "MonodromyRatchet", "PhaseLift"];
    let quelle = concat!(
        include_str!("../src/lib.rs"),
        include_str!("../src/null_anchor.rs"),
        include_str!("../src/canonical_state.rs"),
        include_str!("../src/signature.rs"),
        include_str!("../src/domain_contract.rs"),
        include_str!("../src/boundary.rs"),
        include_str!("../src/closure_mode.rs"),
        include_str!("../src/arms.rs"),
        include_str!("../src/diagnostic_field.rs"),
        include_str!("../src/wish.rs"),
    );
    for name in l6_namen {
        assert!(
            !quelle.contains(&format!("pub struct {name}")),
            "{name} ist gebaut - die Stufenmessung ist fortzuschreiben"
        );
    }
    println!("NRAII-5 bis NRAII-9: nicht erreicht, nicht behauptet");
}
