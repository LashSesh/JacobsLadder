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
//! - NRAII-5: "Quotientenstabiler Forward/Inverse-Channel mit Reobservation"
//! - NRAII-6: "Peristaltische Assimilation, Support-Akkretion,
//!   Boundary-Renewal, Monodromie-Ratchet und 4pi-Lift"
//! - NRAII-7: "Attraktorstack, FoldBundle, Proof-Horizon und
//!   Falsifikationsharness"
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
    ProofHorizon, ProofObligation, ReciprocityWitness, ResidualPart, Response, ResponseOrigin,
    Signed, WingMesh, Wish, WishDistance, WishOutcome, N0,
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

/// Ein gebundener Vertrag, dessen GateSet genau die genannten
/// Bezeichner fuehrt - die Quelle des Zyklusgates nach
/// QPM Regel 14.5 (Woher das Gate des Zyklus kommt).
fn vertrag_mit_gates(gates: &[&str]) -> DomainContract {
    let entries: Vec<(ContractComponent, Vec<String>)> = vertrag()
        .into_iter()
        .map(|(c, v)| {
            if c == ContractComponent::Gates {
                (c, gates.iter().map(|g| g.to_string()).collect())
            } else {
                (c, v)
            }
        })
        .collect();
    DomainContract::bind(&entries, ClaimStatus::N, "jacobs-ladder-reference")
        .expect("zehn Komponenten belegt")
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

    // Das VOKABULAR des Harness steht - zehn Pruefungen - und der
    // Proof-Horizon trennt stabil von geschlossen.
    assert_eq!(FalsificationCheck::all().len(), 10);
    let offen = ProofHorizon {
        version: "1.0.0".into(),
        obligations: vec![ProofObligation::open("offen")],
    };
    assert!(!offen.is_closed());

    println!("L4 gebaut: Attraktorkarte, Gegenhorizontpflicht, Pruefungsvokabular, Proof-Horizon");
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

/// NRAII-5, gemessen: "Quotientenstabiler Forward/Inverse-Channel mit
/// Reobservation".
///
/// Drei Bestandteile, einzeln geprueft. Der Channel selbst hat im
/// NRAII-Teil keinen eigenen Block - siehe den Befund im Modulkopf von
/// `wish`; gemessen wird deshalb, was die benachbarten Bloecke tragen.
#[test]
fn nraii_five_all_three_parts() {
    // Teil 1: Forward und Inverse - beide Richtungen stehen.
    let wish = Wish::declare(vec![Facet {
        id: "f".into(),
        weight: 1,
        evidence: "e".into(),
        gate: "N-WISH".into(),
    }])
    .expect("deklarierbar");
    assert_eq!(wish.facets().len(), 1, "Forward: der deklarative Wish");
    let inverse = narrow_class(vec!["h1".into()], true, true);
    assert!(
        matches!(inverse, WishOutcome::Unique { .. }),
        "Inverse: die rekonstruktive Klasse"
    );

    // Teil 2: quotientenstabil - der Channel wird GEHOBEN, und ein
    // klassenzerreissender wird zurueckgewiesen.
    let stabil = |h: &Referenzzustand| Referenzzustand {
        inhalt: "durchgelaufen",
        ..h.clone()
    };
    let zeugen = [(
        Referenzzustand {
            art: "A",
            inhalt: "eins",
        },
        Referenzzustand {
            art: "A",
            inhalt: "zwei",
        },
    )];
    let gehoben = psk_nraii::lift_channel(stabil, &zeugen).expect("quotientenstabil");
    assert_eq!(gehoben.checked_pairs(), 1);
    let instabil = |h: &Referenzzustand| Referenzzustand {
        art: if h.inhalt == "eins" { "A" } else { "B" },
        ..h.clone()
    };
    assert!(psk_nraii::lift_channel(instabil, &zeugen).is_err());

    // Teil 3: mit Reobservation - der Kreis schliesst dort und nirgends
    // sonst.
    let m = Materialization::after_full_pass();
    assert!(!m.is_closed());
    assert!(reobserve(m, "erneut gemessen")
        .expect("Reobservation")
        .was_reobserved());

    // Und der Abhaengigkeitsquotient als BEFUND, nicht als Einordnung.
    let paare = psk_nraii::dependent_pairs(&[
        psk_nraii::WishPerspective {
            hypothesis: "h1".into(),
            source: "q1".into(),
            calibration: "k1".into(),
            heuristic: "x".into(),
            preprocessing: "y".into(),
        },
        psk_nraii::WishPerspective {
            hypothesis: "h2".into(),
            source: "q1".into(),
            calibration: "k2".into(),
            heuristic: "z".into(),
            preprocessing: "w".into(),
        },
    ]);
    assert_eq!(paare.len(), 1);
    assert!(paare[0].2.contains(&psk_nraii::SharedDependency::Source));

    println!("NRAII-5: Forward/Inverse, quotientenstabil gehoben, Reobservation");
}

/// NRAII-6, gemessen: "Peristaltische Assimilation, Support-Akkretion,
/// Boundary-Renewal, Monodromie-Ratchet und 4pi-Lift".
#[test]
fn nraii_six_all_parts() {
    use psk_nraii::{
        assimilate, closure_degree, excalibrate, pass_gate, renew, sediment, ClosureDegree,
        CycleGate, MonodromyRatchet, RawMass,
    };

    // Peristaltische Assimilation mit Akkretion: die Kette laeuft
    // vollstaendig, und die abgetrennte Masse ist ein Residuum.
    let x = excalibrate(
        vec![
            RawMass {
                id: "a".into(),
                content: "eins".into(),
            },
            RawMass {
                id: "fremd".into(),
                content: "zwei".into(),
            },
        ],
        &["fremd".into()],
    );
    assert_eq!(x.separated().len(), 1, "kein Verlust, ein Residuum");

    // Der Gatebezeichner kommt aus dem GateSet des Vertrags
    // (QPM Regel 14.5 (Woher das Gate des Zyklus kommt)), nicht aus
    // diesem Test.
    let vertrag = vertrag_mit_gates(&["N-AUFNAHME"]);
    let gate = CycleGate::from_gate_set(&vertrag, "N-AUFNAHME").expect("im GateSet deklariert");
    let sigma = renew(assimilate(sediment(
        pass_gate(x, &gate, true).expect("Gate"),
    )))
    .expect("Boundary-Renewal");

    // Boundary-Renewal: die neue Traglast liegt innen, und die Kette
    // ist vollstaendig - fuenf Schritte, keiner uebersprungen.
    assert_eq!(sigma.encloses(), 1);
    assert_eq!(sigma.provenance().len(), 5);

    // Monodromie-Ratchet: der Liftindex steigt.
    let klasse = Digest::sha256(b"chi");
    let r = MonodromyRatchet::start(klasse)
        .complete_cycle(klasse, true)
        .expect("Umlauf")
        .complete_cycle(klasse, true)
        .expect("Umlauf");
    assert_eq!(r.lift_index(), 2);

    // 4pi-Lift: zwei Umlaeufe schliessen die Orientierung, einer nicht.
    assert_eq!(closure_degree(4), Some(ClosureDegree::FourPi));
    assert_eq!(closure_degree(2), Some(ClosureDegree::TwoPi));

    println!("NRAII-6: Assimilation, Akkretion, Renewal, Ratchet, 4pi-Lift");
}

/// NRAII-7, vierteilig gemessen: "Attraktorstack, FoldBundle,
/// Proof-Horizon und Falsifikationsharness".
///
/// Zwei der vier Namen trug L4 schon. Die Vormessung hat gefragt, ob
/// sie dieselbe Sache sind oder nur gleich heissen - dieselbe Frage wie
/// bei der Wish-Fuenfermenge, und mit zwei verschiedenen Antworten:
///
/// - **Proof-Horizon: dieselbe Sache, aber zu klein.** L4 setzte
///   QPM Definition 13.5 (Proof-Horizon) woertlich um; der Gebrauch in
///   QPM Definition 16.3 (4-4-4-Closure) verlangt einen zweiten Weg
///   ("explizit als nichtclosurewirksam klassifiziert"), den L4 nicht
///   ausdruecken konnte. Nachgetragen, nicht neu gebaut.
/// - **Falsifikationsharness: nur der Name.** L4 baute das Vokabular
///   der zehn Pruefungen; der Harness PRUEFT
///   (QPM Struktur 13.4 (Nullmodelle und Falsifikationsharness)).
///
/// Gemessen wird deshalb jedes der vier Stuecke an dem, was es TUT.
#[test]
fn nraii_seven_all_four_parts() {
    use psk_nraii::{
        reach_fixpoint, run_harness, AttractorStack, CanonicalState, CheckOutcome, FoldBundle,
        ObligationStanding, Probe, ProofObligation, Reproducer, StackLevel,
    };

    fn zustand(inhalt: &str) -> CanonicalState {
        CanonicalState::canonicalize(inhalt.as_bytes(), psk_canon::Media::Json)
            .expect("kanonisierbar")
    }
    fn stufe(id: &str, origins: &[ResponseOrigin]) -> StackLevel {
        StackLevel {
            id: id.to_string(),
            map: AttractorMap::triangulate(
                origins
                    .iter()
                    .enumerate()
                    .map(|(i, o)| Response {
                        marker: format!("m{i}"),
                        value: "v".into(),
                        origin: *o,
                    })
                    .collect(),
            ),
        }
    }

    // Teil 1: Attraktorstack - Ebenen mit zertifizierten Uebergaengen.
    // Ein Uebergang, der eine Herkunftsklasse unverbucht verliert,
    // ergibt keinen Stack.
    let unten = stufe("unten", &[ResponseOrigin::Data, ResponseOrigin::NullModel]);
    let oben = stufe("oben", &[ResponseOrigin::Data]);
    assert!(
        AttractorStack::embed(vec![unten.clone(), oben.clone()], &[]).is_err(),
        "das Nullmodell verschwaende unverbucht"
    );
    let stack = AttractorStack::embed(
        vec![unten, oben],
        &[(
            ResponseOrigin::NullModel,
            "in die Kondensation eingegangen, Residuum R-1".into(),
        )],
    )
    .expect("verbucht");
    assert_eq!(stack.certificates().len(), 1);
    assert_eq!(stack.top().id, "oben");

    // Teil 2: FoldBundle - drei Wege, ein Ergebnis
    // (QPM Regel 17.4 (Irreduzibler Kern)).
    let gleich = || zustand(r#"{"kern":"K"}"#);
    let fix = reach_fixpoint(&stack, &FoldBundle::bundle(gleich(), gleich(), gleich()))
        .expect("drei Wege, ein Ergebnis");
    assert_eq!(fix.condensed_from(), "oben");
    let uneinig = FoldBundle::bundle(gleich(), zustand(r#"{"kern":"X"}"#), gleich());
    assert!(
        reach_fixpoint(&stack, &uneinig).is_err(),
        "ein abweichender Weg laesst den Fixpunkt fallen"
    );

    // Teil 3: Proof-Horizon - und zwar mit der Unterscheidung, die
    // QPM Definition 16.3 (4-4-4-Closure) braucht.
    let horizont = ProofHorizon {
        version: "1.0.0".into(),
        obligations: vec![ProofObligation {
            text: "Nullmodellfamilie ist domaenengeliefert (NRAII-OBL-002)".into(),
            standing: ObligationStanding::NotClosureEffective {
                justification: "das Werk liefert sie nicht universell".into(),
            },
        }],
    };
    assert!(
        horizont.closure_admissible(),
        "klassifiziert blockiert nicht"
    );
    assert!(!horizont.is_closed(), "und bleibt trotzdem offen");

    // Teil 4: Falsifikationsharness - er PRUEFT, und eine ungelaufene
    // Pruefung ist kein Freispruch.
    struct Sonde(FalsificationCheck, bool);
    impl Probe for Sonde {
        fn check(&self) -> FalsificationCheck {
            self.0
        }
        fn run(&self, _s: &CanonicalState) -> CheckOutcome {
            if self.1 {
                CheckOutcome::Held {
                    evidence: "geprueft".into(),
                }
            } else {
                CheckOutcome::Falsified {
                    evidence: "schlug an".into(),
                }
            }
        }
    }
    let subjekt = zustand(r#"{"k":1}"#);
    let alle: Vec<Sonde> = FalsificationCheck::all()
        .into_iter()
        .map(|c| Sonde(c, true))
        .collect();
    let refs: Vec<&dyn Probe> = alle.iter().map(|s| s as &dyn Probe).collect();
    assert!(run_harness(&subjekt, &refs).is_clean(), "zehn liefen");
    assert!(
        !run_harness(&subjekt, &refs[..9]).is_clean(),
        "neun gelaufene Pruefungen ergeben keinen sauberen Bericht"
    );
    assert_eq!(run_harness(&subjekt, &[]).unprobed().len(), 10);

    assert_eq!(Reproducer::all().len(), 3);
    println!("NRAII-7: Attraktorstack, FoldBundle, Proof-Horizon, Falsifikationsharness");
}

/// Die Gegenprobe zur Stufenmessung: was NICHT erreicht ist, ist auch
/// nicht erreichbar behauptet.
///
/// Die NAECHSTE OFFENE Stufe ist NRAII-8: "4-4-4-, Gate-, Replay-,
/// PathInv- und Irreduzibilitaetszertifizierter Kern" - L8. Der
/// Vorausblick steht bewusst dort und nicht auf der naechsten Nummer in
/// der Liste: stuende er auf einer bereits erreichten, deckte er eine
/// Luecke, statt sie zu melden.
///
/// Er hat seine Aufgabe schon dreimal erfuellt: in seinen vorigen
/// Fassungen standen NRAII-2, NRAII-3 und NRAII-7 hier, und der Bau der
/// jeweiligen Schicht hat ihn planmaessig zu Fall gebracht.
#[test]
fn nraii_eight_is_not_claimed() {
    // Die Namen, die L8 einfuehren wuerde. Zeichenketten statt echter
    // Bezuege: ein echter waere ein Kompilierfehler, und der Test soll
    // MESSEN, nicht selbst nicht bauen.
    //
    // `IrreducibleCore` ist bewusst dabei, obwohl L7 den Fixpunkt schon
    // baut: [`psk_nraii::StackFixpoint`] heisst mit Absicht anders,
    // weil der gate- und replayzertifizierte Kern K* zu NRAII-8 gehoert
    // (QPM Regel 16.4 (Kein lokaler Sieg als Globalbeweis)).
    let l8_namen = [
        "C444",
        "IrreducibleCore",
        "ProjectionTwin",
        "AbstractLock",
        "PathInv",
    ];
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
        include_str!("../src/peristalsis.rs"),
        include_str!("../src/stack_closure.rs"),
    );
    for name in l8_namen {
        assert!(
            !quelle.contains(&format!("pub struct {name}")),
            "{name} ist gebaut - die Stufenmessung ist fortzuschreiben"
        );
    }
    println!("NRAII-8 und NRAII-9: nicht erreicht, nicht behauptet");
}
