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
    decompose, diamond_equivalent, lift, residue_for_residual_part, seal_mode, witness_seam,
    ClaimStatus, ContractComponent, DiamondClass, DomainContract, Involution, ReciprocityWitness,
    ResidualPart, Signed, N0,
};
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

/// Die Gegenprobe zur Stufenmessung: was NICHT erreicht ist, ist auch
/// nicht erreichbar behauptet.
///
/// NRAII-3 verlangt "Radiale Arme, Armtypen, Wing-Mesh, Zykluswitness" -
/// L3. Nichts davon existiert, und dieser Test haelt fest, dass das
/// Paket auch nichts davon exportiert. Faellt er, weil ein Name
/// auftaucht, ist die Stufenmessung fortzuschreiben statt
/// stillschweigend zu veralten.
///
/// Er hat das schon einmal getan: in seiner vorigen Fassung stand
/// NRAII-2 hier, und der Bau von L2 hat ihn planmaessig zu Fall
/// gebracht.
#[test]
fn nraii_three_is_not_claimed() {
    // Die Namen, die L3 einfuehren wuerde. Zeichenketten statt echter
    // Bezuege: ein echter waere ein Kompilierfehler, und der Test soll
    // MESSEN, nicht selbst nicht bauen.
    let l3_namen = ["RadialArm", "ArmType", "WingMesh", "CycleWitness"];
    let quelle = concat!(
        include_str!("../src/lib.rs"),
        include_str!("../src/null_anchor.rs"),
        include_str!("../src/canonical_state.rs"),
        include_str!("../src/signature.rs"),
        include_str!("../src/domain_contract.rs"),
        include_str!("../src/boundary.rs"),
        include_str!("../src/closure_mode.rs"),
    );
    for name in l3_namen {
        assert!(
            !quelle.contains(&format!("pub struct {name}")),
            "{name} ist gebaut - die Stufenmessung ist fortzuschreiben"
        );
    }
    println!("NRAII-3 bis NRAII-9: nicht erreicht, nicht behauptet");
}
