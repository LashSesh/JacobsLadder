//! Die Stufenmessung nach L0+L1 - gemessen an dem, was das Paket
//! HERVORBRINGT, nicht an einer Liste im Bericht.
//!
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB):
//!
//! - NRAII-0: "Zielidentitaet, Domain-Vertrag und Statusdisziplin
//!   definiert"
//! - NRAII-1: "Kanonischer Zustand, Signatur, Quotient, zustandsloser
//!   Nullanker"
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
    diamond_equivalent, lift, ClaimStatus, ContractComponent, DiamondClass, DomainContract, Signed,
    N0,
};

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

/// Die Gegenprobe zur Stufenmessung: was NICHT erreicht ist, ist auch
/// nicht erreichbar behauptet.
///
/// NRAII-2 verlangt "Reflexive Boundary, Projektorzerlegung,
/// Residuenvertrag, nullverankerter Closure-Modus" - L2. Nichts davon
/// existiert, und dieser Test haelt fest, dass das Paket auch nichts
/// davon exportiert. Faellt er, weil ein Name auftaucht, ist die
/// Stufenmessung fortzuschreiben statt stillschweigend zu veralten.
#[test]
fn nraii_two_is_not_claimed() {
    // Die Namen, die L2 einfuehren wuerde. `stringify!` statt echter
    // Bezug: ein echter waere ein Kompilierfehler, und der Test soll
    // MESSEN, nicht selbst nicht bauen.
    let l2_namen = [
        "ReflexiveBoundary",
        "ProjectorDecomposition",
        "ResidueContract",
        "ClosureMode",
    ];
    let quelle = concat!(
        include_str!("../src/lib.rs"),
        include_str!("../src/null_anchor.rs"),
        include_str!("../src/canonical_state.rs"),
        include_str!("../src/signature.rs"),
        include_str!("../src/domain_contract.rs"),
    );
    for name in l2_namen {
        assert!(
            !quelle.contains(&format!("pub struct {name}")),
            "{name} ist gebaut - die Stufenmessung ist fortzuschreiben"
        );
    }
    println!("NRAII-2 bis NRAII-9: nicht erreicht, nicht behauptet");
}
