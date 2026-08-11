//! L3: die radiale Armflaeche - Arme, Armtypen, Wing-Mesh,
//! Zykluswitness.
//!
//! QPM Struktur 12.2 (Radialer Arm):
//! `w_i = (a_i, U_i, Pi_i, O_i, H_i, G_i, E_i, rho_i, tau_i)
//!  = Anchor_i o Condense_i o Harvest_i o Orbit_i o Probe_i`.
//!
//! QPM Regel 12.1 (Bildbegriff) haelt fest, dass der Codename der
//! Zwischenmembran "keine tragende Bedeutung ausserhalb dieser
//! Definition" hat und in der "Praezedenzordnung, unterste Stufe"
//! steht. Deshalb heisst der Typ hier [`WingMesh`] nach seiner
//! Funktion - `W: dQ -> {w_1, ..., w_n}` -, nicht nach dem Bild.
//!
//! ## Wo L3 auf L2 aufsetzt
//!
//! Zwei der zehn Armtypen greifen unmittelbar in die Boundary:
//! `MirrorArm` ("Reflexion, Inversion, Seamwitness vergleichen") und
//! `ExCalArm` ("inkompatible Masse an Boundary und Residuenregister
//! verweisen"). Der [`CycleWitness`] bindet die Orbitstufe an genau
//! diese Schicht - er nimmt einen [`crate::SeamWitness`] entgegen und
//! kann ohne ihn nicht entstehen.
//!
//! **Befund, gemeldet statt gefuellt.** Der Begriff "Zykluswitness"
//! erscheint im Werk AUSSCHLIESSLICH in der Stufenliste
//! (QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB), NRAII-3)
//! und im Registerlisting - es gibt keinen Definitions-, Struktur- oder
//! Vertragsblock dazu. Gebaut ist deshalb, was aus den vorhandenen
//! Bloecken folgt: die Orbitstufe aus QPM Struktur 12.2 (Radialer Arm),
//! bezeugt gegen die Seam aus QPM Struktur 10.8 (Seam). Was das Werk
//! darueber hinaus meint, ist nicht abzulesen und hier auch nicht
//! erfunden. Dieselbe Lage wie bei L6 vor v1.0.10, nur kleiner.

use std::collections::BTreeSet;

use crate::boundary::SeamWitness;

/// QPM Struktur 12.3 (Zehn kanonische Armtypen) - geschlossen und
/// woertlich.
///
/// Geschlossen, weil die Vollstaendigkeitsbuchfuehrung sonst nicht
/// vollstaendig sein KANN: sie laeuft ueber [`ArmType::all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArmType {
    /// "Marker, Responses, lokale Gegenmodelle"
    Probe,
    /// "Reflexion, Inversion, Seamwitness vergleichen"
    Mirror,
    /// "deklarierte Facetten in pruefbare Unterraeume expandieren"
    Wish,
    /// "Zielhypothesen aus beobachtbaren Spuren rekonstruieren"
    Inverse,
    /// "invariantenrelevante Struktur zurueckziehen"
    Harvest,
    /// "inkompatible Masse an Boundary und Residuenregister verweisen"
    ExCal,
    /// "offene Proof-/Validation-Horizonte reduzieren"
    Proof,
    /// "Struktur zwischen Quotientenraeumen transportieren"
    Codec,
    /// "deterministische Wiederholung und Pfadgleichheit pruefen"
    Replay,
    /// "read-only Messereignisse an PSK-QPM-RA projizieren (Teil C)".
    ///
    /// **Erklaerter Nullstand** nach Regel 7.51 (Erklärter Nullstand):
    /// dieser Armtyp ist DEKLARIERT und hat KEINEN Erzeuger.
    ///
    /// - Benannte Bedingung: er projiziert an PSK-QPM-RA und gehoert
    ///   damit zu L9 (gekoppelte Beobachtungskavitaet), nicht zu L3.
    ///   Erzeugbar wird er, wenn L9 gebaut ist - und dessen Vorbedingung
    ///   ist NRAII-7 plus QPM-8.
    /// - Nachweis, der bei Eintritt faellt:
    ///   `the_qpm_arm_is_declared_without_a_producer` misst, dass
    ///   [`ArmType::has_producer_at_l3`] fuer ihn falsch ist und fuer
    ///   die uebrigen neun wahr.
    /// - Sichtbarkeit: er steht in [`ArmType::all`] und wird von der
    ///   Deckungsrechnung mitgezaehlt - als deklarierter Kanal ohne
    ///   Arm, nicht als Abwesenheit.
    ///
    /// Die Ersatzfuellung waere gewesen, ihn wegzulassen: dann waere
    /// die Zehnerliste eine Neunerliste, und niemand saehe, dass einer
    /// fehlt.
    Qpm,
}

impl ArmType {
    pub fn all() -> [ArmType; 10] {
        use ArmType::*;
        [
            Probe, Mirror, Wish, Inverse, Harvest, ExCal, Proof, Codec, Replay, Qpm,
        ]
    }

    pub fn label(&self) -> &'static str {
        use ArmType::*;
        match self {
            Probe => "ProbeArm",
            Mirror => "MirrorArm",
            Wish => "WishArm",
            Inverse => "InverseArm",
            Harvest => "HarvestArm",
            ExCal => "ExCalArm",
            Proof => "ProofArm",
            Codec => "CodecArm",
            Replay => "ReplayArm",
            Qpm => "QPMArm",
        }
    }

    /// Ob dieser Armtyp auf L3 einen Erzeuger hat.
    ///
    /// Neun von zehn ja; `QPMArm` nein - siehe den erklaerten Nullstand
    /// an [`ArmType::Qpm`]. Die Naht bleibt dabei unberuehrt: dieser
    /// Wert sagt, wo der Arm GEBAUT wird, nicht wie die Naht aussieht.
    pub fn has_producer_at_l3(&self) -> bool {
        !matches!(self, ArmType::Qpm)
    }

    /// Der Grund, wenn keiner da ist - benannt statt zu erraten.
    pub fn missing_producer_reason(&self) -> Option<&'static str> {
        match self {
            ArmType::Qpm => Some(
                "projiziert read-only an PSK-QPM-RA und gehoert damit zu L9 \
                 (gekoppelte Beobachtungskavitaet); erzeugbar mit L9, dessen \
                 Vorbedingung NRAII-7 und QPM-8 ist",
            ),
            _ => None,
        }
    }
}

/// Die drei Ausgaenge von QPM Invariante 12.4 (Radiale Kontraktion).
///
/// "Jeder akzeptierte Arm erfuellt `dim w_i(x) <= dim x` ODER
/// `RelDim(w_i(x)) < RelDim(x)`, ODER weist EXPLIZIT NACH, weshalb
/// isolierte Freiheitsgrade fuer Identifizierbarkeit notwendig
/// bleiben."
///
/// Drei Ausgaenge, nicht zwei. Der dritte ist kein Schlupfloch, sondern
/// eine Begruendungspflicht - und deshalb traegt er als Feld eine
/// [`PrivateJustification`], die von aussen nicht bildbar ist. Der
/// einzige Weg dorthin ist
/// [`Contraction::isolated_degrees_justified`], die eine leere
/// Begruendung zurueckweist:
///
/// ```compile_fail,E0423
/// let _ = psk_nraii::PrivateJustification("erfundene Begruendung".to_string());
/// ```
///
/// Der Code E0423 ist an einem echten Pruefpaket GEMESSEN. Die erste
/// Fassung dieses Doctests versuchte
/// `IsolatedDegreesJustified { justification: String::new() }` und war
/// gruen - aber aus dem falschen Grund: das ist ein Typfehler (E0308),
/// nicht die Privatheitsschranke. Siehe den Modulkopf von
/// `null_anchor` zu dem, was ein Fehlercode in `compile_fail` leistet
/// und was nicht.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contraction {
    /// `dim w_i(x) <= dim x` - die Dimension waechst nicht.
    DimensionNotIncreased { before: usize, after: usize },
    /// `RelDim(w_i(x)) < RelDim(x)` - die relative Dimension faellt
    /// echt.
    RelativeDimensionDecreased { before: usize, after: usize },
    /// Weder das eine noch das andere, aber mit ausdruecklichem
    /// Nachweis. Das Feld ist privat: siehe den Typkommentar.
    IsolatedDegreesJustified { justification: PrivateJustification },
}

/// Eine nichtleere Begruendung.
///
/// Eigener Typ statt `String`, damit der dritte Ausgang von aussen
/// nicht als Literal bildbar ist - dasselbe Muster wie
/// `GateAuthorization`. Wer ihn erreicht, ist durch
/// [`Contraction::isolated_degrees_justified`] gegangen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateJustification(String);

impl PrivateJustification {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Warum ein Arm nicht angenommen wird.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArmBreach {
    /// Der dritte Ausgang wurde ohne Begruendung versucht. Genau das,
    /// was QPM Invariante 12.4 (Radiale Kontraktion) mit "weist explizit
    /// nach" ausschliesst.
    UnjustifiedIsolatedDegrees,
    /// Der Armtyp hat auf dieser Schicht keinen Erzeuger.
    NoProducerAtThisLayer {
        arm: &'static str,
        reason: &'static str,
    },
}

impl Contraction {
    /// Der einzige Weg zum dritten Ausgang.
    pub fn isolated_degrees_justified(justification: &str) -> Result<Self, ArmBreach> {
        if justification.trim().is_empty() {
            return Err(ArmBreach::UnjustifiedIsolatedDegrees);
        }
        Ok(Contraction::IsolatedDegreesJustified {
            justification: PrivateJustification(justification.to_string()),
        })
    }

    /// Ob dieser Ausgang eine echte Verkleinerung belegt - oder eine
    /// begruendete Ausnahme davon ist. Beides ist zulaessig; die
    /// Unterscheidung bleibt sichtbar.
    pub fn contracts(&self) -> bool {
        !matches!(self, Contraction::IsolatedDegreesJustified { .. })
    }
}

/// Ein angenommener radialer Arm.
///
/// Es gibt keinen anderen Weg hierher als [`accept_arm`]: der Armtyp
/// muss auf dieser Schicht einen Erzeuger haben, und die Kontraktion
/// muss einen der drei Ausgaenge belegen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadialArm {
    arm_type: ArmType,
    contraction: Contraction,
    /// Die fuenf Stufen aus QPM Struktur 12.2 (Radialer Arm), in ihrer
    /// Reihenfolge: Probe, Orbit, Harvest, Condense, Anchor.
    stages: [&'static str; 5],
}

impl RadialArm {
    pub fn arm_type(&self) -> ArmType {
        self.arm_type
    }

    pub fn contraction(&self) -> &Contraction {
        &self.contraction
    }

    /// Die Komposition von rechts nach links, wie die Struktur sie
    /// schreibt: `Anchor o Condense o Harvest o Orbit o Probe`. Hier in
    /// AUSFUEHRUNGSreihenfolge, also umgekehrt gelesen.
    pub fn stages(&self) -> &[&'static str; 5] {
        &self.stages
    }
}

/// Nimmt einen Arm an - wenn Typ und Kontraktion es tragen.
pub fn accept_arm(arm_type: ArmType, contraction: Contraction) -> Result<RadialArm, ArmBreach> {
    if !arm_type.has_producer_at_l3() {
        return Err(ArmBreach::NoProducerAtThisLayer {
            arm: arm_type.label(),
            reason: arm_type
                .missing_producer_reason()
                .expect("ohne Erzeuger gibt es einen Grund"),
        });
    }
    Ok(RadialArm {
        arm_type,
        contraction,
        stages: ["Probe", "Orbit", "Harvest", "Condense", "Anchor"],
    })
}

/// `W: dQ -> {w_1, ..., w_n}` - die Zwischenmembran aus
/// QPM Regel 12.1 (Bildbegriff), die eine Boundary-Struktur in
/// scanbare, gate-gebundene Projektionsarme ueberfuehrt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WingMesh {
    arms: Vec<RadialArm>,
    /// Die im Domain-Vertrag deklarierte Armfamilie - der Bezugspunkt
    /// der Deckungsrechnung.
    declared: BTreeSet<ArmType>,
}

impl WingMesh {
    /// Baut die Membran ueber einer DEKLARIERTEN Armfamilie.
    pub fn over(declared: &[ArmType], arms: Vec<RadialArm>) -> Self {
        WingMesh {
            arms,
            declared: declared.iter().copied().collect(),
        }
    }

    pub fn arms(&self) -> &[RadialArm] {
        &self.arms
    }

    /// `Coverage_D(Pi_rad) = 1` nach
    /// QPM Vertrag 12.5 (Scope-relative Vollständigkeit): "vollstaendige
    /// Buchfuehrung ueber die im Domain-Vertrag DEKLARIERTE Armfamilie -
    /// keine Behauptung ueber technisch nicht vorhandene Kanaele."
    ///
    /// Der Nenner ist deshalb die deklarierte Familie und NICHT
    /// [`ArmType::all`]. Dieselbe Entscheidung wie `scope_contract_breaks`
    /// auf der QPM-Seite - Bindung, kein zweiter Deckungsbegriff.
    pub fn coverage_is_complete(&self) -> bool {
        self.declared
            .iter()
            .all(|t| self.arms.iter().any(|a| a.arm_type == *t))
    }

    /// Welche deklarierten Armtypen keinen Arm haben - benannt, nicht
    /// als Zahl.
    pub fn uncovered(&self) -> Vec<ArmType> {
        self.declared
            .iter()
            .filter(|t| !self.arms.iter().any(|a| a.arm_type == **t))
            .copied()
            .collect()
    }

    /// Die Armtypen, die es GIBT, aber die diese Domaene nicht
    /// deklariert hat. Sie sind nicht ungedeckt - sie sind ausserhalb
    /// des Scopes, und der Unterschied ist der ganze Punkt von
    /// QPM Vertrag 12.5 (Scope-relative Vollständigkeit).
    pub fn out_of_scope(&self) -> Vec<ArmType> {
        ArmType::all()
            .into_iter()
            .filter(|t| !self.declared.contains(t))
            .collect()
    }
}

/// Der Zykluswitness: die Orbitstufe eines Arms, bezeugt gegen die
/// Boundary.
///
/// Die Stelle, an der L3 auf L2 aufsetzt. Er nimmt einen
/// [`SeamWitness`] entgegen und kann ohne ihn nicht entstehen - ein
/// geschlossener Orbit, der die Boundary nicht bezeugt, waere eine
/// Behauptung ueber einen Umlauf, den niemand gesehen hat.
///
/// Siehe den Modulkopf zum Befund, dass das Werk den Begriff nur in der
/// Stufenliste fuehrt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleWitness<X> {
    /// Welcher Arm den Orbit lief.
    pub arm: ArmType,
    /// Der Boundary-Beleg aus L2.
    pub seam: SeamWitness<X>,
    /// Ob der Orbit geschlossen ist: Ausgangspunkt und Rueckkehrpunkt
    /// fallen zusammen.
    pub closed: bool,
}

/// Bezeugt den Orbit eines Arms.
///
/// `closed` wird GEMESSEN (Start gleich Ziel), nicht uebergeben.
pub fn witness_cycle<X: PartialEq + Clone>(
    arm: &RadialArm,
    start: &X,
    end: &X,
    seam: SeamWitness<X>,
) -> CycleWitness<X> {
    CycleWitness {
        arm: arm.arm_type,
        closed: start == end,
        seam,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::boundary::{witness_seam, Involution};
    use crate::N0;

    fn spiegelung(x: &i64) -> i64 {
        -x
    }

    fn seam_beleg() -> SeamWitness<i64> {
        let r = Involution::check(spiegelung, &[1i64, 0]).expect("R^2 = I");
        witness_seam(&r, &|x: &i64| 10 - x, &1i64, &N0)
    }

    /// QPM Struktur 12.3 (Zehn kanonische Armtypen): zehn, geschlossen,
    /// in der Reihenfolge des Werks.
    #[test]
    fn there_are_exactly_ten_arm_types() {
        assert_eq!(ArmType::all().len(), 10);
        let labels: Vec<&str> = ArmType::all().iter().map(|t| t.label()).collect();
        assert_eq!(
            labels,
            vec![
                "ProbeArm",
                "MirrorArm",
                "WishArm",
                "InverseArm",
                "HarvestArm",
                "ExCalArm",
                "ProofArm",
                "CodecArm",
                "ReplayArm",
                "QPMArm"
            ]
        );
    }

    /// Der erklaerte Nullstand am QPMArm.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: genau EINER der zehn
    /// hat auf L3 keinen Erzeuger, und zwar QPMArm; die uebrigen neun
    /// haben einen. Ein Ausbleiben - etwa weil alle zehn keinen
    /// Erzeuger haetten - saehe sonst wie ein bestandener Test aus.
    #[test]
    fn the_qpm_arm_is_declared_without_a_producer() {
        let ohne: Vec<ArmType> = ArmType::all()
            .into_iter()
            .filter(|t| !t.has_producer_at_l3())
            .collect();
        assert_eq!(ohne, vec![ArmType::Qpm], "genau einer, und zwar QPMArm");
        assert_eq!(
            ArmType::all()
                .into_iter()
                .filter(|t| t.has_producer_at_l3())
                .count(),
            9,
            "die uebrigen neun HABEN einen Erzeuger"
        );

        // Der Grund steht am Typ, nicht in der Prosa.
        let grund = ArmType::Qpm
            .missing_producer_reason()
            .expect("ohne Erzeuger gibt es einen Grund");
        assert!(grund.contains("L9"));
        assert!(grund.contains("NRAII-7"));

        // Und der Versuch, ihn hier zu bauen, faellt MIT diesem Grund.
        let versuch = accept_arm(
            ArmType::Qpm,
            Contraction::DimensionNotIncreased {
                before: 3,
                after: 2,
            },
        );
        assert_eq!(
            versuch.expect_err("darf auf L3 nicht entstehen"),
            ArmBreach::NoProducerAtThisLayer {
                arm: "QPMArm",
                reason: grund
            }
        );
    }

    /// QPM Invariante 12.4 (Radiale Kontraktion), alle DREI Ausgaenge.
    ///
    /// ERWARTUNG: die ersten beiden sind ohne Weiteres bildbar, der
    /// dritte NUR mit nichtleerer Begruendung - und eine leere
    /// Begruendung erzeugt einen benannten Fehler, kein stilles
    /// Durchrutschen.
    #[test]
    fn the_third_exit_is_unreachable_without_a_justification() {
        // Ausgang 1 und 2: frei bildbar.
        let a = Contraction::DimensionNotIncreased {
            before: 5,
            after: 5,
        };
        let b = Contraction::RelativeDimensionDecreased {
            before: 5,
            after: 3,
        };
        assert!(a.contracts());
        assert!(b.contracts());

        // Ausgang 3 mit Begruendung: erreichbar, und er ist als
        // Ausnahme erkennbar.
        let c = Contraction::isolated_degrees_justified(
            "zwei isolierte Freiheitsgrade bleiben fuer die Identifizierbarkeit noetig",
        )
        .expect("mit Begruendung erreichbar");
        assert!(
            !c.contracts(),
            "der dritte Ausgang belegt KEINE Verkleinerung - das bleibt sichtbar"
        );

        // Ohne Begruendung: nicht erreichbar.
        assert_eq!(
            Contraction::isolated_degrees_justified("").expect_err("leer"),
            ArmBreach::UnjustifiedIsolatedDegrees
        );
        assert_eq!(
            Contraction::isolated_degrees_justified("   ").expect_err("nur Leerraum"),
            ArmBreach::UnjustifiedIsolatedDegrees
        );
    }

    /// QPM Vertrag 12.5 (Scope-relative Vollständigkeit): der Nenner ist
    /// die DEKLARIERTE Familie.
    ///
    /// ERWARTUNG: eine Domaene, die drei Armtypen deklariert und drei
    /// Arme fuehrt, hat Coverage 1 - obwohl sieben der zehn Typen
    /// fehlen. Die sieben sind ausserhalb des Scopes, nicht ungedeckt.
    /// Wuerde die Deckung gegen `ArmType::all` gerechnet, faende dieser
    /// Test Coverage < 1, und der Vertrag waere verletzt.
    #[test]
    fn coverage_counts_the_declared_family_not_all_ten() {
        let deklariert = [ArmType::Probe, ArmType::Mirror, ArmType::Harvest];
        let arme: Vec<RadialArm> = deklariert
            .iter()
            .map(|t| {
                accept_arm(
                    *t,
                    Contraction::DimensionNotIncreased {
                        before: 4,
                        after: 3,
                    },
                )
                .expect("Erzeuger vorhanden")
            })
            .collect();
        let mesh = WingMesh::over(&deklariert, arme);

        assert!(mesh.coverage_is_complete(), "Coverage_D = 1");
        assert!(mesh.uncovered().is_empty());
        // Und die sieben uebrigen sind BENANNT ausserhalb des Scopes -
        // nicht abwesend, nicht ungedeckt.
        assert_eq!(mesh.out_of_scope().len(), 7);
        assert!(mesh.out_of_scope().contains(&ArmType::Qpm));

        // Gegenprobe: fehlt ein DEKLARIERTER Arm, faellt die Deckung -
        // und der fehlende ist benannt.
        let luecke = WingMesh::over(&deklariert, vec![]);
        assert!(!luecke.coverage_is_complete());
        assert_eq!(luecke.uncovered().len(), 3);
    }

    /// Der Zykluswitness setzt auf L2 auf.
    ///
    /// ERWARTUNG: ein geschlossener Orbit wird als geschlossen gemessen,
    /// ein offener als offen - und der Boundary-Beleg aus L2 kommt
    /// unveraendert mit. Ohne den zweiten Fall sagte der erste nur, dass
    /// `closed` irgendeinen Wert hat.
    #[test]
    fn the_cycle_witness_rests_on_the_boundary_from_l2() {
        let arm = accept_arm(
            ArmType::Mirror,
            Contraction::RelativeDimensionDecreased {
                before: 6,
                after: 2,
            },
        )
        .expect("Erzeuger vorhanden");

        let geschlossen = witness_cycle(&arm, &7i64, &7i64, seam_beleg());
        assert!(geschlossen.closed);
        assert_eq!(geschlossen.arm, ArmType::Mirror);
        // Der L2-Beleg ist mitgekommen und sagt weiterhin, dass J nicht R ist.
        assert!(!geschlossen.seam.agree);

        let offen = witness_cycle(&arm, &7i64, &9i64, seam_beleg());
        assert!(
            !offen.closed,
            "ein offener Orbit wird nicht geschlossen genannt"
        );
    }

    /// Die fuenf Stufen aus QPM Struktur 12.2 (Radialer Arm), in der
    /// Reihenfolge der Ausfuehrung.
    #[test]
    fn an_arm_carries_its_five_stages() {
        let arm = accept_arm(
            ArmType::Probe,
            Contraction::DimensionNotIncreased {
                before: 2,
                after: 2,
            },
        )
        .expect("Erzeuger vorhanden");
        assert_eq!(
            arm.stages(),
            &["Probe", "Orbit", "Harvest", "Condense", "Anchor"]
        );
    }
}
