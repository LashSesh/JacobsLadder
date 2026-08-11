//! L1, dritter Teil: der Domain-Vertrag und die Statusdisziplin - die
//! beiden Stuecke, die die Schichtentabelle L1 zuschreibt
//! ("Typen, Identitaet, Signatur, Quotient, Domain-Vertrag") und die
//! zusammen mit ihnen die Stufe NRAII-0 tragen.
//!
//! QPM Struktur 10.1 (Domain-Vertrag):
//! `D = (Obj, Obs, Pred, Fam, Op, Eq, Null, Gates, Proof, Export)`.
//! Zehn Komponenten, keine davon optional - "Universalitaet wird
//! konstruiert, nicht vorausgesetzt".
//!
//! ## Warum jede Komponente belegt sein MUSS
//!
//! Ein Vertrag mit leerer Komponente ist kein halber Vertrag, sondern
//! eine unbelegte Zusage: er behauptete eine Domaene, ueber die er
//! nichts sagt. Deshalb ist [`DomainContract::bind`] der einzige Weg,
//! und er weist jede leere Komponente zurueck, mit ihrem Namen.
//!
//! Das ist NICHT dasselbe wie ein erklaerter Nullstand nach
//! Regel 7.51 (Erklärter Nullstand): dort ist die Leere die Aussage und
//! traegt Bedingung, Nachweis und Sichtbarkeit. Hier gibt es nichts zu
//! erklaeren - eine Domaene ohne Observablen ist keine Domaene, und der
//! Vertrag ist der Ort, an dem das auffallen muss.
//!
//! ## Statusdisziplin
//!
//! QPM Regel 10.4 (Statusdisziplin D1–D4, N): "Diese Fuenferskala steht
//! neben, nicht anstelle von PSK-RAs Statusklassen und gilt nur
//! innerhalb von NRAII-RA." Beides ist hier woertlich genommen: die
//! Skala ist ein eigenes, geschlossenes Vokabular
//! ([`ClaimStatus`]), und sie hat keine Abbildung auf PSK-RAs
//! Statusklassen - eine solche waere das "anstelle", das die Regel
//! ausschliesst.

use std::collections::BTreeMap;

/// Die Fuenferskala aus QPM Regel 10.4 (Statusdisziplin D1–D4, N),
/// geschlossen und woertlich.
///
/// Absichtlich OHNE Umrechnung auf PSK-RAs Statusklassen: "steht neben,
/// nicht anstelle". Wer beide Skalen an einem Objekt braucht, fuehrt
/// beide - er rechnet nicht die eine in die andere um.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ClaimStatus {
    /// "definitorisch wahr innerhalb dieser Spezifikation"
    D1,
    /// "aus expliziten Axiomen bzw. Standardmathematik ableitbar"
    D2,
    /// "Forschungsprogramm oder offene Beweisverpflichtung"
    D3,
    /// "heuristische Motivation oder Bildschicht"
    D4,
    /// "normative Forderung an jede konforme Instanz"
    N,
}

impl ClaimStatus {
    /// Alle fuenf - die Menge ist geschlossen, und diese Funktion ist
    /// der Ort, an dem das nachpruefbar ist.
    pub fn all() -> [ClaimStatus; 5] {
        [
            ClaimStatus::D1,
            ClaimStatus::D2,
            ClaimStatus::D3,
            ClaimStatus::D4,
            ClaimStatus::N,
        ]
    }

    /// Die Bezeichnung, wie das Werk sie schreibt.
    pub fn label(&self) -> &'static str {
        match self {
            ClaimStatus::D1 => "D1",
            ClaimStatus::D2 => "D2",
            ClaimStatus::D3 => "D3",
            ClaimStatus::D4 => "D4",
            ClaimStatus::N => "N",
        }
    }
}

/// Die zehn Komponenten aus QPM Struktur 10.1 (Domain-Vertrag), als
/// geschlossenes Vokabular statt als Feldnamen.
///
/// Geschlossen, weil die Vollstaendigkeitspruefung sonst nicht
/// vollstaendig sein KANN: sie laeuft ueber [`ContractComponent::all`],
/// und eine elfte Komponente muesste dort erscheinen, um zu zaehlen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ContractComponent {
    /// Obj - die Objekte der Domaene.
    Obj,
    /// Obs - die Observablen.
    Obs,
    /// Pred - die Praedikate.
    Pred,
    /// Fam - die Familien.
    Fam,
    /// Op - die Operatoren.
    Op,
    /// Eq - die Gleichheit.
    Eq,
    /// Null - die Nullmodelle.
    Null,
    /// Gates - die Gates.
    Gates,
    /// Proof - die Beweispflichten.
    Proof,
    /// Export - was hinausgeht.
    Export,
}

impl ContractComponent {
    pub fn all() -> [ContractComponent; 10] {
        use ContractComponent::*;
        [Obj, Obs, Pred, Fam, Op, Eq, Null, Gates, Proof, Export]
    }

    pub fn label(&self) -> &'static str {
        use ContractComponent::*;
        match self {
            Obj => "Obj",
            Obs => "Obs",
            Pred => "Pred",
            Fam => "Fam",
            Op => "Op",
            Eq => "Eq",
            Null => "Null",
            Gates => "Gates",
            Proof => "Proof",
            Export => "Export",
        }
    }
}

/// Warum ein vorgelegter Vertrag nicht bindet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractBreach {
    /// Eine Komponente fehlt ganz oder ist leer. Beide Faelle sind
    /// derselbe: eine Domaene, ueber die der Vertrag nichts sagt.
    UnboundComponent { component: &'static str },
}

/// Ein gebundener Domain-Vertrag D.
///
/// Es gibt keinen anderen Weg hierher als [`DomainContract::bind`] -
/// dasselbe Muster wie `GateAuthorization` und
/// [`crate::QuotientOperator`]. Das Gate N-DOMAIN
/// (`domain_contract_bound`) sitzt genau an diesem Konstruktor: wer
/// einen `DomainContract` in der Hand haelt, haelt einen mit zehn
/// belegten Komponenten.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainContract {
    components: BTreeMap<&'static str, Vec<String>>,
    /// Die Statusdisziplin, unter der die Aussagen dieses Vertrags
    /// stehen. Ohne sie waere NRAII-0 halb: die Stufe verlangt
    /// "Zielidentitaet, Domain-Vertrag UND Statusdisziplin definiert".
    status: ClaimStatus,
    /// Die Zielidentitaet, auf die der Vertrag lautet - das dritte
    /// Stueck von NRAII-0.
    target_identity: String,
}

impl DomainContract {
    /// Bindet einen Domain-Vertrag - wenn alle zehn Komponenten belegt
    /// sind und die Zielidentitaet benannt ist.
    ///
    /// Meldet die ERSTE unbelegte Komponente mit ihrem Namen: ein
    /// "irgendwas fehlt" waere so wenig wert wie ein Gate ohne Grund.
    pub fn bind(
        entries: &[(ContractComponent, Vec<String>)],
        status: ClaimStatus,
        target_identity: &str,
    ) -> Result<Self, ContractBreach> {
        if target_identity.trim().is_empty() {
            return Err(ContractBreach::UnboundComponent {
                component: "target_identity",
            });
        }
        let mut components: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
        for (component, values) in entries {
            let filled: Vec<String> = values
                .iter()
                .filter(|v| !v.trim().is_empty())
                .cloned()
                .collect();
            if !filled.is_empty() {
                components.insert(component.label(), filled);
            }
        }
        for component in ContractComponent::all() {
            if !components.contains_key(component.label()) {
                return Err(ContractBreach::UnboundComponent {
                    component: component.label(),
                });
            }
        }
        Ok(DomainContract {
            components,
            status,
            target_identity: target_identity.to_string(),
        })
    }

    pub fn component(&self, component: ContractComponent) -> &[String] {
        self.components
            .get(component.label())
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    pub fn status(&self) -> ClaimStatus {
        self.status
    }

    pub fn target_identity(&self) -> &str {
        &self.target_identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vollstaendig() -> Vec<(ContractComponent, Vec<String>)> {
        ContractComponent::all()
            .into_iter()
            .map(|c| (c, vec![format!("{}-eintrag", c.label())]))
            .collect()
    }

    /// QPM Struktur 10.1 (Domain-Vertrag): zehn Komponenten, und der
    /// gebundene Vertrag traegt jede.
    #[test]
    fn a_contract_binds_when_all_ten_components_are_filled() {
        let d = DomainContract::bind(&vollstaendig(), ClaimStatus::N, "jacobs-ladder-reference")
            .expect("vollstaendig");
        assert_eq!(ContractComponent::all().len(), 10);
        for component in ContractComponent::all() {
            assert!(
                !d.component(component).is_empty(),
                "{} unbelegt",
                component.label()
            );
        }
        assert_eq!(d.status(), ClaimStatus::N);
        assert_eq!(d.target_identity(), "jacobs-ladder-reference");
    }

    /// Die Gegenprobe, und zwar KOMPONENTENWEISE: fuer jede der zehn
    /// einzeln geprueft, dass ihr Fehlen den Vertrag reisst - und dass
    /// der Befund SIE benennt.
    ///
    /// Ein einziger Test mit einer fehlenden Komponente sagte nur, dass
    /// irgendeine Pruefung greift; er liesse offen, ob die anderen neun
    /// ueberhaupt geprueft werden. Dieselbe Ueberlegung wie bei der
    /// feldweisen Nachweispflicht am Zertifikat.
    #[test]
    fn every_one_of_the_ten_components_is_load_bearing() {
        for fehlend in ContractComponent::all() {
            let entries: Vec<(ContractComponent, Vec<String>)> = vollstaendig()
                .into_iter()
                .filter(|(c, _)| *c != fehlend)
                .collect();
            let breach =
                DomainContract::bind(&entries, ClaimStatus::N, "d").expect_err("darf nicht binden");
            assert_eq!(
                breach,
                ContractBreach::UnboundComponent {
                    component: fehlend.label()
                },
                "das Fehlen von {} muss SIE benennen",
                fehlend.label()
            );
        }
    }

    /// Eine Komponente, die nur aus Leerraum besteht, ist unbelegt -
    /// sonst waere die Vollstaendigkeit mit einem Leerzeichen je
    /// Komponente erreichbar.
    #[test]
    fn whitespace_does_not_fill_a_component() {
        let mut entries = vollstaendig();
        entries[3].1 = vec!["   ".to_string()];
        let breach =
            DomainContract::bind(&entries, ClaimStatus::D1, "d").expect_err("darf nicht binden");
        assert_eq!(
            breach,
            ContractBreach::UnboundComponent {
                component: ContractComponent::all()[3].label()
            }
        );
    }

    /// Die Zielidentitaet ist das dritte Stueck von NRAII-0 und
    /// ebenfalls tragend.
    #[test]
    fn the_target_identity_is_load_bearing_too() {
        let breach = DomainContract::bind(&vollstaendig(), ClaimStatus::N, "  ")
            .expect_err("darf nicht binden");
        assert_eq!(
            breach,
            ContractBreach::UnboundComponent {
                component: "target_identity"
            }
        );
    }

    /// QPM Regel 10.4 (Statusdisziplin D1–D4, N): die Skala ist
    /// geschlossen und fuenfstellig.
    #[test]
    fn the_status_scale_is_closed_and_has_five_values() {
        assert_eq!(ClaimStatus::all().len(), 5);
        let labels: Vec<&str> = ClaimStatus::all().iter().map(|s| s.label()).collect();
        assert_eq!(labels, vec!["D1", "D2", "D3", "D4", "N"]);
        // Und jeder Wert ist von jedem anderen verschieden - eine Skala,
        // deren Stufen zusammenfielen, unterschiede nichts.
        for (i, a) in ClaimStatus::all().iter().enumerate() {
            for (j, b) in ClaimStatus::all().iter().enumerate() {
                assert_eq!(i == j, a == b);
            }
        }
    }
}
