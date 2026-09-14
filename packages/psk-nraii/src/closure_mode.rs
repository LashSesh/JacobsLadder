//! L2, zweiter Teil: der nullverankerte Closure-Modus - das vierte
//! Stueck von NRAII-2.
//!
//! QPM Definition 15.2 (Closure-Modus): "Fuer aktive innere Anregung
//! psi_t und erneuerbare Reflexionsboundary Sigma_t: chi_t =
//! [(psi_t, Sigma_t)]_Can. chi_t ist weder mit psi_t noch mit Sigma_t
//! allein identisch."
//!
//! QPM Regel 15.1 (Status) haelt ausdruecklich fest, was der Gegenstand
//! NICHT ist: "kein physisches Elementarteilchen und keine neue
//! Teilchenart, sondern eine quasiteilchenartige, kanonisch persistente
//! Anregungsform innerhalb eines deklarierten Zustandsraums". Der
//! Anschauungsname traegt "keine eigene normative Bedeutung", und
//! QPM Vertrag 15.5 (Keine physikalische Überdehnung) macht die
//! physikalische Lesart zum blockierenden Negativtest. Deshalb steht
//! hier nichts als Physik: `chi` ist eine Kanonisierungsklasse ueber
//! einem Paar, mehr behauptet dieser Typ nicht.
//!
//! ## Die Klammer ist der ganze Punkt
//!
//! `[(psi, Sigma)]_Can` ist die Klasse des PAARES - nicht das Paar und
//! nicht eine seiner Haelften. Der Typ macht das nachpruefbar: [`chi`]
//! kanonisiert die beiden GEMEINSAM, und
//! `the_mode_is_neither_half_alone` misst, dass der Digest von keiner
//! der beiden Haelften allein getroffen wird.
//!
//! ## Reziproke Erhaltung
//!
//! QPM Invariante 15.3 (Reziproke Erhaltung): "Die Boundary erhaelt die
//! zulaessige Anregung, waehrend die Anregung die Boundary reproduziert
//! oder erneuert. Eine EINSEITIGE Erklaerung ohne Rueckkopplungsbeleg
//! ist unvollstaendig."
//!
//! Der zweite Satz ist die Bauanweisung: ein Modus, der nur eine
//! Richtung belegt, ist nicht unvollstaendig markiert, sondern gar
//! nicht ausstellbar. [`ReciprocityWitness`] verlangt beide Richtungen,
//! und [`seal_mode`] ist der einzige Weg zu einem [`ClosureMode`].

use psk_canon::Media;
use psk_types::{Digest, PskError};

use crate::canonical_state::CanonicalState;

/// Der Rueckkopplungsbeleg beider Richtungen.
///
/// Zwei getrennte Felder und kein gemeinsames Flag: waere es eines,
/// koennte eine Richtung fuer die andere einstehen - genau die
/// "einseitige Erklaerung", die
/// QPM Invariante 15.3 (Reziproke Erhaltung) unvollstaendig nennt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReciprocityWitness {
    /// Die Boundary erhaelt die zulaessige Anregung - womit belegt.
    pub boundary_preserves_excitation: String,
    /// Die Anregung reproduziert oder erneuert die Boundary - womit
    /// belegt.
    pub excitation_renews_boundary: String,
}

impl ReciprocityWitness {
    /// Ob beide Richtungen belegt sind. Leerraum belegt nichts -
    /// dieselbe Haltung wie beim Domain-Vertrag.
    pub fn is_complete(&self) -> bool {
        !self.boundary_preserves_excitation.trim().is_empty()
            && !self.excitation_renews_boundary.trim().is_empty()
    }

    /// Welche Richtung fehlt - benannt, nicht zu erraten.
    pub fn missing_direction(&self) -> Option<&'static str> {
        if self.boundary_preserves_excitation.trim().is_empty() {
            Some("boundary_preserves_excitation")
        } else if self.excitation_renews_boundary.trim().is_empty() {
            Some("excitation_renews_boundary")
        } else {
            None
        }
    }
}

/// Warum ein Closure-Modus nicht versiegelt werden kann.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModeBreach {
    /// Eine Richtung der reziproken Erhaltung ist unbelegt.
    OneSidedExplanation { missing: &'static str },
    /// Anregung oder Boundary sind nicht kanonisierbar.
    NotCanonicalizable,
}

/// chi_t = [(psi_t, Sigma_t)]_Can.
///
/// Es gibt keinen anderen Weg hierher als [`seal_mode`] - dasselbe
/// Muster wie bei den uebrigen geprueften Objekten dieses Pakets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosureMode {
    class: CanonicalState,
    reciprocity: ReciprocityWitness,
}

impl ClosureMode {
    /// Der Digest der Klasse - H(Can((psi, Sigma))), ueber die geteilte
    /// Kanonisierung.
    pub fn digest(&self) -> Digest {
        self.class.digest()
    }

    pub fn reciprocity(&self) -> &ReciprocityWitness {
        &self.reciprocity
    }
}

/// Bildet die Kanonisierungsklasse des Paares.
///
/// Getrennt von [`seal_mode`], damit `chi` auch dort gebildet werden
/// kann, wo (noch) kein Rueckkopplungsbeleg vorliegt - der Wert ist
/// dann eine Klasse, aber kein ausgestellter Closure-Modus. Genau diese
/// Trennung verlangt QPM Invariante 15.3 (Reziproke Erhaltung).
pub fn chi(excitation: &[u8], boundary: &[u8]) -> Result<CanonicalState, PskError> {
    // Beide Haelften ZUERST kanonisieren, dann das Paar aus den
    // kanonisierten WERTEN bilden.
    //
    // Die erste Fassung packte die Rohbytes als Zeichenketten ins Paar -
    // damit war chi die Klasse der SCHREIBWEISEN statt der Werte, und
    // zwei Paare, die sich nur in der Schluesselreihenfolge einer
    // Haelfte unterschieden, fielen auseinander.
    // `the_class_is_canonical_not_literal` hat es gefangen.
    //
    // Dass die Haelften danach im Paar nochmals durch `can` gehen,
    // aendert sie nicht: QPM Axiom 10.3 (Kanonisierungsidempotenz) -
    // "Can(Can(x)) = Can(x)".
    let psi = CanonicalState::canonicalize(excitation, Media::Json)?;
    let sigma = CanonicalState::canonicalize(boundary, Media::Json)?;
    let psi_value: serde_json::Value =
        serde_json::from_slice(psi.as_bytes()).map_err(|_| PskError::CanonicalizationFailed)?;
    let sigma_value: serde_json::Value =
        serde_json::from_slice(sigma.as_bytes()).map_err(|_| PskError::CanonicalizationFailed)?;
    let pair = serde_json::json!({ "psi": psi_value, "sigma": sigma_value });
    let bytes = serde_json::to_vec(&pair).map_err(|_| PskError::CanonicalizationFailed)?;
    CanonicalState::canonicalize(&bytes, Media::Json)
}

/// Stellt einen Closure-Modus aus - wenn beide Richtungen belegt sind.
pub fn seal_mode(
    excitation: &[u8],
    boundary: &[u8],
    reciprocity: ReciprocityWitness,
) -> Result<ClosureMode, ModeBreach> {
    if let Some(missing) = reciprocity.missing_direction() {
        return Err(ModeBreach::OneSidedExplanation { missing });
    }
    let class = chi(excitation, boundary).map_err(|_| ModeBreach::NotCanonicalizable)?;
    Ok(ClosureMode { class, reciprocity })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn beleg() -> ReciprocityWitness {
        ReciprocityWitness {
            boundary_preserves_excitation: "Sigma haelt psi im Fixraum der Involution".into(),
            excitation_renews_boundary: "psi erneuert Sigma ueber den Seam-Zeugen".into(),
        }
    }

    /// QPM Definition 15.2 (Closure-Modus), letzter Satz: "chi_t ist
    /// weder mit psi_t noch mit Sigma_t allein identisch."
    ///
    /// Gemessen, nicht behauptet: der Digest der Klasse trifft weder
    /// den der Anregung noch den der Boundary.
    #[test]
    fn the_mode_is_neither_half_alone() {
        let psi = br#"{"anregung":1}"#;
        let sigma = br#"{"boundary":2}"#;
        let modus = seal_mode(psi, sigma, beleg()).expect("beide Richtungen belegt");

        let nur_psi = CanonicalState::canonicalize(psi, Media::Json).expect("kanonisierbar");
        let nur_sigma = CanonicalState::canonicalize(sigma, Media::Json).expect("kanonisierbar");
        assert_ne!(modus.digest(), nur_psi.digest());
        assert_ne!(modus.digest(), nur_sigma.digest());

        // Und die Klasse haengt an BEIDEN: eine geaenderte Haelfte
        // aendert chi. Ohne diese Gegenprobe koennte chi eine Konstante
        // sein und die beiden Ungleichungen oben trotzdem bestehen.
        let anders_psi = seal_mode(br#"{"anregung":9}"#, sigma, beleg()).expect("ausstellbar");
        let anders_sigma = seal_mode(psi, br#"{"boundary":9}"#, beleg()).expect("ausstellbar");
        assert_ne!(modus.digest(), anders_psi.digest());
        assert_ne!(modus.digest(), anders_sigma.digest());
    }

    /// QPM Invariante 15.3 (Reziproke Erhaltung): eine einseitige
    /// Erklaerung ist nicht "unvollstaendig markiert", sondern nicht
    /// ausstellbar - und der Befund nennt die FEHLENDE Richtung.
    ///
    /// Beide Richtungen einzeln geprueft: ein Test mit nur einer
    /// fehlenden Seite liesse offen, ob die andere ueberhaupt geprueft
    /// wird.
    #[test]
    fn a_one_sided_explanation_cannot_be_sealed() {
        let psi = br#"{"a":1}"#;
        let sigma = br#"{"b":2}"#;

        let ohne_erhaltung = ReciprocityWitness {
            boundary_preserves_excitation: "   ".into(),
            ..beleg()
        };
        assert_eq!(
            seal_mode(psi, sigma, ohne_erhaltung).expect_err("darf nicht siegeln"),
            ModeBreach::OneSidedExplanation {
                missing: "boundary_preserves_excitation"
            }
        );

        let ohne_erneuerung = ReciprocityWitness {
            excitation_renews_boundary: String::new(),
            ..beleg()
        };
        assert_eq!(
            seal_mode(psi, sigma, ohne_erneuerung).expect_err("darf nicht siegeln"),
            ModeBreach::OneSidedExplanation {
                missing: "excitation_renews_boundary"
            }
        );

        // Gegenprobe: mit beiden Belegen geht es.
        assert!(seal_mode(psi, sigma, beleg()).is_ok());
    }

    /// Die Klasse ist eine KANONISIERUNGSklasse: zwei Paare, die sich
    /// nur in der Schreibweise unterscheiden, fallen zusammen.
    #[test]
    fn the_class_is_canonical_not_literal() {
        let a = chi(br#"{"x":1,"y":2}"#, br#"{"b":1}"#).expect("kanonisierbar");
        let b = chi(br#"{"y":2,"x":1}"#, br#"{"b":1}"#).expect("kanonisierbar");
        assert_eq!(a.digest(), b.digest());
    }
}
