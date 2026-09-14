//! L1, erster Teil: der kanonische Zustand - und die Stelle, an der
//! QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)
//! praktisch wird.
//!
//! QPM Axiom 10.3 (Kanonisierungsidempotenz): "Can(Can(x)) = Can(x),
//! identisch zu PSK-RAs eigener Kanonisierungsinvariante." Das Wort
//! "identisch" ist die Anweisung: `psk_canon::can` wird BEZOGEN, nicht
//! nachgebaut. Es gibt in diesem Paket keine zweite Kanonisierung und
//! keine zweite Digestbildung.
//!
//! ## Zwei Schranken, eine je Ebene
//!
//! [`CanonicalState`] traegt ein privates Feld; der einzige Konstruktor
//! ist [`CanonicalState::canonicalize`], und der ruft `psk_canon::can`.
//! Wer einen kanonischen NRAII-Zustand in der Hand haelt, haelt damit
//! einen, der durch die geteilte Kanonisierung gegangen ist - eine
//! Eigenschaft des Typs, keine Zusage im Kommentar. Dasselbe Muster wie
//! `GateAuthorization`, aus demselben Grund.
//!
//! Das allein reichte nicht: bis v1.0.12 trug `psk_canon::CanonicalBytes`
//! selbst ein oeffentliches Tupelfeld, sodass ein Aufrufer kanonische
//! Bytes ohne Kanonisierung bilden konnte. Der Befund entstand an dieser
//! Stelle, gehoert aber PSK-RA: nicht NRAII haette dann eine zweite
//! Kanonisierung, sondern jeder Digest darueber waere faelschbar
//! gewesen. Er ist in derselben Runde an der Quelle behoben - siehe den
//! Typkommentar von `CanonicalBytes`. Beide Ebenen sind damit
//! geschlossen, und das Feld unten haelt den psk-canon-Typ statt roher
//! Bytes, damit die untere Schranke auch hier traegt.

use psk_canon::{can, CanonicalBytes, Media};
use psk_types::{Digest, PskError};

/// Ein Zustand, der durch die geteilte Kanonisierung gegangen ist.
///
/// Das Feld ist privat: es gibt keinen Weg, einen `CanonicalState` zu
/// bilden, ohne `psk_canon::can` zu durchlaufen. Von aussen ist der
/// Konstruktor damit unerreichbar:
///
/// ```compile_fail,E0451
/// let _ = psk_nraii::CanonicalState { canonical: todo!() };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalState {
    /// Das Ergebnis von `psk_canon::can` in SEINEM Typ, nicht in einem
    /// eigenen. Seit v1.0.12 ist auch `CanonicalBytes` von aussen nicht
    /// mehr konstruierbar - was hier liegt, ist damit auf beiden Ebenen
    /// als kanonisiert ausgewiesen und nicht bloss so benannt.
    canonical: CanonicalBytes,
}

impl CanonicalState {
    /// Der einzige Weg zu einem kanonischen Zustand.
    ///
    /// QPM Struktur 10.2 (NRAII-Zustand) nennt `z` die "kanonische
    /// Serialisierung" des Zustands. Welche - sagt sie nicht, weil es
    /// nur eine gibt (QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen),
    /// letzter Absatz: "welche, sagt er nicht, weil es nur eine gibt").
    pub fn canonicalize(bytes: &[u8], media: Media) -> Result<Self, PskError> {
        Ok(CanonicalState {
            canonical: can(bytes, media)?,
        })
    }

    /// H(Can(x)) - der Digest der geteilten Kanonisierung, nicht ein
    /// eigener. Geht ueber `psk_canon::CanonicalBytes::digest`, damit
    /// auch die Digestbildung bezogen und nicht nachgebaut ist.
    pub fn digest(&self) -> Digest {
        self.canonical.digest()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.canonical.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &[u8] = br#"{"b":2,"a":1}"#;
    const B: &[u8] = br#"{"a":1,"b":2}"#;

    /// QPM Axiom 10.3 (Kanonisierungsidempotenz) auf NRAII-Seite
    /// GEMESSEN, nicht von psk-canon geerbt: ein zweiter Durchlauf
    /// aendert nichts.
    ///
    /// Der Test steht hier und nicht nur drueben, weil er eine Aussage
    /// ueber DIESEN Weg macht - `CanonicalState::canonicalize` koennte
    /// die Idempotenz verlieren, ohne dass psk-canons eigener Test es
    /// merkte.
    #[test]
    fn canonicalization_is_idempotent_through_the_nraii_path() {
        let once = CanonicalState::canonicalize(A, Media::Json).expect("kanonisierbar");
        let twice =
            CanonicalState::canonicalize(once.as_bytes(), Media::Json).expect("kanonisierbar");
        assert_eq!(once, twice);
        assert_eq!(once.digest(), twice.digest());
    }

    /// Der Nachweis, dass die Kanonisierung die GETEILTE ist: derselbe
    /// Inhalt, ueber NRAII und ueber PSK-RA gefuehrt, ergibt densel- ben
    /// Digest - Byte fuer Byte.
    ///
    /// Die Gegenprobe steckt in der zweiten Haelfte: zwei Eingaben, die
    /// sich nur in der Schluesselreihenfolge unterscheiden, fallen auf
    /// DENSELBEN Digest. Ohne sie pruefte die erste Haelfte nur, dass
    /// zwei Aufrufe derselben Funktion gleich sind.
    #[test]
    fn the_canonicalization_is_psk_ras_own_not_a_second_one() {
        let via_nraii = CanonicalState::canonicalize(A, Media::Json).expect("kanonisierbar");
        let via_psk = can(A, Media::Json).expect("kanonisierbar");
        assert_eq!(via_nraii.as_bytes(), via_psk.as_bytes());
        assert_eq!(via_nraii.digest(), via_psk.digest());

        // Und die Kanonisierung TUT etwas: verschiedene Schreibweisen
        // desselben Inhalts fallen zusammen.
        let anders = CanonicalState::canonicalize(B, Media::Json).expect("kanonisierbar");
        assert_eq!(via_nraii.digest(), anders.digest());
        assert_ne!(A, B, "die beiden Eingaben sind wirklich verschieden");
    }

    /// Was nicht kanonisierbar ist, wird kein Zustand. Der Fehler kommt
    /// aus dem geteilten Fehlervokabular - NRAII fuehrt keinen eigenen
    /// Code dafuer ein.
    #[test]
    fn what_cannot_be_canonicalized_never_becomes_a_state() {
        let kaputt = CanonicalState::canonicalize(b"{nicht json", Media::Json);
        assert!(matches!(kaputt, Err(PskError::CanonicalizationFailed)));
    }
}
