//! NRAII-RA, die innere aktive Maschine: Schicht L0 (Nullanker).
//!
//! ## Warum dieses Paket kein PSK-RA-Modul besitzt
//!
//! QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen):
//! "NRAII-RA bindet an keine PSK-RA-Module und fuehrt eigene Schichten,
//! Gates und Konformanzstufen. Diese Eigenstaendigkeit betrifft
//! Architektur - Module, Ports, Autoritaet - und DARF NICHT die
//! Grundlagen." Deshalb steht hier kein M00-M27-Eintrag: das Paket ist
//! kein Pipelinemitglied, und `verify-dependencies` nimmt es aus der
//! Portdeckungspruefung aus, WEIL es kein Modul besitzt - dieselbe
//! Ausnahme, die schon psk-conformance und die Werkzeuge tragen. Die
//! Regel ist damit im Werkzeug abgebildet, nicht bloss zugesagt.
//!
//! ## Warum L0 dennoch nichts von PSK-RA uebernimmt
//!
//! Dieselbe Regel verlangt in der Gegenrichtung, dass Kanonisierung,
//! Digestbildung, Identitaetsprojektion, append-only Trace und
//! Residuenbuchfuehrung UEBERNOMMEN werden: "Eine zweite Kanonisierung
//! waere eine zweite Antwort auf dieselbe Frage."
//!
//! L0 uebernimmt davon nichts - und das ist kein Verstoss, sondern ein
//! erklaerter Nullstand nach Regel 7.51 (Erklärter Nullstand):
//!
//! - Benannte Bedingung: sobald eine L0-Struktur einen Payload traegt,
//!   ist eine Kanonisierung faellig, und sie MUSS die geteilte sein.
//! - Nachweis, der bei Eintritt faellt: `the_null_anchor_carries_no_payload`
//!   misst `size_of::<NullAnchor>() == 0`. Ein Feld an `NullAnchor` laesst
//!   ihn fallen, bevor die Frage der Kanonisierung ueberhaupt entsteht.
//! - Sichtbarkeit: die leere `[dependencies]`-Tabelle in Cargo.toml mit
//!   ihrer Begruendung.
//!
//! Die Ersatzfuellung, die Regel 7.51 (Erklärter Nullstand) verbietet,
//! waere hier gewesen,
//! `psk-canon` aufzunehmen und ungenutzt stehen zu lassen, um die
//! Uebernahme zu BEHAUPTEN. Die erste echte Abhaengigkeit entsteht mit
//! L1 (kanonischer Zustandsraum), wo QPM Axiom 10.3 (Kanonisierungsidempotenz)
//! die Kanonisierung ausdruecklich als "identisch zu PSK-RAs eigener
//! Kanonisierungsinvariante" bindet.
//!
//! ## Schichten und Stufen laufen nicht parallel
//!
//! QPM Struktur 9.1 (Normative Schichten L0–L9) traegt die
//! Abhaengigkeiten (L2 setzt L1 setzt L0 voraus),
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB)
//! ist das Messwerk. Die
//! beiden Leitern decken sich NICHT: die Nullanker-Statelessness, die
//! dieses Modul herstellt, ist Mindestanforderung von NRAII-**1**
//! ("Kanonischer Zustand, Signatur, Quotient und zustandsloser
//! Nullanker"), nicht von NRAII-0. Gebaut wird schichtweise, gemessen
//! stufenweise - dieselbe Trennung wie I0-I8 gegen FC0-FC8 auf der
//! PSK-RA-Seite.

mod null_anchor;
pub use null_anchor::{
    apparent_connection, AnchoredRelation, ApparentConnection, NullAnchor, Step, Traversable, N0,
};
