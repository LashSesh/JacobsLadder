//! L2, erster Teil: die reflexive Boundary und die Seam.
//!
//! ## Die Trennung, die diese Schicht durchzieht
//!
//! Zwei Dinge kommen hier zusammen, die auseinanderzuhalten sind:
//!
//! - Die Boundary-**Regel** ist Bindung.
//!   QPM Invariante 9.7 (Boundary vor Absorption) - "Nicht integrierbare
//!   Struktur wird an die Boundary verwiesen und als Residuum, Exklusion,
//!   Deferred-Anteil oder Gegenbefund sichtbar. Sie wird DARF NICHT still
//!   in den Kern geschoben" - ist PSK-RAs Residuenprinzip. Der
//!   Residuenvertrag unten BEZIEHT `psk_types::objects::ResidueRecord`
//!   statt einen zweiten zu fuehren
//!   (QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)).
//! - Die Boundary-**Algebra** ist Neubau.
//!   QPM Struktur 10.7 (Reflexive Boundary) und
//!   QPM Struktur 10.8 (Seam) haben in PSK-RA kein Gegenstueck -
//!   nachgemessen bei der Bestandsaufnahme: keine Involution, kein
//!   Projektor.
//!
//! ## Was von der Projektorzerlegung woertlich baubar ist
//!
//! QPM Struktur 10.7 (Reflexive Boundary) schreibt fuer eine
//! selbstadjungierte Involution `R = R*, R^2 = I` auf einem
//! Innenproduktraum H:
//!
//! ```text
//! B+ = 1/2 (I + R),  B- = 1/2 (I - R)
//! B+ + B- = I,  B+ B- = 0,  (B±)^2 = B±
//! ```
//!
//! Ein Innenproduktraum liegt hier nicht vor - NRAII-2 verlangt die
//! Zerlegung, nicht eine Zahlenbibliothek. Gebaut ist deshalb die
//! Zerlegung ueber einer DISKRETEN Traegermenge, und die vier Gesetze
//! sind dort exakt und ganzzahlig nachpruefbar:
//!
//! | `B+ + B- = I`   | jedes Element liegt in genau einer der beiden Haelften |
//! | `B+ B- = 0`     | die Haelften sind disjunkt                              |
//! | `(B±)^2 = B±`   | nochmaliges Zerlegen aendert nichts                     |
//! | `R^2 = I`       | an vorgelegten Zeugen geprueft, siehe [`Involution`]    |
//!
//! Der tragende Satz der Struktur ist der letzte: "Kein Anteil darf
//! zwischen akzeptiertem Fixraum und Residualraum verschwinden." Das ist
//! eine BUCHFUEHRUNGSaussage, dieselbe Klasse wie
//! QPM Axiom 3.1 (Kein stiller Ausschluss) auf der QPM-Seite - und in
//! dieser Form ist sie hier auch gemessen.
//!
//! **Erklaerter Nullstand** nach Regel 7.52 (Erklärter Nullstand):
//! `R = R*` (Selbstadjungiertheit) ist NICHT geprueft, weil kein
//! Innenprodukt deklariert ist - ohne `<x,y>` gibt es nichts, woran
//! `<Rx,y> = <x,Ry>` zu messen waere. Benannte Bedingung: sobald der
//! Traegerraum ein Innenprodukt fuehrt. Nachweis, der bei Eintritt
//! faellt: [`Involution::self_adjointness_unchecked`] gibt den Grund
//! zurueck und ist der Ort, an dem die Pruefung einzuhaengen ist.
//! Sichtbarkeit: das Feld steht im Zeugen. Die Ersatzfuellung waere
//! gewesen, `R^2 = I` als "selbstadjungiert" auszugeben - zwei
//! verschiedene Bedingungen, von denen nur eine geprueft ist.

use std::collections::BTreeSet;

use psk_types::objects::{
    ObligationExpr, ResidueRecord, ResidueRecordSeverityKind, ResidueRecordTypeKind, ScopeExpr,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId};

use crate::null_anchor::{AnchoredRelation, NullAnchor};

/// Warum eine vorgelegte Abbildung keine Involution ist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvolutionBreach {
    /// `R(R(x)) != x` an einem Zeugen - die Abbildung ist keine
    /// Involution, und `B± = 1/2(I ± R)` waeren keine Projektoren.
    NotAnInvolution { witness_index: usize },
    /// Kein Zeuge vorgelegt. Eine Involutionspruefung ohne Zeugen
    /// prueft nichts - dieselbe Haltung wie bei
    /// [`crate::CompatibilityBreach::VacuousWitnessSet`].
    VacuousWitnessSet,
}

/// Eine Involution R mit GEPRUEFTEM `R^2 = I`.
///
/// Es gibt keinen anderen Weg zu diesem Typ als [`Involution::check`] -
/// dasselbe Muster wie `GateAuthorization`, [`crate::QuotientOperator`]
/// und [`crate::DomainContract`]. Wer eine `Involution` haelt, haelt
/// eine, deren Involutivitaet an echten Zeugen gemessen wurde.
pub struct Involution<X, F: Fn(&X) -> X> {
    map: F,
    checked_witnesses: usize,
    _marker: std::marker::PhantomData<X>,
}

impl<X, F: Fn(&X) -> X> std::fmt::Debug for Involution<X, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Involution")
            .field("checked_witnesses", &self.checked_witnesses)
            .finish_non_exhaustive()
    }
}

impl<X: PartialEq, F: Fn(&X) -> X> Involution<X, F> {
    /// Prueft `R(R(x)) = x` an jedem Zeugen. Eine leere Zeugenmenge
    /// wird zurueckgewiesen.
    pub fn check(map: F, witnesses: &[X]) -> Result<Self, InvolutionBreach> {
        if witnesses.is_empty() {
            return Err(InvolutionBreach::VacuousWitnessSet);
        }
        for (i, x) in witnesses.iter().enumerate() {
            if map(&map(x)) != *x {
                return Err(InvolutionBreach::NotAnInvolution { witness_index: i });
            }
        }
        Ok(Involution {
            map,
            checked_witnesses: witnesses.len(),
            _marker: std::marker::PhantomData,
        })
    }

    /// R(x).
    pub fn apply(&self, x: &X) -> X {
        (self.map)(x)
    }

    /// Ob R dieses Element festhaelt - das Kriterium, nach dem
    /// [`decompose`] in Fixraum und Residualraum trennt.
    pub fn fixes(&self, x: &X) -> bool {
        self.apply(x) == *x
    }

    pub fn checked_witnesses(&self) -> usize {
        self.checked_witnesses
    }

    /// Der erklaerte Nullstand: WARUM `R = R*` hier nicht geprueft ist.
    ///
    /// Gibt den Grund zurueck statt `true` zu behaupten. Sobald der
    /// Traegerraum ein Innenprodukt fuehrt, gehoert die Pruefung
    /// hierher, und diese Funktion verschwindet.
    pub fn self_adjointness_unchecked(&self) -> &'static str {
        "kein Innenprodukt deklariert: <Rx,y> = <x,Ry> ist ohne <.,.> nicht messbar; \
         geprueft ist ausschliesslich R^2 = I"
    }
}

/// Die Zerlegung eines Traegers in Fixraum und Residualraum.
///
/// `B+` (`fixed`) und `B-` (`residual`) nach
/// QPM Struktur 10.7 (Reflexive Boundary), ueber einer diskreten
/// Traegermenge. Die Buchfuehrung ist Teil des Typs: [`BoundarySplit`]
/// entsteht nur ueber [`decompose`], und die Gesetze sind dort geprueft.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundarySplit<X: Ord> {
    fixed: BTreeSet<X>,
    residual: BTreeSet<X>,
    /// Wie gross der Traeger war, ueber den zerlegt wurde. Der Wert,
    /// gegen den `B+ + B- = I` geprueft wird.
    carrier: usize,
}

impl<X: Ord + Clone> BoundarySplit<X> {
    /// B+: der akzeptierte Fixraum.
    pub fn fixed(&self) -> &BTreeSet<X> {
        &self.fixed
    }

    /// B-: der Residualraum.
    pub fn residual(&self) -> &BTreeSet<X> {
        &self.residual
    }

    /// `B+ + B- = I`, gemessen: keine Masse verschwindet zwischen den
    /// Haelften. Der Satz, den die Struktur ausdruecklich nennt.
    pub fn accounts_for_everything(&self) -> bool {
        self.fixed.len() + self.residual.len() == self.carrier
    }

    /// `B+ B- = 0`, gemessen: die Haelften sind disjunkt.
    pub fn halves_are_disjoint(&self) -> bool {
        self.fixed.intersection(&self.residual).count() == 0
    }
}

/// Zerlegt einen Traeger unter einer geprueften Involution.
///
/// Jedes Element geht in genau eine Haelfte: fixiert R es, in `B+`,
/// sonst in `B-`. Damit gilt `B+ + B- = I` konstruktiv, und
/// [`BoundarySplit::accounts_for_everything`] misst es trotzdem - eine
/// Buchfuehrung, die sich auf ihre eigene Konstruktion verliesse,
/// bemerkte einen kuenftigen Umbau nicht.
pub fn decompose<X, F>(involution: &Involution<X, F>, carrier: &[X]) -> BoundarySplit<X>
where
    X: Ord + Clone + PartialEq,
    F: Fn(&X) -> X,
{
    let mut fixed = BTreeSet::new();
    let mut residual = BTreeSet::new();
    for x in carrier {
        if involution.fixes(x) {
            fixed.insert(x.clone());
        } else {
            residual.insert(x.clone());
        }
    }
    BoundarySplit {
        fixed,
        residual,
        carrier: carrier.iter().collect::<BTreeSet<_>>().len(),
    }
}

/// Ein abgetrennter Anteil, wie L2 ihn hervorbringt: Rueckbezug und
/// Grund.
///
/// QPM Invariante 10.10 (Residualvollständigkeit) verlangt drei Stuecke:
/// "Provenienz, Grund und Rueckbezug". Zwei davon stehen hier; das
/// dritte kann NRAII nicht liefern, und das ist kein Versehen.
///
/// **Befund.** PSK-RAs `ResidueRecord` fuehrt `origin_module: ModuleId`
/// als Pflichtfeld. NRAII besitzt aber kein M00-M27-Modul - genau das
/// verlangt
/// QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen)
/// ("bindet an keine PSK-RA-Module"). Der uebernommene Typ verlangt
/// also ein Feld, das die Eigenstaendigkeitsregel NRAII verwehrt. Ein
/// hier festverdrahtetes Modul waere genau die Architekturbindung, die
/// die Regel ausschliesst - und `verify-dependencies` saehe sie nicht,
/// weil ein modulloses Paket von der Portdeckungspruefung ausgenommen
/// ist.
///
/// Aufloesung: NRAII liefert den INHALT, die Ausstellung bleibt an der
/// Grenze. [`residue_for_residual_part`] nimmt das ausstellende Modul
/// als Parameter - wer den Satz ins Ledger legt, benennt sich selbst.
/// Der Residuenvertrag ist damit erfuellt, ohne dass NRAII eine
/// Modulzugehoerigkeit erfindet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualPart {
    /// Rueckbezug: woran der abgetrennte Anteil haengt.
    pub origin_object: ObjectId,
    /// Grund: warum er nicht in die tragende Klasse eingeht.
    pub reason: String,
}

/// Bildet aus einem abgetrennten Anteil den PSK-RA-`ResidueRecord` -
/// BEZOGEN, nicht nachgebaut.
///
/// `issuing_module` ist Parameter und keine Konstante: siehe den Befund
/// an [`ResidualPart`]. Die Zuordnung der drei Pflichten aus
/// QPM Invariante 10.10 (Residualvollständigkeit), die die
/// Bestandsaufnahme als "zu treffen" gemeldet hatte:
///
/// | Provenienz | `origin_module` - vom Aufrufer benannt            |
/// | Rueckbezug | `origin_object` - aus dem Anteil                  |
/// | Grund      | `open_obligation` - aus dem Anteil, im Klartext   |
///
/// `severity` steht auf `non_blocking`: ein Residualanteil unter einer
/// Involution ist ein REGULAERES Ergebnis der Zerlegung, kein Defekt -
/// QPM Struktur 10.7 (Reflexive Boundary) nennt ihn den "Residualraum",
/// nicht einen Fehler.
pub fn residue_for_residual_part(
    part: &ResidualPart,
    issuing_module: ModuleId,
    at: DualTime,
) -> ResidueRecord {
    ResidueRecord {
        schema: "psk.residue/1.0".to_string(),
        id: ObjectId::new(
            psk_types::objects::SortId::Residue,
            Digest::sha256(part.reason.as_bytes()),
        ),
        r#type: ResidueRecordTypeKind::Seam,
        origin_module: issuing_module,
        origin_object: part.origin_object,
        scope: ScopeExpr("nraii:L2:boundary".to_string()),
        severity: ResidueRecordSeverityKind::NonBlocking,
        open_obligation: ObligationExpr(part.reason.clone()),
        allowed_followups: vec![],
        opened_at: at,
        closed_by: None,
        state: psk_types::objects::ResidueRecordStateKind::Open,
    }
}

/// Der Seam-Zeuge: der protokollierte Vergleich von R und J.
///
/// QPM Struktur 10.8 (Seam): "Die Inversion J bildet auf die deklarierte
/// Gegenseite ab und ist NICHT automatisch identisch mit R. Die Seam
/// protokolliert den Vergleich: `Qs(x) = Witness(R(x), J(x), N0)`."
///
/// Deshalb nimmt [`witness_seam`] ZWEI Abbildungen und nicht eine mit
/// einem Schalter: waeren J und R derselbe Wert, gaebe es nichts zu
/// vergleichen, und der Zeuge waere eine Tautologie. Die Uebereinstimmung
/// ist ein SONDERFALL, den der Zeuge festhaelt - kein Normalfall, den er
/// voraussetzt.
///
/// N_0 steht in der Formel und steht deshalb auch hier: der Vergleich
/// findet RELATIV zu ihm statt, als Spiegelung im Sinne von
/// QPM Vertrag 10.6 (Nichttraversal) - nicht als Pfad durch ihn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeamWitness<X> {
    /// R(x) - die Reflexion.
    pub reflected: X,
    /// J(x) - die Inversion auf die deklarierte Gegenseite.
    pub inverted: X,
    /// Ob beide an diesem Element uebereinstimmen. FALSE ist der
    /// erwartbare Fall; TRUE sagt etwas ueber DIESES Element, nicht
    /// ueber die Abbildungen.
    pub agree: bool,
    /// Die Art, in der die scheinbare Verbindung besteht - Spiegelung,
    /// relativ zu N_0.
    pub relation: AnchoredRelation,
    /// Der Bezugspunkt. Kostet nichts (siehe
    /// `the_anchor_adds_no_bytes_to_what_references_it`), sagt aber, dass
    /// der Vergleich verankert ist.
    pub anchor: NullAnchor,
}

/// `Qs(x) = Witness(R(x), J(x), N_0)`.
pub fn witness_seam<X, FR, FJ>(
    reflection: &Involution<X, FR>,
    inversion: &FJ,
    x: &X,
    anchor: &NullAnchor,
) -> SeamWitness<X>
where
    X: PartialEq + Clone,
    FR: Fn(&X) -> X,
    FJ: Fn(&X) -> X,
{
    let _ = anchor;
    let reflected = reflection.apply(x);
    let inverted = inversion(x);
    SeamWitness {
        agree: reflected == inverted,
        reflected,
        inverted,
        relation: AnchoredRelation::Mirroring,
        anchor: crate::null_anchor::N0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Vorzeichenwechsel: eine echte Involution mit einem Fixpunkt (0).
    fn spiegelung(x: &i64) -> i64 {
        -x
    }

    /// QPM Struktur 10.7 (Reflexive Boundary): `R^2 = I`, an Zeugen
    /// geprueft - und die Gegenprobe, dass eine Nicht-Involution
    /// zurueckgewiesen wird.
    #[test]
    fn an_involution_is_checked_not_assumed() {
        let r = Involution::check(spiegelung, &[1i64, -3, 0, 7]).expect("R^2 = I");
        assert_eq!(r.checked_witnesses(), 4);

        // Gegenprobe: eine Abbildung, die keine Involution ist, kommt
        // nicht durch - und der Befund nennt den Zeugen.
        let keine = Involution::check(|x: &i64| x + 1, &[0i64, 5]);
        assert_eq!(
            keine.expect_err("darf nicht durchgehen"),
            InvolutionBreach::NotAnInvolution { witness_index: 0 }
        );

        // Und eine leere Zeugenmenge prueft nichts.
        let leer: [i64; 0] = [];
        assert_eq!(
            Involution::check(spiegelung, &leer).expect_err("vakuum"),
            InvolutionBreach::VacuousWitnessSet
        );
    }

    /// Die drei Projektorgesetze, ueber der Traegermenge gemessen.
    #[test]
    fn the_decomposition_obeys_the_three_projector_laws() {
        let r = Involution::check(spiegelung, &[1i64, 0]).expect("R^2 = I");
        let traeger = vec![0i64, 1, -1, 2, -2];
        let split = decompose(&r, &traeger);

        // B+ + B- = I: nichts verschwindet.
        assert!(split.accounts_for_everything());
        assert_eq!(split.fixed().len() + split.residual().len(), 5);

        // B+ B- = 0: disjunkt.
        assert!(split.halves_are_disjoint());

        // Der Fixraum ist genau {0} - die Zerlegung TUT etwas, sie
        // schiebt nicht alles in eine Haelfte.
        assert_eq!(split.fixed().iter().copied().collect::<Vec<_>>(), vec![0]);
        assert_eq!(split.residual().len(), 4);

        // (B±)^2 = B±: nochmaliges Zerlegen des Fixraums laesst ihn ganz
        // im Fixraum, nochmaliges Zerlegen des Residualraums ganz im
        // Residualraum.
        let fix_nochmal = decompose(&r, &split.fixed().iter().copied().collect::<Vec<_>>());
        assert_eq!(fix_nochmal.residual().len(), 0);
        assert_eq!(fix_nochmal.fixed().len(), split.fixed().len());
        let res_nochmal = decompose(&r, &split.residual().iter().copied().collect::<Vec<_>>());
        assert_eq!(res_nochmal.fixed().len(), 0);
        assert_eq!(res_nochmal.residual().len(), split.residual().len());
    }

    /// "Kein Anteil darf zwischen akzeptiertem Fixraum und Residualraum
    /// verschwinden" - die Gegenprobe zur Buchfuehrung: ein von Hand
    /// beschaedigter Split faellt auf.
    ///
    /// Ohne sie sagte `accounts_for_everything` nur, dass `decompose`
    /// tut, was `decompose` tut.
    #[test]
    fn a_lost_part_is_caught_by_the_accounting() {
        let r = Involution::check(spiegelung, &[1i64, 0]).expect("R^2 = I");
        let mut split = decompose(&r, &[0i64, 1, -1, 2]);
        assert!(split.accounts_for_everything());

        // Ein Element verschwindet - genau das, was die Struktur
        // verbietet.
        split.residual.remove(&1);
        assert!(
            !split.accounts_for_everything(),
            "ein verschwundener Anteil MUSS auffallen"
        );
    }

    /// Der erklaerte Nullstand: die Selbstadjungiertheit ist NICHT
    /// geprueft, und der Grund steht am Objekt statt in der Prosa.
    #[test]
    fn self_adjointness_is_a_declared_null_state_with_its_reason() {
        let r = Involution::check(spiegelung, &[1i64]).expect("R^2 = I");
        let grund = r.self_adjointness_unchecked();
        assert!(grund.contains("kein Innenprodukt"));
        assert!(grund.contains("R^2 = I"));
    }

    /// QPM Struktur 10.8 (Seam): J ist NICHT automatisch R - und der
    /// Zeuge sieht den Unterschied.
    #[test]
    fn the_seam_witness_sees_that_j_is_not_r() {
        let r = Involution::check(spiegelung, &[1i64, 0]).expect("R^2 = I");
        // J: eine ANDERE Gegenseite - Kehrwert des Vorzeichens ist R,
        // hier stattdessen die Verschiebung auf die deklarierte
        // Gegenseite.
        let j = |x: &i64| 10 - x;

        // An x = 5 stimmen sie zufaellig NICHT ueberein.
        let w = witness_seam(&r, &j, &1i64, &crate::N0);
        assert_eq!(w.reflected, -1);
        assert_eq!(w.inverted, 9);
        assert!(!w.agree, "J und R sind verschieden - der Zeuge sagt es");
        assert_eq!(w.relation, AnchoredRelation::Mirroring);

        // Und an der Stelle, an der sie zusammenfallen, sagt der Zeuge
        // AUCH das - Uebereinstimmung ist ein Befund ueber DIESES
        // Element, nicht ueber die Abbildungen.
        let w5 = witness_seam(&r, &j, &5i64, &crate::N0);
        assert_eq!((w5.reflected, w5.inverted), (-5, 5));
        assert!(!w5.agree);
        let w_gleich = witness_seam(&r, &|x: &i64| -x, &3i64, &crate::N0);
        assert!(
            w_gleich.agree,
            "wo J zufaellig wie R wirkt, haelt der Zeuge es fest"
        );
    }

    /// Der Residuenvertrag traegt alle drei Pflichten aus
    /// QPM Invariante 10.10 (Residualvollständigkeit) - und er ist ein
    /// PSK-RA-`ResidueRecord`, kein zweiter Typ.
    ///
    /// Die Provenienz kommt vom Aufrufer, nicht aus NRAII: der Test
    /// fuehrt sie deshalb ZWEIMAL mit verschiedenen ausstellenden
    /// Modulen. Waere sie hier festverdrahtet, koennte er das nicht.
    #[test]
    fn the_residue_contract_carries_provenance_reason_and_backlink() {
        let object = ObjectId::new(
            psk_types::objects::SortId::Context,
            Digest::sha256(b"traeger"),
        );
        let part = ResidualPart {
            origin_object: object,
            reason: "Anteil liegt im Residualraum der Involution".to_string(),
        };
        let at = DualTime {
            tau_i: 1,
            tau_e: "2026-08-11T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        };

        let von_closure = residue_for_residual_part(&part, ModuleId::ClosureGlueEngine, at.clone());
        // Rueckbezug und Grund kommen aus dem Anteil ...
        assert_eq!(von_closure.origin_object, object);
        assert!(von_closure.open_obligation.0.contains("Residualraum"));
        // ... die Provenienz vom Aufrufer.
        assert_eq!(von_closure.origin_module, ModuleId::ClosureGlueEngine);

        let von_scheduler = residue_for_residual_part(&part, ModuleId::Scheduler, at);
        assert_eq!(von_scheduler.origin_module, ModuleId::Scheduler);
        assert_ne!(von_closure.origin_module, von_scheduler.origin_module);

        // Ein regulaeres Zerlegungsergebnis, kein Defekt.
        assert_eq!(von_closure.severity, ResidueRecordSeverityKind::NonBlocking);
    }
}
