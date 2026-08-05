//! M13 ValidationPlanner (Kapitel 21.2).
//!
//! Regel 21.6 (Validierungsprioritaet), woertlich: "M13 waehlt den Schritt
//! mit maximalem erwartetem Informationsgewinn pro Kosten. Bei Gleichstand
//! entscheidet die kleinere ObjectId. Read-only-Schritte besitzen Vorrang
//! vor effektbehafteten Schritten gleichen Gewinns."
//!
//! Das Mass fuer den Informationsgewinn ist nach OBL-006 modellrelativ:
//! "Die Norm verlangt Monotonie, Nichtnegativitaet und Kostenbezug; sie
//! schreibt kein Mass vor." Der Gewinn kommt deshalb je Schritt als
//! bereits bestimmter Wert herein (`expected_information_gain`, Struktur
//! 21.5) - M13 misst nicht, M13 ordnet.
//!
//! Was M13 dagegen vollstaendig traegt, ist die Ordnung selbst: sie ist
//! "deterministisch, stabil sortiert" (Struktur 21.5, Feld `ordering`) und
//! hier als totale Ordnung ohne Rest implementiert, damit zwei Laeufe nie
//! verschiedene Plaene ergeben.
//!
//! v1.0.8 (Fehlerkorrektur Punkt 13): `expected_information_gain` ist jetzt
//! `Scaled` (numerator/scale) statt der zuvor undefinierten `Decimal`. Der
//! Gewinn hat damit "eine Grundlage im Typ statt nur im Vergleich" - die
//! kreuzweise i128-Ganzzahlarithmetik unten war vorher eine Reaktion auf
//! ein Dokumentproblem (Vertrag 6.3 verbietet Gleitkomma, aber Decimal war
//! nicht spezifiziert); jetzt liest sie den Wert direkt aus dem Typ, ohne
//! Zeichenkette zu parsen. `cost` bleibt `BudgetSpec` (Zeichenkette) - das
//! ist keiner der vier von v1.0.8 erfassten Faelle.

use std::cmp::Ordering;

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    ObligationExpr, Scaled, SortId, Step, ValidationOrderingId, ValidationPlan,
    ValidationPlanStopConditionKind,
};
use psk_types::{Digest, ObjectId, PskError};

/// Ein Schritt zusammen mit der ObjectId, die ihn bei Gleichstand ordnet.
///
/// Struktur 21.5 fuehrt fuer `steps` keine eigene Kennung, Regel 21.6
/// verlangt aber "bei Gleichstand entscheidet die kleinere ObjectId". Die
/// einzige ObjectId, die ein Schritt hat, ist die seines Ziels - deshalb
/// traegt der Kandidat sie explizit mit. Ableitung dokumentiert.
pub struct StepCandidate {
    pub step: Step,
    pub target: ObjectId,
}

/// Gewinn pro Kosten als exakter Bruch, ohne Gleitkomma.
///
/// `cost` (BudgetSpec) ist weiterhin eine Zeichenkette und wird geparst;
/// `gain` kommt direkt aus `Scaled`. Beide werden auf dieselbe Zielskala
/// gebracht, damit die kreuzweise Multiplikation exakt bleibt. Ein
/// Vergleich ueber f64 waere plattform- und rundungsabhaengig und damit
/// genau der Nichtdeterminismus, den Invariante 11.3 (Passdeterminismus)
/// verbietet: g1/c1 > g2/c2  <=>  g1*c2 > g2*c1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GainPerCost {
    gain: i128,
    cost: i128,
}

impl GainPerCost {
    const TARGET_SCALE: u32 = 9;

    /// Normalisiert `Scaled{numerator, scale}` auf `TARGET_SCALE`.
    /// `scale > TARGET_SCALE` schneidet Nachkommastellen ab (nicht
    /// runden) - dieselbe Behandlung, die zuvor `parse_decimal_string` auf
    /// Zeichenketten mit mehr als neun Nachkommastellen anwandte.
    /// `scale < 0` ist ein Formatverstoss (Struktur 7.25: "scale >= 0").
    fn normalize_scaled(value: &Scaled) -> Option<i128> {
        if value.scale < 0 {
            return None;
        }
        let scale = value.scale as u32;
        let num = i128::from(value.numerator);
        if scale <= Self::TARGET_SCALE {
            num.checked_mul(10i128.pow(Self::TARGET_SCALE - scale))
        } else {
            Some(num / 10i128.pow(scale - Self::TARGET_SCALE))
        }
    }

    /// `cost` (BudgetSpec) ist keiner der vier durch v1.0.8 auf Scaled
    /// vereinheitlichten Faelle und bleibt eine Dezimalzeichenkette.
    fn parse_decimal_string(s: &str) -> Option<i128> {
        let t = s.trim();
        let (int_part, frac_part) = match t.split_once('.') {
            Some((i, f)) => (i, f),
            None => (t, ""),
        };
        let mut frac = frac_part.to_string();
        frac.truncate(Self::TARGET_SCALE as usize);
        while frac.len() < Self::TARGET_SCALE as usize {
            frac.push('0');
        }
        let negative = int_part.starts_with('-');
        let int_digits = int_part.trim_start_matches(['-', '+']);
        if !int_digits.chars().all(|c| c.is_ascii_digit())
            || !frac.chars().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        let whole: i128 = if int_digits.is_empty() {
            0
        } else {
            int_digits.parse().ok()?
        };
        let fraction: i128 = frac.parse().ok()?;
        let magnitude = whole
            .checked_mul(10i128.pow(Self::TARGET_SCALE))?
            .checked_add(fraction)?;
        Some(if negative { -magnitude } else { magnitude })
    }

    fn of(step: &Step) -> Option<GainPerCost> {
        let gain = Self::normalize_scaled(&step.expected_information_gain)?;
        let cost = Self::parse_decimal_string(&step.cost.0)?;
        Some(GainPerCost { gain, cost })
    }

    /// Vergleicht g1/c1 mit g2/c2. Kosten <= 0 gelten als "unbekannt teuer"
    /// und ordnen sich hinter jeden Schritt mit positiven Kosten ein: ein
    /// Schritt ohne Kostenangabe DARF sich nicht an die Spitze setzen.
    fn cmp_ratio(&self, other: &GainPerCost) -> Ordering {
        match (self.cost > 0, other.cost > 0) {
            (true, true) => (self.gain * other.cost).cmp(&(other.gain * self.cost)),
            (true, false) => Ordering::Greater,
            (false, true) => Ordering::Less,
            (false, false) => Ordering::Equal,
        }
    }
}

/// OBL-006, Nichtnegativitaet: ein negativer Informationsgewinn ist kein
/// zulaessiger Wert. Er wuerde zudem `stop_condition: no_positive_gain`
/// unentscheidbar machen.
///
/// Direkt auf `numerator` geprueft (das Vorzeichen von Scaled liegt
/// vollstaendig dort, da 10^scale > 0 fuer scale >= 0 immer gilt) - nicht
/// ueber `GainPerCost::of`, damit ein nicht parsbares `cost` diese Pruefung
/// nicht mit der falschen Fehlerursache scheitern laesst.
fn check_gain_non_negative(c: &StepCandidate) -> Result<(), PskError> {
    if c.step.expected_information_gain.numerator >= 0 {
        Ok(())
    } else {
        Err(PskError::BudgetOrScheduleViolation)
    }
}

/// Regel 21.6 als totale Ordnung. Absteigend: der beste Schritt zuerst.
///
/// Die drei Kriterien in der Reihenfolge des Textes:
///   1. Gewinn pro Kosten, absteigend.
///   2. read_only vor effektbehaftet bei gleichem Gewinn.
///   3. kleinere ObjectId.
fn rank(a: &StepCandidate, b: &StepCandidate) -> Ordering {
    let (ga, gb) = (GainPerCost::of(&a.step), GainPerCost::of(&b.step));
    let by_ratio = match (ga, gb) {
        (Some(x), Some(y)) => y.cmp_ratio(&x), // absteigend
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    };
    by_ratio
        // read_only zuerst: true soll vor false stehen, deshalb umgekehrt.
        .then_with(|| b.step.read_only.cmp(&a.step.read_only))
        .then_with(|| a.target.to_string().cmp(&b.target.to_string()))
}

const PLAN_SORT: SortId = SortId::Witness;

fn compute_identity(draft: &ValidationPlan) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    object_id(PLAN_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

/// M13: baut den ValidationPlan (Struktur 21.5).
///
/// `stop_condition` wird nicht gewaehlt, sondern festgestellt: sie folgt
/// aus dem Zustand der Schritte und Obligationen und ist damit
/// reproduzierbar.
pub fn plan_validation(
    target_refs: Vec<ObjectId>,
    open_obligations: Vec<ObligationExpr>,
    mut candidates: Vec<StepCandidate>,
    budget_exhausted: bool,
) -> Result<ValidationPlan, PskError> {
    for c in &candidates {
        check_gain_non_negative(c)?;
    }

    // `sort_by` ist in Rust stabil; zusammen mit der ObjectId als letztem
    // Kriterium ist die Ordnung total und damit unabhaengig von der
    // Eingabereihenfolge.
    candidates.sort_by(rank);

    let any_positive_gain = candidates
        .iter()
        .filter_map(|c| GainPerCost::of(&c.step))
        .any(|g| g.gain > 0 && g.cost > 0);

    let stop_condition = if open_obligations.is_empty() {
        ValidationPlanStopConditionKind::ObligationsClosed
    } else if budget_exhausted {
        ValidationPlanStopConditionKind::BudgetExhausted
    } else if !any_positive_gain {
        ValidationPlanStopConditionKind::NoPositiveGain
    } else {
        // Offene Obligationen, Budget vorhanden, positiver Gewinn: der Plan
        // laeuft, bis die Obligationen geschlossen sind.
        ValidationPlanStopConditionKind::ObligationsClosed
    };

    let draft = ValidationPlan {
        id: ObjectId::new(PLAN_SORT, Digest::sha256(b"")), // Platzhalter
        target_refs,
        open_obligations,
        steps: candidates.into_iter().map(|c| c.step).collect(),
        ordering: ValidationOrderingId::ByInformationGainPerCost,
        stop_condition,
    };

    let id = compute_identity(&draft)?;
    Ok(ValidationPlan { id, ..draft })
}

/// Der naechste auszufuehrende Schritt: der erste des geordneten Plans.
/// `None`, wenn der Plan leer ist oder die Stoppbedingung schon greift.
pub fn next_step(plan: &ValidationPlan) -> Option<&Step> {
    if plan.stop_condition != ValidationPlanStopConditionKind::ObligationsClosed
        || plan.open_obligations.is_empty()
    {
        // ObligationsClosed bei leeren Obligationen heisst: nichts zu tun.
        if plan.open_obligations.is_empty() {
            return None;
        }
    }
    plan.steps.first()
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{BudgetSpec, CapabilityId, ProbeSpec};

    /// `gain` als "numerator" oder "numerator/scale" (z.B. "5" oder
    /// "30000000001/11" fuer 0.30000000001) - die Tests brauchen ueberwiegend
    /// scale:0, ein paar pruefen explizit hohe Skalen.
    fn scaled(spec: &str) -> Scaled {
        match spec.split_once('/') {
            Some((num, scale)) => Scaled {
                schema: "psk.scaled/1.0".into(),
                numerator: num.parse().unwrap(),
                scale: scale.parse().unwrap(),
            },
            None => Scaled {
                schema: "psk.scaled/1.0".into(),
                numerator: spec.parse().unwrap(),
                scale: 0,
            },
        }
    }

    fn candidate(
        probe: &str,
        gain: &str,
        cost: &str,
        read_only: bool,
        target_seed: &[u8],
    ) -> StepCandidate {
        StepCandidate {
            step: Step {
                probe: ProbeSpec(probe.into()),
                expected_information_gain: scaled(gain),
                cost: BudgetSpec(cost.into()),
                capability: if read_only {
                    None
                } else {
                    Some(CapabilityId("fs.write".into()))
                },
                read_only,
            },
            target: ObjectId::new(SortId::Context, Digest::sha256(target_seed)),
        }
    }

    fn plan(cands: Vec<StepCandidate>) -> ValidationPlan {
        plan_validation(
            vec![ObjectId::new(SortId::Context, Digest::sha256(b"ziel"))],
            vec![ObligationExpr("offen".into())],
            cands,
            false,
        )
        .unwrap()
    }

    #[test]
    fn highest_gain_per_cost_comes_first() {
        // Regel 21.6, erstes Kriterium.
        let p = plan(vec![
            candidate("a", "1", "10", true, b"a"), // 0.1
            candidate("b", "9", "10", true, b"b"), // 0.9
            candidate("c", "5", "10", true, b"c"), // 0.5
        ]);
        let order: Vec<_> = p.steps.iter().map(|s| s.probe.0.clone()).collect();
        assert_eq!(order, vec!["b", "c", "a"]);
    }

    #[test]
    fn ratio_not_absolute_gain_decides() {
        // 2/1 = 2.0 schlaegt 10/100 = 0.1, obwohl 10 > 2.
        let p = plan(vec![
            candidate("teuer", "10", "100", true, b"a"),
            candidate("guenstig", "2", "1", true, b"b"),
        ]);
        assert_eq!(p.steps[0].probe.0, "guenstig");
    }

    #[test]
    fn read_only_wins_at_equal_gain() {
        // Regel 21.6, dritter Satz.
        let p = plan(vec![
            candidate("effekt", "5", "10", false, b"a"),
            candidate("lesend", "5", "10", true, b"b"),
        ]);
        assert_eq!(p.steps[0].probe.0, "lesend");
        assert!(p.steps[0].read_only);
    }

    #[test]
    fn smaller_object_id_breaks_remaining_ties() {
        // Regel 21.6, zweiter Satz. Beide lesend, beide 5/10.
        let a = candidate("x", "5", "10", true, b"aaa");
        let b = candidate("y", "5", "10", true, b"bbb");
        let (id_a, id_b) = (a.target.to_string(), b.target.to_string());
        let expect_first = if id_a < id_b { "x" } else { "y" };
        let p = plan(vec![b, a]); // absichtlich verkehrt herum eingegeben
        assert_eq!(p.steps[0].probe.0, expect_first);
    }

    #[test]
    fn ordering_is_independent_of_input_order() {
        // Struktur 21.5: "deterministisch, stabil sortiert".
        let forward = plan(vec![
            candidate("a", "1", "10", true, b"a"),
            candidate("b", "9", "10", false, b"b"),
            candidate("c", "9", "10", true, b"c"),
        ]);
        let backward = plan(vec![
            candidate("c", "9", "10", true, b"c"),
            candidate("b", "9", "10", false, b"b"),
            candidate("a", "1", "10", true, b"a"),
        ]);
        assert_eq!(forward.steps, backward.steps);
        assert_eq!(forward.id, backward.id);
    }

    #[test]
    fn scaled_gains_compare_without_floating_point() {
        let p = plan(vec![
            candidate("a", "30000000001/11", "1", true, b"a"),
            candidate("b", "30000000002/11", "1", true, b"b"),
        ]);
        assert_eq!(p.steps[0].probe.0, "b");
    }

    #[test]
    fn negative_gain_is_rejected() {
        // OBL-006 verlangt Nichtnegativitaet.
        let r = plan_validation(
            vec![],
            vec![ObligationExpr("offen".into())],
            vec![candidate("a", "-1", "10", true, b"a")],
            false,
        );
        assert_eq!(r, Err(PskError::BudgetOrScheduleViolation));
    }

    #[test]
    fn zero_cost_step_does_not_jump_the_queue() {
        // Ohne Kostenbezug (OBL-006) ist der Quotient nicht gebildet; ein
        // solcher Schritt DARF sich nicht vor einen bewerteten setzen.
        let p = plan(vec![
            candidate("unbewertet", "9", "0", true, b"a"),
            candidate("bewertet", "1", "10", true, b"b"),
        ]);
        assert_eq!(p.steps[0].probe.0, "bewertet");
    }

    #[test]
    fn stop_condition_is_observed_not_chosen() {
        let closed = plan_validation(vec![], vec![], vec![], false).unwrap();
        assert_eq!(
            closed.stop_condition,
            ValidationPlanStopConditionKind::ObligationsClosed
        );

        let exhausted = plan_validation(
            vec![],
            vec![ObligationExpr("offen".into())],
            vec![candidate("a", "5", "10", true, b"a")],
            true,
        )
        .unwrap();
        assert_eq!(
            exhausted.stop_condition,
            ValidationPlanStopConditionKind::BudgetExhausted
        );

        let no_gain = plan_validation(
            vec![],
            vec![ObligationExpr("offen".into())],
            vec![candidate("a", "0", "10", true, b"a")],
            false,
        )
        .unwrap();
        assert_eq!(
            no_gain.stop_condition,
            ValidationPlanStopConditionKind::NoPositiveGain
        );
    }

    #[test]
    fn next_step_is_the_head_of_the_ordered_plan() {
        let p = plan(vec![
            candidate("schwach", "1", "10", true, b"a"),
            candidate("stark", "9", "10", true, b"b"),
        ]);
        assert_eq!(next_step(&p).unwrap().probe.0, "stark");
    }

    #[test]
    fn a_plan_without_open_obligations_has_no_next_step() {
        let p = plan_validation(
            vec![],
            vec![],
            vec![candidate("a", "5", "10", true, b"a")],
            false,
        )
        .unwrap();
        assert!(next_step(&p).is_none());
    }
}
