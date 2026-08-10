//! M25 Scheduler, Ressourcen- und Risikobudgets (Struktur 14.11 (BudgetLedger),
//! BudgetLedger).
//!
//! BudgetLedger traegt kein `id`-Feld (Struktur 14.11 (BudgetLedger) fuehrt keines) und
//! ist damit kein kanonisches Kapitel-7-Objekt - es lebt nur als
//! Laufzeitzustand, nicht als inhaltsadressiertes Objekt. Es bleibt deshalb
//! hier ein reiner Rust-Typ, ohne Registrierung in object_schemas.yaml.
//!
//! v1.0.19-Praezisierung: BudgetLedger ist keine der elf benannten
//! Sigma_t-Positionen (Definition 13.1 (Laufzustand) nennt C/I/At/Tt/Ft/Ht/Wt/Qt/Et/Lt/Rt
//! woertlich, keine Budgetposition) - die fruehere Notiz hier ("Teil von
//! Sigma, Ft und benachbarte Komponenten") war eine Vermutung aus der Zeit
//! vor einem realen `Sigma`-Typ. Jetzt, wo `sigma::Sigma` real existiert,
//! ist BudgetLedger dort ein eigenes, ausdruecklich als Zusatz markiertes
//! Feld (`Sigma::budget`), keine Unterposition von `Ft` (Feldregister).
//!
//! Vertrag 14.12 (Keine implizite Unendlichkeit): "Jede Klasse besitzt ein
//! deklariertes Limit; Erschoepfung erzeugt HOLD und ein ResidueRecord des
//! Typs budget." `policy_on_exhaustion: HOLD # niemals silent_drop` -
//! `charge` wendet die Belastung deshalb NICHT an, wenn sie das Limit
//! ueberschreiten wuerde (kein Teilverbrauch, kein stilles Sattigen);
//! der Aufrufer erhaelt `Exhausted` und MUSS mit HOLD + ResidueRecord(budget)
//! reagieren (Algorithmus 14.5 (Tick): "if budget.exhausted: M19.residue(item,
//! kind: budget); continue").

use psk_types::objects::Scaled;
use psk_types::RunId;

/// Eine der sieben ganzzahligen Ressourcenklassen aus Definition 14.10 (Ressourcenklassen).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
pub struct ResourceClass {
    pub limit: u64,
    pub used: u64,
}

/// Die Risikoklasse: einzige nichtganzzahlige Klasse, deshalb `Scaled`
/// statt `u64` (Struktur 14.11 (BudgetLedger), Feld `risk`).
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct RiskClass {
    pub limit: Scaled,
    pub used: Scaled,
}

/// `Serialize` (nicht `Deserialize`): das Ledger ist Teil von Sigma und
/// geht damit in `I_t = H(Can(Sigma_t))` ein (siehe `sigma::sigma_digest`).
/// Ein Budgetstand entsteht ueber `open`/`charge`, nie durch Einspielen -
/// sonst waere Vertrag 14.12 (Keine implizite Unendlichkeit) umgehbar.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct BudgetLedger {
    pub run_id: RunId,
    pub compute: ResourceClass,
    pub memory: ResourceClass,
    pub context: ResourceClass,
    pub network: ResourceClass,
    pub audit: ResourceClass,
    pub governance: ResourceClass,
    pub time: ResourceClass,
    pub risk: RiskClass,
}

impl BudgetLedger {
    /// Eroeffnet ein Ledger mit den sieben deklarierten Limits und
    /// `used: 0` in jeder Klasse - "jede Klasse besitzt ein deklariertes
    /// Limit" (Vertrag 14.12 (Keine implizite Unendlichkeit)); ein Ledger ohne Limit ist mit diesem
    /// Konstruktor nicht baubar.
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        run_id: RunId,
        compute_limit: u64,
        memory_limit: u64,
        context_limit: u64,
        network_limit: u64,
        audit_limit: u64,
        governance_limit: u64,
        time_limit: u64,
        risk_limit: Scaled,
    ) -> Self {
        let zero = |limit| ResourceClass { limit, used: 0 };
        BudgetLedger {
            run_id,
            compute: zero(compute_limit),
            memory: zero(memory_limit),
            context: zero(context_limit),
            network: zero(network_limit),
            audit: zero(audit_limit),
            governance: zero(governance_limit),
            time: zero(time_limit),
            risk: RiskClass {
                used: Scaled {
                    schema: risk_limit.schema.clone(),
                    numerator: 0,
                    scale: risk_limit.scale,
                },
                limit: risk_limit,
            },
        }
    }
}

/// Welche der sieben Klassen belastet wird.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceKind {
    Compute,
    Memory,
    Context,
    Network,
    Audit,
    Governance,
    Time,
}

/// Ergebnis von `charge`. `Exhausted` traegt die Klasse mit, damit der
/// Aufrufer ein ResidueRecord des Typs `budget` mit einer konkreten
/// Ursache oeffnen kann (`open_obligation`), statt nur "irgendetwas ist
/// leer" zu wissen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChargeOutcome {
    Ok,
    Exhausted(ResourceKind),
    /// Nur von `charge_risk`: das Risikobudget selbst ist erschoepft.
    RiskExhausted,
    /// Nur von `charge_risk`: `amount` traegt eine andere Skala als das
    /// Ledger - kein Formatverstoss wird stillschweigend umgerechnet.
    RiskScaleMismatch,
}

fn class_mut(ledger: &mut BudgetLedger, kind: ResourceKind) -> &mut ResourceClass {
    match kind {
        ResourceKind::Compute => &mut ledger.compute,
        ResourceKind::Memory => &mut ledger.memory,
        ResourceKind::Context => &mut ledger.context,
        ResourceKind::Network => &mut ledger.network,
        ResourceKind::Audit => &mut ledger.audit,
        ResourceKind::Governance => &mut ledger.governance,
        ResourceKind::Time => &mut ledger.time,
    }
}

/// Belastet eine ganzzahlige Klasse um `amount`. Wuerde das Limit
/// ueberschritten, bleibt `used` unveraendert und das Ergebnis ist
/// `Exhausted` - kein Teilverbrauch bis zum Limit, kein Saettigen.
pub fn charge(ledger: &mut BudgetLedger, kind: ResourceKind, amount: u64) -> ChargeOutcome {
    let class = class_mut(ledger, kind);
    match class.used.checked_add(amount) {
        Some(new_used) if new_used <= class.limit => {
            class.used = new_used;
            ChargeOutcome::Ok
        }
        _ => ChargeOutcome::Exhausted(kind),
    }
}

/// Belastet das Risikobudget. `Scaled`-Arithmetik verlangt eine gemeinsame
/// Skala; unterschiedliche `scale`-Werte werden hier NICHT stillschweigend
/// angeglichen (das waere eine Rundungsannahme) - ein Aufrufer mit
/// abweichender Skala scheitert, statt ein falsches Ergebnis zu erhalten.
pub fn charge_risk(ledger: &mut BudgetLedger, amount: Scaled) -> ChargeOutcome {
    if amount.scale != ledger.risk.limit.scale || amount.scale != ledger.risk.used.scale {
        return ChargeOutcome::RiskScaleMismatch;
    }
    match ledger.risk.used.numerator.checked_add(amount.numerator) {
        Some(new_used) if new_used <= ledger.risk.limit.numerator => {
            ledger.risk.used.numerator = new_used;
            ChargeOutcome::Ok
        }
        _ => ChargeOutcome::RiskExhausted,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scaled(numerator: i64, scale: i64) -> Scaled {
        Scaled {
            schema: "psk.scaled/1.0".to_string(),
            numerator,
            scale,
        }
    }

    fn ledger() -> BudgetLedger {
        BudgetLedger::open(
            RunId("run-0".into()),
            100,
            100,
            100,
            100,
            100,
            100,
            100,
            scaled(50, 2),
        )
    }

    #[test]
    fn charging_within_limit_succeeds() {
        let mut l = ledger();
        assert_eq!(charge(&mut l, ResourceKind::Compute, 40), ChargeOutcome::Ok);
        assert_eq!(l.compute.used, 40);
    }

    #[test]
    fn charging_past_the_limit_is_rejected_without_partial_use() {
        let mut l = ledger();
        assert_eq!(
            charge(&mut l, ResourceKind::Compute, 150),
            ChargeOutcome::Exhausted(ResourceKind::Compute)
        );
        // Vertrag 14.12 (Keine implizite Unendlichkeit): kein stilles Saettigen - used bleibt bei 0, nicht 100.
        assert_eq!(l.compute.used, 0);
    }

    #[test]
    fn charging_exactly_to_the_limit_succeeds() {
        let mut l = ledger();
        assert_eq!(charge(&mut l, ResourceKind::Memory, 100), ChargeOutcome::Ok);
        assert_eq!(
            charge(&mut l, ResourceKind::Memory, 1),
            ChargeOutcome::Exhausted(ResourceKind::Memory)
        );
    }

    #[test]
    fn classes_are_independent() {
        let mut l = ledger();
        charge(&mut l, ResourceKind::Compute, 100);
        assert_eq!(charge(&mut l, ResourceKind::Memory, 100), ChargeOutcome::Ok);
    }

    #[test]
    fn risk_budget_charges_in_the_same_scale() {
        let mut l = ledger();
        assert_eq!(charge_risk(&mut l, scaled(30, 2)), ChargeOutcome::Ok);
        assert_eq!(l.risk.used.numerator, 30);
        assert_eq!(
            charge_risk(&mut l, scaled(30, 2)),
            ChargeOutcome::RiskExhausted
        );
    }

    #[test]
    fn mismatched_scale_is_rejected_not_silently_converted() {
        let mut l = ledger();
        assert_eq!(
            charge_risk(&mut l, scaled(1, 3)),
            ChargeOutcome::RiskScaleMismatch
        );
        assert_eq!(l.risk.used.numerator, 0);
    }

    #[test]
    fn a_freshly_opened_ledger_has_no_usage() {
        let l = ledger();
        assert_eq!(l.compute.used, 0);
        assert_eq!(l.risk.used.numerator, 0);
    }
}
