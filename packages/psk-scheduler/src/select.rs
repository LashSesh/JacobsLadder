//! M25 Scheduler: `queue = M25.select(phase, state)` (Algorithmus 14.4 (Tick),
//! "deterministische Auswahl") und die Prioritaetsordnung (Regel 14.5 (Prioritätsordnung)).
//!
//! Eine fruehere Fassung nahm "statt dessen direkt die bereits
//! identifizierten anstehenden Elemente entgegen" und verwies die
//! Identifikation an die "Phase-Dispatchlogik". Diese Entscheidung ist
//! vom Auftraggeber ausdruecklich zurueckgenommen: die vollstaendig
//! vorbefuellten Warteschlangen waren die Abweichung, nicht der
//! Algorithmus. `select` leitet die anstehende Arbeit jetzt JE PHASE aus
//! Sigma ab, innerhalb der Taktschleife, nach dem Zustandsupdate der
//! Vorphase - Phase 6 sieht die Projektionen aus Phase 5, Phase 9 den
//! Gate-Bericht aus Phase 8.
//!
//! ## Ordnung: Pflichtabhaengigkeiten, dann Raenge, dann ObjectId
//!
//! Regel 14.5 (Prioritätsordnung) beginnt mit "Prioritaet entsteht aus Pflichtabhaengigkeiten,
//! nicht aus rhetorischer Dringlichkeit" und nennt DANN die sechs Raenge;
//! "bei Gleichrang entscheidet die aufsteigende ObjectId". Ein Element,
//! das die Eingabe eines anderen erzeugt (AnchorBind vor der Praegung,
//! Regel 5.9 (Kandidat und Gedankenkörper): "Anker in anchor, Praegung ebendort"), steht zu diesem
//! nicht im Gleichrang - `obligation_rank` traegt diese Abhaengigkeits-
//! stellung, und die Gesamtordnung ist (tier, obligation_rank,
//! expires_at_tau_i, ObjectId): total und replaystabil.
//!
//! ## Verweise loesen beim Dispatch, nicht beim Einreihen
//!
//! Ein spaeteres Element derselben Phase darf die Ergebnisse der
//! frueheren voraussetzen (die Praegung findet den soeben versiegelten
//! Anker vor). Wo das anstehende Element ein noch nicht existierendes
//! Objekt benennen muesste, traegt es `None` und loest beim Dispatch
//! ("das in dieser Phase entstandene") - siehe `ExecuteRun`. Die Kapsel
//! dagegen wird NICHT verkettet: eine Kapsel, die in einem Takt nicht
//! bis zum Kapselfixpunkt oder RESIDUAL kommt, ueberlebt in
//! `Sigma.capsules` und steht im naechsten Takt unter Rang 5
//! ("bestehende Kapseln im Ratchet") wieder an - genau der Mechanismus,
//! den Regel 14.5 (Prioritätsordnung) fuer sie vorsieht.

use psk_types::objects::{GateId, GateReportDecisionKind, SortId};
use psk_types::{Digest, ObjectId, Phase, CANONICAL_PHASES};

use crate::{PendingWork, ResourceKind, Sigma};

/// Die sechs Raenge aus Regel 14.5 (Prioritätsordnung), in der im Text genannten Reihenfolge.
/// `Ord` sortiert nach Deklarationsreihenfolge - Rang 1 ist der kleinste
/// Diskriminant und damit (aufsteigend sortiert) der erste.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PriorityTier {
    UnknownEffectOrOpenReconciliation,
    ExpiringEffectToken,
    BlockingWitnessOrResidue,
    DeclaredExternalDanger,
    RatchetingCapsule,
    SpeculativeBranch,
}

/// Ein fuer eine Phase anstehendes Element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchedulableItem {
    pub id: ObjectId,
    pub tier: PriorityTier,
    /// Nur fuer `ExpiringEffectToken` bedeutsam (Kriterium 2: "kleinstes
    /// zuerst"); bei jedem anderen Rang `None` und ohne Einfluss auf die
    /// Ordnung, weil Elemente unterschiedlicher Raenge bereits durch `tier`
    /// entschieden sind.
    pub expires_at_tau_i: Option<u64>,
    /// Stellung in der Pflichtabhaengigkeitskette der Phase (Regel 14.5 (Prioritätsordnung)
    /// Satz 1) - 0, wo keine Abhaengigkeit besteht. Ordnet VOR der
    /// ObjectId: zwei Elemente, von denen eines die Eingabe des anderen
    /// erzeugt, stehen nicht im Gleichrang.
    pub obligation_rank: u32,
}

/// Ein fuer eine Phase anstehendes Element mit Budgetkosten (`cost`, geht
/// in `charge()` ein) und dem Verweis auf die Arbeit (`work`, geht in
/// `dispatch()` ein). Der Pseudocode kennt nur "item" - `charge(item)`
/// und `dispatch(phase, item, state)` lesen daraus verschiedene Seiten.
pub struct QueuedItem {
    pub schedulable: SchedulableItem,
    pub cost: (ResourceKind, u64),
    pub work: PendingWork,
}

/// Regel 14.5 (Prioritätsordnung) als totale Ordnung: `tier` aufsteigend, dann
/// `obligation_rank` (Satz 1), dann `expires_at_tau_i` aufsteigend, dann
/// die ObjectId in ihrer Bytedarstellung (`to_string()` liefert
/// "psk:<sorte>:<digest>" - lexikographisch auf dieser Zeichenkette ist
/// dieselbe Ordnung wie auf den zugrundeliegenden Bytes).
pub fn priority_order(mut items: Vec<SchedulableItem>) -> Vec<SchedulableItem> {
    items.sort_by(|a, b| {
        a.tier
            .cmp(&b.tier)
            .then_with(|| a.obligation_rank.cmp(&b.obligation_rank))
            .then_with(|| a.expires_at_tau_i.cmp(&b.expires_at_tau_i))
            .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
    });
    items
}

/// Deterministische Kennung eines abgeleiteten Arbeitselements, das noch
/// kein kanonisches Objekt benennt. `SortId::Trace`: die dauerhafte Spur
/// eines Arbeitselements ist sein Traceseg­ment.
fn work_id(phase: Phase, tag: &str) -> ObjectId {
    ObjectId::new(
        SortId::Trace,
        Digest::sha256(format!("select:{}:{}", phase.label(), tag).as_bytes()),
    )
}

/// Die Einheitskosten eines Arbeitselements (Definition 14.9 (Ressourcenklassen): Compute).
/// Eine feinere Kostenzuordnung je Arbeitsart waere eine eigene, hier
/// nicht getroffene Deklarationsentscheidung - die Belastung selbst
/// (Algorithmus 14.4 (Tick): "budget = M25.charge(item)") laeuft real.
const UNIT_COST: (ResourceKind, u64) = (ResourceKind::Compute, 1);

fn item(phase: Phase, tag: &str, tier: PriorityTier, rank: u32, work: PendingWork) -> QueuedItem {
    QueuedItem {
        schedulable: SchedulableItem {
            id: work_id(phase, tag),
            tier,
            expires_at_tau_i: None,
            obligation_rank: rank,
        },
        cost: UNIT_COST,
        work,
    }
}

fn object_item(
    id: ObjectId,
    tier: PriorityTier,
    rank: u32,
    expires: Option<u64>,
    work: PendingWork,
) -> QueuedItem {
    QueuedItem {
        schedulable: SchedulableItem {
            id,
            tier,
            expires_at_tau_i: expires,
            obligation_rank: rank,
        },
        cost: UNIT_COST,
        work,
    }
}

/// `M25.select(phase, state)`: leitet die anstehende Arbeit der Phase aus
/// Sigma ab und ordnet sie nach Regel 14.5 (Prioritätsordnung). Jede Bedingung liest
/// Fortschrittsmarken des Zustands - was erledigt ist, steht nicht mehr
/// an; ein Lauf ohne offene Arbeit liefert ueberall leere Warteschlangen
/// (siehe `has_pending_work`).
pub fn select(phase: Phase, state: &Sigma) -> Vec<QueuedItem> {
    use PriorityTier::*;
    let mut queue: Vec<QueuedItem> = Vec::new();

    match phase {
        Phase::Observe => {
            for (i, r) in state.program.records.iter().enumerate() {
                if r.provenance.is_none() {
                    queue.push(item(
                        phase,
                        &format!("observe:{i}"),
                        SpeculativeBranch,
                        0,
                        PendingWork::Observe { record: i },
                    ));
                }
            }
        }

        Phase::Normalize => {
            for (i, c) in state.candidates.iter().enumerate() {
                if c.canonical_digest.is_none() {
                    queue.push(item(
                        phase,
                        &format!("normalize:{i}"),
                        SpeculativeBranch,
                        0,
                        PendingWork::NormalizeCandidate { candidate: i },
                    ));
                }
            }
        }

        Phase::Type => {
            for (i, c) in state.candidates.iter().enumerate() {
                if c.canonical_digest.is_some() && c.sort.is_none() {
                    queue.push(item(
                        phase,
                        &format!("type:{i}"),
                        SpeculativeBranch,
                        0,
                        PendingWork::TypeCandidate { candidate: i },
                    ));
                }
            }
        }

        Phase::Anchor => {
            // Rang 0: gebundene Records versiegeln (Schritt 2).
            let mut binds = 0usize;
            for (i, r) in state.program.records.iter().enumerate() {
                if r.provenance.is_some() && r.anchor_ref.is_none() {
                    binds += 1;
                    queue.push(item(
                        phase,
                        &format!("bind:{i}"),
                        SpeculativeBranch,
                        0,
                        PendingWork::AnchorBind { record: i },
                    ));
                }
            }
            let anchor_available = !state.anchors.is_empty() || binds > 0;
            // Rang 1: die Praegung (Regel 5.9 (Kandidat und Gedankenkörper), "Praegung ebendort") - der
            // Anker liegt beim Dispatch vor, weil der Bind derselben
            // Phase frueher angewandt wurde.
            let mut mints = 0usize;
            for (i, c) in state.candidates.iter().enumerate() {
                if c.sort.is_some() && c.minted.is_none() && anchor_available {
                    mints += 1;
                    queue.push(item(
                        phase,
                        &format!("mint:{i}"),
                        SpeculativeBranch,
                        1,
                        PendingWork::MintThought { candidate: i },
                    ));
                }
            }
            // Rang 2: Klassifikation (Schritt 4) - je gepraegtem Gedanken
            // genau eine; die Zaehlung traegt die Bedingung, weil die
            // Praegung derselben Phase erst beim Dispatch sichtbar wird.
            let minted_now = state
                .candidates
                .iter()
                .filter(|c| c.minted.is_some())
                .count();
            let classified = state.reality_horizon.len();
            let mut to_classify = (minted_now + mints).saturating_sub(classified);
            for (i, c) in state.candidates.iter().enumerate() {
                if to_classify == 0 {
                    break;
                }
                if c.sort.is_some() {
                    queue.push(item(
                        phase,
                        &format!("classify:{i}"),
                        SpeculativeBranch,
                        2,
                        PendingWork::AnchorClassify { candidate: i },
                    ));
                    to_classify -= 1;
                }
            }
        }

        Phase::Project => {
            let reality_known = !state.reality_horizon.is_empty();
            for (i, e) in state.program.field_family.iter().enumerate() {
                let registering = e.registered.is_none();
                if registering {
                    queue.push(item(
                        phase,
                        &format!("field:{i}"),
                        SpeculativeBranch,
                        0,
                        PendingWork::ProjectField { entry: i },
                    ));
                }
                if e.projected.is_none() && (e.registered.is_some() || registering) && reality_known
                {
                    queue.push(item(
                        phase,
                        &format!("lens:{i}"),
                        SpeculativeBranch,
                        1,
                        PendingWork::ProjectLens { entry: i },
                    ));
                }
            }
        }

        Phase::Compile => {
            let family = &state.program.field_family;
            let projections_complete =
                !family.is_empty() && state.projections.len() == family.len();
            let quotient_pending = projections_complete
                && state.dependencies.is_empty()
                && state.program.consensus_scope.is_some();
            if quotient_pending {
                queue.push(item(
                    phase,
                    "quotient",
                    SpeculativeBranch,
                    0,
                    PendingWork::CompileQuotient,
                ));
            }
            // Der Zusammenbau: einmal als Compile-Kandidat, und erst wenn
            // die Reconciliation vorliegt noch einmal als finaler Graph -
            // ein Zwischenbau haette die permits/feeds-Kanten nur
            // weglassen muessen (siehe dispatch::assemble).
            let quotient_available = !state.dependencies.is_empty() || quotient_pending;
            let assemble_pending = state.program.declarations.is_some()
                && quotient_available
                && (state.assemblies.is_empty()
                    || (!state.reconciliations.is_empty()
                        && !state
                            .assemblies
                            .last()
                            .map(|a| a.includes_late)
                            .unwrap_or(true)));
            if assemble_pending {
                queue.push(item(
                    phase,
                    "assemble",
                    SpeculativeBranch,
                    1,
                    PendingWork::CompileAssemble,
                ));
            }
            if state.glue.is_none()
                && state.program.glue_spec.is_some()
                && (!state.assemblies.is_empty() || assemble_pending)
            {
                queue.push(item(
                    phase,
                    "glue",
                    SpeculativeBranch,
                    2,
                    PendingWork::CompileGlue,
                ));
            }
        }

        Phase::Challenge => {
            if !state.program.requirements.is_empty()
                && state.contradictions.is_none()
                && state.program.obstruction_cell.is_some()
                && !state.anchors.is_empty()
            {
                queue.push(item(
                    phase,
                    "contradictions",
                    SpeculativeBranch,
                    0,
                    PendingWork::ChallengeContradictions,
                ));
            }
            if state.program.capsule_spec.is_some()
                && state.capsules.is_empty()
                && !state.dependencies.is_empty()
                && !state.thoughts.is_empty()
            {
                queue.push(item(
                    phase,
                    "capsulate",
                    SpeculativeBranch,
                    1,
                    PendingWork::ChallengeCapsulate,
                ));
            }
            // Bestehende Kapseln im Ratchet (Rang 5): jede nicht
            // terminale Kapsel steht an, bis sie Fixpunkt oder RESIDUAL
            // erreicht. Bewusst NICHT mit dem Versiegeln verkettet -
            // siehe Modulkopf.
            use psk_types::objects::CandidateCapsulePhaseKind as CP;
            for c in &state.capsules {
                let terminal = matches!(
                    c.phase,
                    CP::Supported | CP::Crystallized | CP::Residual | CP::Quarantined
                );
                if !terminal && state.contradictions.is_some() {
                    queue.push(object_item(
                        c.id,
                        RatchetingCapsule,
                        2,
                        None,
                        PendingWork::ChallengeResolve { capsule: c.id },
                    ));
                }
            }
        }

        Phase::Verify => {
            if state.program.closure_evidence.is_some() && state.closure_reports.is_empty() {
                queue.push(item(
                    phase,
                    "closure",
                    SpeculativeBranch,
                    0,
                    PendingWork::VerifyClosure,
                ));
            }
            if state.glue.is_some() && state.validation_obligations.is_none() {
                queue.push(item(
                    phase,
                    "validation",
                    SpeculativeBranch,
                    0,
                    PendingWork::VerifyValidation,
                ));
            }
            let gate_done = state
                .gates_and_tokens
                .reports
                .iter()
                .any(|r| r.gate_id == GateId::GEffect);
            if state.glue.is_some()
                && state.program.patch_gate.is_some()
                && state.program.patch_plan.is_some()
                && !gate_done
            {
                queue.push(item(
                    phase,
                    "patch-gate",
                    SpeculativeBranch,
                    1,
                    PendingWork::VerifyPatchGate,
                ));
            }
            if let Some(last) = state.assemblies.iter().rposition(|a| a.includes_late) {
                if !state.cell_reports.iter().any(|s| s.assembly_index == last) {
                    queue.push(item(
                        phase,
                        "cell-closure",
                        SpeculativeBranch,
                        2,
                        PendingWork::VerifyCellClosure,
                    ));
                }
            }
        }

        Phase::Execute => {
            let pass = state.gates_and_tokens.reports.iter().any(|r| {
                r.gate_id == GateId::GEffect && r.decision == GateReportDecisionKind::Pass
            });
            let issue_pending = pass
                && state.program.patch_plan.is_some()
                && state.gates_and_tokens.issued.is_empty();
            if issue_pending {
                queue.push(item(
                    phase,
                    "issue",
                    SpeculativeBranch,
                    0,
                    PendingWork::ExecuteIssue,
                ));
            }
            // Schritt 9 und 10 teilen die Phase (Regel 24.4 (Der Golden Run läuft unter tick): "execute
            // (9, 10)") - ein soeben auszustellendes Token wird deshalb
            // verkettet ausgefuehrt (`token: None`, aufgeloest beim
            // Dispatch), ein aus einem frueheren Takt liegendes steht
            // unter Rang 2 mit seiner Ablaufzeit an.
            if state.effects.is_empty() {
                for t in &state.gates_and_tokens.issued {
                    let issued = matches!(
                        state.gates_and_tokens.ledger.state_of(&t.idempotency_key),
                        Some(psk_effect::TokenState::Issued)
                    );
                    if issued {
                        queue.push(object_item(
                            t.id,
                            ExpiringEffectToken,
                            0,
                            Some(t.expires_at_tau_i),
                            PendingWork::ExecuteRun { token: Some(t.id) },
                        ));
                    }
                }
                if issue_pending {
                    queue.push(item(
                        phase,
                        "run",
                        SpeculativeBranch,
                        1,
                        PendingWork::ExecuteRun { token: None },
                    ));
                }
            }
        }

        Phase::Observe2 => {
            for (i, d) in state.program.receipt_deposits.iter().enumerate() {
                if !d.ingressed {
                    queue.push(item(
                        phase,
                        &format!("receipt:{i}"),
                        SpeculativeBranch,
                        0,
                        PendingWork::Observe2Receipt { deposit: i },
                    ));
                }
            }
        }

        Phase::Reconcile => {
            if let Some(attempt) = state.effects.first() {
                if !state.receipts.is_empty()
                    && state.reconciliations.is_empty()
                    && state.program.reconcile_spec.is_some()
                    && state.program.patch_plan.is_some()
                {
                    // Ein unversoehnter Effekt IST "offene Reconciliation"
                    // (Regel 14.5 (Prioritätsordnung), Rang 1).
                    queue.push(object_item(
                        attempt.id,
                        UnknownEffectOrOpenReconciliation,
                        0,
                        None,
                        PendingWork::Reconcile,
                    ));
                }
            }
        }

        Phase::Archive => {
            if state.residues.all().len() as u64 > state.archive_watermark {
                queue.push(item(
                    phase,
                    "gather",
                    SpeculativeBranch,
                    0,
                    PendingWork::ArchiveGatherResidues,
                ));
            }
        }
    }

    order_queue(queue)
}

/// Ordnet eine abgeleitete Warteschlange nach Regel 14.5 (siehe
/// `priority_order`), ohne die Nutzlast zu duplizieren.
pub(crate) fn order_queue(mut queue: Vec<QueuedItem>) -> Vec<QueuedItem> {
    let schedulables: Vec<SchedulableItem> = queue.iter().map(|q| q.schedulable).collect();
    let ordered = priority_order(schedulables);
    let mut result = Vec::with_capacity(queue.len());
    for target in ordered {
        let pos = queue
            .iter()
            .position(|q| q.schedulable.id == target.id)
            .expect("priority_order darf keine Elemente verlieren oder erfinden");
        result.push(queue.remove(pos));
    }
    result
}

/// Ob IRGENDEINE Phase noch Arbeit ableitet - die Terminierungsfrage der
/// Taktschleife eines Laufs: `while has_pending_work(state) { tick(...) }`.
/// Rein lesend und deterministisch (dieselbe Ableitung wie `select`).
pub fn has_pending_work(state: &Sigma) -> bool {
    CANONICAL_PHASES
        .into_iter()
        .any(|phase| !select(phase, state).is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(tier: PriorityTier, seed: &[u8], expires: Option<u64>) -> SchedulableItem {
        SchedulableItem {
            id: ObjectId::new(SortId::Context, Digest::sha256(seed)),
            tier,
            expires_at_tau_i: expires,
            obligation_rank: 0,
        }
    }

    #[test]
    fn higher_tiers_come_first() {
        let out = priority_order(vec![
            item(PriorityTier::SpeculativeBranch, b"a", None),
            item(PriorityTier::UnknownEffectOrOpenReconciliation, b"b", None),
            item(PriorityTier::RatchetingCapsule, b"c", None),
        ]);
        let tiers: Vec<_> = out.iter().map(|i| i.tier).collect();
        assert_eq!(
            tiers,
            vec![
                PriorityTier::UnknownEffectOrOpenReconciliation,
                PriorityTier::RatchetingCapsule,
                PriorityTier::SpeculativeBranch,
            ]
        );
    }

    #[test]
    fn within_expiring_tokens_smallest_expiry_first() {
        let out = priority_order(vec![
            item(PriorityTier::ExpiringEffectToken, b"a", Some(100)),
            item(PriorityTier::ExpiringEffectToken, b"b", Some(10)),
            item(PriorityTier::ExpiringEffectToken, b"c", Some(50)),
        ]);
        let expiries: Vec<_> = out.iter().map(|i| i.expires_at_tau_i).collect();
        assert_eq!(expiries, vec![Some(10), Some(50), Some(100)]);
    }

    #[test]
    fn ties_break_on_ascending_object_id() {
        let a = item(PriorityTier::RatchetingCapsule, b"zzz", None);
        let b = item(PriorityTier::RatchetingCapsule, b"aaa", None);
        let expect_first = if a.id.to_string() < b.id.to_string() {
            a.id
        } else {
            b.id
        };
        let out = priority_order(vec![a, b]);
        assert_eq!(out[0].id, expect_first);
    }

    #[test]
    fn a_lower_tier_never_jumps_an_expiring_token_regardless_of_expiry() {
        // Rang 1 vor Rang 2: unabhaengig davon, wie knapp das Token ablaeuft.
        let out = priority_order(vec![
            item(PriorityTier::ExpiringEffectToken, b"a", Some(1)),
            item(PriorityTier::UnknownEffectOrOpenReconciliation, b"b", None),
        ]);
        assert_eq!(out[0].tier, PriorityTier::UnknownEffectOrOpenReconciliation);
    }

    /// Regel 14.5 (Prioritätsordnung) Satz 1: Pflichtabhaengigkeiten ordnen VOR der ObjectId.
    /// Die Gegenprobe steckt im Aufbau: Rang 1 bekommt das Element mit
    /// der lexikographisch KLEINEREN ID - ohne den Rang kaeme es zuerst.
    #[test]
    fn obligation_rank_orders_before_the_object_id_tie_break() {
        let a = item(PriorityTier::SpeculativeBranch, b"aaa", None);
        let b = item(PriorityTier::SpeculativeBranch, b"zzz", None);
        let (mut smaller, larger) = if a.id.to_string() < b.id.to_string() {
            (a, b)
        } else {
            (b, a)
        };
        smaller.obligation_rank = 1;
        let out = priority_order(vec![smaller, larger]);
        assert_eq!(
            out[0].obligation_rank, 0,
            "Rang 0 zuerst, trotz groesserer ID"
        );
    }

    #[test]
    fn ordering_is_total_and_replay_stable() {
        let items = vec![
            item(PriorityTier::SpeculativeBranch, b"a", None),
            item(PriorityTier::DeclaredExternalDanger, b"b", None),
            item(PriorityTier::BlockingWitnessOrResidue, b"c", None),
        ];
        let once = priority_order(items.clone());
        let twice = priority_order(items);
        assert_eq!(once, twice);
    }

    #[test]
    fn empty_queue_is_fine() {
        assert!(priority_order(vec![]).is_empty());
    }

    /// Ein leerer Zustand leitet nirgends Arbeit ab - die Taktschleife
    /// eines Laufs ohne Programm terminiert sofort.
    #[test]
    fn an_empty_sigma_derives_no_work_in_any_phase() {
        let state = crate::sigma::tests::sample_sigma();
        for phase in CANONICAL_PHASES {
            assert!(
                select(phase, &state).is_empty(),
                "Phase {} leitet Arbeit aus leerem Zustand ab",
                phase.label()
            );
        }
        assert!(!has_pending_work(&state));
    }
}
