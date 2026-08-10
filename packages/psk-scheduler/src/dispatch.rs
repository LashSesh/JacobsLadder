//! `dispatch(phase, item, state)` (Algorithmus 14.4). Fuer jede Phase die
//! reale Modulfunktion, die Definition 14.2 (Phasen-Modul-Bindung) ihr
//! zuordnet - aufgeschluesselt in der 12-Phasen-Auditbericht dieser
//! Umsetzung.
//!
//! ## Empfaenger je Phase
//!
//! | Phase | Modul(e) | Reale Funktion(en) hier aufgerufen |
//! |---|---|---|
//! | Observe | M17 | `psk_anchor::bind_provenance` + `check_observer_separation` |
//! | Normalize | M01 | `psk_canon::can` |
//! | Type | M03, M06 | `psk_thought::compile_thought` (M06). M03: siehe unten |
//! | Anchor | M05, M07 | `psk_anchor::seal_anchor` (M05), `psk_thought::classify` (M07) |
//! | Project | M08, M09 | `psk_fields::register_field` (M08), `route_lens` (M09) |
//! | Compile | M10, M23 | `psk_dependency::dependency_quotient` (M10). M23: siehe unten |
//! | Challenge | M24 | `psk_adversarial::capsulate` + `ratchet` + `is_capsule_resolved` |
//! | Verify | M11, M14 | `psk_closure::evaluate` (M11), `psk_gate::evaluate_gate` (M14) |
//! | Execute | M15, M16 | `psk_effect::issue`, `execute_effect` - siehe Regel 22.3 unten |
//! | Observe (2) | M17 | `psk_anchor::build_receipt`. "oder UNKNOWN_EFFECT": siehe unten |
//! | Reconcile | M18 | `psk_reconciliation::reconcile` |
//! | Archive | M19 | `ResidueLedger::open_residues` (Sammelschritt; `seal_phase`/`close_tick` selbst laufen in `tick()`, nicht hier - siehe dortigen Kopf) |
//!
//! ## Fuenf dokumentierte Luecken (Audit vor dieser Umsetzung, Kapselfixpunkt
//! seither geschlossen)
//!
//! Vier leben als echte, aufrufbare `unimplemented!()`-Funktionen in ihrem
//! jeweils zustaendigen Paket (Muster `psk_topology::boundary`, jede mit
//! Verweis auf die konkrete Blockade): `psk_anchor::request_reanchor`
//! (Anchor, "oder ReanchorRequest"), `psk_ir::compile_ir_bundle` (Compile,
//! M23-Haelfte), `psk_closure::evaluate_with_gate_reports` (Verify,
//! ClosureReport-GateReport-Aggregation), `psk_anchor::observe_unknown_effect`
//! (Observe(2), "oder UNKNOWN_EFFECT"). Diese Datei ruft sie nicht auf -
//! `PendingWork` hat fuer sie bewusst keine Variante, da ein Aufruf nur in
//! einen Panic liefe.
//!
//! Die fuenfte (M03, Type-Phase) ist KEINE Funktionslücke: SchemaValidator
//! wird bereits real durchgesetzt, nur compile-time statt als Laufzeitpass
//! (`IRNode.sort: SortId` ist ein generiertes Pflichtfeld ohne `Option`,
//! siehe `architecture/object_schemas.yaml`/`psk-types::objects`). Es gibt
//! keine sinnvolle Laufzeitfunktion, die hier noch fehlt - deshalb keine
//! fuenfte `unimplemented!()`-Funktion, nur diese Feststellung.
//!
//! ## Warum `state: &mut Sigma` statt nur lesend
//!
//! Der Pseudocode liest `dispatch(phase, item, state)` als reine Funktion;
//! `M19.append`/`state = apply(...)` folgen separat. Zwei reale, bereits
//! getestete Empfaenger widersprechen dem strukturell: `evaluate_gate`
//! (Algorithmus 18.6, Invariante 18.7) und - fuer Regel 22.3s
//! Tokeninvalidierung - `TokenLedger::advance` verlangen `&mut
//! TraceStore`/`&mut ResidueLedger`/`&mut TokenLedger` als Teil ihrer
//! EIGENEN Korrektheit (die Synchronitaetsregel P28/P33 zwingt
//! `evaluate_gate` dazu, seinen TraceSegment selbst und unbedingt zu
//! schreiben). Diese Funktionen umzuschreiben, nur damit `dispatch()` rein
//! bliebe, haette bereits getestetes, richtiges Verhalten geopfert. Diese
//! Umsetzung nimmt deshalb `state: &mut Sigma`; `result.trace_segments`
//! traegt nur noch das AEUSSERE, taktbezogene Segment (wird die Phase
//! ueberhaupt durchlaufen), nicht das innere, das die aufgerufene Funktion
//! bereits selbst geschrieben hat (siehe die einzelnen Match-Arme).
//!
//! ## Warum `PendingWork` bereits typisierte Eingaben traegt, keine `ObjectId`
//!
//! `M25::select`s eigener Kopfkommentar haelt fest: "welche Elemente in
//! einer Phase ueberhaupt anstehen, ist Sache der Phase-Dispatchlogik,
//! nicht der Prioritaetsordnung selbst." Diese Umsetzung liest das als:
//! `dispatch()` ist ein typisierter Router zu bereits vorhandenen,
//! einzeln getesteten Funktionen, kein autonomer Entdeckungsmechanismus.
//! Jede `PendingWork`-Variante traegt deshalb die vollstaendigen,
//! bereits zusammengestellten Eingaben (genau wie `AnchorInputs`/
//! `ThoughtInputs`/`GateInputs` ueberall sonst im Werk vom AUFRUFER
//! kommen) statt einer `ObjectId`, die `dispatch()` selbst erst ausloesen
//! muesste. Woher diese Eingaben stammen (eine reale Aussenwelt-Queue),
//! baut diese Umsetzung nicht - das waere weit ueber "die Schale" hinaus.

use psk_anchor::ExternalRecord;
use psk_canon::Media;
use psk_effect::EffectAdapter;
use psk_gate::GateAuthorization;
use psk_trace::SegmentInputs;
use psk_types::objects::{
    AdapterId, ArchetypeId, CandidateCapsule, CapsuleId, DependencyProfileConsensusScopeKind,
    EffectToken, EventTypeId, FieldIdentity, FieldProjection, GateReport, ThoughtBody,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId, Phase, PskError};

use crate::Sigma;

/// Ein fuer eine Phase anstehendes Arbeitselement, bereits mit den
/// vollstaendigen Eingaben der Zielfunktion. Siehe Modulkopf.
pub enum PendingWork {
    Observe {
        record: ExternalRecord,
        source_adapter: AdapterId,
        observer_identity: Digest,
        method: String,
        effect_adapter_identity: Option<Digest>,
    },
    Normalize {
        bytes: Vec<u8>,
        media: Media,
    },
    TypeThought(psk_thought::ThoughtInputs),
    AnchorBind(psk_anchor::AnchorInputs),
    AnchorClassify {
        body: ThoughtBody,
        inputs: psk_thought::ClassificationInputs,
    },
    ProjectField {
        archetype: ArchetypeId,
        inputs: psk_fields::FieldRegistrationInputs,
    },
    ProjectLens {
        field: FieldIdentity,
        inputs: psk_fields::ProjectionInputs,
    },
    CompileDependency {
        projections: Vec<FieldProjection>,
        consensus_scope: DependencyProfileConsensusScopeKind,
    },
    ChallengeCapsulate {
        class: Vec<FieldProjection>,
        inputs: psk_adversarial::CapsuleInputs,
    },
    ChallengeRatchet {
        capsule: CandidateCapsule,
        survivors: Vec<CapsuleId>,
        rounds_used: u32,
        ratchet_max_rounds: u32,
    },
    VerifyClosure {
        c360: psk_closure::Close360Evidence,
        c720: psk_closure::Close720Evidence,
    },
    VerifyGate(psk_gate::GateInputs),
    ExecuteIssue {
        auth: GateAuthorization,
        inputs: psk_effect::IssueInputs,
    },
    /// Regel 22.3 (Replay laeuft unter shadow) entscheidet sich HIER: bei
    /// `state.i.profile in {Shadow, Readonly}` wird `adapter` nie
    /// aufgerufen - siehe den Execute-Match-Arm.
    ExecuteRun {
        token: EffectToken,
        current_tau_i: u64,
        started_at: DualTime,
        /// `Send`, damit `PendingWork` als Ganzes zwischen Threads
        /// wandern kann (Regel 14.7, siehe `concurrency_eligible`) - der
        /// Adapter selbst laeuft nie nebenlaeufig, aber eine Variante
        /// ohne `Send` machte das ganze Enum unbeweglich.
        adapter: Box<dyn EffectAdapter + Send>,
    },
    Observe2Receipt(psk_anchor::ObservationInputs),
    Reconcile(psk_reconciliation::ReconcileInputs),
    /// Sammelschritt fuer "Residuen persistiert" (siehe Modulkopf, M19-Zeile).
    ArchiveGatherResidues,
}

/// Was eine Phase produziert hat - `apply()`s Eingabe.
pub enum DispatchOutcome {
    Observed(psk_types::objects::Provenance),
    Normalized(Digest),
    ThoughtCompiled(ThoughtBody),
    AnchorSealed(psk_types::objects::AnchorSnapshot),
    RealityClassified(psk_types::objects::RealityClassification),
    FieldRegistered(FieldIdentity),
    LensRouted(psk_fields::LensOutcome),
    DependencyQuotiented(psk_types::objects::DependencyProfile),
    CapsuleSealed(CandidateCapsule),
    CapsuleRatcheted {
        capsule: CandidateCapsule,
        resolved: bool,
    },
    ClosureEvaluated(psk_closure::ClosureReport),
    GateEvaluated(GateReport),
    TokenIssued(EffectToken),
    EffectExecuted(psk_types::objects::EffectAttempt),
    /// Regel 22.3: Token wurde ueber P37/`plan_changed` invalidiert statt
    /// ausgefuehrt.
    EffectInvalidated {
        idempotency_key: String,
    },
    ReceiptBuilt(psk_types::objects::ExternalReceipt),
    Reconciled(psk_types::objects::ReconciliationReport),
    ResiduesGathered(Vec<ObjectId>),
}

/// `result` aus Algorithmus 14.4: das aeussere Traceseg­ment (falls die
/// aufgerufene Funktion nicht bereits selbst eines schreibt - siehe
/// Modulkopf) plus das Ergebnis fuer `apply()`.
pub struct DispatchResult {
    pub trace_segments: Vec<SegmentInputs>,
    pub outcome: DispatchOutcome,
}

fn seg(
    module: ModuleId,
    phase: Phase,
    payload: &impl serde::Serialize,
    time: DualTime,
    object_refs: Vec<ObjectId>,
) -> Result<SegmentInputs, PskError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| PskError::CanonicalizationFailed)?;
    let payload_digest = psk_canon::can(&bytes, Media::Json)?.digest();
    Ok(SegmentInputs {
        event_type: EventTypeId(format!("dispatch.{}", phase.label())),
        module,
        port_id: None,
        object_refs,
        payload_digest,
        time,
        attestation: None,
    })
}

/// `dispatch(phase, item, state)`. `phase` und die Variante von `work`
/// MUESSEN zusammenpassen (z.B. `Phase::Observe` nur mit
/// `PendingWork::Observe`) - eine Fehlpaarung ist ein Aufruffehler des
/// Taktschleifenverwalters (`tick()`/dessen Aufrufer), nicht etwas, das
/// diese Funktion heilen sollte; sie scheitert dafuer mit `UntypedInput`.
/// Regel 14.7 (Nebenlaeufigkeitsmodell): "Nebenlaeufigkeit ist zulaessig
/// innerhalb einer Phase und ausschliesslich fuer Operationen ohne
/// gemeinsamen Schreibzustand."
///
/// Genau vier Arbeitsarten haben gemeinsamen Schreibzustand, und sie sind
/// hier abschliessend aufgezaehlt, nicht geschaetzt - jede ist an ihrem
/// Match-Arm in `dispatch` nachlesbar:
///
/// - `VerifyGate`: `evaluate_gate` schreibt Trace UND Residuen selbst und
///   unbedingt (Algorithmus 18.6, Invariante 18.7).
/// - `ExecuteRun`: verbraucht bzw. invalidiert im `TokenLedger` - die
///   Einmaligkeitsgarantie IST gemeinsamer Schreibzustand.
/// - `Reconcile`: oeffnet Residuen (`residualize`).
/// - `ArchiveGatherResidues`: liest den Residuenstand; sein Ergebnis
///   haengt davon ab, welche Residuen zuvor geoeffnet wurden, ist also
///   reihenfolgeabhaengig, auch ohne selbst zu schreiben.
///
/// Alles Uebrige berechnet ein Ergebnis aus seinen eigenen, bereits
/// vollstaendigen Eingaben und beruehrt `Sigma` erst in `apply()` - das
/// ist der Teil, den Regel 14.7 freigibt.
pub fn concurrency_eligible(work: &PendingWork) -> bool {
    !matches!(
        work,
        PendingWork::VerifyGate(_)
            | PendingWork::ExecuteRun { .. }
            | PendingWork::Reconcile(_)
            | PendingWork::ArchiveGatherResidues
    )
}

/// Die zustandsfreie Haelfte von `dispatch` - dieselbe Berechnung, aber
/// ohne Zugriff auf `Sigma`, damit sie nebenlaeufig laufen DARF.
///
/// Gibt `UntypedInput` fuer jede nicht freigegebene Arbeitsart zurueck;
/// `dispatch` unten ruft sie nur fuer freigegebene auf. Die Trennung ist
/// damit nicht bloss dokumentiert, sondern typseitig wirksam: diese
/// Funktion KANN keinen gemeinsamen Zustand veraendern, weil sie keinen
/// bekommt.
pub fn dispatch_stateless(
    phase: Phase,
    work: PendingWork,
    time: DualTime,
) -> Result<DispatchResult, PskError> {
    if !concurrency_eligible(&work) {
        return Err(PskError::UntypedInput);
    }
    let mut unused = None;
    dispatch_inner(phase, work, &mut unused, time)
}

pub fn dispatch(
    phase: Phase,
    work: PendingWork,
    state: &mut Sigma,
    time: DualTime,
) -> Result<DispatchResult, PskError> {
    dispatch_inner(phase, work, &mut Some(state), time)
}

/// Gemeinsame Implementierung beider Einstiege. `state` ist `Option`,
/// damit `dispatch_stateless` denselben Code ohne Sigma benutzen kann -
/// EINE Match-Tabelle statt zweier, die auseinanderlaufen koennten. Die
/// vier zustandsbehafteten Arme fordern das `Some` ausdruecklich an; sie
/// sind ueber `concurrency_eligible` ohnehin von `dispatch_stateless`
/// ausgeschlossen, scheitern hier aber zusaetzlich fail-closed, statt
/// stillschweigend etwas anderes zu tun.
fn dispatch_inner(
    phase: Phase,
    work: PendingWork,
    state: &mut Option<&mut Sigma>,
    time: DualTime,
) -> Result<DispatchResult, PskError> {
    match (phase, work) {
        (
            Phase::Observe,
            PendingWork::Observe {
                record,
                source_adapter,
                observer_identity,
                method,
                effect_adapter_identity,
            },
        ) => {
            psk_anchor::check_observer_separation(observer_identity, effect_adapter_identity)?;
            let provenance =
                psk_anchor::bind_provenance(&record, source_adapter, observer_identity, method);
            let segment = seg(
                ModuleId::ExternalRecordIngress,
                phase,
                &provenance,
                time,
                vec![],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::Observed(provenance),
            })
        }

        (Phase::Normalize, PendingWork::Normalize { bytes, media }) => {
            let canonical = psk_canon::can(&bytes, media)?;
            let digest = canonical.digest();
            let segment = seg(ModuleId::Canonicalizer, phase, &digest, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::Normalized(digest),
            })
        }

        (Phase::Type, PendingWork::TypeThought(inputs)) => {
            // M03 (SchemaValidator): keine Laufzeitfunktion - siehe Modulkopf.
            let body = psk_thought::compile_thought(inputs)?;
            let segment = seg(ModuleId::ThoughtCompiler, phase, &body, time, vec![body.id])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ThoughtCompiled(body),
            })
        }

        (Phase::Anchor, PendingWork::AnchorBind(inputs)) => {
            let anchor = psk_anchor::seal_anchor(inputs)?;
            let segment = seg(
                ModuleId::AnchorRegistry,
                phase,
                &anchor,
                time,
                vec![anchor.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::AnchorSealed(anchor),
            })
        }
        (Phase::Anchor, PendingWork::AnchorClassify { body, inputs }) => {
            let classification = psk_thought::classify(&body, inputs)?;
            let segment = seg(
                ModuleId::RealityTyper,
                phase,
                &classification,
                time,
                vec![classification.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::RealityClassified(classification),
            })
        }

        (Phase::Project, PendingWork::ProjectField { archetype, inputs }) => {
            let field = psk_fields::register_field(archetype, inputs)?;
            let segment = seg(ModuleId::FieldRegistry, phase, &field, time, vec![field.id])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::FieldRegistered(field),
            })
        }
        (Phase::Project, PendingWork::ProjectLens { field, inputs }) => {
            let outcome = psk_fields::route_lens(&field, inputs)?;
            let segment = match &outcome {
                psk_fields::LensOutcome::Projected(p) => {
                    seg(ModuleId::SpectralLensRouter, phase, p, time, vec![p.id])?
                }
                psk_fields::LensOutcome::NotApplicable(r) => {
                    seg(ModuleId::SpectralLensRouter, phase, r, time, vec![r.id])?
                }
            };
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::LensRouted(outcome),
            })
        }

        (
            Phase::Compile,
            PendingWork::CompileDependency {
                projections,
                consensus_scope,
            },
        ) => {
            // M23 (IRCodec, IRBundle-Kandidat): siehe psk_ir::compile_ir_bundle
            // und Modulkopf - hier nicht aufgerufen.
            let profile = psk_dependency::dependency_quotient(psk_dependency::QuotientInputs {
                projections: &projections,
                method: psk_dependency::RankMethod::QuotientClassCount,
                consensus_scope,
            })?;
            let segment = seg(
                ModuleId::DependencyAnalyzer,
                phase,
                &profile,
                time,
                vec![profile.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::DependencyQuotiented(profile),
            })
        }

        (Phase::Challenge, PendingWork::ChallengeCapsulate { class, inputs }) => {
            let capsule = psk_adversarial::capsulate(&class, inputs)?;
            let segment = seg(
                ModuleId::AdversarialKernel,
                phase,
                &capsule,
                time,
                vec![capsule.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::CapsuleSealed(capsule),
            })
        }
        (
            Phase::Challenge,
            PendingWork::ChallengeRatchet {
                capsule,
                survivors,
                rounds_used,
                ratchet_max_rounds,
            },
        ) => {
            let after =
                psk_adversarial::ratchet(&capsule, &survivors, rounds_used, ratchet_max_rounds)?;
            let resolved = psk_adversarial::is_capsule_resolved(&capsule, &after);
            let segment = seg(
                ModuleId::AdversarialKernel,
                phase,
                &after,
                time,
                vec![after.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::CapsuleRatcheted {
                    capsule: after,
                    resolved,
                },
            })
        }

        (Phase::Verify, PendingWork::VerifyClosure { c360, c720 }) => {
            // ClosureReport ist handgeschrieben (nicht generiert, kein
            // gesicherter Serialize-Impl) - das Traceseg­ment traegt deshalb
            // die drei Felder einzeln statt des ganzen Berichts.
            let report = psk_closure::evaluate(&c360, &c720);
            let payload = (report.close360, report.close720, report.executable_eligible);
            let segment = seg(ModuleId::ClosureGlueEngine, phase, &payload, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ClosureEvaluated(report),
            })
        }
        (Phase::Verify, PendingWork::VerifyGate(inputs)) => {
            let state = state.as_deref_mut().ok_or(PskError::UntypedInput)?;
            // evaluate_gate schreibt sein TraceSegment bereits selbst,
            // unbedingt (Algorithmus 18.6/Invariante 18.7) - kein
            // zusaetzliches aeusseres Segment (siehe Modulkopf).
            let report = psk_gate::evaluate_gate(inputs, &mut state.trace, &mut state.residues)?;
            Ok(DispatchResult {
                trace_segments: vec![],
                outcome: DispatchOutcome::GateEvaluated(report),
            })
        }

        (Phase::Execute, PendingWork::ExecuteIssue { auth, inputs }) => {
            let token = psk_effect::issue(&auth, inputs)?;
            let segment = seg(
                ModuleId::EffectTokenService,
                phase,
                &token,
                time,
                vec![token.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::TokenIssued(token),
            })
        }
        (
            Phase::Execute,
            PendingWork::ExecuteRun {
                token,
                current_tau_i,
                started_at,
                mut adapter,
            },
        ) => {
            let state = state.as_deref_mut().ok_or(PskError::UntypedInput)?;
            match state.i.profile {
                psk_types::objects::ProfileId::Shadow | psk_types::objects::ProfileId::Readonly => {
                    // Regel 22.3 (Replay laeuft unter shadow): "Plan und Token
                    // werden erzeugt, aber sofort invalidiert." Durchsetzung
                    // ueber die bestehende Tokeninvalidierung
                    // (FSM-TOKEN-Operator `plan_changed`, P37), NICHT ueber
                    // `execute_effect` - der Adapter wird nie aufgerufen.
                    let key = token.idempotency_key.clone();
                    state
                        .gates_and_tokens
                        .ledger
                        .advance(&key, "plan_changed")?;
                    let segment = seg(ModuleId::EffectBoundary, phase, &key, time, vec![token.id])?;
                    Ok(DispatchResult {
                        trace_segments: vec![segment],
                        outcome: DispatchOutcome::EffectInvalidated {
                            idempotency_key: key,
                        },
                    })
                }
                _ => {
                    let attempt = psk_effect::execute_effect(
                        &mut state.gates_and_tokens.ledger,
                        &token,
                        current_tau_i,
                        started_at.clone(),
                        &mut adapter,
                    )?;
                    let segment = seg(
                        ModuleId::EffectBoundary,
                        phase,
                        &attempt,
                        started_at,
                        vec![attempt.id],
                    )?;
                    Ok(DispatchResult {
                        trace_segments: vec![segment],
                        outcome: DispatchOutcome::EffectExecuted(attempt),
                    })
                }
            }
        }

        (Phase::Observe2, PendingWork::Observe2Receipt(inputs)) => {
            // "oder UNKNOWN_EFFECT": siehe psk_anchor::observe_unknown_effect
            // und Modulkopf - hier nicht aufgerufen.
            let receipt = psk_anchor::build_receipt(inputs)?;
            let segment = seg(
                ModuleId::ExternalRecordIngress,
                phase,
                &receipt,
                time,
                vec![receipt.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ReceiptBuilt(receipt),
            })
        }

        (Phase::Reconcile, PendingWork::Reconcile(inputs)) => {
            let state = state.as_deref_mut().ok_or(PskError::UntypedInput)?;
            let report = psk_reconciliation::reconcile(inputs, &mut state.residues)?;
            let segment = seg(
                ModuleId::ReconciliationEngine,
                phase,
                &report,
                time,
                vec![report.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::Reconciled(report),
            })
        }

        (Phase::Archive, PendingWork::ArchiveGatherResidues) => {
            let state = state.as_deref_mut().ok_or(PskError::UntypedInput)?;
            let open_ids: Vec<ObjectId> = state.residues.open_residues().map(|r| r.id).collect();
            let segment = seg(
                ModuleId::TraceReplayResidueStore,
                phase,
                &open_ids,
                time,
                open_ids.clone(),
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ResiduesGathered(open_ids),
            })
        }

        _ => Err(PskError::UntypedInput),
    }
}
