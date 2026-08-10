//! `dispatch(phase, item, state)` (Algorithmus 14.4 (Tick)). Fuer jede Phase die
//! reale Modulfunktion, die Definition 14.2 (Phasen-Modul-Bindung) ihr
//! zuordnet.
//!
//! ## Empfaenger je Phase
//!
//! | Phase | Modul(e) | Reale Funktion(en) hier aufgerufen |
//! |---|---|---|
//! | Observe | M17 | `psk_anchor::bind_provenance` + `check_observer_separation` |
//! | Normalize | M01 | `psk_canon::can` (C1 ueber dem Kandidaten, Regel 5.9 (Kandidat und Gedankenkörper)) |
//! | Type | M03, M06 | C2: Primaersorte des Kandidaten. M03: siehe unten |
//! | Anchor | M05, M06, M07 | `psk_anchor::seal_anchor` (M05), `psk_thought::compile_thought` (M06 - die Praegung, Regel 5.9 (Kandidat und Gedankenkörper): "Anker in anchor, Praegung ebendort"), `psk_thought::classify` (M07) |
//! | Project | M08, M09 | `psk_fields::register_field` (M08), `route_lens` (M09) |
//! | Compile | M10, M23 | `psk_dependency::dependency_quotient` (M10), `psk_ir::build_node`/`assemble_ir_bundle` (M23), `psk_topology::close_all_18` + `psk_closure::glue` (Schritt 6: "lokale Resultate verkleben") |
//! | Challenge | M24 | `psk_adversarial::identify_contradictions`/`integrator_obstruction` + `capsulate` + `ratchet`-bis-Aufloesung + `check_support` |
//! | Verify | M11, M14, M22 | `psk_closure::evaluate` (M11), `psk_topology::close_all_18` (M22, Vertrag 9.7 (Zellclosure) ueber dem finalen Graphen), `psk_gate::evaluate_gate` (M14) |
//! | Execute | M15, M16 | `psk_effect::issue`, `prestate` + `execute_effect` ueber die angeschlossene Leitung (Regel 20.6 (Vorzustand und Versuch klammern den Effekt)) - Regel 22.3 (Replay läuft unter shadow) siehe unten |
//! | Observe (2) | M17 | `psk_anchor::ingress_p24_via_exclusive_pipe` ueber das Deponat. "oder UNKNOWN_EFFECT": siehe unten |
//! | Reconcile | M18 | `psk_reconciliation::reconcile` |
//! | Archive | M19 | Sammelschritt ueber dem Residuenstand (`seal_phase`/`close_tick` laufen in `tick()`, nicht hier) |
//!
//! Die Praegung (M06) laeuft nach Regel 5.9 (Kandidat und Gedankenkoerper)
//! in der ANCHOR-Phase ("Praegung ebendort"), obwohl Definition 14.2 (Phasen-Modul-Bindung) der
//! Anchor-Phase M05/M07 zuordnet - die speziellere und juengere Regel
//! entscheidet die Phasenlage der Praegung ausdruecklich. Ebenso laeuft
//! das Verkleben (M11) als Teil von Schritt 6 in der Compile-Phase: Regel
//! 24.4 ordnet Schritt 6 compile/challenge zu, und die Zellclosure ueber
//! dem Compile-Graphen ist die Eingabeableitung des Verklebens
//! (`cells_closed` ist ein Messwert, keine Behauptung).
//!
//! ## Verbleibende dokumentierte Luecken
//!
//! Drei leben als echte, aufrufbare `unimplemented!()`-Funktionen in ihrem
//! jeweils zustaendigen Paket: `psk_anchor::request_reanchor` (Anchor,
//! "oder ReanchorRequest"), `psk_closure::evaluate_with_gate_reports`
//! (Verify, ClosureReport-GateReport-Aggregation),
//! `psk_anchor::observe_unknown_effect` (Observe(2), "oder
//! UNKNOWN_EFFECT"). `psk_ir::compile_ir_bundle` war die vierte; ihr
//! Gegenstand - der IRBundle-Kandidat als Compile-Phasenarbeit - laeuft
//! seit der Taktumverdrahtung real ueber `CompileAssemble` unten
//! (`psk_ir::builders` + `assemble_ir_bundle`). Die M03-Feststellung
//! (SchemaValidator compile-time statt Laufzeitpass) gilt unveraendert.
//!
//! ## Verweise statt eingebetteter Werte
//!
//! Eine fruehere Fassung dieses Kopfes begruendete, warum jede
//! `PendingWork`-Variante "die vollstaendigen, bereits zusammengestellten
//! Eingaben" trug, und stuetzte sich dabei auf `select`s damaligen
//! Kopfkommentar. Diese Entscheidung ist vom Auftraggeber ausdruecklich
//! zurueckgenommen ("Ich habe damit den Kommentar der Implementierung
//! ueber den Algorithmus gestellt"): `M25.select(phase, state)` leitet
//! die anstehende Arbeit aus Sigma ab, und die Varianten tragen VERWEISE
//! in den Zustand - Indizes in die deponierten Programmlisten, ObjectIds
//! fuer kanonische Objekte. Aufgeloest wird BEIM DISPATCH, nicht beim
//! Einreihen: so sieht ein spaeteres Element derselben Phase die
//! Ergebnisse der frueheren (Regel 5.9 (Kandidat und Gedankenkörper) verlangt genau das fuer die
//! Praegung), und ein Verweis, der nicht aufloest, scheitert typisiert
//! mit `UntypedInput` statt still.
//!
//! ## Lesende und schreibende Arme (Regel 14.7 (Nebenläufigkeitsmodell))
//!
//! Regel 14.7 (Nebenläufigkeitsmodell) laesst Nebenlaeufigkeit "ausschliesslich fuer Operationen
//! ohne gemeinsamen SCHREIBzustand" zu. Verweisaufloesung ist Lesen.
//! Deshalb gibt es zwei Einstiege: `dispatch_readonly(phase, work,
//! &Sigma, time)` fuer die freigegebenen Arme (aufloesen + rechnen, kein
//! Schreiben - typseitig erzwungen, die Funktion BEKOMMT kein `&mut`)
//! und `dispatch(phase, work, &mut Sigma, lines, time)` fuer alles;
//! die fuenf schreibenden Arme sind in `concurrency_eligible`
//! abschliessend aufgezaehlt, jede an ihrem Match-Arm nachlesbar:
//!
//! - `ChallengeContradictions`: oeffnet Residuen (der Integrator).
//! - `VerifyPatchGate`: `evaluate_gate` schreibt Trace UND Residuen
//!   selbst und unbedingt (Algorithmus 18.6 (Gate-Auswertung), Invariante 18.7 (Gatebericht immer)).
//! - `ExecuteRun`: verbraucht bzw. invalidiert im `TokenLedger` und
//!   spricht die exklusive Effektleitung - beides gemeinsamer
//!   Schreibzustand.
//! - `Reconcile`: residualisiert (`reconcile` nimmt den Ledger).
//! - `ArchiveGatherResidues`: liest den Residuenstand reihenfolgeabhaengig.

use psk_canon::Media;
use psk_effect::EffectLines;
use psk_trace::SegmentInputs;
use psk_types::objects::{
    EventTypeId, GateId, GateReportDecisionKind, RelationSortId, SortId, SurfaceDescriptor,
    ThoughtBody, TickId,
};
use psk_types::{Digest, DualTime, ModuleId, ObjectId, Phase, PskError, TraceRef};

use crate::Sigma;

/// Ein fuer eine Phase anstehendes Arbeitselement - Verweise in den
/// Laufzustand, aufgeloest beim Dispatch (siehe Modulkopf). `usize`-Felder
/// sind Indizes in die jeweilige deponierte Programmliste; `ObjectId`-
/// Felder verweisen auf kanonische Objekte in Sigma.
pub enum PendingWork {
    /// Observe (M17): Provenienz eines deponierten Aussenrecords binden.
    Observe { record: usize },
    /// Normalize (M01/C1): den Kandidaten kanonisieren (Regel 5.9 (Kandidat und Gedankenkörper)).
    NormalizeCandidate { candidate: usize },
    /// Type (C2): die Primaersorte des Kandidaten bestimmen (Regel 5.9 (Kandidat und Gedankenkörper)).
    TypeCandidate { candidate: usize },
    /// Anchor (M05): das gebundene Record als AnchorSnapshot versiegeln.
    AnchorBind { record: usize },
    /// Anchor (M06): die Praegung - Regel 5.9 (Kandidat und Gedankenkörper), "Praegung ebendort".
    MintThought { candidate: usize },
    /// Anchor (M07): den gepraegten Gedanken klassifizieren (Schritt 4).
    AnchorClassify { candidate: usize },
    /// Project (M08): einen deklarierten Archetyp registrieren.
    ProjectField { entry: usize },
    /// Project (M09): die Projektion des registrierten Felds routen.
    ProjectLens { entry: usize },
    /// Compile (M10): Abhaengigkeiten quotieren.
    CompileQuotient,
    /// Compile (M23): den IRBundle-Kandidaten zusammenbauen.
    CompileAssemble,
    /// Compile (M22+M11, Schritt 6b): Zellclosure ueber dem
    /// Compile-Graphen, dann verkleben - `cells_closed` als Messwert.
    CompileGlue,
    /// Challenge (M24): Widersprueche identifizieren, offene
    /// residualisieren, Obstruktionen erzeugen (der Integrator).
    ChallengeContradictions,
    /// Challenge (M24): je Quotientenklasse eine Kapsel versiegeln.
    ChallengeCapsulate,
    /// Challenge (M24): Ratchet bis Kapselfixpunkt oder RESIDUAL
    /// (Definition 14.2 (Phasen-Modul-Bindung): beides ist ein Zustand NACH beliebig vielen
    /// Runden), dann Nichttrivialitaetswache und Supportentscheidung.
    ChallengeResolve { capsule: ObjectId },
    /// Verify (Schritt 7): offene Obligationen read-only pruefen.
    VerifyValidation,
    /// Verify (M11): Definition 9.16 (360-Grad-Closure)/9.17 ueber deponierte Evidenzen -
    /// der generische Pfad; der Referenzlauf nimmt die Zellclosure.
    VerifyClosure,
    /// Verify (M22, Vertrag 9.7 (Zellclosure)): alle 18 Zellen ueber dem finalen
    /// Graphen schliessen.
    VerifyCellClosure,
    /// Verify (M14, Schritt 8): das Folgen- und Risikogate des
    /// Patchplans auswerten.
    VerifyPatchGate,
    /// Execute (M15, Schritt 9): EffectToken fuer den deponierten
    /// Patchplan ausstellen.
    ExecuteIssue,
    /// Execute (M16, Schritt 10). Regel 22.3 (Replay laeuft unter
    /// shadow) entscheidet sich HIER: bei `state.i.profile in {Shadow,
    /// Readonly}` wird die Leitung nie gesprochen - siehe Match-Arm.
    /// `token: None` heisst "das in dieser Phase ausgestellte" (Regel
    /// 24.4 legt Schritt 9 und 10 in EINE Phase; beim Einreihen
    /// existiert die Token-ID noch nicht, beim Dispatch schon).
    ExecuteRun { token: Option<ObjectId> },
    /// Observe(2) (M17): eine deponierte P24-Antwort ingressieren.
    Observe2Receipt { deposit: usize },
    /// Reconcile (M18, Schritt 12).
    Reconcile,
    /// Archive (M19): Sammelschritt fuer "Residuen persistiert".
    ArchiveGatherResidues,
}

/// Was eine Phase produziert hat - `apply()`s Eingabe. Indizes verbinden
/// das Produkt mit seinem Programmeintrag (Fortschrittsmarken).
pub enum DispatchOutcome {
    Observed {
        record: usize,
        provenance: psk_types::objects::Provenance,
    },
    CandidateNormalized {
        candidate: usize,
        digest: Digest,
    },
    CandidateTyped {
        candidate: usize,
        sort: SortId,
    },
    AnchorSealed {
        record: usize,
        anchor: psk_types::objects::AnchorSnapshot,
    },
    ThoughtMinted {
        candidate: usize,
        body: ThoughtBody,
    },
    RealityClassified(psk_types::objects::RealityClassification),
    FieldRegistered {
        entry: usize,
        field: psk_types::objects::FieldIdentity,
    },
    LensRouted {
        entry: usize,
        projection: psk_types::objects::FieldProjection,
    },
    DependencyQuotiented(psk_types::objects::DependencyProfile),
    Assembled(crate::AssemblyRecord),
    Glued {
        assembly_index: usize,
        cells: Vec<psk_topology::CellReport>,
        outcome: psk_closure::GlueOutcome,
    },
    ContradictionsIdentified {
        contradictions: Vec<psk_adversarial::Contradiction>,
        obstructions: Vec<psk_types::objects::ObstructionRecord>,
    },
    CapsuleSealed(psk_types::objects::CandidateCapsule),
    ChallengeResolved {
        /// Die ID der versiegelten Kapsel, die zur Aufloesung anstand -
        /// die Aufloesung praegt eine neue (inhaltsadressierte) ID, und
        /// `apply` ersetzt am Platz der alten.
        sealed: ObjectId,
        capsule: psk_types::objects::CandidateCapsule,
        record: crate::ChallengeRecord,
    },
    ValidationChecked {
        obligations: Vec<psk_types::objects::ObligationExpr>,
    },
    ClosureEvaluated(psk_closure::ClosureReport),
    CellsClosed {
        assembly_index: usize,
        reports: Vec<psk_topology::CellReport>,
    },
    GateEvaluated(psk_types::objects::GateReport),
    TokenIssued(psk_types::objects::EffectToken),
    EffectExecuted(psk_types::objects::EffectAttempt),
    /// Regel 22.3 (Replay läuft unter shadow): Token wurde ueber P37/`plan_changed` invalidiert statt
    /// ausgefuehrt.
    EffectInvalidated {
        idempotency_key: String,
    },
    ReceiptIngressed {
        deposit: usize,
        receipt: psk_types::objects::ExternalReceipt,
    },
    Reconciled(psk_types::objects::ReconciliationReport),
    ResiduesGathered(Vec<ObjectId>),
}

/// `result` aus Algorithmus 14.4 (Tick): das aeussere Traceseg­ment (falls die
/// aufgerufene Funktion nicht bereits selbst eines schreibt) plus das
/// Ergebnis fuer `apply()`.
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

/// Regel 14.7 (Nebenlaeufigkeitsmodell): welche Arbeitsarten OHNE
/// gemeinsamen Schreibzustand rechnen. Die fuenf schreibenden sind im
/// Modulkopf aufgezaehlt und an ihren Match-Armen nachlesbar.
pub fn concurrency_eligible(work: &PendingWork) -> bool {
    !matches!(
        work,
        PendingWork::ChallengeContradictions
            | PendingWork::VerifyPatchGate
            | PendingWork::ExecuteRun { .. }
            | PendingWork::Reconcile
            | PendingWork::ArchiveGatherResidues
    )
}

// ------------------------------------------------------- Aufloesehelfer

fn record_at(state: &Sigma, i: usize) -> Result<&crate::PendingRecord, PskError> {
    state.program.records.get(i).ok_or(PskError::UntypedInput)
}

fn candidate_at(state: &Sigma, i: usize) -> Result<&psk_thought::Candidate, PskError> {
    state.candidates.get(i).ok_or(PskError::UntypedInput)
}

fn entry_at(state: &Sigma, i: usize) -> Result<&crate::FieldFamilyEntry, PskError> {
    state
        .program
        .field_family
        .get(i)
        .ok_or(PskError::UntypedInput)
}

fn first_anchor(state: &Sigma) -> Result<&psk_types::objects::AnchorSnapshot, PskError> {
    state.anchors.first().ok_or(PskError::UntypedInput)
}

fn first_thought(state: &Sigma) -> Result<&ThoughtBody, PskError> {
    state.thoughts.first().ok_or(PskError::UntypedInput)
}

fn declarations(state: &Sigma) -> Result<&crate::AssemblyDeclarations, PskError> {
    state
        .program
        .declarations
        .as_ref()
        .ok_or(PskError::UntypedInput)
}

/// Vertrag 9.7 (Zellclosure) ueber einem Zusammenbau: Kontext aus deponierten
/// Registern und den Sondierungsvermerken des Zusammenbaus bauen und
/// alle 18 Zellen schliessen. Von CompileGlue (Compile-Graph) und
/// VerifyCellClosure (finaler Graph) gleichermassen benutzt.
fn close_cells_over(
    state: &Sigma,
    record: &crate::AssemblyRecord,
) -> Result<Vec<psk_topology::CellReport>, PskError> {
    let decls = declarations(state)?;
    let ctx = psk_topology::ClosureContext {
        witnesses: &record.bundle.witnesses,
        residues: &record.bundle.residues,
        bundle_trace: &record.bundle.trace_ref,
        port_matrix: &decls.port_matrix,
        sort_owner: &decls.sort_owner,
        module_layer: &decls.module_layer,
        shared_pass_carriers: &decls.shared_pass_carriers,
        probes: &record.probes,
        max_depth: state.i.max_depth,
    };
    psk_topology::close_all_18(&record.bundle.graph, &ctx)
}

/// Der Zusammenbau (Compile, M23): Knoten aus den kanonischen Objekten
/// des Laufs, Kanten nur, wo ein reales Objektfeld die Verknuepfung
/// festhaelt. Die Effektobjekte (Schritte 9-12) kommen erst in den
/// FINALEN Graphen - ein fruehererer Zusammenbau haette dieselben Kanten
/// nur weglassen muessen (deshalb schaltet `select` den zweiten
/// Zusammenbau erst, wenn die Reconciliation vorliegt).
fn assemble(state: &Sigma, time: DualTime) -> Result<crate::AssemblyRecord, PskError> {
    use psk_ir::{build_node, edge, NodeEnvelope};

    let decls = declarations(state)?;
    let anchor = first_anchor(state)?;
    let thought = first_thought(state)?;
    let reality = state
        .reality_horizon
        .first()
        .ok_or(PskError::UntypedInput)?;
    let profile = state.dependencies.first().ok_or(PskError::UntypedInput)?;
    let late = if state.reconciliations.is_empty() {
        None
    } else {
        Some((
            state
                .gates_and_tokens
                .issued
                .first()
                .ok_or(PskError::UntypedInput)?,
            state.effects.first().ok_or(PskError::UntypedInput)?,
            state.receipts.first().ok_or(PskError::UntypedInput)?,
            state
                .reconciliations
                .first()
                .ok_or(PskError::UntypedInput)?,
        ))
    };

    let trace_ref = TraceRef(state.trace.head());
    // QPM Regel 3.9 (Präzedenz unter den Erzeugern) baut auf diesem Rueckverweis auf: der Ledger fuehrt
    // `origin_object` vorwaerts, der Knoten fuehrt ihn zurueck. Ohne ihn
    // koennte die Massenklasse Residuum nie von null verschieden werden.
    let opened_residues = state.residues.all();
    let by_origin = psk_ir::residues_by_origin(opened_residues);
    let env_for = |id: ObjectId| NodeEnvelope {
        residue_refs: by_origin.get(&id).cloned().unwrap_or_default(),
        // Der einzige reale ContextRef des Laufs sitzt auf dem Anker;
        // die Lineage ist die, die der Lauf am ThoughtBody deklariert -
        // beides aus dem Zustand, nichts hier erfunden.
        context: anchor.context.clone(),
        lineage: thought.lineage.clone(),
        reality_status: reality.reality_status,
        facticity: thought.facticity,
        anchor_ref: anchor.id,
        trace_ref,
    };

    let mut probes: Vec<(ObjectId, Vec<u8>)> = Vec::new();
    let mut nodes = Vec::new();
    nodes.push(build_node(
        anchor,
        anchor.id,
        SortId::Anchor,
        &env_for(anchor.id),
        &mut probes,
    )?);
    nodes.push(build_node(
        thought,
        thought.id,
        SortId::Context,
        &env_for(thought.id),
        &mut probes,
    )?);
    nodes.push(build_node(
        reality,
        reality.id,
        SortId::Horizon,
        &env_for(reality.id),
        &mut probes,
    )?);
    for f in &state.fields {
        nodes.push(build_node(
            f,
            f.id,
            SortId::FieldIdentity,
            &env_for(f.id),
            &mut probes,
        )?);
    }
    for p in &state.projections {
        nodes.push(build_node(
            p,
            p.id,
            SortId::Projection,
            &env_for(p.id),
            &mut probes,
        )?);
    }
    nodes.push(build_node(
        profile,
        profile.id,
        SortId::Dependency,
        &env_for(profile.id),
        &mut probes,
    )?);
    if let Some((token, attempt, receipt, reconciliation)) = late {
        nodes.push(build_node(
            token,
            token.id,
            SortId::Capability,
            &env_for(token.id),
            &mut probes,
        )?);
        nodes.push(build_node(
            attempt,
            attempt.id,
            SortId::Effect,
            &env_for(attempt.id),
            &mut probes,
        )?);
        nodes.push(build_node(
            receipt,
            receipt.id,
            SortId::Receipt,
            &env_for(receipt.id),
            &mut probes,
        )?);
        nodes.push(build_node(
            reconciliation,
            reconciliation.id,
            SortId::Reconciliation,
            &env_for(reconciliation.id),
            &mut probes,
        )?);
    }

    let mut candidates = Vec::new();
    // grounds: ThoughtBody.anchor_refs enthaelt anchor.id.
    if thought.anchor_refs.contains(&anchor.id) {
        candidates.push(edge(
            anchor.id,
            thought.id,
            RelationSortId::Grounds,
            "ThoughtBody.anchor_refs",
            trace_ref,
        ));
    }
    // defines: RealityClassification.anchor_ref == anchor.id.
    if reality.anchor_ref == anchor.id {
        candidates.push(edge(
            anchor.id,
            reality.id,
            RelationSortId::Defines,
            "RealityClassification.anchor_ref",
            trace_ref,
        ));
    }
    // projects: FieldProjection.field_ref == field.id.
    for p in &state.projections {
        if let Some(f) = state.fields.iter().find(|f| f.id == p.field_ref) {
            candidates.push(edge(
                f.id,
                p.id,
                RelationSortId::Projects,
                "FieldProjection.field_ref",
                trace_ref,
            ));
        }
    }
    // shares_source: die Projektion steht in einer Quotientenklasse.
    for p in &state.projections {
        if profile
            .quotient_classes
            .iter()
            .any(|class| class.contains(&p.id))
        {
            candidates.push(edge(
                p.id,
                profile.id,
                RelationSortId::SharesSource,
                "DependencyProfile.quotient_classes",
                trace_ref,
            ));
        }
    }
    if let Some((token, attempt, receipt, reconciliation)) = late {
        // authorizes: EffectToken.gate_report_ref. Deklariert und belegt -
        // aber der GateReport traegt keinen Knoten (zellgebunden), also
        // entsteht keine Kante, sondern EndpointMissing. Der Kandidat wird
        // trotzdem vorgelegt, damit die Luecke im Bericht erscheint statt
        // stillschweigend zu fehlen.
        candidates.push(edge(
            token.gate_report_ref,
            token.id,
            RelationSortId::Authorizes,
            "EffectToken.gate_report_ref",
            trace_ref,
        ));
        // permits: EffectAttempt.token_ref == token.id.
        if attempt.token_ref == token.id {
            candidates.push(edge(
                token.id,
                attempt.id,
                RelationSortId::Permits,
                "EffectAttempt.token_ref",
                trace_ref,
            ));
        }
        // feeds: ReconciliationReport.receipt_refs enthaelt receipt.id.
        if reconciliation.receipt_refs.contains(&receipt.id) {
            candidates.push(edge(
                receipt.id,
                reconciliation.id,
                RelationSortId::Feeds,
                "ReconciliationReport.receipt_refs",
                trace_ref,
            ));
        }
    }

    let outcome = psk_ir::assemble_ir_bundle(psk_ir::AssemblyInputs {
        version: decls.version.clone(),
        constitution_id: state.i.constitution_id,
        nodes,
        edge_candidates: candidates,
        declarations: &decls.edge_conditions,
        port_matrix: &decls.port_matrix,
        anchor_refs: vec![anchor.id],
        field_projections: state.projections.iter().map(|p| p.id).collect(),
        dependencies: profile.id,
        // Kein EvidenceObject im Referenzlauf.
        witnesses: Vec::new(),
        // IRBundle.residues (R) ist das Aufloesungsuniversum der
        // Residuenverweise - seit die Knoten `residue_refs` tragen, MUSS
        // es sie enthalten (Vertrag 9.7 (Zellclosure)).
        residues: opened_residues.iter().map(|r| r.id).collect(),
        gate_reports: Vec::new(),
        trace_ref,
        opened_at: time,
        scope: decls.scope.clone(),
    })?;
    Ok(crate::AssemblyRecord {
        bundle: outcome.bundle,
        probes,
        omissions: outcome.omissions,
        scope_residues: outcome.residues,
        includes_late: late.is_some(),
    })
}

// ----------------------------------------------------------- Einstiege

/// Die lesende Haelfte (Regel 14.7 (Nebenläufigkeitsmodell)): loest Verweise auf und rechnet,
/// OHNE Sigma veraendern zu koennen - sie bekommt kein `&mut`. Gibt
/// `UntypedInput` fuer jede nicht freigegebene Arbeitsart zurueck.
pub fn dispatch_readonly(
    phase: Phase,
    work: PendingWork,
    state: &Sigma,
    time: DualTime,
) -> Result<DispatchResult, PskError> {
    match (phase, work) {
        (Phase::Observe, PendingWork::Observe { record }) => {
            let entry = record_at(state, record)?;
            psk_anchor::check_observer_separation(
                entry.observer_identity,
                entry.effect_adapter_identity,
            )?;
            let provenance = psk_anchor::bind_provenance(
                &entry.record,
                entry.source_adapter.clone(),
                entry.observer_identity,
                entry.method.clone(),
            );
            let segment = seg(
                ModuleId::ExternalRecordIngress,
                phase,
                &provenance,
                time,
                vec![],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::Observed { record, provenance },
            })
        }

        (Phase::Normalize, PendingWork::NormalizeCandidate { candidate }) => {
            let c = candidate_at(state, candidate)?;
            // C1: H(Can(Quellfelder)) - die kanonisierte Vorform. Die
            // Feldreihenfolge ist die der Struktur, nicht neu gewaehlt.
            let source = (
                &c.claim,
                &c.models,
                &c.trajectories,
                &c.uncertainty,
                &c.consequences,
                &c.lineage,
            );
            let bytes =
                serde_json::to_vec(&source).map_err(|_| PskError::CanonicalizationFailed)?;
            let digest = psk_canon::can(&bytes, Media::Json)?.digest();
            let segment = seg(ModuleId::Canonicalizer, phase, &digest, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::CandidateNormalized { candidate, digest },
            })
        }

        (Phase::Type, PendingWork::TypeCandidate { candidate }) => {
            let c = candidate_at(state, candidate)?;
            if c.canonical_digest.is_none() {
                // C2 setzt C1 voraus (Regel 5.9 (Kandidat und Gedankenkörper): "kanonisierte, sortierte
                // Vorform" - in dieser Reihenfolge).
                return Err(PskError::UntypedInput);
            }
            // M03 (SchemaValidator): keine Laufzeitfunktion - compile-time
            // durchgesetzt (siehe Modulkopf). Die Primaersorte des
            // Auftragskandidaten ist S-CTX: dieselbe Sorte, unter der der
            // gepraegte ThoughtBody im Zusammenbau seinen Knoten traegt
            // (`assemble` unten) - EINE Zuordnung, zwei Leser.
            let sort = SortId::Context;
            let segment = seg(ModuleId::ThoughtCompiler, phase, &sort.id(), time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::CandidateTyped { candidate, sort },
            })
        }

        (Phase::Anchor, PendingWork::AnchorBind { record }) => {
            let entry = record_at(state, record)?;
            let provenance = entry.provenance.clone().ok_or(PskError::UntypedInput)?;
            let anchor = psk_anchor::seal_anchor(psk_anchor::AnchorInputs {
                observations: entry.observations.clone(),
                provenance,
                uncertainty: psk_anchor::no_declared_uncertainty(entry.uncertainty_model.clone()),
                context: entry.context.clone(),
                time: time.clone(),
                validity: entry.validity.clone(),
                boundary: entry.boundary.clone(),
            })?;
            let segment = seg(
                ModuleId::AnchorRegistry,
                phase,
                &anchor,
                time,
                vec![anchor.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::AnchorSealed { record, anchor },
            })
        }

        (Phase::Anchor, PendingWork::MintThought { candidate }) => {
            let c = candidate_at(state, candidate)?;
            if c.sort.is_none() {
                // Praegung setzt die sortierte Vorform voraus (Regel 5.9 (Kandidat und Gedankenkörper)).
                return Err(PskError::UntypedInput);
            }
            // Alle versiegelten Anker des Laufs gruenden den Gedanken -
            // beim Referenzlauf genau einer. Aufgeloest BEIM DISPATCH:
            // der AnchorBind derselben Phase ist bereits angewandt.
            let anchor_refs: Vec<ObjectId> = state.anchors.iter().map(|a| a.id).collect();
            if anchor_refs.is_empty() {
                return Err(PskError::MissingAnchor);
            }
            let body = psk_thought::compile_thought(psk_thought::ThoughtInputs {
                anchor_refs,
                unanchored: false,
                claim: c.claim.clone(),
                models: c.models.clone(),
                trajectories: c.trajectories.clone(),
                uncertainty: c.uncertainty.clone(),
                consequences: c.consequences.clone(),
                lineage: c.lineage.clone(),
                trace_ref: TraceRef(state.trace.head()),
            })?;
            let segment = seg(ModuleId::ThoughtCompiler, phase, &body, time, vec![body.id])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ThoughtMinted { candidate, body },
            })
        }

        (Phase::Anchor, PendingWork::AnchorClassify { candidate }) => {
            let c = candidate_at(state, candidate)?;
            let minted = c.minted.ok_or(PskError::UntypedInput)?;
            let body = state
                .thoughts
                .iter()
                .find(|t| t.id == minted)
                .ok_or(PskError::UntypedInput)?;
            let anchor = first_anchor(state)?;
            // Vertrag 27.2 (Domänengelieferte opake Eingaben) Pflicht 3: kein Klassifikationsplugin im
            // Workspace - der treue Zustand ist "nichts festgestellt",
            // und classify() erzwingt selbst, dass daraus nur UNKNOWN
            // werden kann. UNKNOWN mit leerem evidence_refs IST die
            // Materialisierung "fehlender Witness" (Vertrag 7.13 (Unknown als wirksamer Status)).
            let classification = psk_thought::classify(
                body,
                psk_thought::ClassificationInputs {
                    anchor_ref: anchor.id,
                    evidence: psk_thought::RealityEvidence::default(),
                    evidence_refs: vec![],
                    method_ref: None,
                    residue_refs: vec![],
                    trace_ref: TraceRef(state.trace.head()),
                    classified_at: time.clone(),
                },
            )?;
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

        (Phase::Project, PendingWork::ProjectField { entry }) => {
            let e = entry_at(state, entry)?;
            let field = psk_fields::register_field(e.archetype, e.registration.clone())?;
            let segment = seg(ModuleId::FieldRegistry, phase, &field, time, vec![field.id])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::FieldRegistered { entry, field },
            })
        }

        (Phase::Project, PendingWork::ProjectLens { entry }) => {
            let e = entry_at(state, entry)?;
            let field_id = e.registered.ok_or(PskError::UntypedInput)?;
            let field = state
                .fields
                .iter()
                .find(|f| f.id == field_id)
                .ok_or(PskError::UntypedInput)?;
            let anchor = first_anchor(state)?;
            let reality = state
                .reality_horizon
                .first()
                .ok_or(PskError::UntypedInput)?;
            let outcome = psk_fields::route_lens(
                field,
                psk_fields::ProjectionInputs {
                    source_refs: vec![anchor.id],
                    candidates: vec![e.node.clone()],
                    resolved: vec![e.node.clone()],
                    distinctions: vec![],
                    source_provenance: e.source_provenance.clone(),
                    reality_view: reality.reality_status,
                    scope: e.scope.clone(),
                    // Der Takt, in dem die Projektion oeffnet - aus dem
                    // Zustand, nicht deponiert.
                    tick: TickId(format!("t{}", state.tick_no)),
                    opened_at: time.clone(),
                },
            )?;
            match outcome {
                psk_fields::LensOutcome::Projected(projection) => {
                    let segment = seg(
                        ModuleId::SpectralLensRouter,
                        phase,
                        &projection,
                        time,
                        vec![projection.id],
                    )?;
                    Ok(DispatchResult {
                        trace_segments: vec![segment],
                        outcome: DispatchOutcome::LensRouted { entry, projection },
                    })
                }
                // Vertrag C5: eine nicht anwendbare Linse ist beim
                // Referenzlauf ein Fehlschlag des Laufs, kein stilles
                // Weiter (dieselbe Entscheidung wie vor der Umverdrahtung).
                psk_fields::LensOutcome::NotApplicable(_residue) => {
                    Err(PskError::FieldProjectionUndefined)
                }
            }
        }

        (Phase::Compile, PendingWork::CompileQuotient) => {
            if state.projections.is_empty() {
                return Err(PskError::UntypedInput);
            }
            let consensus_scope = state
                .program
                .consensus_scope
                .ok_or(PskError::UntypedInput)?;
            let profile = psk_dependency::dependency_quotient(psk_dependency::QuotientInputs {
                projections: &state.projections,
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

        (Phase::Compile, PendingWork::CompileAssemble) => {
            let record = assemble(state, time.clone())?;
            // IRBundle traegt keine eigene ObjectId (Struktur 7.21 (IRBundle)) - das
            // Segment digestet den ganzen Kandidaten.
            let segment = seg(ModuleId::IRCodec, phase, &record.bundle, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::Assembled(record),
            })
        }

        (Phase::Compile, PendingWork::CompileGlue) => {
            let assembly_index = state
                .assemblies
                .len()
                .checked_sub(1)
                .ok_or(PskError::UntypedInput)?;
            let record = &state.assemblies[assembly_index];
            let spec = state
                .program
                .glue_spec
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            // Schritt 6b: erst Vertrag 9.7 (Zellclosure) ueber dem Compile-Graphen -
            // `cells_closed` ist ab hier ein Messwert -, dann verkleben.
            let cells = close_cells_over(state, record)?;
            let cells_closed = psk_topology::all_18_closed(&cells);
            let restrictions: Vec<psk_closure::CapsuleRestriction> = state
                .projections
                .iter()
                .map(|p| psk_closure::CapsuleRestriction {
                    capsule: p.id,
                    cells: vec![spec.shared_cell.clone()],
                    restriction_digests: vec![spec.restriction_digest],
                })
                .collect();
            let outcome = psk_closure::glue(&restrictions, cells_closed)?;
            let payload = (outcome.section, outcome.hold_reason);
            let segment = seg(ModuleId::ClosureGlueEngine, phase, &payload, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::Glued {
                    assembly_index,
                    cells,
                    outcome,
                },
            })
        }

        (Phase::Challenge, PendingWork::ChallengeCapsulate) => {
            let profile = state.dependencies.first().ok_or(PskError::UntypedInput)?;
            let thought = first_thought(state)?;
            let spec = state
                .program
                .capsule_spec
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            // Die eine Quotientenklasse als Projektionsmenge aufloesen -
            // ueber die IDs des realen Profils, nicht "alle Projektionen".
            let class_ids = profile
                .quotient_classes
                .first()
                .ok_or(PskError::CorrelatedWitnessOvercount)?;
            let class: Vec<psk_types::objects::FieldProjection> = state
                .projections
                .iter()
                .filter(|p| class_ids.contains(&p.id))
                .cloned()
                .collect();
            let capsule = psk_adversarial::capsulate(
                &class,
                psk_adversarial::CapsuleInputs {
                    // Die behauptete Rolle IST der formale Claim des
                    // Gedankens - ein Laufwert, kein Etikett.
                    surface: SurfaceDescriptor(thought.claim.formal.0.clone()),
                    replay: spec.replay.clone(),
                    boundary: spec.boundary.clone(),
                    trace_ref: TraceRef(state.trace.head()),
                    coupling: vec![],
                    allowed_next: spec.allowed_next.clone(),
                },
            )?;
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

        (Phase::Challenge, PendingWork::ChallengeResolve { capsule }) => {
            let sealed = state
                .capsules
                .iter()
                .find(|c| c.id == capsule)
                .ok_or(PskError::UntypedInput)?;
            let spec = state
                .program
                .capsule_spec
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            let patch_artifact = state
                .program
                .patch_plan
                .as_ref()
                .map(|p| p.scope.0.as_str())
                .unwrap_or("");
            let countermodels = psk_adversarial::falsifier_countermodels(
                state.contradictions.as_deref().unwrap_or(&[]),
            );
            // `survivors` = die Nachfolgemenge OHNE die vom Falsifikator
            // widerlegten Kandidaten.
            let survivors: Vec<psk_types::objects::CapsuleId> = sealed
                .allowed_next
                .iter()
                .filter(|c| {
                    !countermodels
                        .iter()
                        .any(|cm| psk_adversarial::refutes(cm, c, patch_artifact))
                })
                .cloned()
                .collect();
            // Ratchet bis Kapselfixpunkt oder Budget (Definition 14.2 (Phasen-Modul-Bindung):
            // "Kapselfixpunkt oder RESIDUAL" ist ein Zustand NACH
            // beliebig vielen Runden, nicht nach einer).
            let mut before = sealed.clone();
            let mut after = psk_adversarial::ratchet(&before, &survivors, 1, spec.max_rounds)?;
            let mut rounds = 1u32;
            while !psk_adversarial::is_capsule_resolved(&before, &after) && rounds < spec.max_rounds
            {
                rounds += 1;
                before = after.clone();
                after = psk_adversarial::ratchet(&before, &survivors, rounds, spec.max_rounds)?;
            }

            // Invariante "Nichttrivialitaet des Ueberlebens": ein
            // Kandidat, der nur unter Ausblendung eines Gegenmodells
            // schliesst, ist nicht adversarial geschlossen (PSK-E003) -
            // festgestellt, nicht verschluckt, als RESIDUAL weitergetragen.
            let closes_without = !sealed.allowed_next.is_empty();
            let closes_with = !after.allowed_next.is_empty();
            let adversarially_closed =
                psk_adversarial::check_adversarial_closure(closes_without, closes_with).is_ok();
            if !psk_adversarial::is_capsule_resolved(&before, &after) {
                // Nach Budgeterschoepfung MUSS `ratchet` selbst auf
                // RESIDUAL gesetzt haben; kommt es hier trotzdem an,
                // stimmt die Terminierung nicht.
                return Err(PskError::MorphogenesisViolation);
            }
            let reached_fixpoint = psk_adversarial::is_capsule_fixpoint(&before, &after);

            // Definition 11.1 (Passfolge)1 (Perkolationssupport): drei Pfade
            // DEKLARIERT (deponiert), zwei BERECHNET.
            let paths = psk_adversarial::SupportPaths {
                gate: spec.support_gate,
                witness: state
                    .i
                    .adapter_versions
                    .keys()
                    .any(|a| a.0 == "observer-local-fs"),
                replay: spec.support_replay,
                resource: spec.support_resource,
                coupling: sealed.coupling.is_empty(),
            };
            let supported = if adversarially_closed {
                psk_adversarial::check_support(&after, &paths)?
            } else {
                psk_adversarial::check_support(
                    &after,
                    &psk_adversarial::SupportPaths {
                        // Der Witnesspfad ist nicht "innerhalb des
                        // geltenden Horizonts definiert", solange ein
                        // Gegenmodell unbeantwortet steht.
                        witness: false,
                        ..paths
                    },
                )?
            };

            let record = crate::ChallengeRecord {
                capsule_ref: supported.id,
                rounds,
                reached_fixpoint,
                adversarially_closed,
            };
            let segment = seg(
                ModuleId::AdversarialKernel,
                phase,
                &supported,
                time,
                vec![supported.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ChallengeResolved {
                    sealed: capsule,
                    capsule: supported,
                    record,
                },
            })
        }

        (Phase::Verify, PendingWork::VerifyValidation) => {
            // Schritt 7 (offene Obligationen read-only validieren): der
            // Referenzlauf eroeffnet keine Witness-Obligation, die den
            // Patch blockiert - die leere Liste ist ein echtes Resultat
            // (nichts offen), keine uebersprungene Pruefung. Gemessen am
            // Witnessbestand des Zustands.
            let obligations: Vec<psk_types::objects::ObligationExpr> = state
                .witnesses
                .iter()
                .map(|w| psk_types::objects::ObligationExpr(format!("witness {} offen", w.id)))
                .collect();
            let segment = seg(ModuleId::WitnessEngine, phase, &obligations, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ValidationChecked { obligations },
            })
        }

        (Phase::Verify, PendingWork::VerifyClosure) => {
            let (c360, c720) = state
                .program
                .closure_evidence
                .ok_or(PskError::UntypedInput)?;
            let report = psk_closure::evaluate(&c360, &c720);
            let payload = (report.close360, report.close720, report.executable_eligible);
            let segment = seg(ModuleId::ClosureGlueEngine, phase, &payload, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ClosureEvaluated(report),
            })
        }

        (Phase::Verify, PendingWork::VerifyCellClosure) => {
            let assembly_index = state
                .assemblies
                .iter()
                .rposition(|a| a.includes_late)
                .ok_or(PskError::UntypedInput)?;
            let reports = close_cells_over(state, &state.assemblies[assembly_index])?;
            let closed = psk_topology::all_18_closed(&reports);
            let segment = seg(ModuleId::M13TopologyService, phase, &closed, time, vec![])?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::CellsClosed {
                    assembly_index,
                    reports,
                },
            })
        }

        (Phase::Execute, PendingWork::ExecuteIssue) => {
            let report = state
                .gates_and_tokens
                .reports
                .iter()
                .find(|r| {
                    r.gate_id == GateId::GEffect && r.decision == GateReportDecisionKind::Pass
                })
                .ok_or(PskError::GateBypass)?;
            let auth = psk_gate::authorize(report)?;
            let plan = state
                .program
                .patch_plan
                .clone()
                .ok_or(PskError::UntypedInput)?;
            let token = psk_effect::issue(&auth, plan)?;
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

        (Phase::Observe2, PendingWork::Observe2Receipt { deposit }) => {
            let d = state
                .program
                .receipt_deposits
                .get(deposit)
                .ok_or(PskError::UntypedInput)?;
            // "oder UNKNOWN_EFFECT": siehe psk_anchor::observe_unknown_effect
            // und Modulkopf - hier nicht aufgerufen.
            let receipt = psk_anchor::ingress_p24_via_exclusive_pipe(&d.payload)?;
            let segment = seg(
                ModuleId::ExternalRecordIngress,
                phase,
                &receipt,
                time,
                vec![receipt.id],
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ReceiptIngressed { deposit, receipt },
            })
        }

        _ => Err(PskError::UntypedInput),
    }
}

/// `dispatch(phase, item, state)`. `phase` und die Variante von `work`
/// MUESSEN zusammenpassen - eine Fehlpaarung ist ein Aufruffehler des
/// Taktschleifenverwalters, nicht etwas, das diese Funktion heilen
/// sollte; sie scheitert dafuer mit `UntypedInput`.
///
/// `lines` sind die angeschlossenen Effektleitungen (M16) - nur der
/// `ExecuteRun`-Arm spricht sie; siehe `psk_effect::EffectLines` dafuer,
/// warum sie kein Sigma-Feld sein KOENNEN.
pub fn dispatch(
    phase: Phase,
    work: PendingWork,
    state: &mut Sigma,
    lines: &mut dyn EffectLines,
    time: DualTime,
) -> Result<DispatchResult, PskError> {
    if concurrency_eligible(&work) {
        return dispatch_readonly(phase, work, state, time);
    }
    match (phase, work) {
        (Phase::Challenge, PendingWork::ChallengeContradictions) => {
            let reqs = state.program.requirements.clone();
            if reqs.is_empty() {
                return Err(PskError::UntypedInput);
            }
            let contradictions = psk_adversarial::identify_contradictions(&reqs)?;
            let anchor_id = first_anchor(state)?.id;
            let cell = state
                .program
                .obstruction_cell
                .clone()
                .ok_or(PskError::UntypedInput)?;
            // Der Integrator: "verklebt ODER erzeugt eine Obstruktion".
            // Je Widerspruch, den die Praezedenz nicht entscheidet, ein
            // Residuum (Typ scope, blockierend - ohne Aussenrecord nicht
            // aufloesbar) und darauf ein ObstructionRecord der Art
            // `order`. Ein aufgeloester Widerspruch erzeugt nichts.
            let mut obstructions = Vec::new();
            for c in contradictions.iter().filter(|c| c.is_open()) {
                let residue_id = state.residues.open(psk_trace::ResidueInputs {
                    r#type: psk_types::objects::ResidueRecordTypeKind::Scope,
                    origin_module: ModuleId::ClosureGlueEngine,
                    origin_object: anchor_id,
                    scope: psk_types::objects::ScopeExpr(c.artifact.clone()),
                    severity: psk_types::objects::ResidueRecordSeverityKind::Blocking,
                    open_obligation: psk_adversarial::open_obligation_for(c),
                    allowed_followups: vec![],
                    opened_at: time.clone(),
                })?;
                obstructions.push(psk_adversarial::integrator_obstruction(
                    c,
                    residue_id,
                    cell.clone(),
                )?);
            }
            // Nullbefund ueber nichtleerer Arbeitsliste: gibt es offene
            // Widersprueche, MUSS auch eine Obstruktion entstanden sein.
            if contradictions.iter().any(|c| c.is_open()) && obstructions.is_empty() {
                return Err(PskError::SurfaceInvariantCollapse);
            }
            let segment = seg(
                ModuleId::AdversarialKernel,
                phase,
                &contradictions,
                time,
                obstructions.iter().map(|o| o.id).collect(),
            )?;
            Ok(DispatchResult {
                trace_segments: vec![segment],
                outcome: DispatchOutcome::ContradictionsIdentified {
                    contradictions,
                    obstructions,
                },
            })
        }

        (Phase::Verify, PendingWork::VerifyPatchGate) => {
            let glue = state.glue.as_ref().ok_or(PskError::UntypedInput)?;
            let spec = state
                .program
                .patch_gate
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            let plan = state
                .program
                .patch_plan
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            let closure_ok = glue.hold_reason.is_none();
            let mut conditions: Vec<psk_gate::ConditionOutcome> = spec
                .declared_conditions
                .iter()
                .map(|ok| {
                    if *ok {
                        psk_gate::ConditionOutcome::True
                    } else {
                        psk_gate::ConditionOutcome::False(psk_types::objects::ReasonCode(
                            "deklarierte Bedingung verneint".into(),
                        ))
                    }
                })
                .collect();
            conditions.push(if closure_ok {
                psk_gate::ConditionOutcome::True
            } else {
                psk_gate::ConditionOutcome::Undecidable(psk_types::objects::ReasonCode(
                    "closure-not-global".into(),
                ))
            });
            let inputs = psk_gate::GateInputs {
                gate_id: GateId::GEffect,
                order: 2,
                input_digests: vec![plan.plan_digest],
                conditions,
                seam_compatible: Some(closure_ok),
                evidence_refs: vec![],
                seam_report_refs: vec![spec.seam_report_ref],
                replay_descriptor: spec.replay.clone(),
                decided_at: time.clone(),
                trace_ref: TraceRef(state.trace.head()),
            };
            // evaluate_gate schreibt sein TraceSegment selbst, unbedingt
            // (Algorithmus 18.6 (Gate-Auswertung)/Invariante 18.7 (Gatebericht immer)) - kein aeusseres Segment.
            let (trace, residues) = (&mut state.trace, &mut state.residues);
            let report = psk_gate::evaluate_gate(inputs, trace, residues)?;
            Ok(DispatchResult {
                trace_segments: vec![],
                outcome: DispatchOutcome::GateEvaluated(report),
            })
        }

        (Phase::Execute, PendingWork::ExecuteRun { token }) => {
            let token = match token {
                Some(id) => state
                    .gates_and_tokens
                    .issued
                    .iter()
                    .find(|t| t.id == id)
                    .cloned()
                    .ok_or(PskError::UntypedInput)?,
                // "das in dieser Phase ausgestellte": das juengste noch
                // ausstehende Token - beim Dispatch aufgeloest, siehe
                // Variantenkommentar.
                None => state
                    .gates_and_tokens
                    .issued
                    .iter()
                    .rev()
                    .find(|t| {
                        matches!(
                            state.gates_and_tokens.ledger.state_of(&t.idempotency_key),
                            Some(psk_effect::TokenState::Issued)
                        )
                    })
                    .cloned()
                    .ok_or(PskError::UntypedInput)?,
            };
            match state.i.profile {
                psk_types::objects::ProfileId::Shadow | psk_types::objects::ProfileId::Readonly => {
                    // Regel 22.3 (Replay laeuft unter shadow): "Plan und
                    // Token werden erzeugt, aber sofort invalidiert."
                    // Durchsetzung ueber die bestehende Tokeninvalidierung
                    // (FSM-TOKEN-Operator `plan_changed`, P37) - die
                    // Leitung wird nie gesprochen.
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
                    // Eine Execute-Arbeit ohne angeschlossene Leitung ist
                    // ein nicht aufloesbarer Verweis - typisierter
                    // Fehlschlag, keine Simulation.
                    let line = lines
                        .line(&token.effect_class)
                        .ok_or(PskError::UntypedInput)?;
                    // Regel 20.6 (Vorzustand und Versuch klammern den
                    // Effekt): beide Haelften auf DERSELBEN Leitung,
                    // nichts dazwischen.
                    let _prestate = line.prestate(&token.scope);
                    let attempt = psk_effect::execute_effect(
                        &mut state.gates_and_tokens.ledger,
                        &token,
                        time.tau_i,
                        time.clone(),
                        line,
                    )?;
                    let segment = seg(
                        ModuleId::EffectBoundary,
                        phase,
                        &attempt,
                        time,
                        vec![attempt.id],
                    )?;
                    Ok(DispatchResult {
                        trace_segments: vec![segment],
                        outcome: DispatchOutcome::EffectExecuted(attempt),
                    })
                }
            }
        }

        (Phase::Reconcile, PendingWork::Reconcile) => {
            let attempt = state
                .effects
                .first()
                .cloned()
                .ok_or(PskError::UntypedInput)?;
            let receipt = state
                .receipts
                .first()
                .cloned()
                .ok_or(PskError::UntypedInput)?;
            let plan = state
                .program
                .patch_plan
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            let spec = state
                .program
                .reconcile_spec
                .as_ref()
                .ok_or(PskError::UntypedInput)?;
            let anchor_id = first_anchor(state)?.id;
            let reality = state
                .reality_horizon
                .first()
                .ok_or(PskError::UntypedInput)?;
            let inputs = psk_reconciliation::ReconcileInputs {
                plan_ref: ObjectId::new(SortId::Effect, plan.plan_digest),
                plan_digest: attempt.plan_digest,
                token_plan_digest: attempt.plan_digest,
                attempt,
                token_issuer_digest: spec.issuer_digest,
                receipts: vec![receipt],
                anchor_ref: anchor_id,
                // Siehe ReconcileSpec: die Diffklasse ist von aussen
                // bestimmt; deponierbar ist bislang nur Empty.
                diff: psk_reconciliation::DiffOutcome::Empty,
                finality: spec.finality,
                witness_ref: spec.witness_ref,
                opened_at: time.clone(),
                // Das Subjekt ist der klassifizierte Gedanke dieses
                // Laufs - seine Werte kommen aus dem Zustand, nicht als
                // Vorgabe (die Promotionssperre bekommt Laufwerte).
                subject_reality_status: reality.reality_status,
                subject_facticity: reality.facticity,
            };
            let residues = &mut state.residues;
            let report = psk_reconciliation::reconcile(inputs, residues)?;
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
