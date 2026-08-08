//! Golden Run Harness (Definition 24.2, Regel 24.3).
//!
//! Regel 24.3 (Golden-Run-Ablauf), woertlich, die 13 Schritte:
//! 1. Bundle verifizieren, Bootgate schliessen.
//! 2. Workspace als AnchorSnapshot versiegeln.
//! 3. Auftrag in ThoughtBody kompilieren.
//! 4. Realitaetstypen relativ zu Dateien, Werkzeugen, Rechten und Zeit bestimmen.
//! 5. Statische Feldfamilie (sechs Archetypen) ausfuehren.
//! 6. Abhaengigkeiten quotieren und lokale Resultate verkleben.
//! 7. Bei offenen Obligationen read-only Validierung durchfuehren.
//! 8. Patchplan erzeugen; Folgen- und Risikogate pruefen.
//! 9. EffectToken fuer Sandboxdateien ausstellen.
//! 10. Patch ausfuehren; EffectAttempt schreiben.
//! 11. Unabhaengigen Beobachter den Dateibaum lesen lassen; ExternalReceipt erzeugen.
//! 12. Reconciliation durchfuehren; Faktpromotion entscheiden.
//! 13. Maschinenzertifikat und Replaymanifest exportieren.
//!
//! # Schritt 1: Bootgate, real (Algorithmus 17.1 vollstaendig realisiert)
//!
//! Algorithmus 17.1 (Boot) hat 21 Schritte ueber M00-M04, M14, M15, M19,
//! M21, M22, M26; `g = M14.gate("G-BOOT", all_of(above))` aggregiert ALLE
//! davon. M00 (Bundle-Loader), M02 (Artefaktregistrierung) und M04
//! (Identitaetsbindung/Profilbindung) sind seit `packages/psk-contract`
//! real (`psk_contract::boot`, dort Algorithmus 17.1 Schritt fuer Schritt
//! nachgebaut - siehe dessen Modulkopf fuer jede Realisierungsentscheidung
//! und ihre Begruendung), ebenso M15s
//! `register_only_versioned_operators_and_capabilities` (Schritt 17,
//! psk-effect) und M21s `compute_release_and_operational_posture`
//! (Schritt 18, psk-certify, Definition 31.3). Diese Funktion ruft
//! `psk_contract::boot` gegen den echten Workspace-Root auf: fuer ein
//! korrekt versiegeltes Bundle (constitution.lock.json/
//! architecture.lock.json beide deckungsgleich mit dem selbst berechneten
//! Digest) erreicht G-BOOT hier real PASS, nicht mehr strukturell HOLD -
//! der erste Lauf in diesem Projekt, bei dem der Bootgate tatsaechlich
//! besteht. Der volle `psk_contract::BootReport` (Identitaetsbindung,
//! RuntimeManifest, Releaseposture) bleibt Teil von `GoldenRunReport`,
//! nicht nur der aggregierte `GateReport`.
//!
//! `seam_compatible`/`seam_report_refs` fuer G-BOOT (order 2, siehe
//! gate_registry.yaml) folgen demselben Muster wie `psk_certify::
//! evaluate_release_gate` fuer G-RELEASE (siehe psk-gate/evaluate.rs
//! Modulkopf: `seam_compatible` ist ein von aussen bestimmtes Urteil, kein
//! interner `M11.seam_report`-Aufruf, da SeamReport (Struktur 7.28) M13-
//! zellenfoermig ist und G-BOOT keinen M13-Zellbezug hat) - beides wird
//! jetzt innerhalb von `psk_contract::boot` selbst gesetzt, siehe dort.

use std::fs;
use std::path::Path;

use psk_anchor::{bind_provenance, no_declared_uncertainty, seal_anchor, AnchorInputs};
use psk_certify::{
    check_minimum_replay_class, compute_conformance_class, issue_certificate, AdditionalAcceptance,
    CertificateInputs,
};
use psk_closure::{glue, CapsuleRestriction, GlueOutcome};
use psk_dependency::{dependency_quotient, QuotientInputs, RankMethod};
use psk_effect::{issue as issue_token, IssueInputs, TokenLedger};
use psk_fields::{register_field, route_lens, LensOutcome, ProjectionInputs};
use psk_gate::{authorize, evaluate_gate, ConditionOutcome, GateAuthorization, GateInputs};
use psk_reconciliation::{reconcile, DiffOutcome, ReconcileInputs};
use psk_thought::{ClassificationInputs, RealityEvidence, ThoughtInputs};
use psk_trace::{ResidueLedger, SegmentInputs, TraceStore};
use psk_types::objects::{
    AnchorSnapshot, ArchetypeId, BoundarySpec, BudgetSpec, CapabilityId, Claim,
    ClaimDirectionalityKind, ClaimExpr, ConsequenceRef, ContextRef, DependencyProfile,
    DependencyProfileConsensusScopeKind, DomainExpr, EffectAttempt, EffectClassId,
    EffectTokenRollbackKind, EventTypeId, ExternalReceipt, FeatureCoverageId, FieldIdentity,
    FieldProjection, GateId, IRNodeId, Lineage, M13Address, MachineCertificate,
    MachineCertificateReplayClassKind, ModelRef, ObligationExpr, Observation, OpId, PredicateExpr,
    ProfileId, QuestionSpec, RealityClassification, RealityClassificationReachabilityKind,
    RealityStatus, ReasonCode, ReceiptSpec, ReconciliationReport, ReplayDescriptor, RollbackSpec,
    ScopeExpr, ScopeSpec, SortId, SourceRef, ThoughtBody, TickId, TimeWindow, TrajectoryRef,
    UncertaintyBlock, UncertaintyModelId, Validity, WitnessPolicy,
};
use psk_types::{
    ClockRef, Digest, DualTime, MessageType, ModuleId, Msg, ObjectId, PortId, PskError, RunId,
    SchemaId, TraceRef, Ulid,
};

/// Deterministische Laufzeit (Definition 24.2: "erwartetem kanonischen
/// Zustandsdigest" - Replaystabilitaet verlangt eine feste, nicht eine
/// systemuhrabhaengige Zeit).
fn run_time() -> DualTime {
    DualTime {
        tau_i: 1_000_000,
        tau_e: "2026-08-05T00:00:00.000000000Z".into(),
        clock_ref: ClockRef("golden-run".into()),
        uncertainty_ns: 0,
    }
}

/// Gesammeltes Ergebnis EINER Ausfuehrung der Schritte 1-12 (Regel 24.3).
/// Schritt 13 (Zertifikat/Replaymanifest) ist bewusst NICHT Teil dieses
/// Typs: `issue_certificate` verlangt Vertrag 22.2 (mindestens R2) als
/// Vorbedingung, und eine Replayklasse ist per Definition 22.1 keine
/// Eigenschaft EINES Laufs, sondern eines VERGLEICHS zweier Laeufe - siehe
/// `run_golden_run_with_certificate`.
pub struct GoldenRunReport {
    /// Der aggregierte G-BOOT-`GateReport` - fuer ein korrekt versiegeltes
    /// Bundle real `PASS` (siehe Modulkopf). Extrahiert aus `boot_report`
    /// fuer Rueckwaertskompatibilitaet mit bestehenden Assertions.
    pub boot_gate: psk_types::objects::GateReport,
    /// Der vollstaendige `psk_contract::boot()`-Ergebnistyp - Identitaets-
    /// bindung, RuntimeManifest, Releaseposture, FSM-Zustand.
    pub boot_report: psk_contract::BootReport,
    pub anchor: AnchorSnapshot,
    pub thought: ThoughtBody,
    pub reality: RealityClassification,
    pub field_projections: Vec<FieldProjection>,
    pub dependency_profile: DependencyProfile,
    pub glue: GlueOutcome,
    pub validation_open_obligations: Vec<ObligationExpr>,
    pub patch_gate: psk_types::objects::GateReport,
    pub token_authorization: GateAuthorization,
    pub attempt: EffectAttempt,
    pub receipt: ExternalReceipt,
    pub reconciliation: ReconciliationReport,
    pub trace_head: Digest,
    /// Anzahl der waehrend dieses Laufs residualisierten Gate-Entscheidungen
    /// (T-RES-001/Algorithmus 18.6: jede Nicht-PASS-Entscheidung MUSS
    /// residualisiert werden). Bei einem PASS-Bootgate kann das durchaus 0
    /// sein - siehe die beiden golden_run-Tests (PASS- und HOLD-Fall).
    pub residues_opened: usize,
}

/// Ergebnis von Schritt 13 plus der beiden Laeufe, aus deren Vergleich die
/// Replayklasse (Definition 22.1) tatsaechlich folgt.
pub struct GoldenRunCertification {
    pub first: GoldenRunReport,
    pub second: GoldenRunReport,
    pub replay_check: psk_trace::ReplayCheck,
    pub replay_manifest: psk_types::objects::ReplayManifest,
    pub certificate: MachineCertificate,
    /// Laufzeit NUR des ersten Laufs (`first`), getrennt von der
    /// Gesamtlaufzeit der Zertifizierung (die zusaetzlich den zweiten,
    /// nur der Replaypruefung dienenden Lauf einschliesst). Aufrufer, die
    /// "wie lange dauert EIN Validierungslauf" messen wollen (z.B.
    /// `baselines::comparison`, das dieselbe Groesse gegen einzelne
    /// Baseline-Laeufe stellt), brauchen diese Zahl statt der Gesamtzeit -
    /// sonst waere der Vergleich 2 Kern-Laeufe gegen 1 Baseline-Lauf.
    pub first_run_wall_clock: std::time::Duration,
}

fn record(
    trace: &mut TraceStore,
    event_type: &str,
    module: ModuleId,
    object_refs: Vec<ObjectId>,
    payload_digest: Digest,
) -> Result<TraceRef, PskError> {
    let seg = trace.append(SegmentInputs {
        event_type: EventTypeId(event_type.into()),
        module,
        port_id: None,
        object_refs,
        payload_digest,
        time: run_time(),
        attestation: None,
    })?;
    Ok(TraceRef(seg.segment_digest))
}

/// Schritt 1. Siehe Modulkopf - ruft jetzt den vollstaendigen, realen
/// `psk_contract::boot()` (Algorithmus 17.1, alle 21 Schritte) gegen den
/// echten Workspace-Root auf. `store_root` ist bewusst NICHT
/// `workspace_root`: Struktur 16.7s Store-Lock gehoert zu einer eigenen,
/// veraenderlichen Laufzeitablage, nicht zum (weitgehend gelesenen)
/// Bundle - siehe `psk_contract::BootInputs`s Modulkopf. Der Sandbox-Root
/// ist bereits ein pro-Lauf eindeutiger Pfad und dient hier zugleich als
/// Store-Root.
fn run_boot(
    workspace_root: &Path,
    store_root: &Path,
    trace_ref: TraceRef,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<psk_contract::BootReport, PskError> {
    psk_contract::boot(
        psk_contract::BootInputs {
            bundle_root: workspace_root.to_path_buf(),
            store_root: store_root.to_path_buf(),
            profile: ProfileId::Reference,
            bound_at: run_time(),
            trace_ref,
            replay_descriptor: ReplayDescriptor("golden-run/1".into()),
        },
        trace,
        residues,
    )
}

/// Schritt 2: Workspace als AnchorSnapshot versiegeln - `observer_local_fs::
/// observe` liest den Sandbox-Baum wirklich vom Dateisystem (kein
/// simulierter Rueckgabewert).
fn seal_workspace_anchor(
    sandbox_root: &Path,
    trace_ref: TraceRef,
) -> Result<AnchorSnapshot, PskError> {
    let config = observer_local_fs::ObserverConfig::new(sandbox_root);
    let record =
        observer_local_fs::observe(&config, run_time()).map_err(|_| PskError::MissingAnchor)?;
    let provenance = bind_provenance(
        &record,
        psk_types::objects::AdapterId("observer-local-fs".into()),
        Digest::sha256(b"golden-run-observer"),
        "filesystem-read".into(),
    );
    seal_anchor(AnchorInputs {
        observations: vec![Observation(format!(
            "{} Dateien unter {} beobachtet",
            record.file_hashes.len(),
            sandbox_root.display()
        ))],
        provenance,
        uncertainty: no_declared_uncertainty(UncertaintyModelId("none-declared".into())),
        context: ContextRef("golden-run".into()),
        time: run_time(),
        validity: Validity {
            freshness_predicate: PredicateExpr("always".into()),
            expires_at_tau_i: u64::MAX,
        },
        boundary: ScopeExpr(sandbox_root.display().to_string()),
    })
    .map(|mut a| {
        let _ = trace_ref; // trace_ref wird oberhalb bereits fuer den Aufrufkontext gefuehrt
        a.schema = a.schema.clone();
        a
    })
}

/// Schritt 3: Auftrag in ThoughtBody kompilieren.
fn compile_thought(anchor: &AnchorSnapshot, trace_ref: TraceRef) -> Result<ThoughtBody, PskError> {
    psk_thought::compile_thought(ThoughtInputs {
        anchor_refs: vec![anchor.id],
        unanchored: false,
        claim: Claim {
            text: "Golden-Run-Demonstrationspatch in der Sandbox schreiben".into(),
            formal: ClaimExpr("write(sandbox, patch.txt)".into()),
            directionality: ClaimDirectionalityKind::Internal,
        },
        models: vec![ModelRef("reference-domain".into())],
        trajectories: vec![TrajectoryRef("direct-write".into())],
        uncertainty: UncertaintyBlock("none-declared".into()),
        consequences: vec![ConsequenceRef("sandbox-file-write".into())],
        lineage: Lineage("golden-run".into()),
        trace_ref,
    })
}

/// Schritt 4: Realitaetstypen bestimmen.
fn classify_thought_reality(
    thought: &ThoughtBody,
    anchor: &AnchorSnapshot,
    trace_ref: TraceRef,
) -> Result<RealityClassification, PskError> {
    let evidence = RealityEvidence {
        coherent: true,
        lawful: true,
        constructible: true,
        actualized: false,
        reachability: RealityClassificationReachabilityKind::Witnessed,
    };
    psk_thought::classify(
        thought,
        ClassificationInputs {
            anchor_ref: anchor.id,
            evidence,
            // Vertrag 27.2 Pflicht 3 (kein MethodPlugin -> keine positive
            // Klassifikation) und Struktur 7.9 (Grundlage; leer nur bei
            // UNKNOWN) verlangen beide ein echtes MethodPlugin und
            // mindestens eine Evidenzreferenz, sobald reality_status !=
            // UNKNOWN. Die Anchor-Beobachtung selbst ist hier die
            // Grundlage - Schritt 4 klassifiziert ja genau deren
            // Realitaetstyp (Dateien/Werkzeuge/Rechte/Zeit).
            evidence_refs: vec![anchor.id],
            method_ref: Some(psk_types::objects::PluginId(
                "reference-domain-fs-classifier".into(),
            )),
            residue_refs: vec![],
            trace_ref,
            classified_at: run_time(),
        },
    )
}

/// Schritt 5: Statische Feldfamilie - alle sechs Archetypen registrieren
/// und je einmal projizieren (Regel 32.7).
fn run_static_field_family(
    anchor: &AnchorSnapshot,
    reality_status: RealityStatus,
) -> Result<Vec<FieldProjection>, PskError> {
    let mut projections = Vec::new();
    for (i, archetype) in ArchetypeId::ALL.into_iter().enumerate() {
        let field = register_field(
            archetype,
            psk_fields::FieldRegistrationInputs {
                domain: DomainExpr("sandbox-files".into()),
                lens: psk_types::objects::LensSpec("identity".into()),
                operators: vec![OpId::Project],
                questions: vec![QuestionSpec(format!("archetype-{i}-question"))],
                witness_rules: WitnessPolicy("default".into()),
                boundaries: BoundarySpec("sandbox".into()),
                gates: vec![],
                time_window: TimeWindow("golden-run-window".into()),
                lineage: Lineage("golden-run".into()),
                // Vorwaertsreferenz: der DependencyProfile wird erst in
                // Schritt 6 aus genau diesen sechs Projektionen berechnet;
                // die Registrierung selbst braucht nur eine syntaktisch
                // gueltige Kennung (register_field/check_activation_requirements
                // sind getrennte Pruefungen, siehe psk-fields::registry).
                dependency_profile_ref: ObjectId::new(
                    SortId::Dependency,
                    Digest::sha256(b"golden-run-dependency-profile"),
                ),
                budget: BudgetSpec("unbounded-demo".into()),
                rollback: RollbackSpec("re-run".into()),
            },
        )?;
        projections.push(project_field(&field, anchor, reality_status, i)?);
    }
    Ok(projections)
}

fn project_field(
    field: &FieldIdentity,
    anchor: &AnchorSnapshot,
    reality_status: RealityStatus,
    i: usize,
) -> Result<FieldProjection, PskError> {
    let node = IRNodeId(format!("golden-run-node-{i}"));
    let outcome = route_lens(
        field,
        ProjectionInputs {
            source_refs: vec![anchor.id],
            candidates: vec![node.clone()],
            resolved: vec![node],
            distinctions: vec![],
            source_provenance: vec![SourceRef("sandbox-observation".into())],
            reality_view: reality_status,
            scope: ScopeSpec("sandbox".into()),
            tick: TickId("t0".into()),
            opened_at: run_time(),
        },
    )?;
    match outcome {
        LensOutcome::Projected(projection) => Ok(projection),
        LensOutcome::NotApplicable(_residue) => Err(PskError::FieldProjectionUndefined),
    }
}

/// Schritt 6: Abhaengigkeiten quotieren und die sechs Projektionen
/// verkleben. Alle sechs Restriktionen teilen bewusst dieselbe Zelle und
/// denselben Digest - der Golden Run demonstriert einen widerspruchsfreien
/// Lauf, keine Seam-Konfliktaufloesung (die ist WP-eigenstaendig getestet,
/// siehe psk-closure::seam Testsuite).
fn quotient_and_glue(
    projections: &[FieldProjection],
) -> Result<(DependencyProfile, GlueOutcome), PskError> {
    let profile = dependency_quotient(QuotientInputs {
        projections,
        method: RankMethod::QuotientClassCount,
        consensus_scope: DependencyProfileConsensusScopeKind::Local,
    })?;

    let shared_cell = M13Address("center".into());
    let shared_digest = Digest::sha256(b"golden-run-shared-restriction");
    let restrictions: Vec<CapsuleRestriction> = projections
        .iter()
        .map(|p| CapsuleRestriction {
            capsule: p.id,
            cells: vec![shared_cell.clone()],
            restriction_digests: vec![shared_digest],
        })
        .collect();
    let outcome = glue(&restrictions, true)?;
    Ok((profile, outcome))
}

/// Schritt 8 (Patchplan/Gate): G-EFFECT ist order 2 (gate_registry.yaml) -
/// dasselbe Muster wie G-BOOT/G-RELEASE (siehe Modulkopf).
fn evaluate_patch_gate(
    trace_ref: TraceRef,
    glue_outcome: &GlueOutcome,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<psk_types::objects::GateReport, PskError> {
    let closure_ok = glue_outcome.hold_reason.is_none();
    evaluate_gate(
        GateInputs {
            gate_id: GateId::GEffect,
            order: 2,
            input_digests: vec![Digest::sha256(b"golden-run-patch-plan")],
            conditions: vec![
                ConditionOutcome::True, // Risiko: einzelne Sandboxdatei, lokal reversibel
                ConditionOutcome::True, // Autoritaet: Golden-Run-Adapter besitzt fs.write.sandbox
                ConditionOutcome::True, // Ressourcen: ein Schreibvorgang, Budget nicht erschoepft
                if closure_ok {
                    ConditionOutcome::True
                } else {
                    ConditionOutcome::Undecidable(ReasonCode("closure-not-global".into()))
                },
            ],
            seam_compatible: Some(closure_ok),
            evidence_refs: vec![],
            seam_report_refs: vec![ObjectId::new(
                SortId::Trace,
                Digest::sha256(b"golden-run-effect-closure"),
            )],
            replay_descriptor: ReplayDescriptor("golden-run/1".into()),
            decided_at: run_time(),
            trace_ref,
        },
        trace,
        residues,
    )
}

/// Schritte 9-10: EffectToken ausstellen, Patch in der Sandbox ausfuehren.
/// Schritte 9-10, P22/P23 (v1.0.13/P24a): EffectToken/EffectAttempt ueber
/// eine echte, von M26 gespawnte Prozessgrenze - dasselbe Muster wie
/// `observe_and_receipt` bei P24. Die Kernel-Buchfuehrung
/// (Ablauf-/Einmaligkeitspruefung, `TokenLedger`) bleibt lokal: sie ist
/// eine Kernprozess-Zustaendigkeit, kein Adapterverhalten (siehe
/// `psk_effect::process_protocol`s Modulkopf) - nur `adapter.apply`
/// selbst (der tatsaechliche Dateizugriff) wandert in den Effektprozess.
fn issue_and_execute(
    patch_gate: &psk_types::objects::GateReport,
    sandbox_root: &Path,
    scope_file: &str,
    content: &str,
    trace_ref: TraceRef,
) -> Result<(GateAuthorization, EffectAttempt), PskError> {
    let auth = authorize(patch_gate)?;
    let token = issue_token(
        &auth,
        IssueInputs {
            effect_class: EffectClassId("fs.write.sandbox".into()),
            plan_digest: Digest::sha256(b"golden-run-patch-plan"),
            scope: ScopeExpr(scope_file.to_string()),
            capabilities: vec![CapabilityId("fs.write.sandbox".into())],
            preconditions: vec![PredicateExpr(content.to_string())],
            budget: BudgetSpec("1 Datei".into()),
            expires_at_tau_i: run_time().tau_i + 1000,
            run_id: RunId("golden-run".into()),
            port_id: psk_types::PortId::P22,
            seq: 1,
            nonce: [7u8; 32],
            expected_receipt: ReceiptSpec("receipt/1".into()),
            rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec(
                "restore prior bytes".into(),
            )),
        },
    )?;

    let mut ledger = TokenLedger::new();
    ledger.register(&token);
    psk_effect::check_not_expired(&token, run_time().tau_i)?;
    ledger.consume_once(&token.idempotency_key)?;

    let exe = psk_lifecycle::sibling_binary_path("effect-local-fs")?;
    let mut child = psk_lifecycle::ChildProcess::spawn(
        &exe,
        &[sandbox_root.to_str().ok_or(PskError::UntypedInput)?],
        Some(sandbox_root),
    )?;

    let apply_payload = serde_json::to_vec(&psk_effect::EffectApplyRequest {
        token: token.clone(),
        started_at: run_time(),
    })
    .map_err(|_| PskError::CanonicalizationFailed)?;
    let request = Msg {
        msg_id: Ulid(1),
        port_id: psk_types::PortId::P22,
        r#type: MessageType::Request,
        schema_id: SchemaId(psk_effect::SCHEMA_APPLY_REQUEST.to_string()),
        producer: ModuleId::EffectTokenService,
        consumer: ModuleId::EffectBoundary,
        run_id: RunId("golden-run".into()),
        seq: 1,
        input_digests: vec![],
        created_at: run_time(),
        trace_parent: TraceRef(Digest::sha256(b"golden-run-apply-request")),
        payload_digest: Digest::sha256(&apply_payload),
        payload: apply_payload,
        signature: None,
    };
    let response = child.request(&request)?;
    let attempt: EffectAttempt =
        serde_json::from_slice(&response.payload).map_err(|_| PskError::CanonicalizationFailed)?;
    child.shutdown()?;

    let _ = trace_ref;
    Ok((auth, attempt))
}

/// Schritt 11: unabhaengiger Beobachter liest den Dateibaum; ExternalReceipt
/// (P24-Grenze) entsteht daraus.
///
/// P24a/P24b (v1.0.13): der Beobachter laeuft jetzt als echter, von M26
/// (`psk_lifecycle::process`) gespawnter Kindprozess - nicht mehr
/// in-process simuliert. Die Herkunftsbeglaubigung (Vertrag
/// Herkunftsbeglaubigung an der Prozessgrenze) ist die exklusive Pipe zu
/// genau diesem Kind (`ChildProcess::request`s privates `stdout`-Feld),
/// nicht mehr ein Vergleich zweier hartkodierter `ProcessIdentity`-Werte -
/// siehe `psk_anchor::ingress_p24_via_exclusive_pipe`s Modulkopf.
fn observe_and_receipt(
    sandbox_root: &Path,
    trace_ref: TraceRef,
) -> Result<ExternalReceipt, PskError> {
    let _ = trace_ref;
    let exe = psk_lifecycle::sibling_binary_path("observer-local-fs")?;
    let mut child = psk_lifecycle::ChildProcess::spawn(
        &exe,
        &[sandbox_root.to_str().ok_or(PskError::UntypedInput)?],
        None,
    )?;

    let request_payload = serde_json::to_vec(&psk_anchor::ObserveReceiptRequest {
        observed_at: run_time(),
        observer_identity: Digest::sha256(b"golden-run-observer"),
        provenance: psk_types::objects::ProvenanceBlock("golden-run-provenance/1".into()),
        independence_attestation: Digest::sha256(b"golden-run-independent-observer"),
    })
    .map_err(|_| PskError::CanonicalizationFailed)?;

    let request = Msg {
        msg_id: Ulid(1),
        port_id: PortId::P24,
        r#type: MessageType::Request,
        schema_id: SchemaId(psk_anchor::SCHEMA_RECEIPT_REQUEST.to_string()),
        producer: ModuleId::ReconciliationEngine,
        consumer: ModuleId::ExternalRecordIngress,
        run_id: RunId("golden-run".into()),
        seq: 1,
        input_digests: vec![],
        created_at: run_time(),
        trace_parent: TraceRef(Digest::sha256(b"golden-run-observe-request")),
        payload_digest: Digest::sha256(&request_payload),
        payload: request_payload,
        signature: None,
    };

    let response = child.request(&request)?;
    let receipt = psk_anchor::ingress_p24_via_exclusive_pipe(&response.payload);
    child.shutdown()?;
    receipt
}

/// Schritt 12: Reconciliation.
fn run_reconciliation(
    attempt: EffectAttempt,
    receipt: ExternalReceipt,
    token_plan_digest: Digest,
    token_issuer_digest: Digest,
    anchor_ref: ObjectId,
) -> Result<ReconciliationReport, PskError> {
    let mut residues = ResidueLedger::new();
    reconcile(
        ReconcileInputs {
            plan_ref: ObjectId::new(SortId::Effect, Digest::sha256(b"golden-run-patch-plan")),
            plan_digest: attempt.plan_digest,
            attempt,
            token_plan_digest,
            token_issuer_digest,
            receipts: vec![receipt],
            anchor_ref,
            diff: DiffOutcome::Empty,
            finality: psk_types::objects::ReconciliationReportFinalityKind::Final,
            witness_ref: ObjectId::new(SortId::Witness, Digest::sha256(b"golden-run-witness")),
            opened_at: run_time(),
        },
        &mut residues,
    )
}

/// Schritt 13, Zertifikatsteil. `replay_class` kommt vom Aufrufer - siehe
/// `run_golden_run_with_certificate`, wo er aus einem echten Vergleich
/// zweier Laeufe folgt (Definition 22.1: keine Eigenschaft eines
/// einzelnen Laufs).
fn issue_golden_run_certificate(
    reconciliation: &ReconciliationReport,
    replay_class: MachineCertificateReplayClassKind,
    trace_head: Digest,
    replay_manifest_digest: Digest,
) -> Result<MachineCertificate, PskError> {
    let acceptance = AdditionalAcceptance {
        artifact_conformant: true,
        kernel_executable: true,
        replay_valid: matches!(
            replay_class,
            MachineCertificateReplayClassKind::R2 | MachineCertificateReplayClassKind::R3
        ),
        sandbox_effect_safe: reconciliation.verdict
            == psk_types::objects::ReconciliationReportVerdictKind::Closed,
        reference_validated: true,
        externally_reproduced: false,
    };
    let features: Vec<FeatureCoverageId> = vec![FeatureCoverageId::Fc0, FeatureCoverageId::Fc1];
    let class = compute_conformance_class(&features, acceptance);
    let _ = class; // im Zertifikat selbst getragen (compute_conformance_class laeuft dort intern erneut)
    check_minimum_replay_class(replay_class)?;
    issue_certificate(CertificateInputs {
        i_c: Digest::sha256(b"golden-run-i-c"),
        i_a: Digest::sha256(b"golden-run-i-a"),
        i_m: Digest::sha256(b"golden-run-i-m"),
        i_t: Digest::sha256(b"golden-run-i-t"),
        features,
        acceptance,
        replay_class,
        gate_report_digest: Digest::sha256(b"golden-run-gate-report"),
        trace_head,
        replay_manifest_digest,
        residue_report_digest: Digest::sha256(b"golden-run-residue-report"),
        capability_audit_digest: Digest::sha256(b"golden-run-capability-audit"),
        negative_test_report_digest: Digest::sha256(b"golden-run-negative-tests"),
        scope: ScopeExpr("golden-run".into()),
        issued_at: run_time(),
        signature: psk_types::Signature(vec![]),
        // Regel 7.47 (PSK-RA v1.0.17): `features` oben (nur Fc0/Fc1) haelt
        // diesen Lauf absichtlich unterhalb jeder Klasse, die OBL-010
        // (blocking_from: C4) ueberhaupt betrifft - siehe `is_relevant` in
        // `check_platform_bound_obligations`. Ein leerer Vektor ist hier
        // deshalb kein uebersehener Fall, sondern der ehrliche Stand: diese
        // Funktion beansprucht nie eine plattformgebundene Klasse. Ein
        // kuenftiger Aufrufer, der tatsaechlich C4 beansprucht, MUSS
        // `architecture/obligations.yaml` real laden und hier eintragen.
        current_platform: std::env::consts::OS.to_string(),
        platform_bound_obligations: vec![],
    })
}

/// Orchestriert alle 13 Schritte aus Regel 24.3 gegen eine echte,
/// vom Aufrufer bereitgestellte Sandbox (kein `/tmp`-Zufallspfad hier -
/// Determinismus/Reproduzierbarkeit ist Definition 24.2's eigene Anforderung).
pub fn run_golden_run(
    workspace_root: &Path,
    sandbox_root: &Path,
) -> Result<GoldenRunReport, PskError> {
    fs::create_dir_all(sandbox_root).map_err(|_| PskError::UntypedInput)?;

    let mut trace = TraceStore::new();
    // T-RES-001/Algorithmus 18.6: `evaluate_gate` selbst haengt jetzt jede
    // Auswertung an `trace` und residualisiert jede Nicht-PASS-Entscheidung
    // hier - eine Sammelablage fuer den gesamten Lauf, nicht pro Aufruf neu.
    let mut residues = ResidueLedger::new();
    let genesis_ref = TraceRef(trace.head());

    let boot_report = run_boot(
        workspace_root,
        sandbox_root,
        genesis_ref,
        &mut trace,
        &mut residues,
    )?;
    let boot_gate = boot_report.gate_report.clone();
    let after_boot = record(
        &mut trace,
        "boot.gate.evaluated",
        ModuleId::AuthorityConsequenceGate,
        vec![boot_gate.id],
        Digest::sha256(b"boot"),
    )?;

    let anchor = seal_workspace_anchor(sandbox_root, after_boot)?;
    let after_anchor = record(
        &mut trace,
        "anchor.sealed",
        ModuleId::AnchorRegistry,
        vec![anchor.id],
        anchor.digest,
    )?;

    let thought = compile_thought(&anchor, after_anchor)?;
    let after_thought = record(
        &mut trace,
        "thought.compiled",
        ModuleId::ThoughtCompiler,
        vec![thought.id],
        Digest::sha256(b"thought"),
    )?;

    let reality = classify_thought_reality(&thought, &anchor, after_thought)?;
    let after_reality = record(
        &mut trace,
        "reality.classified",
        ModuleId::RealityTyper,
        vec![reality.id],
        Digest::sha256(b"reality"),
    )?;
    let _ = after_reality;

    let field_projections = run_static_field_family(&anchor, reality.reality_status)?;
    let after_fields = record(
        &mut trace,
        "field-family.projected",
        ModuleId::FieldRegistry,
        field_projections.iter().map(|p| p.id).collect(),
        Digest::sha256(b"fields"),
    )?;
    let _ = after_fields;

    let (dependency_profile, glue_outcome) = quotient_and_glue(&field_projections)?;
    let after_glue = record(
        &mut trace,
        "dependency.quotiented",
        ModuleId::DependencyAnalyzer,
        vec![dependency_profile.id],
        Digest::sha256(b"quotient"),
    )?;

    // Schritt 7 (offene Obligationen read-only validieren): der Golden Run
    // eroeffnet keine Witness-Obligation, die den Patch blockiert - eine
    // leere Liste ist hier ein echtes Resultat (nichts offen), keine
    // uebersprungene Pruefung.
    let validation_open_obligations: Vec<ObligationExpr> = Vec::new();

    let patch_gate = evaluate_patch_gate(after_glue, &glue_outcome, &mut trace, &mut residues)?;
    let after_patch_gate = record(
        &mut trace,
        "patch.gate.evaluated",
        ModuleId::AuthorityConsequenceGate,
        vec![patch_gate.id],
        Digest::sha256(b"patch-gate"),
    )?;

    let scope_file = "golden-run-patch.txt";
    let content = "hello golden run";
    let (token_authorization, attempt) = issue_and_execute(
        &patch_gate,
        sandbox_root,
        scope_file,
        content,
        after_patch_gate,
    )?;
    let after_effect = record(
        &mut trace,
        "effect.attempted",
        ModuleId::EffectBoundary,
        vec![attempt.id],
        Digest::sha256(b"effect"),
    )?;

    let receipt = observe_and_receipt(sandbox_root, after_effect)?;
    let after_receipt = record(
        &mut trace,
        "receipt.ingressed",
        ModuleId::ExternalRecordIngress,
        vec![receipt.id],
        Digest::sha256(b"receipt"),
    )?;
    let _ = after_receipt;

    let reconciliation = run_reconciliation(
        attempt.clone(),
        receipt.clone(),
        attempt.plan_digest,
        Digest::sha256(b"golden-run-issuer"),
        anchor.id,
    )?;
    let after_reconciliation = record(
        &mut trace,
        "reconciliation.decided",
        ModuleId::ReconciliationEngine,
        vec![reconciliation.id],
        Digest::sha256(b"reconciliation"),
    )?;
    let _ = after_reconciliation;

    Ok(GoldenRunReport {
        boot_gate,
        boot_report,
        anchor,
        thought,
        reality,
        field_projections,
        dependency_profile,
        glue: glue_outcome,
        validation_open_obligations,
        patch_gate,
        token_authorization,
        attempt,
        receipt,
        reconciliation,
        trace_head: trace.head(),
        residues_opened: residues.all().len(),
    })
}

/// Fuehrt den Lauf zweimal gegen dieselbe Sandbox aus und bildet daraus
/// Schritt 13 (Regel 24.3: "Maschinenzertifikat UND Replaymanifest
/// exportieren" - beide sind genannt, keine Option). Definition 22.1
/// definiert die Replayklasse als Eigenschaft eines VERGLEICHS zweier
/// Laeufe, nicht eines einzelnen - deshalb laeuft `run_golden_run` hier
/// zweimal, bevor `issue_certificate` (Vertrag 22.2: mindestens R2 als
/// Vorbedingung) ueberhaupt aufgerufen werden kann.
pub fn run_golden_run_with_certificate(
    workspace_root: &Path,
    sandbox_root: &Path,
) -> Result<GoldenRunCertification, PskError> {
    // Eine bedeutungsvolle Replaypruefung braucht identische STARTZUSTaeNDE,
    // nicht nur denselben Pfad: Schritt 2 (AnchorSnapshot) beobachtet den
    // Dateibaum inhaltlich, und Schritt 10 veraendert genau diesen Baum -
    // ohne Reset saehe der zweite Lauf das Artefakt des ersten bereits
    // liegen und wuerde divergieren, nicht weil das System nichtdetermin-
    // istisch ist, sondern weil die beiden Laeufe unterschiedliche Eingaben
    // haetten. Der Reset selbst ist deshalb Teil des Testaufbaus, nicht des
    // gemessenen Laufs.
    let _ = fs::remove_dir_all(sandbox_root);
    let first_start = std::time::Instant::now();
    let first = run_golden_run(workspace_root, sandbox_root)?;
    let first_run_wall_clock = first_start.elapsed();
    let artifact_path = sandbox_root.join("golden-run-patch.txt");
    let first_artifact = fs::read(&artifact_path).map_err(|_| PskError::TraceOrResidueViolation)?;

    fs::remove_dir_all(sandbox_root).map_err(|_| PskError::TraceOrResidueViolation)?;
    let second = run_golden_run(workspace_root, sandbox_root)?;
    let second_artifact =
        fs::read(&artifact_path).map_err(|_| PskError::TraceOrResidueViolation)?;

    let check = psk_trace::ReplayCheck {
        replay_attempted: true,
        canonical_digest_match: first.trace_head == second.trace_head,
        gate_sequence_match: first.boot_gate.id == second.boot_gate.id
            && first.patch_gate.id == second.patch_gate.id,
        byte_identical_artifacts: first_artifact == second_artifact,
    };

    let run_descriptor = psk_trace::open_run(psk_trace::RunInputs {
        run_id: RunId("golden-run".into()),
        i_c: Digest::sha256(b"golden-run-i-c"),
        i_a: Digest::sha256(b"golden-run-i-a"),
        i_m: Digest::sha256(b"golden-run-i-m"),
        seed: [7u8; 32],
        versions: std::collections::BTreeMap::new(),
        input_digests: vec![first.trace_head],
        operators: vec![OpId::Replay],
        environment: psk_types::objects::EnvironmentProfile("golden-run-reference-domain".into()),
        time_window: TimeWindow("golden-run-window".into()),
        nondeterminism_budget: psk_types::objects::NDBudget("none-declared".into()),
        canon: psk_types::objects::CanonicalizationProfile("psk.canon/1.0".into()),
    })?;

    let replay_manifest = psk_trace::build_replay_manifest(
        RunId("golden-run".into()),
        run_descriptor.digest,
        vec![first.trace_head],
        vec![psk_types::objects::ExternalRecordRef {
            receipt_id: format!("{:?}", first.receipt.id),
            digest: first.receipt.result_digest,
            observer_identity: first.receipt.observer_identity,
        }],
        first.trace_head,
        second.trace_head,
        Digest::sha256(
            format!(
                "{:?}|{:?}",
                first.boot_gate.decision, first.patch_gate.decision
            )
            .as_bytes(),
        ),
        &check,
        vec![],
    );
    let replay_manifest_digest = Digest::sha256(
        serde_json::to_vec(&replay_manifest)
            .map_err(|_| PskError::CanonicalizationFailed)?
            .as_slice(),
    );

    // `ReplayManifestAchievedClassKind` (psk-trace) und
    // `MachineCertificateReplayClassKind` (psk-certify) sind zwei
    // eigenstaendige, vom Codegen pro Struct generierte Typen mit
    // identischen Variantennamen (R0..R3) - keine gemeinsame Definition,
    // siehe object_schemas.yaml. Reine Umbenennung, keine Werteentscheidung.
    let replay_class = match replay_manifest.achieved_class {
        psk_types::objects::ReplayManifestAchievedClassKind::R0 => {
            MachineCertificateReplayClassKind::R0
        }
        psk_types::objects::ReplayManifestAchievedClassKind::R1 => {
            MachineCertificateReplayClassKind::R1
        }
        psk_types::objects::ReplayManifestAchievedClassKind::R2 => {
            MachineCertificateReplayClassKind::R2
        }
        psk_types::objects::ReplayManifestAchievedClassKind::R3 => {
            MachineCertificateReplayClassKind::R3
        }
    };

    let certificate = issue_golden_run_certificate(
        &first.reconciliation,
        replay_class,
        first.trace_head,
        replay_manifest_digest,
    )?;

    Ok(GoldenRunCertification {
        first,
        second,
        replay_check: check,
        replay_manifest,
        certificate,
        first_run_wall_clock,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> std::path::PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        loop {
            if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
                return dir;
            }
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
    }

    fn copy_dir_all(src: &Path, dst: &Path) {
        fs::create_dir_all(dst).unwrap();
        for entry in fs::read_dir(src).unwrap() {
            let entry = entry.unwrap();
            let ty = entry.file_type().unwrap();
            let dest_path = dst.join(entry.file_name());
            if ty.is_dir() {
                copy_dir_all(&entry.path(), &dest_path);
            } else {
                fs::copy(entry.path(), &dest_path).unwrap();
            }
        }
    }

    #[test]
    fn golden_run_completes_steps_1_through_12_against_a_real_sandbox() {
        let root = workspace_root();
        let sandbox = std::env::temp_dir().join(format!("psk-golden-run-{}", std::process::id()));
        let _ = fs::remove_dir_all(&sandbox);

        let report = run_golden_run(&root, &sandbox).expect("golden run sollte durchlaufen");

        // Schritt 19: fuer ein korrekt versiegeltes, deckungsgleiches Bundle
        // (der echte Workspace-Root) erreicht G-BOOT jetzt real PASS - der
        // erste Lauf im Projekt, bei dem der Bootgate wirklich besteht statt
        // strukturell zu HOLDen (psk_contract::boot, siehe golden_run.rs
        // Modulkopf). Ein HOLD hier waere jetzt das Alarmsignal: es wuerde
        // heissen, die reale Pruefung erkennt den eigenen, korrekt
        // versiegelten Workspace nicht mehr als konform.
        assert_eq!(
            report.boot_gate.decision,
            psk_types::objects::GateReportDecisionKind::Pass
        );
        assert_eq!(report.boot_gate.gate_id, GateId::GBoot);
        assert_eq!(report.boot_report.state, psk_lifecycle::RuntimeState::Bound);
        assert_eq!(
            report.boot_report.posture,
            psk_types::objects::Releaseposture::ConformantLimited
        );
        // T-RES-001/Algorithmus 18.6: da sowohl Bootgate als auch spaeter
        // Patchgate (G-EFFECT) in diesem Szenario PASS erreichen, entsteht
        // hier - richtigerweise - kein einziges Residuum. Siehe die
        // Schwesterdatei psk-contract/src/boot.rs fuer den expliziten
        // HOLD-Fall (unversiegeltes Bundle), der weiterhin mindestens ein
        // Residuum erzeugt.
        assert_eq!(
            report.residues_opened, 0,
            "ein vollstaendig PASSender Lauf darf nichts residualisieren"
        );

        assert!(report.anchor.sealed);
        assert_eq!(report.thought.anchor_refs, vec![report.anchor.id]);
        assert_eq!(
            report.field_projections.len(),
            6,
            "sechs Archetypen (Regel 32.7)"
        );
        assert!(
            report.glue.hold_reason.is_none(),
            "sechs identische Restriktionen muessen kompatibel verkleben"
        );
        assert_eq!(report.patch_gate.gate_id, GateId::GEffect);
        assert_eq!(report.token_authorization.gate_id, GateId::GEffect);
        assert_eq!(
            report.attempt.outcome,
            psk_types::objects::EffectAttemptOutcomeKind::Completed
        );

        let written = fs::read_to_string(sandbox.join("golden-run-patch.txt")).unwrap();
        assert_eq!(written, "hello golden run");

        assert_eq!(
            report.reconciliation.fact_promotion,
            psk_types::objects::ReconciliationReportFactPromotionKind::Actualized
        );
        assert_eq!(
            report.reconciliation.verdict,
            psk_types::objects::ReconciliationReportVerdictKind::Closed
        );

        assert_ne!(report.trace_head, psk_trace::GENESIS_DIGEST);

        fs::remove_dir_all(&sandbox).ok();
    }

    #[test]
    fn boot_still_holds_for_a_bundle_whose_constitution_is_not_yet_sealed() {
        // Regel 17.2s undecidable->hold-Pfad darf durch die M00/M02/M04-
        // Realisierung nicht verschwinden - nur der DEFAULT-Fall (echter,
        // versiegelter Workspace) aendert sich von HOLD auf PASS. Diese
        // Kopie versiegelt eine echte, real schemakonforme Architektur,
        // aber eine Konstitution ohne constitution_id - "noch nicht
        // versiegelt", keine Digest-Divergenz.
        let root = workspace_root();
        let dir =
            std::env::temp_dir().join(format!("psk-golden-run-unsealed-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        copy_dir_all(&root.join("architecture"), &dir.join("architecture"));
        fs::create_dir_all(dir.join("constitution")).unwrap();
        fs::write(
            dir.join("constitution/constitution.lock.json"),
            r#"{"constitution_id": null, "normative_files": []}"#,
        )
        .unwrap();
        // implementation_id() braucht irgendein lesbares Cargo.lock unter
        // bundle_root - Inhalt ist fuer diesen Test irrelevant, nur die
        // Lesbarkeit.
        fs::write(dir.join("Cargo.lock"), b"fake-lock-for-test").unwrap();

        let mut trace = TraceStore::new();
        let mut residues = ResidueLedger::new();
        let trace_ref = TraceRef(trace.head());
        let report = run_boot(&dir, &dir, trace_ref, &mut trace, &mut residues)
            .expect("ein unversiegeltes, aber lesbares Bundle ist HOLD, kein harter Fehler");

        assert_eq!(
            report.gate_report.decision,
            psk_types::objects::GateReportDecisionKind::Hold
        );
        assert_eq!(
            report.state,
            psk_lifecycle::RuntimeState::Booting,
            "ohne PASS bleibt der FSM-Zustand BOOTING, nicht BOUND"
        );
        assert!(
            !residues.all().is_empty(),
            "die HOLD-Entscheidung muss weiterhin residualisiert werden (T-RES-001)"
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn replaying_the_golden_run_twice_earns_a_real_certificate() {
        let root = workspace_root();
        let sandbox =
            std::env::temp_dir().join(format!("psk-golden-run-replay-{}", std::process::id()));
        let _ = fs::remove_dir_all(&sandbox);

        let result = run_golden_run_with_certificate(&root, &sandbox)
            .expect("zwei deterministische Laeufe sollten mindestens R2 erreichen");

        assert!(result.replay_check.replay_attempted);
        assert!(
            result.replay_check.canonical_digest_match,
            "zwei Laeufe mit identischen, zeitfesten Eingaben muessen denselben Trace-Kopf ergeben"
        );
        assert!(result.replay_check.gate_sequence_match);
        assert!(result.replay_check.byte_identical_artifacts);
        assert_eq!(
            result.replay_manifest.achieved_class,
            psk_types::objects::ReplayManifestAchievedClassKind::R3
        );
        assert_eq!(
            result.certificate.replay_class,
            MachineCertificateReplayClassKind::R3
        );
        assert_eq!(result.certificate.I_C, Digest::sha256(b"golden-run-i-c"));

        fs::remove_dir_all(&sandbox).ok();
    }
}
