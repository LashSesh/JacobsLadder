//! Golden Run Harness (Definition 24.2 (Golden Run), Regel 24.3 (Golden-Run-Ablauf)).
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
//! # Schritt 1: Bootgate, real (Algorithmus 17.1 (Boot) vollstaendig realisiert)
//!
//! Algorithmus 17.1 (Boot) hat 21 Schritte ueber M00-M04, M14, M15, M19,
//! M21, M22, M26; `g = M14.gate("G-BOOT", all_of(above))` aggregiert ALLE
//! davon. M00 (Bundle-Loader), M02 (Artefaktregistrierung) und M04
//! (Identitaetsbindung/Profilbindung) sind seit `packages/psk-contract`
//! real (`psk_contract::boot`, dort Algorithmus 17.1 (Boot) Schritt fuer Schritt
//! nachgebaut - siehe dessen Modulkopf fuer jede Realisierungsentscheidung
//! und ihre Begruendung), ebenso M15s
//! `register_only_versioned_operators_and_capabilities` (Schritt 17,
//! psk-effect) und M21s `compute_release_and_operational_posture`
//! (Schritt 18, psk-certify, Definition 31.3 (Releaseposture)). Diese Funktion ruft
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
//! interner `M11.seam_report`-Aufruf, da SeamReport (Struktur 7.30 (SeamReport / ObstructionRecord)) M13-
//! zellenfoermig ist und G-BOOT keinen M13-Zellbezug hat) - beides wird
//! jetzt innerhalb von `psk_contract::boot` selbst gesetzt, siehe dort.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use psk_certify::{
    check_minimum_replay_class, issue_certificate, AdditionalAcceptance, CertificateInputs,
};
use psk_closure::GlueOutcome;
use psk_effect::{EffectAdapter, EffectLines, IssueInputs, ProcessEffectAdapter};
use psk_gate::{authorize, evaluate_gate, ConditionOutcome, GateAuthorization, GateInputs};
use psk_scheduler::{
    has_pending_work, sigma_digest, tick, AssemblyDeclarations, CapsuleSpec, FieldFamilyEntry,
    GlueSpec, PatchGateSpec, PendingRecord, Profiling, ReceiptDeposit, ReconcileSpec, Sigma,
};
use psk_trace::{ResidueLedger, TraceStore};
use psk_types::objects::{
    AnchorSnapshot, ArchetypeId, BoundarySpec, BudgetSpec, CapabilityId, Claim,
    ClaimDirectionalityKind, ClaimExpr, ConsequenceRef, ContextRef, DependencyProfile,
    DependencyProfileConsensusScopeKind, DomainExpr, EffectAttempt, EffectClassId,
    EffectTokenRollbackKind, ExternalReceipt, FeatureCoverageId, FieldIdentity, FieldProjection,
    GateId, IRNodeId, Lineage, M13Address, MachineCertificate, MachineCertificateReplayClassKind,
    ModelRef, ObligationExpr, Observation, OpId, PredicateExpr, ProfileId, QuestionSpec,
    RealityClassification, ReasonCode, ReceiptSpec, ReconciliationReport, ReplayDescriptor,
    RollbackSpec, ScopeExpr, ScopeSpec, SemVer, SortId, SourceRef, ThoughtBody, TimeWindow,
    TrajectoryRef, UncertaintyBlock, UncertaintyModelId, Validity, WitnessPolicy,
};
use psk_types::{
    ClockRef, Digest, DualTime, MessageType, ModuleId, Msg, ObjectId, PortId, PskError, RunId,
    SchemaId, TraceRef, Ulid,
};

/// Regel 12.7 (Selektionsdruck) / v1.0.26: das Ratchet-Rundenbudget dieses Laufs. EINE
/// deklarierte Quelle fuer beide Verbraucher - der RunDescriptor traegt
/// die Deklaration ("im RunDescriptor erzwungen"), die Challenge-Phase
/// verbraucht denselben Wert. Zwei getrennte Zahlen waeren zwei
/// Wahrheiten.
const GOLDEN_RUN_RATCHET_MAX_ROUNDS: u32 = 4;

/// Das Artefakt, ueber dem die Anforderungen des Korpus streiten und das
/// der Patch aendert - eine Zeichenkette, zwei Verbraucher (Korpus und
/// Lauf), damit sie nicht auseinanderlaufen.
const GOLDEN_RUN_PATCH_TARGET: &str = "golden-run-patch.txt";

/// Deterministische Laufzeit (Definition 24.2 (Golden Run): "erwartetem kanonischen
/// Zustandsdigest" - Replaystabilitaet verlangt eine feste, nicht eine
/// systemuhrabhaengige Zeit). Basiszeit der Deponate und des Zertifikats.
fn run_time() -> DualTime {
    DualTime {
        tau_i: 1_000_000,
        tau_e: "2026-08-05T00:00:00.000000000Z".into(),
        clock_ref: ClockRef("golden-run".into()),
        uncertainty_ns: 0,
    }
}

/// Die Zeit eines Takts: tau_i schreitet je Takt deterministisch fort
/// ("reale Zeitfortschreibung je Ereignis ist Sache des Aufrufers",
/// tick.rs) - logische Zeit, die steht, waehrend tick_no steigt, waere
/// eine Uhr, die luegt. tau_e bleibt fest: die Wanduhr ist volatil und
/// geht in keinen Digest ein (Invariante 6.14 (Replayneutralität der Wanduhr)).
fn tick_time(tick_no: u64) -> DualTime {
    DualTime {
        tau_i: 1_000_000 + tick_no,
        ..run_time()
    }
}

/// Gesammeltes Ergebnis EINER Ausfuehrung der Schritte 1-12 (Regel 24.3 (Golden-Run-Ablauf)).
/// Schritt 13 (Zertifikat/Replaymanifest) ist bewusst NICHT Teil dieses
/// Typs: `issue_certificate` verlangt Vertrag 22.4 (Replayklasse des Referenzrelease), mindestens R2 als
/// Vorbedingung, und eine Replayklasse ist per Definition 22.1 (Replayklassen) keine
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
    /// (T-RES-001/Algorithmus 18.6 (Gate-Auswertung): jede Nicht-PASS-Entscheidung MUSS
    /// residualisiert werden). Bei einem PASS-Bootgate kann das durchaus 0
    /// sein - siehe die beiden golden_run-Tests (PASS- und HOLD-Fall).
    pub residues_opened: usize,
    /// Die Kapsel des Laufs nach Challenge (eine je Quotientenklasse;
    /// dieser Lauf hat genau eine Klasse). Herausgegeben als FC5-Artefakt:
    /// Kandidatenkapsel, Ratchet und Supportentscheidung sind an ihr
    /// ablesbar. `capsule_reached_fixpoint` haelt fest, WELCHER der beiden
    /// zulaessigen Challenge-Ausgaenge eintrat (Definition 14.2 (Phasen-Modul-Bindung)) -
    /// Fixpunkt, nicht Budget-RESIDUAL.
    pub capsule: psk_types::objects::CandidateCapsule,
    pub capsule_reached_fixpoint: bool,
    /// Wie viele Ratchet-Runden bis zum Fixpunkt noetig waren. Ohne
    /// Gegenmodelle stand er in Runde 1; mit ihnen kontrahiert Runde 1
    /// erst, und der Fixpunkt steht eine Runde spaeter.
    pub ratchet_rounds: u32,
    /// Ob der Kandidat adversarial geschlossen ist (Invariante
    /// "Nichttrivialitaet des Ueberlebens"). `false` heisst: er schliesst
    /// nur unter Ausblendung eines Gegenmodells - PSK-E003, als Residuum
    /// weitergetragen statt still verworfen.
    pub adversarially_closed: bool,
    /// Schritt 2/3 des Referenzauftrags: die im Korpus identifizierten
    /// Widersprueche samt bestimmter Geltung.
    pub contradictions: Vec<crate::Contradiction>,
    /// Was der Integrator daraus gemacht hat - je offenem Widerspruch
    /// eine Obstruktion der Art `order`.
    pub obstructions: Vec<psk_types::objects::ObstructionRecord>,
    /// Die sechs Feldidentitaeten des Laufs (Regel 32.7 (Feldfamilie der Referenzdomäne)) - herausgegeben,
    /// weil sie Lin_lambda tragen: FC4s Lineage-Beleg zaehlt NICHTLEERE
    /// Lineages an realen Laufobjekten, und ein Objekt, das der Bericht
    /// nicht enthaelt, kann nichts belegen. Dieselbe Ueberlegung, aus der
    /// schon `residues` und der EffectToken herausgegeben wurden.
    pub field_identities: Vec<FieldIdentity>,
    /// Der IRBundle-Kandidat dieses Laufs (Definition 14.2 (Phasen-Modul-Bindung), Compile).
    /// `emission_class` ist HOLD - siehe psk_ir::assembly.
    pub ir_bundle: psk_types::objects::IRBundle,
    /// Regel 10.9 (Herkunft der Kantenbedingungen): je Relationssorte ohne Deklaration im Domaenenprofil
    /// ein ResidueRecord(scope).
    ///
    /// BEWUSST getrennt von `residues`: jene sind Gate-Residuen
    /// (Algorithmus 18.6 (Gate-Auswertung), "jede Nicht-PASS-Entscheidung MUSS
    /// residualisiert werden"), diese halten eine fehlende
    /// Domaenendeklaration fest. Beides in einen Topf zu werfen wuerde
    /// zwei verschiedene Bedeutungen vermengen - und die Aussage von
    /// `residues_opened == 0` ("ein vollstaendig PASSender Lauf darf
    /// nichts residualisieren") zerstoeren, obwohl sie zutreffend bleibt.
    pub ir_scope_residues: Vec<psk_types::objects::ResidueRecord>,
    /// Jede nicht gebaute Kante mit Grund.
    pub ir_omissions: Vec<psk_ir::EdgeOmission>,
    /// Die Residuensaetze selbst, nicht nur ihre Anzahl - Eingabe des
    /// `residue_report_digest`, das Struktur 7.49 (MachineCertificate) als einen der vier
    /// Berichtsdigests verlangt. Ein Bericht ueber eine Zahl waere keiner.
    pub residues: Vec<psk_types::objects::ResidueRecord>,
    /// Vertrag 9.7 (Zellclosure) ueber dem finalen Graphen: alle 18 Zellberichte
    /// (Regel 9.9 (Leere Zelle schließt vakuum, aber nicht stillschweigend) verlangt, die Vakuumschliessungen AUSZUWEISEN - die
    /// Zahl steht in den occupancy-Feldern, `vacuum_closed_count`
    /// leitet sie ab).
    pub cell_reports: Vec<psk_topology::CellReport>,
    /// Die sieben Bedingungen aus pass_registry.executable_requires,
    /// einzeln abgeleitet. `close720_replay_canon_eq` bleibt im
    /// Einzellauf None - Definition 22.1 (Replayklassen) macht die Replayklasse zur
    /// Eigenschaft eines VERGLEICHS zweier Laeufe; erst die
    /// Zertifizierung fuellt sie.
    pub executable: ExecutableCheck,
    /// Wie viele Takte der Lauf brauchte (Regel 24.4 (Der Golden Run
    /// laeuft unter tick)): `Sigma.tick_no` nach der Schleife. Der
    /// positive Nachweis, dass die Schritte 2-13 als Phasenarbeit
    /// liefen - 0 hiesse: der Lauf hat den Taktzyklus nie betreten.
    pub ticks: u64,
    /// I_t = H(Can(Sigma_t)) NACH den Takten (Regel 6.10 (Vier Identitäten), Vier
    /// Identitaeten; Regel 24.4 (Der Golden Run läuft unter tick): "Sigma_t ist der Zustand nach den
    /// Takten"). Abgeleitet, nie behauptet.
    pub i_t: Digest,
    /// Die Tracesegmente des Laufs - nicht nur ihr Kopf. QPM-3 misst den
    /// Phasenlift an den SIEGELN: eine Beobachtung ohne Siegelbezug waere
    /// eine Ablesung im offenen Umlauf. Dieselbe Ueberlegung, aus der
    /// schon `residues` und die Feldidentitaeten herausgegeben wurden.
    pub trace_segments: Vec<psk_trace::TraceSegment>,
}

/// pass_registry.yaml, `executable_requires`: [fully_typed,
/// anchor_bound_or_declared_unanchored, all_18_cells_closed, close720,
/// unique_global_section, all_blocking_gates_pass, no_blocking_residue].
/// Jedes Feld ist abgeleitet, keines behauptet; die Herkunft steht am
/// Feld. Regel 9.21 (Triviale Route ist eine Route): die beiden trivial wahren Close720-Schenkel sind
/// als trivial AUSGEWIESEN und gelten nicht als Beleg fuer
/// Transportkorrektheit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutableCheck {
    /// Jeder Knoten traegt genau eine Primaersorte (typkonstruktiv).
    pub fully_typed: bool,
    /// Jeder Knoten traegt anchor_refs oder waere als unanchored
    /// deklariert (der Referenzlauf deklariert keines).
    pub anchor_bound_or_declared_unanchored: bool,
    /// psk_topology::all_18_closed ueber den 18 Zellberichten.
    pub all_18_cells_closed: bool,
    /// Regel 9.9 (Leere Zelle schließt vakuum, aber nicht stillschweigend): wie viele der geschlossenen Zellen vakuum schlossen.
    pub cells_vacuum_closed: usize,
    /// Close720-Schenkel 1: Phi^2(x) ==can x. Bei max_depth = 0 gilt
    /// Phi = I aus T_ii = I (Regel 9.21 (Triviale Route ist eine Route)) - TRIVIAL, ausgewiesen.
    pub close720_phi_squared_trivially: bool,
    /// Close720-Schenkel 2: Hol(Phi^2) = I - ebenso trivial (Regel 9.21 (Triviale Route ist eine Route)).
    pub close720_holonomy_trivially: bool,
    /// Close720-Schenkel 3: Replay(Phi^2) ==can x. Braucht den
    /// Zweitlauf (Definition 22.1 (Replayklassen)); None heisst "in diesem Artefakt
    /// nicht bestimmbar", nicht "bestanden".
    pub close720_replay_canon_eq: Option<bool>,
    /// GlueOutcome.section ist eindeutig vorhanden.
    pub unique_global_section: bool,
    /// Beide Gates des Laufs (G-BOOT, G-EFFECT) auf PASS.
    pub all_blocking_gates_pass: bool,
    /// Kein Residuum des Laufs traegt severity Blocking.
    pub no_blocking_residue: bool,
    /// Die Namen der verletzten Bedingungen - leer heisst: EXECUTABLE
    /// haengt nur noch am Replay-Schenkel.
    pub blockers: Vec<String>,
}

impl ExecutableCheck {
    /// Close720 gesamt: die zwei trivialen Schenkel und der Replayschenkel.
    pub fn close720(&self) -> Option<bool> {
        self.close720_replay_canon_eq.map(|replay| {
            self.close720_phi_squared_trivially && self.close720_holonomy_trivially && replay
        })
    }

    /// EXECUTABLE erreichbar? None, solange der Replayschenkel offen ist.
    pub fn executable_reachable(&self) -> Option<bool> {
        self.close720().map(|c720| {
            self.fully_typed
                && self.anchor_bound_or_declared_unanchored
                && self.all_18_cells_closed
                && c720
                && self.unique_global_section
                && self.all_blocking_gates_pass
                && self.no_blocking_residue
        })
    }
}

/// Ergebnis von Schritt 13 plus der beiden Laeufe, aus deren Vergleich die
/// Replayklasse (Definition 22.1 (Replayklassen)) tatsaechlich folgt.
pub struct GoldenRunCertification {
    pub first: GoldenRunReport,
    pub second: GoldenRunReport,
    pub replay_check: psk_trace::ReplayCheck,
    pub replay_manifest: psk_types::objects::ReplayManifest,
    pub certificate: MachineCertificate,
    /// PROPOSE_REVISION: der eine Vorschlag dieses Laufs (Struktur 12.12 (RevisionProposal)),
    /// mit getrennt gefuehrten vorhandenen/fehlenden CRA-Eingaben.
    pub revision_proposal: psk_types::objects::RevisionProposal,
    /// G-SELF-COMPILE ueber den Vorschlag - das FC7-Artefakt. Sein
    /// decision-Feld ist der Messwert, nicht das Ziel.
    pub self_compile_gate: psk_types::objects::GateReport,
    /// Die Residuen der Gateauswertung (Nicht-PASS residualisiert).
    pub self_compile_residues: Vec<psk_types::objects::ResidueRecord>,
    /// Laufzeit NUR des ersten Laufs (`first`), getrennt von der
    /// Gesamtlaufzeit der Zertifizierung (die zusaetzlich den zweiten,
    /// nur der Replaypruefung dienenden Lauf einschliesst). Aufrufer, die
    /// "wie lange dauert EIN Validierungslauf" messen wollen (z.B.
    /// `baselines::comparison`, das dieselbe Groesse gegen einzelne
    /// Baseline-Laeufe stellt), brauchen diese Zahl statt der Gesamtzeit -
    /// sonst waere der Vergleich 2 Kern-Laeufe gegen 1 Baseline-Lauf.
    pub first_run_wall_clock: std::time::Duration,
}

/// Schritt 1. Siehe Modulkopf - ruft jetzt den vollstaendigen, realen
/// `psk_contract::boot()` (Algorithmus 17.1 (Boot), alle 21 Schritte) gegen den
/// echten Workspace-Root auf. `store_root` ist bewusst NICHT
/// `workspace_root`: Struktur 16.7 (Store-Layout)s Store-Lock gehoert zu einer eigenen,
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
            budget: psk_contract::default_budget(psk_types::RunId("golden-run".into())),
            // Skalentiefe 0: der Referenzlauf betritt nur M13(0), er
            // steigt nicht ab. Deklariert, nicht bequem gewaehlt.
            max_depth: 0,
        },
        trace,
        residues,
    )
}

/// Schritt 2: Workspace als AnchorSnapshot versiegeln - `observer_local_fs::
/// observe` liest den Sandbox-Baum wirklich vom Dateisystem (kein
/// simulierter Rueckgabewert).
/// Kopiert das Korpus in das beobachtete Verzeichnis und liefert seinen
/// Digest - die Groesse, an die das Frischepraedikat des Ankers gebunden
/// wird. Kopiert der Aufruf nichts, ist das ein Fehlschlag und kein
/// leerer Erfolg: ein Korpus, das nicht ankommt, versiegelt sich nicht.
fn stage_corpus(corpus_root: &Path, sandbox_root: &Path) -> Result<Digest, PskError> {
    fn copy_into(src: &Path, dst: &Path, count: &mut usize) -> Result<Vec<u8>, PskError> {
        let mut acc = Vec::new();
        let mut entries: Vec<_> = fs::read_dir(src)
            .map_err(|_| PskError::UntypedInput)?
            .filter_map(Result::ok)
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let from = e.path();
            let to = dst.join(e.file_name());
            if from.is_dir() {
                fs::create_dir_all(&to).map_err(|_| PskError::UntypedInput)?;
                acc.extend(copy_into(&from, &to, count)?);
            } else {
                let bytes = fs::read(&from).map_err(|_| PskError::UntypedInput)?;
                fs::write(&to, &bytes).map_err(|_| PskError::UntypedInput)?;
                acc.extend(e.file_name().to_string_lossy().as_bytes());
                acc.extend(&bytes);
                *count += 1;
            }
        }
        Ok(acc)
    }
    let mut count = 0usize;
    let material = copy_into(corpus_root, sandbox_root, &mut count)?;
    if count == 0 {
        // Nullbefund ueber nichtleerer Arbeitsliste.
        return Err(PskError::UntypedInput);
    }
    Ok(Digest::sha256(&material))
}

/// Die sieben Bedingungen aus `executable_requires`, einzeln abgeleitet.
/// Jede Zeile nennt ihre Quelle; nichts hier ist gesetzt, damit ein
/// bestimmter Ausgang eintritt.
fn derive_executable_check(
    bundle: &psk_types::objects::IRBundle,
    cell_reports: &[psk_topology::CellReport],
    glue_outcome: &GlueOutcome,
    gates: &[&psk_types::objects::GateReport],
    residues: &ResidueLedger,
) -> ExecutableCheck {
    use psk_types::objects::GateReportDecisionKind;

    // fully_typed: SortId ist ein geschlossenes Enum - jeder Knoten
    // TRAEGT genau eine Primaersorte, sonst waere er nicht vom Typ
    // IRNode. Ein leerer Graph traegt nichts und belegt nichts.
    let fully_typed = !bundle.graph.nodes.is_empty();
    // Vertrag 11.6 (C3): Ankerreferenz oder ausdrueckliches
    // unanchored=true. Der Lauf deklariert kein unanchored - also MUSS
    // jeder Knoten anchor_refs tragen.
    let anchor_bound = bundle.graph.nodes.iter().all(|n| !n.anchor_refs.is_empty());
    let all_18 = psk_topology::all_18_closed(cell_reports);
    let vacuum = psk_topology::vacuum_closed_count(cell_reports);
    // Regel 9.21 (Triviale Route ist eine Route): bei max_depth = 0 folgt Phi = I aus T_ii = I - beide
    // Schenkel gelten TRIVIAL und sind hier als solche ausgewiesen
    // (die Felder heissen so). Der ClosureMode der Zellberichte traegt
    // dieselbe Auskunft je Zelle.
    // Kein Zellbericht traegt Substantive: alle Schliessungen sind
    // trivial oder vakuum (Regel 9.21 (Triviale Route ist eine Route)/9.9) - und werden genau so
    // ausgewiesen, nicht als gepruefte Struktur (Regel 9.11 (Vakuum ist kein Beleg)).
    let trivially = cell_reports
        .iter()
        .all(|r| r.closure_mode != psk_topology::ClosureMode::Substantive);
    let unique_section = glue_outcome.section.is_some();
    let gates_pass = gates
        .iter()
        .all(|g| g.decision == GateReportDecisionKind::Pass);
    let no_blocking = residues
        .all()
        .iter()
        .all(|r| r.severity != psk_types::objects::ResidueRecordSeverityKind::Blocking);

    let mut blockers = Vec::new();
    if !fully_typed {
        blockers.push("fully_typed".to_string());
    }
    if !anchor_bound {
        blockers.push("anchor_bound_or_declared_unanchored".to_string());
    }
    if !all_18 {
        for r in cell_reports.iter().filter(|r| !r.closed()) {
            blockers.push(format!(
                "all_18_cells_closed: Zelle {:?}{} offen",
                r.cell.kind, r.cell.k
            ));
        }
    }
    if !unique_section {
        blockers.push(format!(
            "unique_global_section: {}",
            glue_outcome.hold_reason.unwrap_or("keine Sektion")
        ));
    }
    if !gates_pass {
        blockers.push("all_blocking_gates_pass".to_string());
    }
    if !no_blocking {
        for r in residues
            .all()
            .iter()
            .filter(|r| r.severity == psk_types::objects::ResidueRecordSeverityKind::Blocking)
        {
            blockers.push(format!("no_blocking_residue: {} ({})", r.id, r.scope.0));
        }
    }

    ExecutableCheck {
        fully_typed,
        anchor_bound_or_declared_unanchored: anchor_bound,
        all_18_cells_closed: all_18,
        cells_vacuum_closed: vacuum,
        close720_phi_squared_trivially: trivially,
        close720_holonomy_trivially: trivially,
        close720_replay_canon_eq: None,
        unique_global_section: unique_section,
        all_blocking_gates_pass: gates_pass,
        no_blocking_residue: no_blocking,
        blockers,
    }
}

/// Ergebnis des getrennten Prozessbaus (Algorithmus Revisionsvorschlag:
/// build_in_isolation). `None`-Faelle gibt es hier nicht - konnte der
/// Kindprozess nicht laufen, sagt `spawned: false` genau das, und die
/// Gatebedingungen bleiben unentscheidbar statt falsch.
struct IsolatedCandidate {
    spawned: bool,
    /// Der Delta-Falsifikator des Kandidaten lief im Kind und fand den
    /// erwarteten Gegenbeleg.
    falsifier_pass: bool,
    /// Der Kandidatenlauf im Kind reproduziert den kanonischen Kopf des
    /// Elternlaufs.
    digest_match: bool,
    /// H(stdout des Kindes) - das Artefakt des isolierten Baus, in den
    /// Vorschlag versiegelt (isolation_build_ref).
    artefact: Option<ObjectId>,
}

/// Spawnt den Kandidaten als ECHTEN zweiten Prozess (dasselbe Muster wie
/// I8: `sibling_binary_path` + `psk-cli`), laesst dort Delta-Falsifikator
/// und vollen Lauf ausfuehren und liest beide Befunde aus dessen stdout.
///
/// Derselbe Sandboxpfad wie der Elternlauf, mit Reset im Kind: der
/// kanonische Kopf haengt ueber die Ankerbeobachtung am beobachteten
/// Pfad, also ist Pfadgleichheit Voraussetzung der Vergleichbarkeit -
/// exakt wie bei `cmd_golden_run_independent`.
fn run_isolated_candidate(
    sandbox_root: &Path,
    expected_countermodel: &str,
    parent_trace_head: Digest,
) -> IsolatedCandidate {
    let no_spawn = IsolatedCandidate {
        spawned: false,
        falsifier_pass: false,
        digest_match: false,
        artefact: None,
    };
    let Ok(exe) = psk_lifecycle::sibling_binary_path("psk-cli") else {
        return no_spawn;
    };
    let Ok(output) = std::process::Command::new(exe)
        .arg("candidate-check")
        .arg(sandbox_root)
        .arg(expected_countermodel)
        .output()
    else {
        return no_spawn;
    };
    if !output.status.success() {
        return IsolatedCandidate {
            spawned: true,
            falsifier_pass: false,
            digest_match: false,
            // Auch ein gescheiterter isolierter Lauf ist ein Artefakt.
            artefact: Some(ObjectId::new(
                SortId::Branch,
                Digest::sha256(&output.stdout),
            )),
        };
    }
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let falsifier_pass = stdout.lines().any(|l| l.trim() == "falsifier=PASS");
    let digest_match = stdout
        .lines()
        .find_map(|l| l.trim().strip_prefix("digest="))
        .map(|d| d == parent_trace_head.to_string())
        .unwrap_or(false);
    IsolatedCandidate {
        spawned: true,
        falsifier_pass,
        digest_match,
        artefact: Some(ObjectId::new(
            SortId::Branch,
            Digest::sha256(stdout.as_bytes()),
        )),
    }
}

/// PROPOSE_REVISION plus G-SELF-COMPILE, auf Zertifizierungsebene - nach
/// beiden Laeufen, weil die Vorbedingungen des Gates (Replay, Residuen)
/// erst dort vollstaendig vorliegen.
///
/// Jede der sechs Bedingungen kommt aus einem realen Artefakt oder ist
/// ehrlich FALSE mit benanntem Grund. Es wird nichts gesetzt, damit das
/// Gate einen bestimmten Ausgang nimmt - faellt es, ist der Grund der
/// Messwert.
struct SelfCompileOutcome {
    proposal: psk_types::objects::RevisionProposal,
    gate_report: psk_types::objects::GateReport,
    /// Die Residuen der Gateauswertung (Algorithmus 18.6 (Gate-Auswertung): jede
    /// Nicht-PASS-Entscheidung MUSS residualisiert werden) - eigenes
    /// Ledger, weil der Schritt nach den Laeufen liegt.
    residues: Vec<psk_types::objects::ResidueRecord>,
}

fn propose_and_evaluate_self_compile(
    workspace_root: &Path,
    sandbox_root: &Path,
    first: &GoldenRunReport,
    second: &GoldenRunReport,
    replay_manifest_digest: Digest,
    canon_profile: &str,
) -> Result<SelfCompileOutcome, PskError> {
    use psk_types::objects::RevisionProposalHardeningClassKind;

    // ---- Die vier real vorliegenden CRA-Eingaben, je als Digest ueber
    // dem echten Artefakt. Fork-Evidenz und Shadow-Witnesses existieren
    // nicht und werden von cra() unter cra_inputs_absent gefuehrt.
    let residue_bytes =
        serde_json::to_vec(&first.residues).map_err(|_| PskError::CanonicalizationFailed)?;
    let residue_ledger_digest =
        psk_canon::identity_projection(&residue_bytes, psk_canon::Media::Json)?.digest();
    let gate_policy_bytes = fs::read(workspace_root.join("constitution/gate_policy.yaml"))
        .map_err(|_| PskError::UntypedInput)?;

    // ---- Der Vorschlagsinhalt, aus Laufwerten: das Gegenmodell des
    // Falsifikators in die stehende Negativsuite aufnehmen - die erste
    // der sechs zugelassenen Klassen (Tests und Falsifikatoren).
    let countermodels = crate::falsifier_countermodels(&first.contradictions);
    let countermodel_name = countermodels
        .first()
        .map(|c| c.0.clone())
        .ok_or(PskError::SelfAmendmentWithoutIdentity)?;

    // build_in_isolation VOR der Emission (Algorithmus Revisionsvorschlag:
    // erst bauen und pruefen, dann vorschlagen) - damit ist der Verweis
    // Teil des versiegelten Inhalts, keine nachtraegliche Mutation.
    let isolated = run_isolated_candidate(sandbox_root, &countermodel_name, first.trace_head);

    let identity = &first.boot_report.identity;
    let proposal = psk_adversarial::cra(
        psk_adversarial::CraInputs {
            residue_ledger: Some(residue_ledger_digest),
            replay_manifest: Some(replay_manifest_digest),
            fork_evidence: None,
            shadow_witnesses: None,
            gate_policy: Some(Digest::sha256(&gate_policy_bytes)),
            canonicalization: Some(Digest::sha256(canon_profile.as_bytes())),
        },
        psk_adversarial::ProposalInputs {
            source_residues: first.residues.iter().map(|r| r.id).collect(),
            source_evidence: first.obstructions.iter().map(|o| o.id).collect(),
            hardening_class: RevisionProposalHardeningClassKind::TestsAndFalsifiers,
            proposed_delta: psk_types::objects::DeltaSpec(format!(
                "Gegenmodell {countermodel_name} als stehenden Falsifikator in die Negativsuite aufnehmen (neuer Branch, neue ID - Regel Branch statt Umschreibung)"
            )),
            isolation_build_ref: isolated.artefact,
            parent_constitution: identity.I_C,
            parent_architecture: identity.I_A,
            parent_implementation: identity.I_M,
            trace_ref: TraceRef(first.trace_head),
        },
    )?;

    // check_hardening_permitted - bisher gebaut und ungerufen. Vor dem
    // Gate prueft der Aufruf genau das, was vor dem Gate pruefbar ist:
    // dass eine Verhaertung dieser Klasse ohne bestandenes G-SELF-COMPILE
    // NICHT wirksam wird. Ein Ok hier waere ein Waechterdefekt.
    if psk_adversarial::check_hardening_permitted(
        Some(psk_adversarial::HardeningClass::TestsAndFalsifiers),
        false,
    )
    .is_ok()
    {
        return Err(PskError::SelfAmendmentWithoutIdentity);
    }

    // ---- Die sechs Bedingungen, in der Reihenfolge des Gateregisters.
    let parent_bound = proposal.parent_binding.constitution == identity.I_C
        && proposal.parent_binding.architecture == identity.I_A
        && proposal.parent_binding.implementation == identity.I_M;
    let invariants_preserved = first.boot_gate.decision
        == psk_types::objects::GateReportDecisionKind::Pass
        && first.patch_gate.decision == psk_types::objects::GateReportDecisionKind::Pass
        && second.boot_gate.decision == psk_types::objects::GateReportDecisionKind::Pass
        && second.patch_gate.decision == psk_types::objects::GateReportDecisionKind::Pass;
    let round_trip = crate::feature_evidence::ir_round_trip(&first.ir_bundle)
        .map(|(a, b)| a == b)
        .unwrap_or(false);
    let residues_visible = !first.residues.is_empty() && !first.obstructions.is_empty();

    let cond = |ok: bool, reason: &str| {
        if ok {
            ConditionOutcome::True
        } else {
            ConditionOutcome::False(ReasonCode(reason.into()))
        }
    };

    let mut trace = TraceStore::new();
    let mut residues = ResidueLedger::new();
    let gate_report = evaluate_gate(
        GateInputs {
            gate_id: GateId::GSelfCompile,
            order: 2,
            input_digests: vec![proposal.id.digest],
            conditions: vec![
                cond(parent_bound, "Elternbindung verletzt"),
                cond(invariants_preserved, "Invarianzerhalt verletzt"),
                cond(round_trip, "Round-Trip des Bundles nicht verlustfrei"),
                // Seit build_in_isolation real laeuft, sind beide
                // Bedingungen aus dem Artefakt des Kindprozesses
                // BERECHNET. Konnte das Kind nicht gespawnt werden, sind
                // sie unentscheidbar (ungeprueft ist nicht widerlegt);
                // lief es und scheiterte, sind sie FALSE - dann zeigt ein
                // Artefakt das Scheitern, genau die Unterscheidung, die
                // beim ersten Bau dieser Stelle gezogen wurde.
                if !isolated.spawned {
                    ConditionOutcome::Undecidable(ReasonCode(
                        "Kindprozess nicht startbar: Negativsuite des Kandidaten ungeprueft".into(),
                    ))
                } else if isolated.falsifier_pass {
                    ConditionOutcome::True
                } else {
                    ConditionOutcome::False(ReasonCode(
                        "Delta-Falsifikator des Kandidaten im isolierten Prozess gescheitert"
                            .into(),
                    ))
                },
                if !isolated.spawned {
                    ConditionOutcome::Undecidable(ReasonCode(
                        "Kindprozess nicht startbar: kein Zweitprozess-Replay des Kandidaten"
                            .into(),
                    ))
                } else if isolated.digest_match {
                    ConditionOutcome::True
                } else {
                    ConditionOutcome::False(ReasonCode(
                        "Kandidatenlauf reproduziert den kanonischen Kopf nicht".into(),
                    ))
                },
                cond(residues_visible, "keine sichtbaren Residuen"),
            ],
            seam_compatible: Some(first.glue.hold_reason.is_none()),
            evidence_refs: first.obstructions.iter().map(|o| o.id).collect(),
            seam_report_refs: vec![ObjectId::new(
                SortId::Trace,
                Digest::sha256(b"golden-run-effect-closure"),
            )],
            replay_descriptor: ReplayDescriptor("golden-run/1".into()),
            decided_at: run_time(),
            trace_ref: TraceRef(first.trace_head),
        },
        &mut trace,
        &mut residues,
    )?;

    // Regel "Urteil verweist, Gegenstand nicht" (v1.0.30, den Befund
    // dieser Stelle schliessend): der GateReport traegt die Zuordnung
    // ueber seine input_digests, der Vorschlag nimmt keinen Rueckverweis
    // auf - das Feld existiert nicht mehr, die Identitaetsfrage stellt
    // sich nicht.
    Ok(SelfCompileOutcome {
        proposal,
        gate_report,
        residues: residues.all().to_vec(),
    })
}

/// Die exklusive Leitung zum Effektkind (Regel 20.6 (Vorzustand und Versuch klammern den Effekt)).
///
/// `ChildProcess::shutdown` nimmt `self` by value, `ExclusiveLine`
/// braucht `&mut self` - deshalb der Halter. Er ist kein Trick, sondern
/// die Stelle, an der das Halten sichtbar wird: solange `Some`, ist es
/// DIESELBE Leitung; nach `shutdown` ist sie fort und kann nicht
/// versehentlich neu erzeugt werden.
struct HeldChild(Option<psk_lifecycle::ChildProcess>);

impl psk_effect::ExclusiveLine for HeldChild {
    fn request(&mut self, request: &psk_types::Msg) -> Result<psk_types::Msg, PskError> {
        self.0
            .as_mut()
            .ok_or(PskError::EffectWithoutToken)?
            .request(request)
    }
    fn shutdown(&mut self) -> Result<(), PskError> {
        match self.0.take() {
            Some(child) => child.shutdown(),
            None => Ok(()),
        }
    }
}

/// Schritt 13, Zertifikatsteil. `replay_class` kommt vom Aufrufer - siehe
/// `run_golden_run_with_certificate`, wo er aus einem echten Vergleich
/// zweier Laeufe folgt (Definition 22.1 (Replayklassen): keine Eigenschaft eines
/// einzelnen Laufs).
/// Schritt 13, Zertifikatsteil. **Jedes Feld kommt vom Aufrufer, keines
/// entsteht hier** - Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat):
/// "Kein Feld eines MachineCertificate DARF einen Wert tragen, der nicht
/// aus einem Artefakt des zertifizierten Laufes stammt."
///
/// Bis v1.0.40 standen hier SIEBEN Konstanten der Form
/// `Digest::sha256(b"golden-run-...")`: I_C, I_A, I_M und die vier
/// Berichtsdigests. Die I_t-Konstante daneben war v1.0.38 geheilt worden,
/// und genau das war die Falle - "ein geheiltes Feld neben sechs
/// konstanten sieht von aussen aus wie ein geheiltes Zertifikat" (Regel
/// 7.50). Die Nachbarn wurden nicht geprueft.
///
/// Diese Funktion nimmt deshalb keine Bequemlichkeitsvorgabe mehr
/// entgegen: sie kann kein Feld erfinden, weil sie keines mehr kennt.
/// `AdditionalAcceptance` ebenso - `conformance_class` IST ein
/// Zertifikatsfeld, also unterliegen seine Eingaben derselben Pflicht.
#[allow(clippy::too_many_arguments)]
fn issue_golden_run_certificate(
    identity: &psk_types::objects::IdentityBinding,
    i_t: Digest,
    features: Vec<FeatureCoverageId>,
    acceptance: AdditionalAcceptance,
    replay_class: MachineCertificateReplayClassKind,
    reports: &crate::AggregatedReports,
    trace_head: Digest,
    replay_manifest_digest: Digest,
) -> Result<MachineCertificate, PskError> {
    check_minimum_replay_class(replay_class)?;
    issue_certificate(CertificateInputs {
        // Punkt 1: "die Werte der IdentityBinding desselben Bootes, nicht
        // neu gebildete oder eingesetzte".
        i_c: identity.I_C,
        i_a: identity.I_A,
        i_m: identity.I_M,
        // Punkt 2: "I_t ist H(Can(Sigma_t)) nach den Takten".
        i_t,
        // Punkt 4: "feature_coverage ist abgeleitet, nicht beansprucht" -
        // vom Aufrufer aus `derive_feature_coverage` ueber der realen
        // Evidenz.
        features,
        acceptance,
        replay_class,
        // Punkt 3: "die vier Berichtsdigests sind Digests der
        // tatsaechlich aggregierten Berichte". `aggregate_reports` war
        // gebaut und wurde von hier nie gerufen.
        gate_report_digest: reports.gate_report.digest,
        // Punkt 5: "trace_head ist der Kopf der Kette dieses Laufes".
        trace_head,
        replay_manifest_digest,
        residue_report_digest: reports.residue_report.digest,
        capability_audit_digest: reports.capability_audit.digest,
        negative_test_report_digest: reports.negative_test_report.digest,
        scope: ScopeExpr("golden-run".into()),
        issued_at: run_time(),
        // BEFUND, gemeldet und nicht ueberspielt: Struktur 7.49 (MachineCertificate) fuehrt
        // `signature: Signature` OHNE Fragezeichen - anders als
        // `Msg.signature` und `EvidenceObject.signature`, die beide
        // `Signature?` sind. Das Feld ist also pflichtig, und ein leerer
        // Vektor ist kein Verfahren. OBL-005 (Security Reduction) macht
        // Signaturverfahren und Schluesselhaltung domaenenabhaengig und
        // ist `blocking_from: C4`; dieser Lauf beansprucht C0. Vertrag
        // 7.52 (Selbstgueltigkeit) verlangt die Signatur fuer
        // SELBSTGUELTIGKEIT, nicht fuer die Ausstellung. Lesart:
        // ausstellbar, aber nicht selbstgueltig - und das gehoert
        // erklaert, nicht stillschweigend getragen. Die Entscheidung
        // liegt beim Auftraggeber; bis dahin bleibt der Wert leer UND
        // ist durch einen Test als erklaerter Nullstand festgehalten.
        signature: psk_types::Signature(vec![]),
        // Regel 7.51 (Plattformgebundene Verpflichtungsaufloesung im
        // Zertifikat): der abgeleitete Vektor haelt diesen Lauf
        // unterhalb jeder Klasse, die OBL-010 (blocking_from: C4)
        // betrifft - siehe `is_relevant` in
        // `check_platform_bound_obligations`. Ein leerer Vektor ist hier
        // deshalb kein uebersehener Fall, sondern der ehrliche Stand.
        current_platform: std::env::consts::OS.to_string(),
        platform_bound_obligations: vec![],
    })
}

/// Die angeschlossenen Effektleitungen des Referenzlaufs (M16-Grenze,
/// `psk_effect::EffectLines`): genau eine Leitung, `fs.write.sandbox`,
/// ueber einen echten, von M26 gespawnten Kindprozess. Der Spawn liegt
/// HIER (Harnischseite) und nicht im Scheduler - `proc.control` gehoert
/// laut module_map.yaml M26, nicht M25; der Kern nimmt typisiert
/// entgegen, was andere besitzen.
///
/// Gespawnt wird bei der ersten Anfrage und gehalten bis `shutdown` -
/// Regel 20.6 (Vorzustand und Versuch klammern den Effekt): derselbe
/// Kindprozess bedient beide Klammerhaelften, und ein Herunterfahren
/// dazwischen waere genau die zweite Erzeugung, die die Regel
/// ausschliesst.
struct GoldenRunLines {
    sandbox: PathBuf,
    adapter: Option<ProcessEffectAdapter<HeldChild>>,
}

impl GoldenRunLines {
    fn new(sandbox: PathBuf) -> Self {
        GoldenRunLines {
            sandbox,
            adapter: None,
        }
    }

    fn shutdown(mut self) -> Result<(), PskError> {
        match self.adapter.take() {
            Some(adapter) => adapter.shutdown(),
            None => Ok(()),
        }
    }
}

impl EffectLines for GoldenRunLines {
    fn line(&mut self, class: &EffectClassId) -> Option<&mut dyn EffectAdapter> {
        if class.0 != "fs.write.sandbox" {
            return None;
        }
        if self.adapter.is_none() {
            // Erst hier spawnen: die Leitung entsteht, wenn die
            // Execute-Phase sie zum ersten Mal verlangt, und bleibt
            // danach DIESELBE (Regel 20.6 (Vorzustand und Versuch klammern den Effekt)). Ein Fehlschlag ergibt keine
            // Leitung - der Execute-Arm scheitert dann typisiert.
            let exe = psk_lifecycle::sibling_binary_path("effect-local-fs").ok()?;
            let arg = self.sandbox.to_str()?.to_string();
            let child =
                psk_lifecycle::ChildProcess::spawn(&exe, &[&arg], Some(&self.sandbox)).ok()?;
            self.adapter = Some(ProcessEffectAdapter::new(
                HeldChild(Some(child)),
                psk_types::objects::AdapterId("effect-local-fs".into()),
                RunId("golden-run".into()),
            ));
        }
        self.adapter.as_mut().map(|a| a as &mut dyn EffectAdapter)
    }
}

/// Deponiert das Laufprogramm in Sigma: die Eingaben, aus denen
/// `select(phase, state)` die Schritte 2 bis 13 als Phasenarbeit
/// ableitet. Deponieren ist die Grenze Welt -> Zustand (siehe sigma.rs);
/// jeder Wert unten stand vor der Taktumverdrahtung woertlich an der
/// jeweiligen Geradeauscode-Stelle - hier steht er EINMAL, im Zustand.
fn deposit_program(
    sigma: &mut Sigma,
    workspace_root: &Path,
    sandbox_root: &Path,
    corpus_root: &Path,
    corpus_digest: Digest,
) -> Result<(), PskError> {
    // Schritt-2-Rohstoff: die Welt (der Beobachteradapter) liest den
    // versiegelten Baum; die Observe-Phase bindet Provenienz, die
    // Anchor-Phase versiegelt.
    let config = observer_local_fs::ObserverConfig::new(sandbox_root);
    let record =
        observer_local_fs::observe(&config, run_time()).map_err(|_| PskError::MissingAnchor)?;
    sigma.program.records.push(PendingRecord {
        observations: vec![Observation(format!(
            "{} Dateien unter {} beobachtet",
            record.file_hashes.len(),
            sandbox_root.display()
        ))],
        record,
        source_adapter: psk_types::objects::AdapterId("observer-local-fs".into()),
        observer_identity: Digest::sha256(b"golden-run-observer"),
        method: "filesystem-read".into(),
        effect_adapter_identity: None,
        uncertainty_model: UncertaintyModelId("none-declared".into()),
        context: ContextRef("golden-run".into()),
        validity: Validity {
            // Regel "Ein Frischepraedikat muss verletzbar sein": es
            // benennt die Beobachtung, unter der es faellt - die
            // Veraenderung genau dieses Verzeichnisses.
            freshness_predicate: PredicateExpr(crate::directory_freshness_predicate(corpus_digest)),
            expires_at_tau_i: u64::MAX,
        },
        boundary: ScopeExpr(sandbox_root.display().to_string()),
        provenance: None,
        anchor_ref: None,
    });

    // Schritt 3: der Auftrag als Kandidat (Regel 5.9 (Kandidat und Gedankenkörper) - Vorform ohne
    // Objektidentitaet; die Praegung geschieht in der Anchor-Phase).
    sigma.candidates.push(psk_thought::Candidate::new(
        Claim {
            text: "Golden-Run-Demonstrationspatch in der Sandbox schreiben".into(),
            formal: ClaimExpr("write(sandbox, patch.txt)".into()),
            directionality: ClaimDirectionalityKind::Internal,
        },
        vec![ModelRef("reference-domain".into())],
        vec![TrajectoryRef("direct-write".into())],
        UncertaintyBlock("none-declared".into()),
        vec![ConsequenceRef("sandbox-file-write".into())],
        Lineage("golden-run".into()),
    ));

    // Schritt 5: die statische Feldfamilie (Regel 32.7 (Feldfamilie der Referenzdomäne)) - sechs
    // Archetypen, je Registrierung plus Projektionswerte.
    for (i, archetype) in ArchetypeId::ALL.into_iter().enumerate() {
        sigma.program.field_family.push(FieldFamilyEntry {
            archetype,
            registration: psk_fields::FieldRegistrationInputs {
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
                // Schritt 6 aus genau diesen sechs Projektionen
                // berechnet; die Registrierung braucht nur eine
                // syntaktisch gueltige Kennung.
                dependency_profile_ref: ObjectId::new(
                    SortId::Dependency,
                    Digest::sha256(b"golden-run-dependency-profile"),
                ),
                budget: BudgetSpec("unbounded-demo".into()),
                rollback: RollbackSpec("re-run".into()),
                // I-FIELD-001: eine Systemidentitaet, die von jeder
                // real erzeugbaren Feld-ID verschieden ist.
                system_identity: Digest::sha256(b"system-identity-not-a-field"),
            },
            node: IRNodeId(format!("golden-run-node-{i}")),
            source_provenance: vec![SourceRef("sandbox-observation".into())],
            scope: ScopeSpec("sandbox".into()),
            registered: None,
            projected: None,
        });
    }

    // Schritt 2/3 des Referenzauftrags: die versiegelte Anforderungsmenge
    // - die Identifikation selbst ist Challenge-Phasenarbeit (M24).
    sigma.program.requirements = crate::load_requirements(corpus_root)?;
    sigma.program.obstruction_cell = Some(M13Address("m13:0/c0".into()));

    // Schritt 9: der eine Aenderungsvorschlag des Laufs, als
    // vollstaendige Ausstellungseingabe. `scope` benennt zugleich das
    // Artefakt, gegen das der Falsifikator Gegenmodelle prueft.
    sigma.program.patch_plan = Some(IssueInputs {
        effect_class: EffectClassId("fs.write.sandbox".into()),
        plan_digest: Digest::sha256(b"golden-run-patch-plan"),
        scope: ScopeExpr(GOLDEN_RUN_PATCH_TARGET.to_string()),
        capabilities: vec![CapabilityId("fs.write.sandbox".into())],
        preconditions: vec![PredicateExpr("hello golden run".to_string())],
        budget: BudgetSpec("1 Datei".into()),
        expires_at_tau_i: run_time().tau_i + 1000,
        run_id: RunId("golden-run".into()),
        port_id: PortId::P22,
        seq: 1,
        nonce: [7u8; 32],
        expected_receipt: ReceiptSpec("receipt/1".into()),
        rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec("restore prior bytes".into())),
    });

    // Schritt 7b: die Kapseldeklaration. Das Rundenbudget ist derselbe
    // Wert, der im RunDescriptor steht (Regel 12.7 (Selektionsdruck): EINE deklarierte
    // Quelle, GOLDEN_RUN_RATCHET_MAX_ROUNDS, zwei Verbraucher).
    sigma.program.capsule_spec = Some(CapsuleSpec {
        replay: ReplayDescriptor("golden-run/1".into()),
        boundary: ScopeExpr("jacobs-ladder-reference".into()),
        // Der eine Aenderungsvorschlag, ueber seinen realen Plandigest
        // benannt - die groesste Nachfolgemenge, die diese Kapsel je
        // haben wird (Invariante 12.6 (Monotone Kontraktion)).
        allowed_next: vec![psk_types::objects::CapsuleId(
            Digest::sha256(b"golden-run-patch-plan").to_string(),
        )],
        max_rounds: GOLDEN_RUN_RATCHET_MAX_ROUNDS,
        // Definition 11.11 (Perkolationssupport): gate (G-EFFECT im Register deklariert),
        // replay (deklarierter ReplayDescriptor), resource (BudgetSpec
        // plus Rundenbudget) - deklariert; witness/coupling werden in
        // der Phase BERECHNET.
        support_gate: true,
        support_replay: true,
        support_resource: true,
    });

    // Schritt 6b: die Verklebungsdeklaration - alle sechs Restriktionen
    // teilen bewusst dieselbe Zelle und denselben Digest (der Golden Run
    // demonstriert einen widerspruchsfreien Lauf, keine Seam-
    // Konfliktaufloesung; die ist WP-eigenstaendig getestet).
    sigma.program.glue_spec = Some(GlueSpec {
        shared_cell: M13Address("center".into()),
        restriction_digest: Digest::sha256(b"golden-run-shared-restriction"),
    });

    // Schritt 8: die deklarierten Gatebedingungen (Risiko: einzelne
    // Sandboxdatei, lokal reversibel; Autoritaet: der Adapter besitzt
    // fs.write.sandbox; Ressourcen: ein Schreibvorgang) - die Closure-
    // Bedingung wird in der Phase aus dem Verklebungsergebnis BERECHNET.
    sigma.program.patch_gate = Some(PatchGateSpec {
        declared_conditions: vec![true, true, true],
        seam_report_ref: ObjectId::new(SortId::Trace, Digest::sha256(b"golden-run-effect-closure")),
        replay: ReplayDescriptor("golden-run/1".into()),
    });

    // Schritt 12: Aussteller- und Witnessverweis der Reconciliation.
    sigma.program.reconcile_spec = Some(ReconcileSpec {
        issuer_digest: Digest::sha256(b"golden-run-issuer"),
        witness_ref: ObjectId::new(SortId::Witness, Digest::sha256(b"golden-run-witness")),
        finality: psk_types::objects::ReconciliationReportFinalityKind::Final,
    });

    // Schritt 6/7: die geladenen Register fuer Zusammenbau und
    // Zellclosure - gelesen von der Domaene (ir_assembly), deponiert als
    // Werte.
    let norms = crate::ir_assembly::load_closure_norms(workspace_root)?;
    sigma.program.declarations = Some(AssemblyDeclarations {
        version: SemVer("1.0.0".into()),
        scope: ScopeExpr("jacobs-ladder-reference".into()),
        edge_conditions: crate::ir_assembly::load_reference_domain_profile(workspace_root)?,
        port_matrix: crate::ir_assembly::load_port_matrix(workspace_root)?,
        sort_owner: norms.sort_owner,
        module_layer: norms.module_layer,
        shared_pass_carriers: norms.shared_pass_carriers,
    });
    sigma.program.consensus_scope = Some(DependencyProfileConsensusScopeKind::Local);

    Ok(())
}

/// Zwischen den Takten: hat der Effekt stattgefunden und liegt noch kein
/// P24-Deponat, laesst der Harnisch den UNABHAENGIGEN Beobachter den
/// Dateibaum lesen und deponiert dessen Antwortbytes. Der Beobachter ist
/// die Welt, nicht der Lauf - der Lauf kann nicht hinausgreifen, er
/// empfaengt (P24-Ingress in der Observe(2)-Phase); die
/// Herkunftsbeglaubigung ist die exklusive Pipe zu genau diesem Kind.
fn maybe_deposit_receipt(sigma: &mut Sigma, sandbox_root: &Path) -> Result<(), PskError> {
    let effect_done = sigma
        .effects
        .first()
        .map(|a| a.outcome == psk_types::objects::EffectAttemptOutcomeKind::Completed)
        .unwrap_or(false);
    if !effect_done || !sigma.program.receipt_deposits.is_empty() {
        return Ok(());
    }

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
    child.shutdown()?;
    sigma.program.receipt_deposits.push(ReceiptDeposit {
        payload: response.payload,
        ingressed: false,
    });
    Ok(())
}

/// Der Bericht ist eine PROJEKTION des Laufzustands: jede Zeile kommt aus
/// Sigma oder dem Boot-Report, nichts wird hier erzeugt. Ein Objekt, das
/// der Lauf nicht hervorgebracht hat, fehlt typisiert statt still.
fn build_report(
    sigma: Sigma,
    boot_report: psk_contract::BootReport,
    boot_gate: psk_types::objects::GateReport,
) -> Result<GoldenRunReport, PskError> {
    let final_index = sigma
        .assemblies
        .iter()
        .rposition(|a| a.includes_late)
        .ok_or(PskError::UntypedInput)?;
    let final_assembly = &sigma.assemblies[final_index];
    let cell_reports = sigma
        .cell_reports
        .iter()
        .find(|s| s.assembly_index == final_index)
        .ok_or(PskError::UntypedInput)?
        .reports
        .clone();
    let glue = sigma.glue.clone().ok_or(PskError::UntypedInput)?;
    let patch_gate = sigma
        .gates_and_tokens
        .reports
        .iter()
        .find(|r| r.gate_id == GateId::GEffect)
        .cloned()
        .ok_or(PskError::UntypedInput)?;
    let executable = derive_executable_check(
        &final_assembly.bundle,
        &cell_reports,
        &glue,
        &[&boot_gate, &patch_gate],
        &sigma.residues,
    );
    let challenge = sigma
        .challenges
        .first()
        .cloned()
        .ok_or(PskError::UntypedInput)?;
    let i_t = sigma_digest(&sigma)?;

    Ok(GoldenRunReport {
        boot_gate,
        boot_report,
        anchor: sigma
            .anchors
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        thought: sigma
            .thoughts
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        reality: sigma
            .reality_horizon
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        capsule: sigma
            .capsules
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        capsule_reached_fixpoint: challenge.reached_fixpoint,
        ratchet_rounds: challenge.rounds,
        adversarially_closed: challenge.adversarially_closed,
        contradictions: sigma.contradictions.clone().unwrap_or_default(),
        obstructions: sigma.obstructions.clone(),
        field_identities: sigma.fields.clone(),
        field_projections: sigma.projections.clone(),
        dependency_profile: sigma
            .dependencies
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        glue,
        validation_open_obligations: sigma.validation_obligations.clone().unwrap_or_default(),
        // Die Autorisierung ist eine reine Ableitung aus dem PASS-Report
        // (unfaelschbarer Capability-Typ M14->M15) - dieselbe, die die
        // Execute-Phase beim Ausstellen ableitete.
        token_authorization: authorize(&patch_gate)?,
        patch_gate,
        attempt: sigma
            .effects
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        receipt: sigma
            .receipts
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        reconciliation: sigma
            .reconciliations
            .first()
            .cloned()
            .ok_or(PskError::UntypedInput)?,
        trace_head: sigma.trace.head(),
        trace_segments: sigma.trace.segments().to_vec(),
        residues_opened: sigma.residues.all().len(),
        residues: sigma.residues.all().to_vec(),
        ir_bundle: final_assembly.bundle.clone(),
        ir_scope_residues: final_assembly.scope_residues.clone(),
        ir_omissions: final_assembly.omissions.clone(),
        cell_reports,
        executable,
        ticks: sigma.tick_no,
        i_t,
    })
}

/// Orchestriert die 13 Schritte aus Regel 24.3 (Golden-Run-Ablauf) gegen
/// eine echte, vom Aufrufer bereitgestellte Sandbox. Schritt 1 geschieht
/// in boot(); die Schritte 2 bis 13 laufen als Arbeit in den
/// Warteschlangen der zwoelf Taktphasen (Regel 24.4 (Der Golden Run
/// laeuft unter tick)) - der Harnisch deponiert das Programm, taktet bis
/// keine Phase mehr Arbeit ableitet, und projiziert den Bericht aus dem
/// Laufzustand.
pub fn run_golden_run(
    workspace_root: &Path,
    sandbox_root: &Path,
) -> Result<GoldenRunReport, PskError> {
    fs::create_dir_all(sandbox_root).map_err(|_| PskError::UntypedInput)?;

    // Schritt 1: Bootgate (Algorithmus 17.1 (Boot), alle 21 Schritte) - vor dem
    // ersten Takt, wie Regel 24.4 (Der Golden Run läuft unter tick) es legt. Trace und Residuen von hier
    // wandern in Sigma: der Laufzustand traegt die Bootspur.
    let mut trace = TraceStore::new();
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

    // Weltvorbereitung: das versiegelte Korpus in das beobachtete
    // Verzeichnis - es MUSS vor dem Versiegeln dort liegen, sonst
    // versiegelt der Anker ein leeres Verzeichnis.
    let corpus_root = workspace_root.join("domains/jacobs-ladder-reference/corpus");
    let corpus_digest = stage_corpus(&corpus_root, sandbox_root)?;

    // Der Lauf, unter dem die Takte stehen (`M19.open_tick(state.tick_no,
    // rd)`): Identitaeten aus der realen Bootbindung, das Korpus als
    // versiegelte Eingabe, das Ratchet-Rundenbudget aus der EINEN Quelle.
    let rd = psk_trace::open_run(psk_trace::RunInputs {
        run_id: RunId("golden-run".into()),
        i_c: boot_report.identity.I_C,
        i_a: boot_report.identity.I_A,
        i_m: boot_report.identity.I_M,
        seed: [7u8; 32],
        versions: BTreeMap::new(),
        input_digests: vec![corpus_digest],
        operators: vec![],
        environment: psk_types::objects::EnvironmentProfile("golden-run-reference-domain".into()),
        time_window: TimeWindow("golden-run-window".into()),
        nondeterminism_budget: psk_types::objects::NDBudget("none-declared".into()),
        ratchet_max_rounds: GOLDEN_RUN_RATCHET_MAX_ROUNDS,
        canon: psk_types::objects::CanonicalizationProfile("psk.canon/1.0".into()),
    })?;

    // Sigma (Definition 13.1 (Laufzustand)): Implementierungsbindung und Budget von
    // aussen, Bootspuren hinein, Programm deponieren.
    let mut sigma = Sigma::new(
        boot_report.runtime_manifest.clone(),
        psk_contract::default_budget(RunId("golden-run".into())),
    );
    sigma.trace = trace;
    sigma.residues = residues;
    sigma.gates_and_tokens.reports.push(boot_gate.clone());
    deposit_program(
        &mut sigma,
        workspace_root,
        sandbox_root,
        &corpus_root,
        corpus_digest,
    )?;

    // Die Taktschleife: takten, solange irgendeine Phase Arbeit ableitet.
    // Profiling aus (T-OBSV-001: der Schalter liegt ausserhalb von
    // Sigma; `record_phase` laeuft trotzdem als No-op).
    let mut lines = GoldenRunLines::new(sandbox_root.to_path_buf());
    let mut profiling = Profiling::off();
    let mut ticks_guard = 0u32;
    while has_pending_work(&sigma) {
        // Nichtterminieren waere ein Ableitungsfehler in select, kein
        // Laufergebnis - die Wache macht ihn zu PSK-E016 statt zu einer
        // Endlosschleife.
        ticks_guard += 1;
        if ticks_guard > 32 {
            return Err(PskError::BudgetOrScheduleViolation);
        }
        let now = tick_time(sigma.tick_no);
        tick(&mut sigma, &rd, &mut lines, now, &mut profiling)?;
        // Zwischen den Takten: die Welt beobachtet, wenn es etwas zu
        // beobachten gibt (Schritt-11-Rohstoff).
        maybe_deposit_receipt(&mut sigma, sandbox_root)?;
    }
    lines.shutdown()?;

    build_report(sigma, boot_report, boot_gate)
}

/// Fuehrt den Lauf zweimal gegen dieselbe Sandbox aus und bildet daraus
/// Schritt 13 (Regel 24.3 (Golden-Run-Ablauf): "Maschinenzertifikat UND Replaymanifest
/// exportieren" - beide sind genannt, keine Option). Definition 22.1 (Replayklassen)
/// definiert die Replayklasse als Eigenschaft eines VERGLEICHS zweier
/// Laeufe, nicht eines einzelnen - deshalb laeuft `run_golden_run` hier
/// zweimal, bevor `issue_certificate` (Vertrag 22.4 (Replayklasse des Referenzrelease): mindestens R2 als
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
    // Close720-Schenkel 3 (Replay(Phi^2) ==can x): mit Phi = I (Regel
    // 9.21) ist das die kanonische Replaygleichheit des Laufs selbst -
    // genau das, was dieser Zweitlauf misst (Definition 22.1 (Replayklassen), R2:
    // kanonischer Digest und Gatefolge). Erst hier wird der Schenkel
    // bestimmbar; der Einzellaufbericht traegt None.
    let mut first = first;
    first.executable.close720_replay_canon_eq =
        Some(check.canonical_digest_match && check.gate_sequence_match);

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
        ratchet_max_rounds: GOLDEN_RUN_RATCHET_MAX_ROUNDS,
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

    // Der Selbstkompilationsvorschlag steht JETZT vor dem Zertifikat, und
    // das ist keine Umsortierung aus Bequemlichkeit: sein GateReport ist
    // FC7s Beleg, und Regel 7.51 (plattformgebundeneverpflichtungsaufloesungimzertifikat)
    // verlangt `feature_coverage` als abgeleiteten Wert. Solange das
    // Zertifikat zuerst entstand, konnte der Vektor nicht abgeleitet
    // werden - er wurde behauptet. Das Zertifikat ist das LETZTE Artefakt
    // des Laufes; es weist aus, was der Lauf hervorgebracht hat.
    let self_compile = propose_and_evaluate_self_compile(
        workspace_root,
        sandbox_root,
        &first,
        &second,
        replay_manifest_digest,
        &run_descriptor.canon.0,
    )?;

    // Punkt 4: abgeleitet, nicht beansprucht. `derive_feature_coverage`
    // war gebaut und wurde vom Zertifikatspfad nie gerufen - dieselbe
    // Klasse wie `aggregate_reports` unten.
    let evidence = crate::collect_feature_evidence_from_parts(
        crate::CoverageParts {
            first: &first,
            second: &second,
            replay_check: &check,
            self_compile_gate: &self_compile.gate_report,
        },
        None,
    );
    let features = psk_certify::derive_feature_coverage(&evidence).covered;

    // Punkt 3: die vier Berichte wirklich aggregieren. Die Gatberichte
    // sind die des Laufes, die Residuen seine, das Manifest seines.
    let reports = crate::aggregate_reports(
        &[&first.boot_gate, &first.patch_gate],
        &first.residues,
        &first.boot_report.runtime_manifest,
        &fs::read_to_string(
            workspace_root.join("packages/psk-conformance/src/conformance_catalog.rs"),
        )
        .map_err(|_| PskError::UntypedInput)?,
    )?;

    // `conformance_class` IST ein Zertifikatsfeld, also unterliegen auch
    // seine Eingaben Regel 7.50. Jede der sechs Annahmen kommt aus einem
    // Laufartefakt oder ist ehrlich false mit benanntem Grund.
    let acceptance = AdditionalAcceptance {
        // C0: "Bundle, Lock, Schemas". Boot hat beide Digests
        // nachgerechnet und deckungsgleich gefunden - das IST die
        // Bundle-/Lockpruefung, nicht eine Behauptung darueber.
        artifact_conformant: first.boot_gate.decision
            == psk_types::objects::GateReportDecisionKind::Pass
            && first.boot_report.constitution_check.matches()
            && first.boot_report.architecture_check.matches(),
        // C1: "Minimaler Kern laeuft und erzeugt valide Artefakte" - das
        // ist genau die EXECUTABLE-Frage, die der Lauf selbst beantwortet.
        // Hier stand `true`, WAEHREND derselbe Lauf `Some(false)` mass:
        // eine Unwahrheit, die bisher folgenlos blieb, weil FC2 fehlt und
        // C1 ohnehin unerreichbar war. Folgenlos ist nicht wahr.
        kernel_executable: first.executable.executable_reachable().unwrap_or(false),
        replay_valid: matches!(
            replay_class,
            MachineCertificateReplayClassKind::R2 | MachineCertificateReplayClassKind::R3
        ),
        sandbox_effect_safe: first.reconciliation.verdict
            == psk_types::objects::ReconciliationReportVerdictKind::Closed,
        // C4: "Reale Referenzdomaene besteht Baselines und Negativtests".
        // Dieser Lauf fuehrt KEINE Baselines aus (das tut
        // `run_baseline_comparison`, ein eigener Einstieg). Hier stand
        // `true` - eine Behauptung ueber einen Vergleich, der nicht
        // stattfand.
        reference_validated: false,
        // C5: keine unabhaengige Instanz. Ehrlich false, war es schon.
        externally_reproduced: false,
    };

    let certificate = issue_golden_run_certificate(
        &first.boot_report.identity,
        // Der Zustand NACH den Takten (Regel 24.4 (Der Golden Run läuft
        // unter tick)) - nicht das Boot-Sigma.
        first.i_t,
        features,
        acceptance,
        replay_class,
        &reports,
        first.trace_head,
        replay_manifest_digest,
    )?;

    Ok(GoldenRunCertification {
        first,
        second,
        replay_check: check,
        replay_manifest,
        certificate,
        revision_proposal: self_compile.proposal,
        self_compile_gate: self_compile.gate_report,
        self_compile_residues: self_compile.residues,
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
        // T-RES-001/Algorithmus 18.6 (Gate-Auswertung): da sowohl Bootgate als auch spaeter
        // Patchgate (G-EFFECT) in diesem Szenario PASS erreichen, entsteht
        // hier - richtigerweise - kein einziges Residuum. Siehe die
        // Schwesterdatei psk-contract/src/boot.rs fuer den expliziten
        // HOLD-Fall (unversiegeltes Bundle), der weiterhin mindestens ein
        // Residuum erzeugt.
        // Frueher stand hier `residues_opened == 0` mit der Begruendung
        // "ein vollstaendig PASSender Lauf darf nichts residualisieren".
        // Diese Praemisse trifft seit dem Korpus nicht mehr zu: der Lauf
        // bekommt eine versiegelte Anforderungsmenge, die einen ohne
        // Aussenrecord nicht aufloesbaren Widerspruch enthaelt, und der
        // Integrator MUSS daraus eine sichtbare Obstruktion machen. Alle
        // Gates stehen weiterhin auf PASS - "PASSend" und
        // "residuenfrei" sind seither zwei verschiedene Aussagen.
        assert_eq!(
            report.residues_opened, 1,
            "genau der eine offene Widerspruch des Korpus residualisiert"
        );

        assert!(report.anchor.sealed);
        assert_eq!(report.thought.anchor_refs, vec![report.anchor.id]);
        assert_eq!(
            report.field_projections.len(),
            6,
            "sechs Archetypen (Regel 32.7 (Feldfamilie der Referenzdomäne))"
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

        // Die UNKNOWN-Promotionssperre greift in diesem Lauf gegen ein
        // echtes Objekt: die einzige Klassifikation ist UNKNOWN (kein
        // Klassifikationsplugin existiert, Vertrag 27.2 (Domänengelieferte opake Eingaben) Pflicht 3), also
        // faellt die von CLOSED beabsichtigte Promotion auf NONE.
        //
        // Das Paar (verdict != UNKNOWN, fact_promotion == NONE) ist ohne
        // die Sperre unerreichbar - nachgewiesen durch Aufzaehlung in
        // psk-reconciliation::a_barred_promotion_is_distinguishable_from_
        // nothing_to_promote. Frueher stand hier Actualized: das Subjekt
        // war ein hartkodiertes Paar, das kein Objekt des Laufs trug.
        assert_eq!(
            report.reality.reality_status,
            psk_types::objects::RealityStatus::Unknown,
            "ohne Plugin DARF keine positive Klassifikation entstehen"
        );
        assert!(
            report.reality.evidence_refs.is_empty() && report.reality.method_ref.is_none(),
            "UNKNOWN mit leerer Grundlage ist die Materialisierung 'fehlender Witness'"
        );
        assert_eq!(
            report.reconciliation.verdict,
            psk_types::objects::ReconciliationReportVerdictKind::Closed
        );
        assert_eq!(
            report.reconciliation.fact_promotion,
            psk_types::objects::ReconciliationReportFactPromotionKind::None,
            "CLOSED beabsichtigt ACTUALIZED; NONE hier heisst: die Sperre griff"
        );

        // Challenge (Definition 14.2 (Phasen-Modul-Bindung)): der gemessene Ausgang ist der
        // KAPSELFIXPUNKT in Runde 1, nicht Budget-RESIDUAL - im Lauf
        // existiert kein Widerlegungserzeuger, der eine Kandidat
        // ueberlebt, allowed_next bleibt gleich (Definition 22.2 (Kapselfixpunkt)). Die
        // Supportentscheidung fiel positiv (alle fuenf Pfade definiert,
        // Definition 11.11 (Perkolationssupport)), also SUPPORTED.
        // Schritt 2/3: beide Widerspruchsarten identifiziert, jede mit
        // bestimmter Geltung. Die Kontrollmenge des Korpus stellt sicher,
        // dass hier nicht einfach alles als widerspruechlich gilt.
        assert_eq!(
            report.contradictions.len(),
            2,
            "{:?}",
            report.contradictions
        );
        assert_eq!(
            report.contradictions.iter().filter(|c| c.is_open()).count(),
            1,
            "genau einer ist ohne Aussenrecord offen"
        );
        // Der Integrator: eine Obstruktion der Art `order`, blockierend.
        assert_eq!(report.obstructions.len(), 1);
        assert_eq!(
            report.obstructions[0].kind,
            psk_types::objects::ObstructionRecordKindKind::Order
        );
        assert_eq!(
            report.obstructions[0].severity,
            psk_types::objects::ObstructionRecordSeverityKind::Blocking
        );

        // Der Ausgang, den der Auftraggeber vorab benannt hatte: mit
        // Gegenmodellen hoert das Ratchet auf, in Runde 1 zu fixieren -
        // Runde 1 kontrahiert, der Fixpunkt steht in Runde 2. Ein
        // Ratchet, das etwas zu verkleinern hat, ist der bessere Beleg
        // fuer denselben Nachweis.
        assert_eq!(
            report.ratchet_rounds, 2,
            "Runde 1 kontrahiert, Runde 2 fixiert"
        );
        assert!(
            !report.adversarially_closed,
            "der Kandidat schliesst nur ohne das Gegenmodell - PSK-E003"
        );
        assert!(
            report.capsule_reached_fixpoint,
            "der Challenge-Ausgang dieses Laufs ist der Fixpunkt, nicht RESIDUAL"
        );
        // Gemessen, nicht gewaehlt: der Kandidat schliesst OHNE das
        // Gegenmodell, aber nicht MIT ihm - genau die Lage, die
        // Invariante "Nichttrivialitaet des Ueberlebens" als PSK-E003
        // beschreibt. Damit ist der Witnesspfad nicht "innerhalb des
        // geltenden Horizonts definiert", und die Kapsel geht nach
        // RESIDUAL statt SUPPORTED. Frueher stand hier SUPPORTED - das
        // war richtig, solange es keinen Gegenmodellerzeuger gab.
        assert_eq!(
            report.capsule.phase,
            psk_types::objects::CandidateCapsulePhaseKind::Residual
        );
        assert_eq!(
            report.capsule.witnesses.len(),
            6,
            "die eine Quotientenklasse traegt alle sechs Projektionen"
        );

        assert_ne!(report.trace_head, psk_trace::GENESIS_DIGEST);

        // Regel 24.4 (Der Golden Run läuft unter tick): der positive Nachweis, dass die Schritte 2-13 als
        // Phasenarbeit liefen - tick_no MUSS von 0 gestiegen sein, und
        // I_t ist der Digest des Zustands NACH den Takten (verschieden
        // vom Digest des leeren Boot-Zustands, weil der Zustand die
        // Arbeit traegt).
        assert!(report.ticks > 0, "der Lauf hat den Taktzyklus nie betreten");

        fs::remove_dir_all(&sandbox).ok();
    }

    /// Die Taktuhr des Laufs: tau_i schreitet je Takt fort (logische
    /// Zeit, die steht, waehrend tick_no steigt, waere eine Uhr, die
    /// luegt), tau_e bleibt eingefroren (Invariante 6.14 (Replayneutralität der Wanduhr): die Wanduhr
    /// geht in keinen Digest ein - und eine deterministische Laufzeit
    /// ist Definition 24.2 (Golden Run)s eigene Anforderung).
    #[test]
    fn the_tick_clock_advances_tau_i_and_freezes_the_wall_clock() {
        let t0 = tick_time(0);
        let t3 = tick_time(3);
        assert_eq!(t0.tau_i + 3, t3.tau_i, "tau_i folgt der Taktzahl");
        assert_eq!(t0.tau_e, t3.tau_e, "tau_e ist eingefroren");
        assert_eq!(
            t0.tau_i,
            run_time().tau_i,
            "Takt 0 traegt die Basiszeit - die Objekte des ersten Takts              entstehen zur selben logischen Zeit wie vor der Umverdrahtung"
        );
    }

    /// Die Effektgrenze des Laufs ist klassengebunden: fuer eine nicht
    /// deklarierte Effektklasse gibt es KEINE Leitung - und damit auch
    /// keinen Kindprozess (die Klassenpruefung steht VOR dem Spawn).
    /// Ein Execute-Element einer fremden Klasse scheitert typisiert,
    /// statt eine beliebige Leitung zu bekommen.
    #[test]
    fn the_effect_line_serves_only_the_declared_class() {
        let mut lines = GoldenRunLines::new(std::env::temp_dir());
        assert!(
            psk_effect::EffectLines::line(&mut lines, &EffectClassId("net.write".into())).is_none(),
            "eine fremde Effektklasse bekommt keine Leitung"
        );
        assert!(
            lines.adapter.is_none(),
            "und es wurde auch kein Kindprozess gespawnt"
        );
        lines.shutdown().expect("nichts zu schliessen");
    }

    #[test]
    fn boot_still_holds_for_a_bundle_whose_constitution_is_not_yet_sealed() {
        // Regel 17.2 (Bootpolitik)s undecidable->hold-Pfad darf durch die M00/M02/M04-
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
        // Hier stand bis v1.0.40:
        //   assert_eq!(result.certificate.I_C, Digest::sha256(b"golden-run-i-c"));
        // Ein Test, der die KONSTANTE festnagelte - er hat die Erfindung
        // nicht verhindert, sondern bewacht. Jetzt die Ableitung (Regel
        // 7.50 (Jedes Zertifikatsfeld ist abgeleitet), Punkt 1); die
        // feldweise Pflicht selbst liegt in
        // tests/every_certificate_field_is_derived.rs.
        assert_eq!(
            result.certificate.I_C, result.first.boot_report.identity.I_C,
            "I_C MUSS aus der IdentityBinding desselben Bootes kommen"
        );
        assert_ne!(
            result.certificate.I_C,
            Digest::sha256(b"golden-run-i-c"),
            "die Konstante darf nicht zurueckkehren"
        );

        // PROPOSE_REVISION + G-SELF-COMPILE: der Vorschlag ist echt (vier
        // von sechs CRA-Eingaben vorhanden, zwei benannt fehlend), und
        // die Gatentscheidung ist der MESSWERT: HOLD, weil der isolierte
        // Kandidatenbau nicht stattfindet - die reasons benennen genau
        // das. Ein PASS hier waere ein Befund gegen die Bedingungen, kein
        // Erfolg.
        assert_eq!(result.revision_proposal.cra_inputs_present.len(), 4);
        assert_eq!(
            result.revision_proposal.cra_inputs_absent,
            vec![
                psk_types::objects::CRAInputId::ForkEvidence,
                psk_types::objects::CRAInputId::ShadowWitnesses
            ]
        );
        assert!(!result.revision_proposal.source_residues.is_empty());
        assert!(!result.revision_proposal.source_evidence.is_empty());
        assert_ne!(
            result.revision_proposal.candidate_id.digest, result.first.boot_report.identity.I_M,
            "der Kandidat DARF NICHT die aktive Instanz sein (PSK-E012)"
        );
        // Der gemessene Ausgang seit build_in_isolation: PASS. Der
        // Kandidat lief als ECHTER zweiter Prozess (psk-cli
        // candidate-check), sein Delta-Falsifikator fand den Gegenbeleg,
        // sein Lauf reproduzierte den kanonischen Kopf des Elternlaufs -
        // alle sechs Bedingungen wahr. Vorher stand hier HOLD mit zwei
        // Undecidable; der Uebergang HOLD -> PASS kam durch den Bau des
        // benannten Mechanismus, nicht durch Aenderung einer Bedingung.
        assert_eq!(
            result.self_compile_gate.decision,
            psk_types::objects::GateReportDecisionKind::Pass,
            "alle sechs Vorbedingungen aus realen Artefakten: {:?}",
            result.self_compile_gate.reasons
        );
        assert!(
            result.revision_proposal.isolation_build_ref.is_some(),
            "der isolierte Bau MUSS sein Artefakt im versiegelten Vorschlag hinterlassen"
        );
        assert!(
            result.self_compile_residues.is_empty(),
            "eine PASS-Entscheidung residualisiert nichts"
        );

        fs::remove_dir_all(&sandbox).ok();
    }
}
