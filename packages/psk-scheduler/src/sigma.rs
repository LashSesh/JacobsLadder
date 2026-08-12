//! Sigma (Definition 13.1 (Laufzustand) / CPSK-Vertrag CPSK Definition 5.2 (Maschinenzustand)): der volle
//! Laufzustand, den `tick()` durch die zwoelf Phasen traegt.
//!
//! `constitution/type_registry.yaml` (TY-SIGT) und die Referenzarchitektur
//! selbst (Kapitel 13, Definition 13.1 (Laufzustand)) stimmen woertlich ueberein:
//! `Sigma_t = (C, I, At, Tt, Ft, Ht, Wt, Qt, Et, Lt, Rt)`, mit Konstitution
//! C, Implementierungsbindung I, Anker At, Gedankenkoerpern Tt, Feldregister
//! Ft, Realitaetshorizont Ht, Witnesses Wt, Gates und Tokens Qt, Effekten
//! Et, Trace/Replay Lt und Residuen Rt.
//!
//! ## Zuordnung der elf Tupelpositionen
//!
//! | Position | Feld hier | Realer Typ |
//! |---|---|---|
//! | C (Konstitution) | *kein eigenes Feld* | `i.constitution_id` traegt denselben Digest bereits; eine zweite, damit stets synchron zu haltende Kopie waere selbst der Fehler, den `pi_vol`/Selbstreferenzausschluss ueberall sonst im Werk vermeidet |
//! | I (Implementierungsbindung) | `i` | `RuntimeManifest` (OBJ-RTM) - traegt `constitution_id`/`architecture_id`/`implementation_id`/`profile`/... bereits vollstaendig, und `profile` ist genau das Feld, das Regel 22.3 (Replay laeuft unter shadow) referenziert ("profile liegt auf dem RuntimeManifest") |
//! | At (Anker) | `anchors` | `Vec<AnchorSnapshot>` |
//! | Tt (Gedankenkoerper) | `thoughts` | `Vec<ThoughtBody>` - die Vorformen dazu in `candidates` (Regel 5.9 (Kandidat und Gedankenkörper)) |
//! | Ft (Feldregister) | `fields` | `Vec<FieldIdentity>` - die Projektionen dazu in `projections` |
//! | Ht (Realitaetshorizont) | `reality_horizon` | `Vec<RealityClassification>` |
//! | Wt (Witnesses) | `witnesses` | `Vec<EvidenceObject>` |
//! | Qt (Gates und Tokens) | `gates_and_tokens` | `GatesAndTokens` (siehe unten) |
//! | Et (Effekte) | `effects` | `Vec<EffectAttempt>` |
//! | Lt (Trace/Replay) | `trace` | `psk_trace::TraceStore` |
//! | Rt (Residuen) | `residues` | `psk_trace::ResidueLedger` |
//!
//! ## Felder ueber die elf Positionen hinaus
//!
//! - `tick_no`: kein Tupelfeld, aber vom Aufrufer der Umsetzung ausdruecklich
//!   verlangt. Gehoert hier und nicht auf `RunDescriptor` - `RunDescriptor`
//!   ist bei Laufoeffnung versiegelt (`psk_trace::open_run`), waehrend
//!   `tick_no` sich jeden Takt aendert.
//! - `capsules`: Regel 14.6 (Prioritätsordnung) fuehrt "bestehende Kapseln im Ratchet" als
//!   eigenen Rang; eine Kapsel, die in einem Takt nicht bis zum
//!   Kapselfixpunkt oder RESIDUAL kommt, MUSS im naechsten wieder
//!   auffindbar sein.
//! - `budget`: `BudgetLedger` (Struktur 14.11 (BudgetLedger)) - Algorithmus 14.5 (Tick) belastet
//!   es jeden Takt, Vertrag 14.12 (Keine implizite Unendlichkeit) verlangt Sichtbarkeit ueber Takte hinweg.
//! - `program` und die Phasenproduktfelder darunter: siehe naechster
//!   Abschnitt.
//!
//! ## Die Revision: der Lauf traegt sein Programm und seine Produkte selbst
//!
//! Eine fruehere Fassung dieses Kopfes hielt fest, dass FieldProjection,
//! DependencyProfile, IRBundle usw. NICHT hier gehalten werden ("ihre
//! dauerhafte Spur ist der Trace"), und schloss: "Ein spaeterer Fund
//! koennte das revidieren; diese Umsetzung erfindet keine zwoelfte
//! Position ohne Textstelle." Der Fund ist eingetreten, und er kam mit
//! der Rueckkehr zu Algorithmus 14.5 (Tick)s woertlicher Form: `M25.select(phase,
//! state)` kann nur aus dem Zustand ableiten, was im Zustand steht.
//! Die Entscheidung des Auftraggebers dazu, woertlich: "PendingWork-
//! Varianten tragen Verweise statt eingebetteter Werte, soweit die Werte
//! in Sigma stehen - was nicht in Sigma steht, gehoert dorthin, sonst
//! waere es ein Zustand neben dem Zustand."
//!
//! Deshalb traegt Sigma jetzt zweierlei zusaetzlich:
//!
//! - **`program`**: die von der Aussenwelt/Domaene DEPONIERTEN Eingaben
//!   des Laufs (Aussenrecords samt Ankerdeklaration, Feldfamilie,
//!   Korpusanforderungen, Patchplan, Kapsel- und Gate-Deklarationen,
//!   geladene Register). Deponieren ist die Grenze Welt -> Zustand,
//!   dasselbe Muster wie `i` und `budget` bei `Sigma::new`.
//! - **Phasenproduktfelder** (`candidates`, `projections`, `dependencies`,
//!   `glue`, `closure_reports`, `contradictions`, `obstructions`,
//!   `validation_obligations`, `challenges`, `assemblies`, `cell_reports`,
//!   `receipts`, `reconciliations`, `archive_watermark`): was eine Phase
//!   hervorbringt und eine spaetere braucht.
//!
//! Beides geht ueber `sigma_digest` in I_t ein - genau das, was I_t
//! behaupten soll: die Identitaet des Laufzustands, nicht eines
//! Nebenprodukts.

use std::collections::{BTreeMap, BTreeSet};

use crate::BudgetLedger;
use psk_effect::TokenLedger;
use psk_trace::{ResidueLedger, TraceStore};
use psk_types::objects::{
    AdapterId, AnchorSnapshot, ArchetypeId, CandidateCapsule, CapsuleId, ContextRef,
    DependencyProfile, DependencyProfileConsensusScopeKind, EffectAttempt, EffectToken,
    EvidenceObject, ExternalReceipt, FieldIdentity, FieldProjection, GateReport, IRNodeId,
    M13Address, ObligationExpr, Observation, ObstructionRecord, RealityClassification,
    ReconciliationReport, RelationSortId, ReplayDescriptor, ResidueRecord, RuntimeManifest,
    ScopeExpr, ScopeSpec, SemVer, SortId, SourceRef, ThoughtBody, UncertaintyModelId, Validity,
};
use psk_types::{Digest, ModuleId, ObjectId, PskError};

/// Qt (Gates und Tokens): ein GateReport-Verlauf, die bereits ausgestellten
/// EffectToken und deren FSM-TOKEN-Zustandsfuehrung. Drei Felder statt
/// eines, weil `TokenLedger` (Zustand je `idempotency_key`) und die
/// vollstaendigen `EffectToken`-Objekte (fuer `execute_effect`, das den
/// realen Token braucht, nicht nur seinen Zustand) unterschiedliche Dinge
/// festhalten - siehe `psk-effect::consume`s Modulkopf.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct GatesAndTokens {
    pub reports: Vec<GateReport>,
    pub issued: Vec<EffectToken>,
    pub ledger: TokenLedger,
}

/// Ein deponiertes Aussenrecord samt seiner Ankerdeklaration: was die
/// Welt geliefert hat (`record` und die Beobachtungsmetadaten fuer die
/// Provenienzbindung, Observe-Phase) und wie der Lauf es versiegeln will
/// (die `AnchorInputs`-Felder ohne Provenienz und Zeit, Anchor-Phase).
/// `provenance`/`anchor_ref` sind die Fortschrittsmarken der beiden
/// Phasen - `select` leitet aus ihnen ab, was noch ansteht.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingRecord {
    pub record: psk_anchor::ExternalRecord,
    pub source_adapter: AdapterId,
    pub observer_identity: Digest,
    pub method: String,
    pub effect_adapter_identity: Option<Digest>,
    pub observations: Vec<Observation>,
    pub uncertainty_model: UncertaintyModelId,
    pub context: ContextRef,
    pub validity: Validity,
    pub boundary: ScopeExpr,
    /// Nach der Observe-Phase: die gebundene Provenienz.
    pub provenance: Option<psk_types::objects::Provenance>,
    /// Nach der Anchor-Phase: der versiegelte Anker.
    pub anchor_ref: Option<ObjectId>,
}

/// Eine deponierte P24-Antwort (exklusive Pipe zum unabhaengigen
/// Beobachter): die Welt legt die Bytes ab, die Observe(2)-Phase
/// ingressiert sie (`ingress_p24_via_exclusive_pipe`).
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReceiptDeposit {
    pub payload: Vec<u8>,
    pub ingressed: bool,
}

/// Ein Eintrag der deklarierten Feldfamilie (Regel 32.7 (Feldfamilie der Referenzdomäne)): Archetyp,
/// Registrierungseingaben und die domaenenbestimmten Projektionswerte.
/// `registered`/`projected` sind die Fortschrittsmarken der
/// Project-Phase.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FieldFamilyEntry {
    pub archetype: ArchetypeId,
    pub registration: psk_fields::FieldRegistrationInputs,
    pub node: IRNodeId,
    pub source_provenance: Vec<SourceRef>,
    pub scope: ScopeSpec,
    pub registered: Option<ObjectId>,
    pub projected: Option<ObjectId>,
}

/// Die Kapseldeklaration des Laufs (Challenge-Phase): Replay- und
/// Bereichsbindung, das Rundenbudget (Regel 12.7 (Selektionsdruck) - derselbe Wert steht im
/// RunDescriptor; EINE deklarierte Quelle speist beide, der Deponierende
/// buergt dafuer). `allowed_next` ist das im LAUF angebotene
/// Kandidatenset, nicht schon die Nachfolgemenge selbst: `capsulate`
/// (Regel 7.29 (Eine Kapsel ist Funktion ihrer Klasse)) entscheidet je Quotientenklasse, welche
/// Kandidaten deren eigene Quellen tragen, und ERST das Ergebnis ist
/// Invariante 12.6s groesste Nachfolgemenge - je Kapsel, nicht laufweit.
/// `support` sind die drei DEKLARIERTEN Supportpfade aus Definition
/// 11.11 (gate/replay/resource); witness und coupling werden in der
/// Phase BERECHNET, nicht deklariert.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CapsuleSpec {
    pub replay: ReplayDescriptor,
    pub boundary: ScopeExpr,
    pub allowed_next: Vec<CapsuleId>,
    pub max_rounds: u32,
    pub support_gate: bool,
    pub support_replay: bool,
    pub support_resource: bool,
}

/// Die Verklebungsdeklaration des Laufs (Schritt 6, "lokale Resultate
/// verkleben"): welche Zelle und welchen Restriktionsdigest alle
/// Projektionen teilen. Der Referenzlauf demonstriert einen
/// widerspruchsfreien Lauf - eine Seam-Konfliktaufloesung ist
/// WP-eigenstaendig getestet (psk-closure::seam).
#[derive(Debug, Clone, serde::Serialize)]
pub struct GlueSpec {
    pub shared_cell: M13Address,
    pub restriction_digest: Digest,
}

/// Die Gate-Deklaration des Patchplans (Schritt 8): die von der Domaene
/// DEKLARIERTEN Bedingungsurteile (Risiko, Autoritaet, Ressourcen beim
/// Referenzlauf) - die Closure-Bedingung wird in der Phase aus dem
/// Verklebungsergebnis BERECHNET und hier nicht gefuehrt.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatchGateSpec {
    pub declared_conditions: Vec<bool>,
    pub seam_report_ref: ObjectId,
    pub replay: ReplayDescriptor,
}

/// Die Reconciliation-Deklaration (Schritt 12): Aussteller- und
/// Witnessverweis sowie die deklarierte Finalitaet. Subjektstatus,
/// Anker und Versuchswerte kommen aus dem Zustand, nicht von hier. Die
/// Diffklasse ist "von aussen bestimmt" (psk-reconciliation); eine
/// deponierte Nicht-Empty-Klasse braeuchte ihren DiffTree im Programm -
/// solange kein Lauf eine deponiert, fuehrt der Reconcile-Arm den
/// Empty-Fall und ein Programmfeld ohne Erzeuger entsteht nicht.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ReconcileSpec {
    pub issuer_digest: Digest,
    pub witness_ref: ObjectId,
    pub finality: psk_types::objects::ReconciliationReportFinalityKind,
}

/// Die von der Domaene geladenen, hier DEPONIERTEN Register fuer den
/// Zusammenbau (Compile) und die Zellclosure (Verify): Kantenbedingungen
/// (Regel 10.9 (Herkunft der Kantenbedingungen)), Portmatrix (Regel 10.6 (Sorten-Port-Matrix)) und die Normdaten der
/// Richtungskonsistenz (Regel 9.8 (Richtungskonsistenz einer Zelle)). Wer sie LIEST, ist die Domaene
/// (psk-conformance::ir_assembly); hier stehen nur die Werte.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AssemblyDeclarations {
    pub version: SemVer,
    pub scope: ScopeExpr,
    pub edge_conditions: psk_ir::EdgeConditionDeclarations,
    pub port_matrix: Vec<(SortId, SortId, RelationSortId)>,
    pub sort_owner: BTreeMap<SortId, ModuleId>,
    pub module_layer: BTreeMap<ModuleId, u8>,
    pub shared_pass_carriers: BTreeSet<(ModuleId, ModuleId)>,
}

/// Das deponierte Laufprogramm: die Eingaben, aus denen `select(phase,
/// state)` die Phasenarbeit ableitet. Siehe Modulkopf ("Die Revision").
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct RunProgram {
    pub records: Vec<PendingRecord>,
    pub receipt_deposits: Vec<ReceiptDeposit>,
    pub field_family: Vec<FieldFamilyEntry>,
    pub requirements: Vec<psk_adversarial::Requirement>,
    /// Die Folgenbeobachtung von M17 (`observer_local_fs::observe_history`,
    /// Regel 32.7 (Feldfamilie der Referenzdomäne): "Historiker rekonstruiert Versionen") - roh, aeltester
    /// Eintrag zuerst. Der Historiker liest DIESES Feld, er beobachtet
    /// nicht selbst (derselbe Aufbau wie `requirements` fuer Falsifikator/
    /// Integrator: M17 deponiert, die Feldrolle interpretiert).
    pub version_history: Vec<psk_anchor::HistoryPoint>,
    /// Der eine Aenderungsvorschlag des Laufs, als vollstaendige
    /// Ausstellungseingabe (M15). `scope` darin benennt zugleich das
    /// Artefakt, gegen das der Falsifikator Gegenmodelle prueft.
    pub patch_plan: Option<psk_effect::IssueInputs>,
    pub capsule_spec: Option<CapsuleSpec>,
    pub glue_spec: Option<GlueSpec>,
    pub patch_gate: Option<PatchGateSpec>,
    pub reconcile_spec: Option<ReconcileSpec>,
    pub declarations: Option<AssemblyDeclarations>,
    pub consensus_scope: Option<DependencyProfileConsensusScopeKind>,
    /// Wo eine Ordnungsobstruktion des Integrators sitzt (Challenge) -
    /// die Traegerzelle der Referenzdomaene.
    pub obstruction_cell: Option<M13Address>,
    /// Fuer den generischen `VerifyClosure`-Pfad (Definition 9.16 (360-Grad-Closure)/9.17
    /// ueber vorgerechnete Evidenzen); der Referenzlauf benutzt die
    /// Zellclosure (Vertrag 9.7 (Zellclosure)) und laesst dies leer.
    pub closure_evidence: Option<(psk_closure::Close360Evidence, psk_closure::Close720Evidence)>,
}

/// Ergebnisdaten einer Challenge-Aufloesung (Ratchet bis Fixpunkt oder
/// RESIDUAL, Definition 14.2 (Phasen-Modul-Bindung)) - die Kapsel selbst steht in `capsules`,
/// hier stehen die Messwerte des Wegs dorthin.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChallengeRecord {
    pub capsule_ref: ObjectId,
    pub rounds: u32,
    pub reached_fixpoint: bool,
    pub adversarially_closed: bool,
}

/// Ein Zusammenbau (Compile, M23-Haelfte): der IRBundle-Kandidat samt
/// Sondierungsvermerken (Struktur 9.10 (CellReport)), Auslassungen (Regel 10.9 (Herkunft der Kantenbedingungen)) und
/// scope-Residuen. `includes_late` unterscheidet den Compile-Graphen
/// (vor den Effektobjekten) vom finalen Graphen des Berichts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AssemblyRecord {
    pub bundle: psk_types::objects::IRBundle,
    pub probes: Vec<(ObjectId, Vec<u8>)>,
    pub omissions: Vec<psk_ir::EdgeOmission>,
    pub scope_residues: Vec<ResidueRecord>,
    pub includes_late: bool,
}

/// Die 18 Zellberichte (Vertrag 9.7 (Zellclosure)) ueber einem Zusammenbau.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CellReportSet {
    pub assembly_index: usize,
    pub reports: Vec<psk_topology::CellReport>,
}

/// Sigma (Definition 13.1 (Laufzustand)). Siehe Modulkopf fuer die vollstaendige
/// Positionszuordnung.
///
/// `Serialize` (nicht `Deserialize`): Grundlage von `I_t =
/// H(Can(Sigma_t))`, siehe `sigma_digest` unten. Die Gegenrichtung fehlt
/// bewusst - ein Laufzustand entsteht ausschliesslich durch `tick()`
/// (Algorithmus 14.5 (Tick)) und das Deponieren seiner Eingaben, nie durch
/// Einspielen eines fremden Werts; Invariante 13.3 (Keine Textzustandsübergänge) verlangt fuer jeden
/// Zustandsuebergang einen Operator und einen GateReport, was eine
/// Deserialisierung strukturell umginge.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Sigma {
    pub tick_no: u64,
    pub i: RuntimeManifest,
    pub anchors: Vec<AnchorSnapshot>,
    pub thoughts: Vec<ThoughtBody>,
    pub fields: Vec<FieldIdentity>,
    pub reality_horizon: Vec<RealityClassification>,
    pub witnesses: Vec<EvidenceObject>,
    pub gates_and_tokens: GatesAndTokens,
    pub effects: Vec<EffectAttempt>,
    pub trace: TraceStore,
    pub residues: ResidueLedger,
    pub capsules: Vec<CandidateCapsule>,
    pub budget: BudgetLedger,
    /// Das deponierte Laufprogramm - siehe Modulkopf ("Die Revision").
    pub program: RunProgram,
    /// Regel 5.9 (Kandidat und Gedankenkörper): die Kandidaten (Vorformen) zwischen normalize/type und
    /// der Praegung in anchor.
    pub candidates: Vec<psk_thought::Candidate>,
    pub projections: Vec<FieldProjection>,
    pub dependencies: Vec<DependencyProfile>,
    pub glue: Option<psk_closure::GlueOutcome>,
    pub closure_reports: Vec<psk_closure::ClosureReport>,
    /// None = noch nicht identifiziert; Some = identifiziert (auch ueber
    /// einem Korpus, in dem die Praezedenz alles entscheidet, waere die
    /// Liste nichtleer - Nullbefund ueber nichtleerem Korpus ist
    /// Fehlschlag, siehe psk_adversarial::identify_contradictions).
    pub contradictions: Option<Vec<psk_adversarial::Contradiction>>,
    pub obstructions: Vec<ObstructionRecord>,
    /// None = Schritt 7 noch nicht gelaufen; Some([]) = geprueft, nichts
    /// offen - zwei verschiedene Aussagen (die leere Liste ist ein
    /// echtes Resultat, keine uebersprungene Pruefung).
    pub validation_obligations: Option<Vec<ObligationExpr>>,
    pub challenges: Vec<ChallengeRecord>,
    pub assemblies: Vec<AssemblyRecord>,
    pub cell_reports: Vec<CellReportSet>,
    pub receipts: Vec<ExternalReceipt>,
    pub reconciliations: Vec<ReconciliationReport>,
    /// Bis zu welchem Residuenstand die Archive-Phase bereits gesammelt
    /// hat - `select` leitet daraus ab, ob Sammelarbeit ansteht.
    pub archive_watermark: u64,
}

impl Sigma {
    /// Ein frischer Laufzustand fuer einen soeben gebundenen Lauf (Boot-
    /// Schritt, vor dem ersten Takt): `tick_no: 0`, alle Sammlungen leer.
    /// `i` (die Implementierungsbindung) und `budget` (die deklarierten
    /// Limits, Vertrag 14.12 (Keine implizite Unendlichkeit)) MUESSEN von aussen kommen - beide entstehen
    /// aus lauf-/domaenenspezifischen Werten, die dieser Konstruktor nicht
    /// erfinden darf (`i` am Boot ueber
    /// `psk_contract::identity_binder::build_runtime_manifest`, `budget`
    /// ueber `BudgetLedger::open` mit den deklarierten Limits). Das
    /// Laufprogramm wird danach DEPONIERT (Felder von `program`), die
    /// Boot-Spuren (Trace, Residuen, G-BOOT-Report) direkt in die
    /// jeweiligen Felder gelegt - beides ist die Grenze Welt -> Zustand,
    /// kein Phasenuebergang.
    pub fn new(i: RuntimeManifest, budget: BudgetLedger) -> Self {
        Sigma {
            tick_no: 0,
            i,
            anchors: Vec::new(),
            thoughts: Vec::new(),
            fields: Vec::new(),
            reality_horizon: Vec::new(),
            witnesses: Vec::new(),
            gates_and_tokens: GatesAndTokens::default(),
            effects: Vec::new(),
            trace: TraceStore::new(),
            residues: ResidueLedger::new(),
            capsules: Vec::new(),
            budget,
            program: RunProgram::default(),
            candidates: Vec::new(),
            projections: Vec::new(),
            dependencies: Vec::new(),
            glue: None,
            closure_reports: Vec::new(),
            contradictions: None,
            obstructions: Vec::new(),
            validation_obligations: None,
            challenges: Vec::new(),
            assemblies: Vec::new(),
            cell_reports: Vec::new(),
            receipts: Vec::new(),
            reconciliations: Vec::new(),
            archive_watermark: 0,
        }
    }

    /// C (Konstitution): realisiert als `i.constitution_id`, kein eigenes
    /// Feld (siehe Modulkopf).
    pub fn c(&self) -> psk_types::Digest {
        self.i.constitution_id
    }
}

/// `I_t = H(Can(Sigma_t))` (Regel 6.10 (Vier Identitäten), Vier Identitaeten).
///
/// **Ueber `identity_projection`, NICHT ueber `can`.** Das ist die
/// tragende Entscheidung dieser Funktion, nicht eine Stilfrage: Sigma
/// enthaelt an vielen Stellen `DualTime` (jedes TraceSegment, jedes
/// ResidueRecord, jeder GateReport), und `DualTime.tau_e`/`clock_ref`/
/// `uncertainty_ns` sind in `architecture/volatile_fields.yaml` als
/// volatil gefuehrt. Ueber `can()` gebildet wuerde I_t die Wanduhr
/// einschliessen und damit Invariante 6.14 (Replayneutralitaet der
/// Wanduhr) verletzen - "tau_e DARF NICHT in eine Kanonisierung, einen
/// Digest oder eine Gate-Entscheidung eingehen" - und zwei inhaltlich
/// identische Laeufe erhielten verschiedene Laufzeit-IDs. `pi_vol`
/// entfernt sie vor der Digestbildung; `record_digest` ueber denselben
/// Zustand DARF abweichen (Definition 6.6 (Objekt-ID)/6.7).
///
/// Damit ist auch die Frage beantwortet, die den Profilingschalter
/// (`crate::profiling`) betrifft: ein Feld namens `runtime_metrics` waere
/// hier automatisch ausgeschlossen. Der Schalter liegt zusaetzlich
/// ausserhalb von Sigma - zwei unabhaengige Schichten, siehe dortigen
/// Modulkopf.
pub fn sigma_digest(sigma: &Sigma) -> Result<psk_types::Digest, PskError> {
    let bytes = serde_json::to_vec(sigma).map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?.digest())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use psk_types::objects::{
        CapabilityMatrixRef, ProfileId, RuntimeManifestDeterminismClassKind, Scaled,
    };
    use psk_types::{Digest, RunId};

    pub(crate) fn sample_manifest() -> RuntimeManifest {
        RuntimeManifest {
            schema: "psk.runtime-manifest/1.0".into(),
            constitution_id: Digest::sha256(b"c"),
            architecture_id: Digest::sha256(b"a"),
            implementation_id: Digest::sha256(b"m"),
            profile: ProfileId::Reference,
            capability_matrix: CapabilityMatrixRef("cap/1".into()),
            build_digest: Digest::sha256(b"build"),
            operator_versions: Default::default(),
            adapter_versions: Default::default(),
            determinism_class: RuntimeManifestDeterminismClassKind::R0,
            max_depth: 0,
        }
    }

    pub(crate) fn sample_sigma() -> Sigma {
        Sigma::new(sample_manifest(), sample_budget())
    }

    pub(crate) fn sample_budget() -> BudgetLedger {
        BudgetLedger::open(
            RunId("run-0".into()),
            1_000,
            1_000,
            1_000,
            1_000,
            1_000,
            1_000,
            1_000,
            Scaled {
                schema: "psk.scaled/1.0".into(),
                numerator: 100,
                scale: 2,
            },
        )
    }

    #[test]
    fn a_fresh_sigma_starts_at_tick_zero_with_empty_collections() {
        let sigma = Sigma::new(sample_manifest(), sample_budget());
        assert_eq!(sigma.tick_no, 0);
        assert!(sigma.anchors.is_empty());
        assert!(sigma.thoughts.is_empty());
        assert!(sigma.fields.is_empty());
        assert!(sigma.reality_horizon.is_empty());
        assert!(sigma.witnesses.is_empty());
        assert!(sigma.gates_and_tokens.reports.is_empty());
        assert!(sigma.gates_and_tokens.issued.is_empty());
        assert!(sigma.effects.is_empty());
        assert!(sigma.trace.segments().is_empty());
        assert!(sigma.residues.all().is_empty());
        assert!(sigma.capsules.is_empty());
        assert!(sigma.program.records.is_empty());
        assert!(sigma.candidates.is_empty());
        assert!(sigma.projections.is_empty());
        assert!(sigma.dependencies.is_empty());
        assert!(sigma.glue.is_none());
        assert!(sigma.contradictions.is_none());
        assert!(sigma.validation_obligations.is_none());
        assert!(sigma.assemblies.is_empty());
        assert!(sigma.receipts.is_empty());
        assert!(sigma.reconciliations.is_empty());
        assert_eq!(sigma.archive_watermark, 0);
    }

    #[test]
    fn c_reads_the_constitution_digest_off_the_runtime_manifest() {
        let manifest = sample_manifest();
        let expected = manifest.constitution_id;
        let sigma = Sigma::new(manifest, sample_budget());
        assert_eq!(sigma.c(), expected);
    }
}
