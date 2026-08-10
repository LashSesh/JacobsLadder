//! Algorithmus 17.1 (Boot), vollstaendig - der Orchestrator, den `load`,
//! `artifact_registry` und `identity_binder` einzeln realisieren, aber
//! keines davon allein zusammensetzt.
//!
//! Woertlich (Kapitel 17.1):
//! ```text
//! function boot(bundle_path, profile) -> BootReport:
//!   1 lock = acquire_store_lock() else FAIL(PSK-E101)
//!   2 image = M00.load(bundle_path) // constitution.lock.json zuerst
//!   3 M02.resolve_artifact_registry(image)
//!   4 canon = M01.canonicalize_all(image.normative_files)
//!   5 cid = M01.collection_digest(canon)
//!   6 require cid == image.lock.constitution_id else FAIL(PSK-E103)
//!   7 M03.register_schemas(canon); M03.validate_all(canon)
//!   8 M22.register_topology(); require |V|=13 and |E|=30 and |Delta|=18
//!   9 register_state_machines(canon); register_invariants(canon)
//!   10 aid = M01.collection_digest(canon.architecture_registers)
//!   11 require aid == image.lock.architecture_id else FAIL(PSK-E103)
//!   12 M04.bind(cid, aid, implementation_id(), runtime_state_digest())
//!   13 M04.check_profile_binding(profile)
//!   14 M19.open_trace_store(); M19.open_residue_ledger()
//!   15 incomplete = M26.detect_incomplete_runs()
//!   16 if incomplete: plan = M26.plan_recovery(incomplete)
//!   17 M15.register_only_versioned_operators_and_capabilities()
//!   18 posture = M21.compute_release_and_operational_posture()
//!   19 g = M14.gate("G-BOOT", all_of(above))
//!   20 require g.decision == PASS else HOLD or QUARANTINE
//!   21 activate_cognition_compiler()
//!   return BootReport{ state: BOUND, ... }
//! ```
//!
//! Realisierungsentscheidungen, explizit (keine davon war durch den Text
//! allein entschieden - siehe die einzelnen Begruendungen):
//!
//! - Schritte 6/11 ("else FAIL(PSK-E103)") speisen `all_of(above)` als
//!   `ConditionOutcome::False` statt vorzeitig zurueckzukehren. Begruendung:
//!   Regel 17.2 fuehrt `digest_mismatch: fail` als EINE von vier
//!   gate-vermittelten Reaktionen, nicht als gatefreien Sonderpfad, und
//!   Schritt 20 selbst spricht von `g.decision` als der massgeblichen
//!   Groesse. Ein direkter frueher Fehler wuerde Schritt 19s eigene
//!   Aggregation ("all_of(above)") um genau die Bedingungen verkuerzen, die
//!   Schritt 6/11 beitragen sollen.
//! - Nur Schritt 1 (Store-Lock) bleibt ein echter frueher Rust-`Err`:
//!   er liegt VOR jeder Bundle-Beruehrung, nichts danach kann ohne ihn
//!   sinnvoll versucht werden.
//! - Ein `Fail`-Gatebefund (Schritt 20) fuehrt am Ende dieser Funktion zu
//!   `Err(PskError::IdentityDigestMismatch)` - ueber
//!   `psk_lifecycle::boot_policy::decide(BootSituation::DigestMismatch)`,
//!   nicht neu erfunden. `Hold` bleibt dagegen ein inspizierbares `Ok`
//!   (wie im bisherigen `golden_run.rs`s Testmuster) - kein Fehlercode
//!   benennt "HOLD" als Fehler, Regel 17.2 nennt es eine Reaktion, kein
//!   FAIL.
//! - Schritt 9 (`register_state_machines`/`register_invariants`) traegt
//!   keine eigene Laufzeitbedingung: beides ist Build-Zeit-Codegen
//!   (`psk_types::automata`) - strukturell erfuellt, sobald dieser Code
//!   ueberhaupt verlinkt ist, nicht etwas, das zur Laufzeit fehlschlagen
//!   koennte.
//! - Schritte 15/16 (M26) tragen ebenfalls keine eigene Bedingung: ohne
//!   einen prozessuebergreifenden, persistenten Run-Store (den es in
//!   dieser Referenzimplementierung nicht gibt) ist "keine unvollstaendigen
//!   Laeufe gefunden" ein ehrliches, aber leeres Resultat - nichts, das
//!   G-BOOT als Bedingung braucht.
//! - Schritt 21 (`activate_cognition_compiler`) ist der bereits reale
//!   FSM-Uebergang BOOTING->BOUND (`psk_lifecycle::runtime::advance`,
//!   Automat 13.2/`state_machines.yaml`) - exakt die Transition, die
//!   `runtime.rs`s eigener Test `boot_requires_g_boot` schon zeigt. Keine
//!   neu erfundene "Kognitionscompiler"-Funktion.

use std::path::{Path, PathBuf};

use psk_gate::{evaluate_gate, ConditionOutcome, GateInputs};
use psk_lifecycle::{advance, decide, BootOutcome, BootSituation, RuntimeState};
use psk_scheduler::{BudgetLedger, Sigma};
use psk_trace::{ResidueLedger, TraceStore};
use psk_types::objects::{
    AdapterId, GateId, GateReport, GateReportDecisionKind, IdentityBinding, OpId, ProfileId,
    ReasonCode, Releaseposture, ReplayDescriptor, RuntimeManifest, Scaled, SemVer, SortId,
};
use psk_types::{Digest, DualTime, ObjectId, PskError, RunId, TraceRef};

use crate::artifact_registry::{self, ArtifactRegistry};
use crate::identity_binder;
use crate::load::{self, BundleImage};
use crate::store_lock::acquire_store_lock;

/// Eingaben, die nicht aus dem Bundle selbst folgen - `bundle_root` ist
/// die Workspace-Wurzel, der Rest sind Laufkontext (Zeit, Profil,
/// Trace-Verkettung), den nur der Aufrufer kennen kann.
///
/// `store_root` und `bundle_root` sind bewusst getrennte Felder:
/// Struktur 16.7 (Store-Layout) zeigt `<store_root>/LOCK` als Teil einer
/// eigenen, veraenderlichen Laufzeit-Datenablage (`objects/`, `trace/`,
/// `residue/`, ...) - nicht des Bundles selbst (constitution/architecture,
/// weitgehend gelesen, nicht geschrieben). Schritt 1 (Store-Lock) steht im
/// Algorithmus auch VOR Schritt 2 (`M00.load(bundle_path)`) - beide waren
/// nie derselbe Pfad. Ein frueher Entwurf hier hatte sie faelschlich
/// gleichgesetzt; zwei Golden-Run-Tests, die parallel denselben
/// Workspace-Root sperren wollten, deckten das ueber einen echten
/// `BootPreconditionFailed` auf (die Sperre tat exakt, wofuer sie gebaut
/// ist - nur an einem zu weit gefassten Pfad).
pub struct BootInputs {
    pub bundle_root: PathBuf,
    pub store_root: PathBuf,
    pub profile: ProfileId,
    pub bound_at: DualTime,
    pub trace_ref: TraceRef,
    pub replay_descriptor: ReplayDescriptor,
    /// Die deklarierten Ressourcengrenzen dieses Laufs (Vertrag 14.12 (Keine implizite Unendlichkeit):
    /// "Jede Klasse besitzt ein deklariertes Limit"). Vom Aufrufer
    /// geliefert, nicht hier erfunden - dasselbe Muster wie
    /// `trace`/`residues`, die ebenfalls von aussen kommen. Sie sind Teil
    /// des Laufzustands, ueber den Schritt 12 `I_t` bildet.
    pub budget: BudgetLedger,
    /// Skalentiefe des M13-Turms (v1.0.32, Struktur 7.1). Eine
    /// DEKLARATION des Laufs - das Topologieregister verweist auf sie
    /// ("scale: {max_depth: declared_in_runtime_manifest}"), berechnen
    /// kann sie niemand. Vom Aufrufer geliefert, wie `budget`.
    pub max_depth: u32,
}

/// `BootReport` (Algorithmus 17.1s Rueckgabetyp - kein registriertes
/// Kapitel-7-Objekt, siehe object_registry.yaml). `state` nutzt das
/// bereits reale `psk_lifecycle::runtime::RuntimeState` statt eines neu
/// erfundenen Enums - siehe Modulkopf.
pub struct BootReport {
    pub state: RuntimeState,
    pub gate_report: GateReport,
    pub constitution_check: verify_bundle::BundleCheck,
    pub architecture_check: verify_architecture::ArchitectureCheck,
    pub identity: IdentityBinding,
    pub runtime_manifest: RuntimeManifest,
    pub posture: Releaseposture,
}

/// Die 23 ISA-Operatoren (Definition 12.1, `OpId::ALL`) plus die beiden
/// real existierenden Adaptercrates dieses Workspace, jeweils Version
/// 1.0.0 - Schritt 17s reale Eingabe fuer DIESE Referenzimplementierung
/// (welche Operatoren/Adapter ein Build traegt, ist eine Buildtatsache,
/// siehe psk-effect::registration Modulkopf).
fn versioned_operators() -> Vec<(OpId, SemVer)> {
    OpId::ALL
        .iter()
        .map(|op| (*op, SemVer("1.0.0".to_string())))
        .collect()
}

fn versioned_adapters() -> Vec<(AdapterId, SemVer)> {
    vec![
        (
            AdapterId("observer-local-fs".into()),
            SemVer("1.0.0".into()),
        ),
        (AdapterId("effect-local-fs".into()), SemVer("1.0.0".into())),
    ]
}

fn sealed_condition(
    sealed: bool,
    matches: bool,
    missing_reason: &str,
    mismatch_reason: &str,
) -> ConditionOutcome {
    if !sealed {
        ConditionOutcome::Undecidable(ReasonCode(missing_reason.into()))
    } else if matches {
        ConditionOutcome::True
    } else {
        ConditionOutcome::False(ReasonCode(mismatch_reason.into()))
    }
}

/// `boot(bundle_path, profile) -> BootReport` - siehe Modulkopf fuer jede
/// Abweichung vom woertlichen Pseudocode und ihre Begruendung.
pub fn boot(
    inputs: BootInputs,
    trace: &mut TraceStore,
    residues: &mut ResidueLedger,
) -> Result<BootReport, PskError> {
    // TEMPORAERE Schritt-Diagnose (siehe store_lock.rs Modulkopf/Commit-
    // Nachricht fuer den Anlass): PskError::BootPreconditionFailed hat
    // mindestens VIER unabhaengige Quellen im fruehen Bootpfad allein
    // (acquire_store_lock, load::load, resolve_artifact_registry,
    // identity_binder::implementation_id/build_digest) - alle verwerfen
    // ihren eigenen io::Error gleich, der Fehlerwert allein unterscheidet
    // sie nicht. Wird entfernt, sobald die reale Fehlerquelle bekannt ist.
    eprintln!(
        "boot: Schritt 1 (acquire_store_lock, store_root={})...",
        inputs.store_root.display()
    );
    // Schritt 1: else FAIL(PSK-E101) - einziger echter frueher Ruecksprung.
    let _lock = acquire_store_lock(&inputs.store_root)?;
    eprintln!("boot: Schritt 1 OK.");

    eprintln!(
        "boot: Schritt 2 (M00.load, bundle_root={})...",
        inputs.bundle_root.display()
    );
    // Schritt 2: M00.load (constitution.lock.json zuerst).
    let image: BundleImage = load::load(&inputs.bundle_root)?;
    eprintln!("boot: Schritt 2 OK.");

    eprintln!("boot: Schritt 3 (M02.resolve_artifact_registry)...");
    // Schritt 3: M02.resolve_artifact_registry(image) - deckt zugleich
    // Schritt 7 (architekturseitig) und Schritte 10/11 ab, siehe
    // artifact_registry.rs Modulkopf.
    let registry: ArtifactRegistry = artifact_registry::resolve_artifact_registry(&image)?;
    eprintln!("boot: Schritt 3 OK.");

    // Schritte 4-6: cid = M01.collection_digest(canon); require cid ==
    // image.lock.constitution_id. `matches()` vergleicht bereits exakt
    // computed_constitution_id gegen stored_constitution_id - den
    // selbstberechneten, versiegelten Wert, NIE
    // declared_ancestor_constitution_id (OBL-009, siehe load.rs Modulkopf).
    let cid = image.constitution_check.computed_constitution_id;
    let constitution_condition = sealed_condition(
        image.constitution_check.sealed(),
        image.constitution_check.matches(),
        "constitution-not-sealed",
        "constitution-digest-mismatch",
    );

    // Schritt 7 (architekturseitig): 18 Register strukturell schemakonform.
    let schema_condition = if registry.architecture_check.schema_conformant() {
        ConditionOutcome::True
    } else {
        ConditionOutcome::False(ReasonCode("architecture-schema-invalid".into()))
    };

    // Schritt 8: M22.register_topology(); |V|=13, |E|=30, |Delta|=18.
    let topology_condition = if psk_topology::nodes().len() == 13
        && psk_topology::edges().len() == 30
        && psk_topology::cells().len() == 18
    {
        ConditionOutcome::True
    } else {
        // Invariante 9.5 verletzt waere ein Programmierfehler im
        // generierten Register, kein Laufzeitzustand - echtes False.
        ConditionOutcome::False(ReasonCode("m13-cardinality-violated".into()))
    };

    // Schritt 9: register_state_machines/register_invariants - Build-Zeit-
    // Codegen, siehe Modulkopf. Keine eigene Bedingung.

    // Schritte 10-11: aid == image.lock.architecture_id.
    let aid = registry.architecture_check.computed_architecture_id;
    let architecture_condition = sealed_condition(
        registry.architecture_check.sealed(),
        registry.architecture_check.matches(),
        "architecture-not-sealed",
        "architecture-digest-mismatch",
    );

    eprintln!("boot: Schritt 12 (M04.bind: implementation_id)...");
    // Schritt 12: M04.bind(cid, aid, implementation_id(), runtime_state_digest()).
    let i_m = identity_binder::implementation_id(&inputs.bundle_root, cid, aid)?;
    eprintln!("boot: Schritt 12 implementation_id OK.");

    // Schritt 17 zuerst berechnet (RuntimeManifest braucht sein Ergebnis),
    // Bedingung/Reihenfolge im all_of() weiter unten folgt Schritt 17s
    // Nummer, nicht der Berechnungsreihenfolge hier. Seit I_t ueber den
    // realen Laufzustand gebildet wird, gilt dasselbe fuer Schritt 12s
    // ZWEITE Haelfte: `Sigma` traegt das RuntimeManifest als Position `I`
    // (Definition 13.1), also MUSS das Manifest vor `bind` stehen. Die
    // Nummernfolge im Bericht bleibt unveraendert; nur die
    // Berechnungsreihenfolge folgt der Datenabhaengigkeit.
    let registration = psk_effect::register_only_versioned_operators_and_capabilities(
        &versioned_operators(),
        &versioned_adapters(),
    );
    let operator_condition = match &registration {
        Ok(_) => ConditionOutcome::True,
        Err(_) => ConditionOutcome::False(ReasonCode("operator-registration-failed".into())),
    };
    eprintln!("boot: Schritt 17 (build_digest)...");
    let build_digest = identity_binder::build_digest()?;
    eprintln!("boot: Schritt 17 build_digest OK.");
    let runtime_manifest = identity_binder::build_runtime_manifest(
        cid,
        aid,
        i_m,
        inputs.profile,
        build_digest,
        registration
            .as_ref()
            .map(|r| r.operator_versions.clone())
            .unwrap_or_default(),
        registration
            .as_ref()
            .map(|r| r.adapter_versions.clone())
            .unwrap_or_default(),
        inputs.max_depth,
    );

    // Schritt 12, zweite Haelfte: der Laufzustand zum Bindezeitpunkt.
    // `Sigma_t` ist hier real und nicht leer - Trace und Residuen kommen
    // vom Aufrufer (siehe Modulkopf) und tragen bei einem Recovery-Boot
    // bereits Inhalt, bei einem frischen Boot nichts. Beides ist ein
    // gueltiger Zustand; erfunden wird keiner.
    let mut boot_sigma = Sigma::new(runtime_manifest.clone(), inputs.budget.clone());
    boot_sigma.trace = trace.clone();
    boot_sigma.residues = residues.clone();
    let i_t = identity_binder::runtime_state_digest(&boot_sigma)?;

    // I-FIELD-001 (severity: blocking), erste Haelfte: keine bereits
    // registrierte Feldidentitaet darf gleich der zu bindenden
    // Systemidentitaet sein. Die Feldliste kommt aus dem Laufzustand -
    // bei einem frischen Boot leer, bei einem Recovery-Boot gefuellt.
    // Als Gatebedingung statt als frueher Err: dieselbe Ordnung wie bei
    // Schritt 6/11 (siehe Modulkopf) - `all_of(above)` soll die
    // Bedingung sehen, nicht um sie verkuerzt werden.
    let registered_field_ids: Vec<ObjectId> = boot_sigma.fields.iter().map(|f| f.id).collect();
    let field_identity_condition =
        match identity_binder::check_no_field_identity_equals_system_identity(
            i_t,
            &registered_field_ids,
        ) {
            Ok(()) => ConditionOutcome::True,
            Err(_) => {
                ConditionOutcome::False(ReasonCode("field-identity-equals-system-identity".into()))
            }
        };

    let identity = identity_binder::bind(cid, aid, i_m, i_t, trace.head(), inputs.bound_at.clone());
    eprintln!("boot: Schritt 12 OK.");

    // Schritt 13: M04.check_profile_binding(profile).
    let profile_condition =
        match identity_binder::check_profile_binding(&runtime_manifest, inputs.profile) {
            Ok(()) => ConditionOutcome::True,
            Err(_) => ConditionOutcome::False(ReasonCode("profile-binding-mismatch".into())),
        };

    // Schritte 14-16: M19 ist bereits offen (trace/residues kommen vom
    // Aufrufer, siehe Modulkopf/T-RES-001). M26 traegt keine eigene
    // Bedingung, siehe Modulkopf.

    // Schritt 18: M21.compute_release_and_operational_posture().
    let posture =
        psk_certify::compute_release_and_operational_posture(psk_certify::PostureInputs {
            constitution_sealed: image.constitution_check.sealed(),
            constitution_matches: image.constitution_check.matches(),
            architecture_sealed: registry.architecture_check.sealed(),
            architecture_matches: registry.architecture_check.matches(),
            architecture_schema_conformant: registry.architecture_check.schema_conformant(),
            identity_bound: true, // Schritt 12 hat oben unbedingt ein IdentityBinding gebaut
            full_release_verified: false, // Vertrag 31.4: am Boot nie erfuellt, siehe posture.rs Modulkopf
            externally_reproduced: false,
        });
    let posture_condition = match posture {
        Releaseposture::Rejected => {
            ConditionOutcome::False(ReasonCode("release-posture-rejected".into()))
        }
        Releaseposture::Quarantined => {
            ConditionOutcome::Undecidable(ReasonCode("release-posture-quarantined".into()))
        }
        Releaseposture::ConformantLimited
        | Releaseposture::ConformantReference
        | Releaseposture::ExternallyValidated => ConditionOutcome::True,
    };

    // Schritt 19: g = M14.gate("G-BOOT", all_of(above)).
    let gate_report = evaluate_gate(
        GateInputs {
            gate_id: GateId::GBoot,
            order: 2, // gate_registry.yaml: G-BOOT, order: 2
            input_digests: vec![cid, aid],
            conditions: vec![
                constitution_condition,
                schema_condition,
                topology_condition,
                architecture_condition,
                profile_condition,
                field_identity_condition,
                operator_condition,
                posture_condition,
            ],
            seam_compatible: Some(true), // G-BOOT ist kein M13-Zellbezug, siehe psk-gate Modulkopf
            evidence_refs: vec![],
            seam_report_refs: vec![ObjectId::new(
                SortId::Trace,
                Digest::sha256(b"boot-closure"),
            )],
            replay_descriptor: inputs.replay_descriptor,
            decided_at: inputs.bound_at,
            trace_ref: inputs.trace_ref,
        },
        trace,
        residues,
    )?;

    // Schritt 20-21: require g.decision == PASS else HOLD or QUARANTINE;
    // activate_cognition_compiler() == FSM BOOTING->BOUND, siehe Modulkopf.
    let _ = advance(RuntimeState::Booting, "bind_identity"); // Operator-Teil von Invariante 13.3; das Gate selbst ist der zweite Teil
    let state = match gate_report.decision {
        GateReportDecisionKind::Pass => RuntimeState::Bound,
        GateReportDecisionKind::Hold => {
            let _ = decide(BootSituation::Undecidable); // Regel 17.2: undecidable -> hold, inspizierbar ueber gate_report
            RuntimeState::Booting
        }
        GateReportDecisionKind::Fail => {
            return match decide(BootSituation::DigestMismatch) {
                BootOutcome::Fail(e) => Err(e),
                _ => unreachable!("BootSituation::DigestMismatch bildet immer auf Fail(..) ab"),
            };
        }
    };

    Ok(BootReport {
        state,
        gate_report,
        constitution_check: image.constitution_check,
        architecture_check: registry.architecture_check,
        identity,
        runtime_manifest,
        posture,
    })
}

/// Hilfsfunktion fuer Aufrufer, die Bundle- und Store-Wurzel kennen und
/// die uebrigen Felder mit vernuenftigen, deterministischen Werten fuellen
/// wollen.
pub fn default_inputs(
    bundle_root: &Path,
    store_root: &Path,
    profile: ProfileId,
    bound_at: DualTime,
    trace_ref: TraceRef,
) -> BootInputs {
    BootInputs {
        bundle_root: bundle_root.to_path_buf(),
        store_root: store_root.to_path_buf(),
        profile,
        bound_at,
        trace_ref,
        replay_descriptor: ReplayDescriptor("boot/1".into()),
        budget: default_budget(RunId(trace_ref_run_id())),
        // Skalentiefe 0: der Referenzlauf steigt nicht ab (M13(0)).
        // Bewusst der niedrigste ehrliche Wert statt eines bequemen
        // grossen - dieselbe Ueberlegung wie beim Vorgabebudget: ein
        // Vorgabewert darf bequem sein, aber keine Tiefe behaupten, die
        // kein Lauf betritt.
        max_depth: 0,
    }
}

/// Ein deklariertes, ENDLICHES Vorgabebudget fuer Aufrufer, die kein
/// eigenes mitbringen. Vertrag 14.12 (Keine implizite Unendlichkeit)
/// verlangt fuer jede Klasse ein deklariertes Limit - der Wert hier ist
/// bewusst konkret und endlich, nicht `u64::MAX`: ein Vorgabewert darf
/// bequem sein, aber nicht die Erschoepfungssemantik aushebeln. Wer reale
/// Grenzen kennt, uebergibt sie ueber `BootInputs::budget` selbst.
pub fn default_budget(run_id: RunId) -> BudgetLedger {
    const DEFAULT_LIMIT: u64 = 1_000_000;
    BudgetLedger::open(
        run_id,
        DEFAULT_LIMIT,
        DEFAULT_LIMIT,
        DEFAULT_LIMIT,
        DEFAULT_LIMIT,
        DEFAULT_LIMIT,
        DEFAULT_LIMIT,
        DEFAULT_LIMIT,
        Scaled {
            schema: "psk.scaled/1.0".to_string(),
            numerator: 100,
            scale: 2,
        },
    )
}

/// `BudgetLedger::open` verlangt eine `RunId`; `default_inputs` kennt an
/// dieser Stelle nur den `TraceRef`. Der Lauf selbst wird erst spaeter
/// (M19 `open_run`) eroeffnet - bis dahin traegt das Vorgabebudget einen
/// festen, deterministischen Bezeichner statt eines erfundenen Laufnamens.
fn trace_ref_run_id() -> String {
    "boot-default".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        loop {
            if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
                return dir;
            }
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
    }

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 1,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("boot-test".into()),
            uncertainty_ns: 0,
        }
    }

    #[test]
    fn booting_the_real_sealed_workspace_reaches_pass_not_hold() {
        let root = workspace_root();
        // Eigener Store-Root (nicht `root` selbst): mehrere Tests/Prozesse
        // koennten sonst um dieselbe LOCK-Datei konkurrieren - siehe
        // `BootInputs`s Modulkopf.
        let store = std::env::temp_dir().join(format!("psk-boot-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&store);
        std::fs::create_dir_all(&store).unwrap();

        let mut trace = TraceStore::new();
        let mut residues = ResidueLedger::new();
        let trace_ref = TraceRef(trace.head());

        let report = boot(
            default_inputs(
                &root,
                &store,
                ProfileId::Reference,
                sample_time(),
                trace_ref,
            ),
            &mut trace,
            &mut residues,
        )
        .expect("ein korrekt versiegeltes Bundle darf boot() nicht mit Err abbrechen");

        assert_eq!(report.gate_report.decision, GateReportDecisionKind::Pass);
        assert_eq!(report.gate_report.gate_id, GateId::GBoot);
        assert_eq!(report.state, RuntimeState::Bound);
        assert!(report.constitution_check.matches());
        assert!(report.architecture_check.matches());
        assert_eq!(
            report.posture,
            Releaseposture::ConformantLimited,
            "kein Lauf hat stattgefunden - Vertrag 31.4 (verified) ist am Boot nie erfuellt"
        );
        assert_eq!(report.runtime_manifest.operator_versions.len(), 23);

        std::fs::remove_dir_all(&store).ok();
    }

    #[test]
    fn booting_an_empty_bundle_holds_rather_than_panics() {
        let dir = std::env::temp_dir().join(format!("psk-boot-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut trace = TraceStore::new();
        let mut residues = ResidueLedger::new();
        let trace_ref = TraceRef(trace.head());

        // Kein constitution/-Verzeichnis -> M00.load() selbst schlaegt
        // schon fehl (BootPreconditionFailed), lange bevor G-BOOT
        // ueberhaupt ausgewertet wird - konsistent mit Schritt 1/2s
        // harten Vorbedingungen. `dir` dient hier fuer Bundle- UND
        // Store-Root - ein isolierter Temp-Pfad, keine Kollisionsgefahr.
        let result = boot(
            default_inputs(&dir, &dir, ProfileId::Reference, sample_time(), trace_ref),
            &mut trace,
            &mut residues,
        );
        assert!(matches!(result, Err(PskError::BootPreconditionFailed)));
        std::fs::remove_dir_all(&dir).ok();
    }
}
