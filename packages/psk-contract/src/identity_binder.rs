//! M04 IdentityBinder, Bootschritte 12-13 (Algorithmus 17.1):
//! `M04.bind(cid, aid, implementation_id(), runtime_state_digest())`;
//! `M04.check_profile_binding(profile)`.
//!
//! M04 besitzt laut object_registry.yaml sowohl OBJ-IDB (IdentityBinding,
//! Struktur 7.2) als auch OBJ-RTM (RuntimeManifest, Struktur 7.1) - beide
//! werden hier gebaut, nicht nur `bind()`s Rueckgabetyp.
//!
//! `implementation_id()`/`runtime_state_digest()` haben in der gesamten
//! bisherigen Quelle keine Definition (weder ein Modul noch eine
//! Formel jenseits von Regel 6.10s Kurzformen). Diese Implementierung
//! macht die Wahl explizit statt sie stillschweigend zu treffen:
//!
//! - `implementation_id()` (I_M). Regel 6.10: "I_M = H(Code||Schemas||
//!   Compiler||Profil)". `Profil` traegt RuntimeManifest bereits als
//!   eigenes Feld (`profile`) - keine zweite Kodierung hier noetig.
//!   `Compiler` ist ohne eine Buildpipeline, die die Toolchain-Version
//!   festhaelt (die es hier nicht gibt), nicht ehrlich messbar. `Code` UND
//!   `Schemas` sind es: Cargo.lock bindet die exakte, gepinnte
//!   Abhaengigkeitsmenge (der praktische "welcher Code laeuft"-Anker
//!   dieses Rust-Workspace), und I_C/I_A SIND bereits die Digests der
//!   Schemas selbst (viel generierter Code entsteht direkt aus ihnen -
//!   `tools/psk-codegen`). `implementation_id` bildet deshalb H(Cargo.lock
//!   || I_C || I_A) - real, reproduzierbar, aendert sich mit jeder
//!   Abhaengigkeits- ODER Registeraenderung, aber ohne eine erfundene
//!   Compiler-Kennung.
//! - `runtime_state_digest()` (I_t). Regel 6.10: "I_t = H(Can(Sigma_t))".
//!   Zum Zeitpunkt von Schritt 12 ist `M19.open_trace_store()` (Schritt
//!   14) noch nicht einmal aufgerufen - der Algorithmus selbst ordnet
//!   Bindung VOR Tracestore-Eroeffnung an. Der einzige ehrliche
//!   Laufzeitzustand an dieser Stelle ist der, den der Trace-Kopf zu
//!   diesem Zeitpunkt tatsaechlich traegt: bei einem frischen Boot der
//!   Genesis-Digest, bei einem Recovery-Boot (Algorithmus 17.6) der
//!   fortgesetzte Kopf. `runtime_state_digest` liest deshalb
//!   `trace.head()` direkt, statt eine Konstante zu erfinden - korrekt in
//!   beiden Faellen, nicht nur im haeufigeren.
//!
//! `build_digest` (RuntimeManifest, getrennt von `implementation_id`):
//! Digest der tatsaechlich laufenden Programmdatei
//! (`std::env::current_exe()`) - das buchstaebliche "Build", waehrend
//! `implementation_id` die weiter gefasste Code/Schema-Identitaet nach
//! Regel 6.10 traegt.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use psk_trace::TraceStore;
use psk_types::objects::{
    AdapterId, CapabilityMatrixRef, IdentityBinding, OpId, ProfileId, RuntimeManifest,
    RuntimeManifestDeterminismClassKind, SemVer,
};
use psk_types::{Digest, DualTime, PskError};

/// Regel 6.10: "I_M = H(Code||Schemas||Compiler||Profil)" - siehe
/// Modulkopf fuer die Cargo.lock/I_C/I_A-Faktorisierung.
pub fn implementation_id(
    workspace_root: &Path,
    i_c: Digest,
    i_a: Digest,
) -> Result<Digest, PskError> {
    let mut bytes = fs::read(workspace_root.join("Cargo.lock"))
        .map_err(|_| PskError::BootPreconditionFailed)?;
    bytes.extend_from_slice(i_c.to_string().as_bytes());
    bytes.extend_from_slice(i_a.to_string().as_bytes());
    Ok(Digest::sha256(&bytes))
}

/// Regel 6.10: "I_t = H(Can(Sigma_t))" - siehe Modulkopf.
pub fn runtime_state_digest(trace: &TraceStore) -> Digest {
    trace.head()
}

/// Digest der laufenden Programmdatei - siehe Modulkopf.
pub fn build_digest() -> Result<Digest, PskError> {
    let exe = std::env::current_exe().map_err(|_| PskError::BootPreconditionFailed)?;
    let bytes = fs::read(&exe).map_err(|_| PskError::BootPreconditionFailed)?;
    Ok(Digest::sha256(&bytes))
}

/// M04, Schritt 12: `bind(cid, aid, implementation_id(),
/// runtime_state_digest())`. `intrinsic_section`/`extrinsic_section`
/// (Struktur 7.2) tragen eigene Feldnotizen: "aus Typ, Provenienz,
/// Konstitutionsbindung, Trace" bzw. "aus Verhalten, Claims, Zertifikaten,
/// Aussenrecords". Am Boot existiert von der zweiten Gruppe (Verhalten,
/// Claims, Zertifikate, Aussenrecords) noch keines - kein Lauf hat
/// stattgefunden. `extrinsic_section` ist deshalb ehrlich der Digest ueber
/// die leere Evidenzmenge, nicht ueber eine erfundene.
/// `equalizer_sector` bleibt `None` - Struktur 7.2 nennt ihn "Pflicht fuer
/// Identitaetsclosure", ein Konzept, das am Boot noch nicht erreicht ist.
pub fn bind(
    i_c: Digest,
    i_a: Digest,
    i_m: Digest,
    i_t: Digest,
    trace_head: Digest,
    bound_at: DualTime,
) -> IdentityBinding {
    let intrinsic_section = Digest::sha256(format!("{i_c}|{i_a}|{i_m}|{trace_head}").as_bytes());
    let extrinsic_section =
        Digest::sha256(b"no-behavior-claims-certificates-or-external-records-yet");
    IdentityBinding {
        schema: "psk.identity-binding/1.0".to_string(),
        I_C: i_c,
        I_A: i_a,
        I_M: i_m,
        I_t: i_t,
        trace_head,
        bound_at,
        intrinsic_section,
        extrinsic_section,
        equalizer_sector: None,
    }
}

/// Baut das RuntimeManifest (OBJ-RTM, Struktur 7.1), das Schritt 13 gegen
/// das angeforderte Profil prueft. `determinism_class` startet bei `R0`:
/// vor jedem tatsaechlichen Lauf ist keine Replaystabilitaet belegt -
/// derselbe Grundsatz wie bei `AdditionalAcceptance` (certify.rs): eine
/// positive Klasse wird nicht ohne Beleg behauptet.
#[allow(clippy::too_many_arguments)]
pub fn build_runtime_manifest(
    i_c: Digest,
    i_a: Digest,
    i_m: Digest,
    profile: ProfileId,
    build_digest: Digest,
    operator_versions: BTreeMap<OpId, SemVer>,
    adapter_versions: BTreeMap<AdapterId, SemVer>,
) -> RuntimeManifest {
    RuntimeManifest {
        schema: "psk.runtime-manifest/1.0".to_string(),
        constitution_id: i_c,
        architecture_id: i_a,
        implementation_id: i_m,
        profile,
        capability_matrix: CapabilityMatrixRef("constitution/capability_matrix.yaml".to_string()),
        build_digest,
        operator_versions,
        adapter_versions,
        determinism_class: RuntimeManifestDeterminismClassKind::R0,
    }
}

/// M04, Schritt 13: `check_profile_binding(profile)`. Vergleicht das
/// angeforderte Profil gegen das im RuntimeManifest gebundene - beide
/// stammen in `boot()` aus demselben Aufrufargument, die Pruefung ist
/// deshalb hier tautologisch WAHR; sie bleibt trotzdem eine echte Funktion
/// (kein `Ok(())`-Passthrough), weil ein kuenftiger Resume-/Recovery-Pfad
/// (Regel 28.2: Profiluebergang) ein bereits gebundenes Manifest gegen ein
/// ANDERES angefordertes Profil pruefen wird.
pub fn check_profile_binding(
    manifest: &RuntimeManifest,
    requested: ProfileId,
) -> Result<(), PskError> {
    if manifest.profile == requested {
        Ok(())
    } else {
        Err(PskError::BootPreconditionFailed)
    }
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

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    #[test]
    fn implementation_id_is_deterministic_for_the_same_inputs() {
        let root = workspace_root();
        let i_c = Digest::sha256(b"c");
        let i_a = Digest::sha256(b"a");
        let first = implementation_id(&root, i_c, i_a).unwrap();
        let second = implementation_id(&root, i_c, i_a).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn implementation_id_changes_with_constitution_id() {
        let root = workspace_root();
        let i_a = Digest::sha256(b"a");
        let first = implementation_id(&root, Digest::sha256(b"c1"), i_a).unwrap();
        let second = implementation_id(&root, Digest::sha256(b"c2"), i_a).unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn implementation_id_fails_closed_without_a_cargo_lock() {
        let dir = std::env::temp_dir().join(format!("psk-implid-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(
            implementation_id(&dir, Digest::sha256(b"c"), Digest::sha256(b"a")),
            Err(PskError::BootPreconditionFailed)
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn runtime_state_digest_of_a_fresh_trace_store_is_the_genesis_digest() {
        let trace = TraceStore::new();
        assert_eq!(runtime_state_digest(&trace), psk_trace::GENESIS_DIGEST);
    }

    #[test]
    fn build_digest_is_real_and_deterministic() {
        let first = build_digest().unwrap();
        let second = build_digest().unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn bind_carries_all_four_identities_and_the_trace_head_unmodified() {
        let (i_c, i_a, i_m, i_t) = (
            Digest::sha256(b"c"),
            Digest::sha256(b"a"),
            Digest::sha256(b"m"),
            Digest::sha256(b"t"),
        );
        let trace_head = Digest::sha256(b"head");
        let binding = bind(i_c, i_a, i_m, i_t, trace_head, sample_time());
        assert_eq!(
            (binding.I_C, binding.I_A, binding.I_M, binding.I_t),
            (i_c, i_a, i_m, i_t)
        );
        assert_eq!(binding.trace_head, trace_head);
        assert!(binding.equalizer_sector.is_none());
    }

    #[test]
    fn matching_profiles_check_out() {
        let manifest = build_runtime_manifest(
            Digest::sha256(b"c"),
            Digest::sha256(b"a"),
            Digest::sha256(b"m"),
            ProfileId::Reference,
            Digest::sha256(b"build"),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(
            manifest.determinism_class,
            RuntimeManifestDeterminismClassKind::R0
        );
        assert!(check_profile_binding(&manifest, ProfileId::Reference).is_ok());
    }

    #[test]
    fn mismatched_profiles_fail_closed() {
        let manifest = build_runtime_manifest(
            Digest::sha256(b"c"),
            Digest::sha256(b"a"),
            Digest::sha256(b"m"),
            ProfileId::Sandbox,
            Digest::sha256(b"build"),
            BTreeMap::new(),
            BTreeMap::new(),
        );
        assert_eq!(
            check_profile_binding(&manifest, ProfileId::Reference),
            Err(PskError::BootPreconditionFailed)
        );
    }
}
