//! Sigma (Definition 13.1 / CPSK-Vertrag Definition 5.2): der volle
//! Laufzustand, den `tick()` durch die zwoelf Phasen traegt.
//!
//! `constitution/type_registry.yaml` (TY-SIGT) und die Referenzarchitektur
//! selbst (Kapitel 13, Definition 13.1) stimmen woertlich ueberein:
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
//! | Tt (Gedankenkoerper) | `thoughts` | `Vec<ThoughtBody>` |
//! | Ft (Feldregister) | `fields` | `Vec<FieldIdentity>` |
//! | Ht (Realitaetshorizont) | `reality_horizon` | `Vec<RealityClassification>` |
//! | Wt (Witnesses) | `witnesses` | `Vec<EvidenceObject>` |
//! | Qt (Gates und Tokens) | `gates_and_tokens` | `GatesAndTokens` (siehe unten) |
//! | Et (Effekte) | `effects` | `Vec<EffectAttempt>` |
//! | Lt (Trace/Replay) | `trace` | `psk_trace::TraceStore` |
//! | Rt (Residuen) | `residues` | `psk_trace::ResidueLedger` |
//!
//! ## Drei Felder ueber die elf Positionen hinaus
//!
//! - `tick_no`: kein Tupelfeld, aber vom Aufrufer der Umsetzung ausdruecklich
//!   verlangt. Gehoert hier und nicht auf `RunDescriptor` - `RunDescriptor`
//!   ist bei Laufoeffnung versiegelt (`psk_trace::open_run`), waehrend
//!   `tick_no` sich jeden Takt aendert. Dieselbe Begruendung wie Regel 22.3
//!   fuer `profile`: ein veraenderlicher Laufzeitwert gehoert auf den
//!   veraenderlichen Laufzustand, nicht auf das versiegelte Laufobjekt.
//! - `capsules`: kein Tupelfeld (Sigma_t nennt keine eigene Kapselposition),
//!   aber strukturell noetig - Regel 14.5 (Prioritaetsordnung) fuehrt
//!   "bestehende Kapseln im Ratchet" als eigenen Rang (Tier 5,
//!   `psk_scheduler::PriorityTier::RatchetingCapsule`); eine Kapsel, die in
//!   einem Takt nicht bis zum Kapselfixpunkt oder RESIDUAL kommt, MUSS im
//!   naechsten wieder auffindbar sein. Ohne ein Feld hier gaebe es keinen
//!   Ort, an dem sie zwischen zwei Takten ueberlebt.
//! - `budget`: `BudgetLedger` (Struktur 14.10) ist ebenfalls keine der elf
//!   benannten Positionen, aber Algorithmus 14.4 belastet es jeden Takt
//!   ("budget = M25.charge(item)") und Vertrag 14.11 verlangt, dass
//!   Erschoepfung ueber Takte hinweg sichtbar bleibt (kein stilles
//!   Zuruecksetzen) - es muss also denselben Lebenszyklus wie der uebrige
//!   Laufzustand teilen. `budget.rs`s eigener Kopfkommentar trug vor dieser
//!   Umsetzung nur eine Vermutung dazu; dies ist die reale Platzierung.
//!
//! Kapitel 7 kennt weitere reale Objekttypen (FieldProjection,
//! DependencyProfile, SeamReport, ValidationPlan, IRBundle), die diese
//! Umsetzung produziert (siehe `dispatch`), aber NICHT hier haelt: sie sind
//! Verarbeitungsergebnisse einzelner Phasen, keine der elf benannten
//! Sigma-Positionen, und ihre dauerhafte Spur ist der Trace
//! (`result.trace_segments`), nicht eine zusaetzliche Sigma-Sammlung. Ein
//! spaeterer Fund koennte das revidieren; diese Umsetzung erfindet keine
//! zwoelfte Position ohne Textstelle.

use crate::BudgetLedger;
use psk_effect::TokenLedger;
use psk_trace::{ResidueLedger, TraceStore};
use psk_types::objects::{
    AnchorSnapshot, CandidateCapsule, EffectAttempt, EffectToken, EvidenceObject, FieldIdentity,
    GateReport, RealityClassification, RuntimeManifest, ThoughtBody,
};

/// Qt (Gates und Tokens): ein GateReport-Verlauf, die bereits ausgestellten
/// EffectToken und deren FSM-TOKEN-Zustandsfuehrung. Drei Felder statt
/// eines, weil `TokenLedger` (Zustand je `idempotency_key`) und die
/// vollstaendigen `EffectToken`-Objekte (fuer `execute_effect`, das den
/// realen Token braucht, nicht nur seinen Zustand) unterschiedliche Dinge
/// festhalten - siehe `psk-effect::consume`s Modulkopf.
#[derive(Debug, Clone, Default)]
pub struct GatesAndTokens {
    pub reports: Vec<GateReport>,
    pub issued: Vec<EffectToken>,
    pub ledger: TokenLedger,
}

/// Sigma (Definition 13.1). Siehe Modulkopf fuer die vollstaendige
/// Positionszuordnung.
#[derive(Debug, Clone)]
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
}

impl Sigma {
    /// Ein frischer Laufzustand fuer einen soeben gebundenen Lauf (Boot-
    /// Schritt, vor dem ersten Takt): `tick_no: 0`, alle Sammlungen leer.
    /// `i` (die Implementierungsbindung) und `budget` (die deklarierten
    /// Limits, Vertrag 14.11) MUESSEN von aussen kommen - beide entstehen
    /// aus lauf-/domaenenspezifischen Werten, die dieser Konstruktor nicht
    /// erfinden darf (`i` am Boot ueber
    /// `psk_contract::identity_binder::build_runtime_manifest`, `budget`
    /// ueber `BudgetLedger::open` mit den deklarierten Limits).
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
        }
    }

    /// C (Konstitution): realisiert als `i.constitution_id`, kein eigenes
    /// Feld (siehe Modulkopf).
    pub fn c(&self) -> psk_types::Digest {
        self.i.constitution_id
    }
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
        }
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
    }

    #[test]
    fn c_reads_the_constitution_digest_off_the_runtime_manifest() {
        let manifest = sample_manifest();
        let expected = manifest.constitution_id;
        let sigma = Sigma::new(manifest, sample_budget());
        assert_eq!(sigma.c(), expected);
    }
}
