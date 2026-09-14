//! Die Domaenenseite des QPM-Laufs: das `qpm:`-Profil aus
//! `domains/jacobs-ladder-reference/domain_profile.yaml` lesen und in
//! die QPM-Objekte uebersetzen.
//!
//! Liegt hier und nicht in psk-fields, aus demselben Grund wie
//! `load_reference_domain_profile`: wer das Domaenenprofil LIEST, ist
//! die Domaene, und die Referenzdomaene ist dieser Konformanzlauf. Der
//! Kern kennt weder Dateipfad noch YAML-Format.

use std::path::Path;

use psk_adversarial::CounterHorizon;
use psk_fields::{
    Aperture, ApertureBank, ApertureId, BudgetSpec, CatalogRef, ChannelId, CoverageSpec,
    DomainContractRef, HorizonSpec, PanopticScope, QuestionSpec, ScopePolicies,
};
use psk_types::objects::{PredicateExpr, SemVer, SortId, TimeWindow};
use psk_types::{Digest, ObjectId, PskError, TraceRef};

use crate::golden_run::GoldenRunReport;

/// Das gelesene Profil, noch nicht in Objekte uebersetzt.
pub struct QpmProfile {
    declared_channels: Vec<ChannelId>,
    undeclared: Vec<(ChannelId, String)>,
    open_set: bool,
    calibration_validity: String,
    catalog_ref: Option<String>,
    bank_version: String,
    apertures: Vec<ProfileAperture>,
    ch_justification: Option<String>,
}

struct ProfileAperture {
    id: String,
    channel_ref: String,
    pass_predicate: String,
    passes_sorts: Vec<SortId>,
    declared_coverage: String,
}

/// Liest den `qpm:`-Abschnitt. Ein fehlender Abschnitt ist ein Fehler,
/// kein Vorgabewert: ohne Domaenenprofil gibt es keinen QPM-Lauf.
pub fn load_qpm_profile(workspace_root: &Path) -> Result<QpmProfile, PskError> {
    let path = workspace_root.join("domains/jacobs-ladder-reference/domain_profile.yaml");
    let text = std::fs::read_to_string(&path).map_err(|_| PskError::UntypedInput)?;
    let doc: serde_yaml::Value = serde_yaml::from_str(&text).map_err(|_| PskError::UntypedInput)?;
    let q = doc.get("qpm").ok_or(PskError::UntypedInput)?;

    let declared_channels: Vec<ChannelId> = q
        .get("declared_channels")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?
        .iter()
        .filter_map(|v| v.as_str().map(|s| ChannelId(s.to_string())))
        .collect();
    if declared_channels.is_empty() {
        // Ein Scope ohne deklarierte Kanaele ist kein Scope.
        return Err(PskError::UntypedInput);
    }

    let undeclared: Vec<(ChannelId, String)> = q
        .get("undeclared_channels")
        .and_then(|v| v.as_mapping())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| {
                    Some((ChannelId(k.as_str()?.to_string()), v.as_str()?.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    let pol = q.get("policies").ok_or(PskError::UntypedInput)?;
    let bank = q.get("aperture_bank").ok_or(PskError::UntypedInput)?;

    let mut apertures = Vec::new();
    for a in bank
        .get("apertures")
        .and_then(|v| v.as_sequence())
        .ok_or(PskError::UntypedInput)?
    {
        let sorts: Vec<SortId> = a
            .get("passes_sorts")
            .and_then(|v| v.as_sequence())
            .ok_or(PskError::UntypedInput)?
            .iter()
            .map(|s| {
                s.as_str()
                    .and_then(SortId::from_id)
                    .ok_or(PskError::UntypedInput)
            })
            .collect::<Result<_, _>>()?;
        apertures.push(ProfileAperture {
            id: str_field(a, "id")?,
            channel_ref: str_field(a, "channel_ref")?,
            pass_predicate: str_field(a, "pass_predicate")?,
            passes_sorts: sorts,
            declared_coverage: str_field(a, "declared_coverage")?,
        });
    }
    if apertures.is_empty() {
        return Err(PskError::UntypedInput);
    }

    Ok(QpmProfile {
        declared_channels,
        undeclared,
        open_set: pol
            .get("open_set")
            .and_then(|v| v.as_bool())
            .ok_or(PskError::UntypedInput)?,
        calibration_validity: str_field(pol, "calibration_validity")?,
        // Ein fehlendes ODER null-Feld heisst hier dasselbe: kein
        // Katalog. QPM-OBL-002 greift in beiden Faellen.
        catalog_ref: pol
            .get("catalog_ref")
            .and_then(|v| v.as_str())
            .map(str::to_string),
        bank_version: str_field(bank, "version")?,
        apertures,
        ch_justification: q
            .get("counter_horizon")
            .and_then(|c| c.get("emptiness_justification"))
            .and_then(|v| v.as_str())
            .map(str::to_string),
    })
}

fn str_field(v: &serde_yaml::Value, key: &str) -> Result<String, PskError> {
    v.get(key)
        .and_then(|x| x.as_str())
        .map(str::to_string)
        .ok_or(PskError::UntypedInput)
}

impl QpmProfile {
    /// QPM Struktur 3.2 (PanopticScope) aus dem Profil.
    pub fn scope(&self) -> PanopticScope {
        PanopticScope {
            schema: "psk.qpm.scope/1.0".to_string(),
            id: ObjectId::new(
                SortId::FieldIdentity,
                Digest::sha256(b"qpm-scope/golden-run"),
            ),
            domain_contract: DomainContractRef("jacobs-ladder-reference".into()),
            questions: vec![QuestionSpec(
                "welche Masse des Referenzlaufs erreicht das Instrument?".into(),
            )],
            horizon: HorizonSpec("m13:0".into()),
            declared_channels: self.declared_channels.clone(),
            budget: BudgetSpec("ein Lauf, keine Wiederholung".into()),
            policies: ScopePolicies {
                open_set: self.open_set,
                calibration_validity: TimeWindow(self.calibration_validity.clone()),
                catalog_ref: self.catalog_ref.clone().map(CatalogRef),
            },
            trace_ref: TraceRef(Digest::sha256(b"qpm-observation")),
        }
    }

    /// QPM Struktur 3.4 (ApertureBank) aus dem Profil.
    pub fn bank(&self) -> ApertureBank {
        ApertureBank {
            schema: "psk.qpm.aperture-bank/1.0".to_string(),
            id: ObjectId::new(
                SortId::FieldIdentity,
                Digest::sha256(b"qpm-bank/golden-run"),
            ),
            version: SemVer(self.bank_version.clone()),
            apertures: self
                .apertures
                .iter()
                .map(|a| Aperture {
                    id: ApertureId(a.id.clone()),
                    channel_ref: ChannelId(a.channel_ref.clone()),
                    pass_predicate: PredicateExpr(a.pass_predicate.clone()),
                    declared_coverage: CoverageSpec(a.declared_coverage.clone()),
                })
                .collect(),
            trace_ref: TraceRef(Digest::sha256(b"qpm-observation")),
        }
    }

    /// Die erste Apertur, die diese Sorte durchlaesst - oder keine.
    pub fn first_aperture_passing(&self, sort: SortId) -> Option<ApertureId> {
        self.apertures
            .iter()
            .find(|a| a.passes_sorts.contains(&sort))
            .map(|a| ApertureId(a.id.clone()))
    }

    /// Die Apertur eines Kanals samt ihrem Praedikat - der Beleg, den
    /// QPM Regel 3.5 (Eine Apertur erzeugt Schatten, keine Abwesenheit) fuer jeden Schatten verlangt.
    pub fn holding_aperture(
        &self,
        channel: &ChannelId,
    ) -> Result<(ApertureId, PredicateExpr), PskError> {
        self.apertures
            .iter()
            .find(|a| a.channel_ref == channel.0)
            .map(|a| {
                (
                    ApertureId(a.id.clone()),
                    PredicateExpr(a.pass_predicate.clone()),
                )
            })
            .ok_or(PskError::UntypedInput)
    }

    /// QPM Regel 3.3 (Scope ist explizit, nie universell): die vorhandenen, nicht deklarierten Kanaele mit
    /// ihrer Begruendung - keiner als Abwesenheit.
    pub fn undeclared_channels(&self) -> Vec<(ChannelId, String)> {
        self.undeclared.clone()
    }

    /// QPM Struktur 3.6 (CounterHorizon) aus dem Profil, auf den
    /// beobachteten Lauf gerichtet.
    pub fn counter_horizon(&self, run: &GoldenRunReport) -> CounterHorizon {
        CounterHorizon {
            schema: "psk.qpm.counter-horizon/1.0".to_string(),
            id: ObjectId::new(SortId::Residue, Digest::sha256(b"qpm-ch/golden-run")),
            subject_ref: crate::qpm_run::run_subject(run),
            null_models: vec![],
            rejected_readings: vec![],
            out_of_scope: vec![],
            pathologies: vec![],
            trace_ref: TraceRef(Digest::sha256(b"qpm-observation")),
            emptiness_justification: self.ch_justification.clone(),
        }
    }
}
