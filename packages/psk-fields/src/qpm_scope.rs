//! QPM-0 und QPM-1, Objektseite: `PanopticScope` (QPM Struktur 3.2) und
//! `ApertureBank` (QPM Struktur 3.4). Beide Profile von S-FLD, Eigner
//! M08 - deshalb liegen sie hier in psk-fields.
//!
//! ## Die QPM-eigenen Feldtypen
//!
//! Die Strukturen nennen Typen, die PSK-RA nicht kennt
//! (`DomainContractRef`, `QuestionSpec`, `HorizonSpec`, `ChannelId`,
//! `BudgetSpec`, `CatalogRef`, `ApertureId`, `CoverageSpec`). Sie
//! stehen hier als Newtypes ueber String: das Werk NENNT sie, gibt
//! ihnen aber keine eigene Feldstruktur - genau wie PSK-RA es mit
//! `LensSpec` oder `ScopeExpr` haelt. Ein erfundener Innenaufbau waere
//! mehr, als das Werk sagt.
//!
//! `PredicateExpr` und `TimeWindow` kommen dagegen aus PSK-RA und
//! werden nicht neu erfunden - QPM benutzt sie ausdruecklich ("wie
//! LensSpec", "derselben Herkunftspflicht").

use psk_types::objects::{PredicateExpr, SemVer, TimeWindow};
use psk_types::{ObjectId, PskError, TraceRef};

macro_rules! qpm_newtype {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(pub String);
    };
}

qpm_newtype!(
    /// Bindet die Domaene (QPM Struktur 3.2: "ohne ihn kein Lauf").
    DomainContractRef
);
qpm_newtype!(
    /// Was beantwortet werden soll, deklariert.
    QuestionSpec
);
qpm_newtype!(
    /// Reichweitengrenze, explizit.
    HorizonSpec
);
qpm_newtype!(
    /// Ein instrumentierter Kanal.
    ChannelId
);
qpm_newtype!(
    /// Mess- und Zeitbudget.
    BudgetSpec
);
qpm_newtype!(
    /// Versionierter Katalog. Fehlt er, endet jeder Lauf UNKNOWN.
    CatalogRef
);
qpm_newtype!(
    /// Kennung einer einzelnen Apertur der Bank.
    ApertureId
);
qpm_newtype!(
    /// Was eine Apertur ueberhaupt erreichen kann.
    CoverageSpec
);

/// QPM Struktur 3.2, `policies`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopePolicies {
    /// UNKNOWN zulaessig? Sonst Q-OPENSET FAIL.
    pub open_set: bool,
    pub calibration_validity: TimeWindow,
    /// QPM-OBL-002: versioniert; fehlend => jeder Lauf UNKNOWN.
    pub catalog_ref: Option<CatalogRef>,
}

/// QPM Struktur 3.2 (PanopticScope), feldgetreu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PanopticScope {
    pub schema: String,
    pub id: ObjectId,
    pub domain_contract: DomainContractRef,
    pub questions: Vec<QuestionSpec>,
    pub horizon: HorizonSpec,
    pub declared_channels: Vec<ChannelId>,
    pub budget: BudgetSpec,
    pub policies: ScopePolicies,
    pub trace_ref: TraceRef,
}

/// Wie ein im Zustandsraum vorhandener Kanal zu behandeln ist, der im
/// Scope NICHT deklariert wurde (QPM Regel 3.3).
///
/// Der Wert `Absent` fehlt hier mit Absicht: "niemals als Abwesenheit"
/// steht woertlich in der Regel, und ein Aufzaehlungswert, den es nicht
/// gibt, ist die einzige Bauform, die das durchsetzt statt es zu
/// dokumentieren.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UndeclaredChannel {
    /// Ausserhalb des erklaerten Umfangs - eine Aussage, kein Fehlen.
    OutOfScope(ChannelId),
    /// Blockierendes Residuum: der Kanal gehoerte in den Scope.
    BlockingResidue(ChannelId),
}

/// Was ein Lauf unter diesem Scope hoechstens erreichen kann.
///
/// QPM Regel 3.3 letzter Satz: "Fehlt catalog_ref, so endet jeder Lauf
/// in UNKNOWN, nicht in FAIL (QPM-OBL-002)." Das ist genau das Muster
/// aus Vertrag 27.2 Pflicht 3: ein fehlendes Plugin erzeugt UNKNOWN,
/// und ein Vorgabezweig auf einen positiven Status waere der
/// Konformitaetsdefekt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeCeiling {
    /// catalog_ref vorhanden: die Ergebnisordnung ist offen.
    Unconstrained,
    /// catalog_ref fehlt: jeder Lauf endet UNKNOWN - kein FAIL.
    ForcedUnknown,
}

impl PanopticScope {
    /// QPM Regel 3.3: der Deckel des Laufs, ABGELEITET aus dem Objekt,
    /// nicht danebengestellt.
    pub fn ceiling(&self) -> ScopeCeiling {
        match self.policies.catalog_ref {
            Some(_) => ScopeCeiling::Unconstrained,
            None => ScopeCeiling::ForcedUnknown,
        }
    }

    /// QPM Regel 3.3: ein vorhandener, nicht deklarierter Kanal.
    ///
    /// Welche der beiden zulaessigen Antworten gilt, entscheidet der
    /// Aufrufer ueber `belongs_in_scope` - der Kern kann nicht wissen,
    /// ob ein Kanal in den erklaerten Umfang gehoert haette. Was er
    /// erzwingt: dass die dritte Antwort ("abwesend") nicht existiert.
    pub fn classify_channel(
        &self,
        present: &ChannelId,
        belongs_in_scope: bool,
    ) -> Option<UndeclaredChannel> {
        if self.declared_channels.contains(present) {
            return None;
        }
        Some(if belongs_in_scope {
            UndeclaredChannel::BlockingResidue(present.clone())
        } else {
            UndeclaredChannel::OutOfScope(present.clone())
        })
    }

    /// QPM Regel 3.3 Satz 1: "declared_channels MUSS vollstaendig sein."
    /// Vollstaendig heisst: gegen die im Zustandsraum vorhandenen
    /// Kanaele geprueft - und jeder Rest benannt, nicht gezaehlt.
    pub fn undeclared_among(&self, present: &[ChannelId]) -> Vec<ChannelId> {
        present
            .iter()
            .filter(|c| !self.declared_channels.contains(c))
            .cloned()
            .collect()
    }
}

/// Eine einzelne Apertur der Bank (QPM Struktur 3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Aperture {
    pub id: ApertureId,
    pub channel_ref: ChannelId,
    /// Domaenengeliefert wie LensSpec, mit derselben Herkunftspflicht.
    pub pass_predicate: PredicateExpr,
    pub declared_coverage: CoverageSpec,
}

/// QPM Struktur 3.4 (ApertureBank), feldgetreu. "versioniert; Wechsel
/// ist ein Branch".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApertureBank {
    pub schema: String,
    pub id: ObjectId,
    pub version: SemVer,
    pub apertures: Vec<Aperture>,
    pub trace_ref: TraceRef,
}

impl ApertureBank {
    /// QPM Regel 3.5 letzter Satz: "ein stets wahres Praedikat ist
    /// Konformitaetsdefekt - eine Apertur, die alles durchlaesst, ist
    /// keine."
    ///
    /// Dieselbe Wache wie `EdgeConditionDeclarations::is_trivially_true`
    /// beim Kantenbau, und aus demselben Grund: ein immer wahres
    /// Praedikat sieht wie eine Pruefung aus und ist keine.
    pub fn check_predicates(&self) -> Result<(), PskError> {
        for a in &self.apertures {
            if is_trivially_true(&a.pass_predicate) {
                return Err(PskError::FieldProjectionUndefined);
            }
        }
        Ok(())
    }

    pub fn aperture(&self, id: &ApertureId) -> Option<&Aperture> {
        self.apertures.iter().find(|a| a.id == *id)
    }
}

/// Ein Praedikat, das nichts aussondert. Dieselbe Liste wie in psk-ir -
/// bewusst eng: nur was ohne Auslegung immer wahr ist.
fn is_trivially_true(p: &PredicateExpr) -> bool {
    let t = p.0.trim().to_ascii_lowercase();
    matches!(t.as_str(), "" | "true" | "wahr" | "1" | "always" | "immer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::Digest;

    fn scope(catalog: Option<&str>, channels: &[&str]) -> PanopticScope {
        PanopticScope {
            schema: "psk.qpm.scope/1.0".to_string(),
            id: ObjectId::new(
                psk_types::objects::SortId::FieldIdentity,
                Digest::sha256(b"scope"),
            ),
            domain_contract: DomainContractRef("jacobs-ladder-reference".into()),
            questions: vec![QuestionSpec("welche Kapsel ueberlebt?".into())],
            horizon: HorizonSpec("m13:0".into()),
            declared_channels: channels.iter().map(|c| ChannelId(c.to_string())).collect(),
            budget: BudgetSpec("one-run".into()),
            policies: ScopePolicies {
                open_set: true,
                calibration_validity: TimeWindow("golden-run-window".into()),
                catalog_ref: catalog.map(|c| CatalogRef(c.to_string())),
            },
            trace_ref: TraceRef(Digest::sha256(b"t")),
        }
    }

    #[test]
    fn a_missing_catalog_forces_unknown_and_never_fail() {
        // QPM-OBL-002 im Objekt verankert: der Deckel wird ABGELEITET.
        assert_eq!(scope(None, &["a"]).ceiling(), ScopeCeiling::ForcedUnknown);
        assert_eq!(
            scope(Some("cat/1.0"), &["a"]).ceiling(),
            ScopeCeiling::Unconstrained
        );
    }

    #[test]
    fn an_undeclared_channel_is_never_absence() {
        let s = scope(Some("cat/1.0"), &["topology", "spectrum"]);
        // Deklariert: keine Sonderbehandlung.
        assert_eq!(
            s.classify_channel(&ChannelId("topology".into()), false),
            None
        );
        // Nicht deklariert, gehoert nicht hinein: OUT_OF_SCOPE.
        assert_eq!(
            s.classify_channel(&ChannelId("phase".into()), false),
            Some(UndeclaredChannel::OutOfScope(ChannelId("phase".into())))
        );
        // Nicht deklariert, haette hineingehoert: blockierendes Residuum.
        assert_eq!(
            s.classify_channel(&ChannelId("phase".into()), true),
            Some(UndeclaredChannel::BlockingResidue(ChannelId(
                "phase".into()
            )))
        );
        // Und die Vollstaendigkeitspruefung benennt die Reste.
        let present = [
            ChannelId("topology".into()),
            ChannelId("phase".into()),
            ChannelId("seam".into()),
        ];
        assert_eq!(
            s.undeclared_among(&present),
            vec![ChannelId("phase".into()), ChannelId("seam".into())]
        );
    }

    fn bank(predicates: &[&str]) -> ApertureBank {
        ApertureBank {
            schema: "psk.qpm.aperture-bank/1.0".to_string(),
            id: ObjectId::new(
                psk_types::objects::SortId::FieldIdentity,
                Digest::sha256(b"bank"),
            ),
            version: SemVer("1.0.0".into()),
            apertures: predicates
                .iter()
                .enumerate()
                .map(|(i, p)| Aperture {
                    id: ApertureId(format!("AP{i}")),
                    channel_ref: ChannelId("topology".into()),
                    pass_predicate: PredicateExpr(p.to_string()),
                    declared_coverage: CoverageSpec("m13:0".into()),
                })
                .collect(),
            trace_ref: TraceRef(Digest::sha256(b"t")),
        }
    }

    #[test]
    fn an_aperture_that_passes_everything_is_not_one() {
        bank(&["knoten traegt eine m13-adresse"])
            .check_predicates()
            .expect("ein aussonderndes Praedikat ist zulaessig");
        for trivial in ["true", "wahr", "1", "immer", "  ", ""] {
            bank(&[trivial])
                .check_predicates()
                .expect_err("stets wahres Praedikat ist Konformitaetsdefekt");
        }
    }

    #[test]
    fn the_bank_resolves_its_apertures_by_id() {
        let b = bank(&["p0", "p1"]);
        assert_eq!(
            b.aperture(&ApertureId("AP1".into()))
                .map(|a| &a.pass_predicate),
            Some(&PredicateExpr("p1".into()))
        );
        assert!(b.aperture(&ApertureId("AP9".into())).is_none());
    }
}
