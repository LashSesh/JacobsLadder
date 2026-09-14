//! M24 AdversarialKernel (Kapitel 12), Paesse C7 und C8.
//!
//! Definition 12.1 (Adversarialer Kern): "C_adv = (Capsule, Split, Ratchet,
//! Support, Occlusion, ResidueFlow, Contraction, Recanon, Harden). M24
//! realisiert genau diese neun Operatoren und keine weiteren."
//!
//! Realisiert sind hier die Operatoren, deren tragende Module in I4
//! existieren: Capsule, Split, Ratchet, Support, Contraction. Occlusion
//! liegt bei M12 (`psk_witness::typed_absence`, Invariante 11.12 (Okklusionsdisziplin));
//! ResidueFlow und Recanon setzen den Residuenspeicher M19 voraus (WP04,
//! Phase I5); Harden laeuft ueber P36 und das Gate G-SELF-COMPILE
//! (Invariante 12.15 (Keine Selbstautorisierung)) und damit ueber M21 (WP15). Die vier bleiben
//! unimplementiert statt vorgetaeuscht - die Neunerliste ist damit nicht
//! erweitert, nur teilweise realisiert.

use std::collections::BTreeSet;

use crate::corpus::Requirement;
use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    CandidateCapsule, CandidateCapsulePhaseKind as Phase, CandidateCapsuleStatusKind as Status,
    CapsuleId, EvidenceObject, FieldProjection, InvariantId, ReplayDescriptor, ScopeExpr, SortId,
    SurfaceDescriptor,
};
use psk_types::{Digest, ObjectId, PskError, TraceRef};

const CAPSULE_SORT: SortId = SortId::Branch;

/// Ein im Lauf angebotener Kandidat: seine Kapsel-ID und das Artefakt, auf
/// das er sich bezieht. `capsulate` (Regel 7.29 (Eine Kapsel ist Funktion ihrer Klasse)) nimmt ihn nur in
/// `allowed_next` auf, wenn die Quellen DIESER Klasse eine Anforderung zu
/// genau diesem Artefakt tragen - sonst ist er fuer diese Klasse kein
/// Kandidat.
#[derive(Debug, Clone)]
pub struct OfferedCandidate {
    pub id: CapsuleId,
    pub artifact: String,
}

/// Eingaben fuer `capsulate`. `phase`, `status` und `id` fehlen: die Phase
/// beginnt bei SEALED, der Status bei OPEN, die ID folgt aus dem Inhalt.
pub struct CapsuleInputs {
    pub surface: SurfaceDescriptor,
    pub replay: ReplayDescriptor,
    pub boundary: ScopeExpr,
    pub trace_ref: TraceRef,
    pub coupling: Vec<ObjectId>,
    /// Das laufweite Angebot, falls der Lauf einen Aenderungsvorschlag
    /// fuehrt. `capsulate` entscheidet je Klasse, ob es hineinkommt -
    /// `None` heisst kein Angebot, nicht ein leeres.
    pub offered: Option<OfferedCandidate>,
}

fn compute_identity(draft: &CandidateCapsule) -> Result<ObjectId, PskError> {
    let mut value = serde_json::to_value(draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let projected = identity_projection(&bytes, Media::Json)?;
    object_id(CAPSULE_SORT.id(), &projected)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)
}

fn seal(draft: CandidateCapsule) -> Result<CandidateCapsule, PskError> {
    let id = compute_identity(&draft)?;
    Ok(CandidateCapsule { id, ..draft })
}

/// Operator 1, `capsulate(class: [FieldProjection]) -> CandidateCapsule`
/// (Schnittstelle 12.18 (M24-Ports)).
///
/// Die Eingabe ist EINE Quotientenklasse aus dem DependencyProfile
/// (Algorithmus 11.19 (Normativer Compilerlauf): `capsules = C7_adversarial_canonicalize(
/// profile.quotient_classes)`) - nicht eine beliebige Projektionsmenge.
/// `invariant_core` beginnt leer: Invarianten treten nur ueber `split` ein,
/// und nur mit unabhaengiger Evidenz (Regel 12.4 (Splitoperator)).
///
/// Regel 7.29 (Eine Kapsel ist Funktion ihrer Klasse): `allowed_next` wird HIER aus `class` gebildet,
/// nicht aus `inputs` durchgereicht. `class` traegt ueber
/// `source_provenance` seine eigenen Quellen; `inputs.offered` kommt nur
/// dann in `allowed_next`, wenn eine Anforderung EINER dieser Quellen sein
/// Artefakt nennt. Zwei Klassen mit verschiedenen Quellen KOENNEN deshalb
/// verschiedene `allowed_next` ergeben - siehe
/// `allowed_next_can_differ_when_class_sources_differ` fuer den Nachweis,
/// dass sie es nicht nur koennten, sondern es unter konstruierten
/// Eingaben tatsaechlich tun.
pub fn capsulate(
    class: &[FieldProjection],
    requirements: &[Requirement],
    inputs: CapsuleInputs,
) -> Result<CandidateCapsule, PskError> {
    let class_sources: BTreeSet<&str> = class
        .iter()
        .flat_map(|p| p.source_provenance.iter().map(|s| s.0.as_str()))
        .collect();
    let class_artifacts: BTreeSet<&str> = requirements
        .iter()
        .filter(|r| class_sources.contains(r.source.as_str()))
        .map(|r| r.artifact.as_str())
        .collect();
    let allowed_next = match &inputs.offered {
        Some(offer) if class_artifacts.contains(offer.artifact.as_str()) => vec![offer.id.clone()],
        _ => Vec::new(),
    };
    seal(CandidateCapsule {
        schema: "psk.candidate-capsule/1.0".to_string(),
        id: ObjectId::new(CAPSULE_SORT, Digest::sha256(b"")), // Platzhalter
        surface: inputs.surface,
        invariant_core: Vec::new(),
        phase: Phase::Sealed,
        witnesses: class.iter().map(|p| p.id).collect(),
        replay: inputs.replay,
        boundary: inputs.boundary,
        trace_ref: inputs.trace_ref,
        coupling: inputs.coupling,
        allowed_next,
        status: Status::Open,
    })
}

/// Ergebnis von `split` (Operator 2): die behauptete Rolle und der
/// geprueft e Kern, getrennt.
#[derive(Debug, Clone, PartialEq)]
pub struct SplitResult {
    pub surface: SurfaceDescriptor,
    pub invariant_core: Vec<InvariantId>,
    /// Die Invarianten, die NICHT eintreten durften, weil ihnen unabhaengige
    /// Evidenz fehlt. Sie verschwinden nicht still (Axiom 7.45 (No Silent Loss), No Silent Loss).
    pub rejected: Vec<InvariantId>,
}

/// Operator 2, Regel 12.4 (Splitoperator): "Split zerlegt jede Kapsel in
/// surface (behauptete Rolle) und invariant_core (geprueft e Invarianten).
/// Ein Element DARF nur dann in invariant_core eintreten, wenn mindestens
/// ein EvidenceObject mit independence_class != der Klasse des Erzeugers
/// vorliegt."
///
/// Axiom 12.3 (Oberflaeche erzeugt keine Invarianz): eine behauptete Rolle
/// traegt nie von sich aus in den Kern. Deshalb wird `claimed` gegen die
/// Evidenz geprueft und nicht uebernommen.
///
/// `has_independent_evidence` kommt als bereits ENTSCHIEDENER Wert herein,
/// nicht als roher `EvidenceObject`/`ClassId`-Import aus psk-witness: M10/
/// M12 haben diese Frage frueher in der Pipeline laengst beantwortet
/// (`psk_witness::has_independent_evidence`, dieselbe Funktion, jetzt beim
/// AUFRUFER statt hier). Split() ist damit eine reine Funktion ihrer
/// deklarierten Eingaben - dasselbe Muster wie ueberall sonst im Werk fuer
/// domaenengelieferte Werte -, kein Live-Aufruf in ein fremdes Crate
/// (T-PORT-001-Befund, behoben statt eines neuen Ports).
pub fn split(
    capsule: &CandidateCapsule,
    claimed: &[InvariantId],
    has_independent_evidence: bool,
) -> SplitResult {
    let mut invariant_core = Vec::new();
    let mut rejected = Vec::new();
    for inv in claimed {
        if has_independent_evidence {
            invariant_core.push(inv.clone());
        } else {
            rejected.push(inv.clone());
        }
    }
    SplitResult {
        surface: capsule.surface.clone(),
        invariant_core,
        rejected,
    }
}

/// Operator 3, Definition 12.5 (Ratchet-Schritt):
/// `S_{n+1} = AllowedNext(G_n, S_n)`, `S_{n+1} ⊆ S_n`.
///
/// Invariante 12.6 (Monotone Kontraktion): "allowed_next ist ueber die
/// Lebensdauer einer Kapsel monoton fallend. Eine Vergroesserung ist
/// ausschliesslich als neuer Branch mit neuer ObjectId und neuer Lineage
/// zulaessig."
///
/// Deshalb nimmt `ratchet` keine neue Menge entgegen, sondern die Menge der
/// durch das Gate ueberlebenden Kandidaten, und schneidet sie mit der
/// bisherigen. Eine Vergroesserung ist so nicht ausdrueckbar - nicht bloss
/// verboten.
pub fn ratchet(
    capsule: &CandidateCapsule,
    survivors: &[CapsuleId],
    rounds_used: u32,
    ratchet_max_rounds: u32,
) -> Result<CandidateCapsule, PskError> {
    let keep: Vec<CapsuleId> = capsule
        .allowed_next
        .iter()
        .filter(|c| survivors.contains(c))
        .cloned()
        .collect();

    // Regel 12.7 (Selektionsdruck): "Die Terminierung ist durch das Budget ratchet_max_rounds
    // im RunDescriptor erzwungen; bei Erschoepfung wird die Kapsel RESIDUAL."
    let phase = if rounds_used >= ratchet_max_rounds {
        Phase::Residual
    } else {
        Phase::Ratcheted
    };

    seal(CandidateCapsule {
        allowed_next: keep,
        phase,
        ..capsule.clone()
    })
}

/// Fail-closed-Wache zu Invariante 12.6 (Monotone Kontraktion), fuer den Fall, dass eine Kapsel
/// nicht ueber `ratchet` entstanden ist: die Nachfolgemenge DARF nie
/// wachsen.
pub fn check_monotone_contraction(
    before: &CandidateCapsule,
    after: &CandidateCapsule,
) -> Result<(), PskError> {
    let grew = after
        .allowed_next
        .iter()
        .any(|c| !before.allowed_next.contains(c));
    if grew {
        // Eine Vergroesserung ist nur als NEUER Branch zulaessig - und dann
        // traegt sie eine andere ObjectId, ist also keine Fortsetzung.
        Err(PskError::MorphogenesisViolation)
    } else {
        Ok(())
    }
}

/// Vertrag 12.10 (Branch statt Umschreibung): "Eine gescheiterte
/// Spezifikation [...] DARF NICHT nachtraeglich so umgeschrieben werden,
/// als sei sie immer korrekt gewesen. Eine Reparatur erzeugt eine neue
/// Branch, neue ID, neue Tracekette und neue Konformitaetspruefung."
///
/// Die Wache prueft genau das: eine Reparatur, die dieselbe ID oder
/// dieselbe Tracekette behaelt, ist eine Umschreibung.
pub fn check_repair_is_a_branch(
    original: &CandidateCapsule,
    repaired: &CandidateCapsule,
) -> Result<(), PskError> {
    if repaired.id == original.id || repaired.trace_ref == original.trace_ref {
        Err(PskError::SelfAmendmentWithoutIdentity)
    } else {
        Ok(())
    }
}

/// Die fuenf Pfade aus Definition 11.11 (Perkolationssupport):
/// "Support(e) = 1 genau dann, wenn Gate-, Witness-, Replay-, Ressourcen-
/// und Kopplungspfad innerhalb des geltenden Horizonts definiert sind."
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SupportPaths {
    pub gate: bool,
    pub witness: bool,
    pub replay: bool,
    pub resource: bool,
    pub coupling: bool,
}

/// Operator 4, Pass C8: `support(c, horizon) -> bool`.
/// Konjunktion aller fuenf - "genau dann, wenn".
pub fn support(paths: &SupportPaths) -> bool {
    paths.gate && paths.witness && paths.replay && paths.resource && paths.coupling
}

/// Pass C8 auf einer Kapsel: bei vollem Support geht sie nach SUPPORTED,
/// sonst nach RESIDUAL. Kein Zwischenweg - ein teilweise gestuetzter
/// Kandidat ist nicht gestuetzt.
pub fn check_support(
    capsule: &CandidateCapsule,
    paths: &SupportPaths,
) -> Result<CandidateCapsule, PskError> {
    seal(CandidateCapsule {
        phase: if support(paths) {
            Phase::Supported
        } else {
            Phase::Residual
        },
        ..capsule.clone()
    })
}

/// Invariante 12.17 (Nichttrivialitaet des Ueberlebens): "Ein Kandidat, der
/// nur unter Ausblendung eines Gegenmodells schliesst, ist nicht
/// adversarial geschlossen. Seine scheinbare Closure ist eine Projektion
/// mit verdeckter Obstruktion und erzeugt PSK-E003."
///
/// Definition 12.16 (Adversarial Closure): `A(M) = Close(M ∪ Countermodels(M) ∪ Stress(M))`. Die
/// Gegenmodelle sind Teil der Menge, ueber der geschlossen wird - nicht
/// etwas, das danach geprueft wird.
pub fn check_adversarial_closure(
    closes_without_countermodels: bool,
    closes_with_countermodels: bool,
) -> Result<(), PskError> {
    if closes_without_countermodels && !closes_with_countermodels {
        Err(PskError::SurfaceInvariantCollapse)
    } else {
        Ok(())
    }
}

/// Das Ergebnis von [`effective_rank_of`] - und der Grund, warum es kein
/// `usize` ist.
///
/// Regel 7.52 (Ein Bodenwert ist keine Messung): "Gibt eine Groesse bei
/// fehlender Eingabe einen Vorgabe- oder Bodenwert zurueck - etwa einen
/// Rang von eins ueber einer leeren Evidenzmenge -, so DARF NICHT dieser
/// Wert als Messergebnis gelesen oder berichtet werden. Er ist von einem
/// berechneten Wert aeusserlich nicht zu unterscheiden und deshalb
/// gefaehrlicher als ein leeres Feld: eine Null faellt auf, eine Eins
/// sieht aus wie ein Befund."
///
/// Genau das war hier der Fall: `classes.len().max(1)` gab ueber einer
/// leeren Evidenzmenge eine Eins zurueck, die von einer gerechneten Eins
/// (eine Quelle, Invariante 12.2 (Kein Selbstwitness)) nicht zu
/// unterscheiden war.
///
/// **Was die Regel verlangt und was hier gebaut ist:** "Jede solche
/// Groesse MUSS unterscheidbar machen, ob sie gemessen oder untergegangen
/// ist - durch einen EIGENEN AUSGANG, nicht durch einen Zahlenwert."
/// Deshalb ein Summentyp und keine Zahl.
///
/// Absichtlich NICHT vorhanden: `Default`, `From<EffectiveRank> for
/// usize`, ein `unwrap_or(1)` oder irgendeine Rechenoperation. Jedes
/// davon holte den Bodenwert durch die Hintertuer zurueck, und die
/// Regel waere wieder eine Zusage statt einer Form. Der Nachweis:
///
/// ```compile_fail,E0369
/// # use psk_adversarial::EffectiveRank;
/// let r = EffectiveRank::Unmeasured;
/// let _ = r + 1;
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EffectiveRank {
    /// Gemessen: die Evidenzmenge war nicht leer, und der Wert ist die
    /// Zahl der Unabhaengigkeitsklassen darin. Eine gemessene Eins ist
    /// der Fall von Invariante 12.2 (Kein Selbstwitness) - "erhaelt
    /// r_eff = 1" - und ein
    /// echter Befund.
    Measured(usize),
    /// Nicht gemessen: es lag keine Evidenz vor. KEIN Rang, auch nicht
    /// eins. "Die erste echte Eingabe hebt den Wert dann nicht bloss an;
    /// sie macht ihn erstmals zu einem Wert."
    Unmeasured,
}

impl EffectiveRank {
    /// Der Rang, WENN einer gemessen wurde. `None` heisst: es gab keinen
    /// - nicht "es gab einen niedrigen".
    pub fn measured(self) -> Option<usize> {
        match self {
            EffectiveRank::Measured(r) => Some(r),
            EffectiveRank::Unmeasured => None,
        }
    }

    pub fn is_measured(self) -> bool {
        matches!(self, EffectiveRank::Measured(_))
    }

    /// Die Kennzeichnung fuer einen Bericht.
    /// Regel 7.52 (Ein Bodenwert ist keine Messung): "Ein Bericht,
    /// der den Bodenwert neben gemessenen Werten fuehrt, ohne ihn zu
    /// kennzeichnen, behauptet eine Messung, die nicht stattfand."
    pub fn label(self) -> String {
        match self {
            EffectiveRank::Measured(r) => format!("{r} (gemessen)"),
            EffectiveRank::Unmeasured => "nicht gemessen (keine Evidenz)".to_string(),
        }
    }
}

/// Invariante 12.2 (Kein Selbstwitness): "Der Compiler DARF NICHT seine
/// eigenen Claims als unabhaengige Witnesses zaehlen. Eine Kapselbewertung,
/// deren einzige Evidenz aus derselben Modell- oder Ableitungsquelle
/// stammt, erhaelt r_eff = 1."
///
/// Die Invariante spricht ueber Kapselbewertungen MIT Evidenz. Ueber den
/// Fall ohne jede Evidenz sagt sie nichts - und die frueher hier
/// stehende `.max(1)` legte ihn still auf eins fest. Seit v1.0.45 ist er
/// ein eigener Ausgang (Regel 7.52 (Ein Bodenwert ist keine Messung));
/// siehe [`EffectiveRank`].
pub fn effective_rank_of(evidence: &[EvidenceObject]) -> EffectiveRank {
    if evidence.is_empty() {
        return EffectiveRank::Unmeasured;
    }
    let classes: std::collections::BTreeSet<&String> =
        evidence.iter().map(|e| &e.independence_class.0).collect();
    EffectiveRank::Measured(classes.len())
}

/// Operator 7, `contract(caps) -> [CandidateCapsule]`. Behaelt die Kapseln,
/// die noch eine Nachfolgemenge haben oder bereits kristallisiert sind;
/// alles andere ist ausgeratscht.
///
/// Regel 12.7 (Selektionsdruck): "Der adversariale Kern versucht nicht,
/// einen Kandidaten sprachlich zu retten. Er maximiert die Chance, ihn
/// unter den deklarierten Invarianten zu widerlegen. Nur replaystabile
/// Reststrukturen DARF kristallisieren."
pub fn contract(capsules: &[CandidateCapsule]) -> Vec<CandidateCapsule> {
    capsules
        .iter()
        .filter(|c| !c.allowed_next.is_empty() || c.phase == Phase::Crystallized)
        .cloned()
        .collect()
}

/// Definition 12.8 (Residuenfluss): `HOLD -> RESIDUE -> Quarantine ->
/// Recanonicalization`. "Kein Scheitern DARF durch stilles Loeschen aus der
/// Lernhistorie entfernt werden."
///
/// Die zulaessige Nachfolgephase im Residuenfluss. `None` heisst: von hier
/// fuehrt kein Residuenweg weiter (der Fluss ist am Ende oder die Phase
/// gehoert nicht dazu).
pub fn residue_flow_next(phase: Phase) -> Option<Phase> {
    match phase {
        Phase::Residual => Some(Phase::Quarantined),
        // Recanonicalization erzeugt eine NEUE Kapsel (Vertrag 12.10 (Branch statt Umschreibung):
        // neue Branch, neue ID) - kein Phasenuebergang derselben Kapsel.
        Phase::Quarantined => None,
        _ => None,
    }
}

/// Regel 12.11 (Zulaessige Selbstverhaertung): M24 DARF ausschliesslich
/// diese sechs Klassen veraendern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardeningClass {
    TestsAndFalsifiers,
    GateAndValidationPolicies,
    ReplayAndResiduePatterns,
    DependencyModels,
    SearchAndBranchStrategies,
    CalibrationProfilesWithinDeclaredBounds,
}

impl HardeningClass {
    pub const ALL: [HardeningClass; 6] = [
        HardeningClass::TestsAndFalsifiers,
        HardeningClass::GateAndValidationPolicies,
        HardeningClass::ReplayAndResiduePatterns,
        HardeningClass::DependencyModels,
        HardeningClass::SearchAndBranchStrategies,
        HardeningClass::CalibrationProfilesWithinDeclaredBounds,
    ];
}

/// Invariante 12.15 (Keine Selbstautorisierung): "Self-Hardening DARF NICHT
/// konstitutionelle Autoritaet, externe Faehigkeit oder Faktizitaet durch
/// Selbstdeklaration erzeugen. Jede Aenderung durchlaeuft P36 und das Gate
/// G-SELF-COMPILE."
///
/// Der Operator `harden` selbst gehoert zu M21/WP15; diese Wache haelt
/// schon jetzt fest, was er nie duerfen wird.
pub fn check_hardening_permitted(
    class: Option<HardeningClass>,
    g_self_compile_passed: bool,
) -> Result<HardeningClass, PskError> {
    let Some(class) = class else {
        // Ausserhalb der sechs Klassen: keine zulaessige Selbstverhaertung.
        return Err(PskError::SelfAmendmentWithoutIdentity);
    };
    if g_self_compile_passed {
        Ok(class)
    } else {
        Err(PskError::SelfAmendmentWithoutIdentity)
    }
}

/// Definition 22.2 (Kapselfixpunkt, v1.0.19). `before`/`after` sind eine
/// Kapsel unmittelbar vor und nach einem `ratchet`-Schritt (`after` MUSS
/// aus `ratchet(before, ...)` stammen; diese Funktion ruft `ratchet` nicht
/// selbst auf und berechnet nichts neu). Woertlich: "Eine Kapsel c steht im
/// Kapselfixpunkt, wenn ein weiterer ratchet-Schritt ihre Menge zulaessiger
/// Nachfolger nicht mehr verkleinert: allowed_next(ratchet(c)) =
/// allowed_next(c)."
///
/// "Erschoepft zuvor das Budget, so ist die Kapsel DARF NICHT als im
/// Fixpunkt stehend zu fuehren, sondern nach RESIDUAL zu routen" - `ratchet`
/// setzt `phase: Residual` bereits genau bei Budgeterschoepfung (Regel
/// 12.7); diese Wache liest das Signal, statt die Rundenzaehlung ein
/// zweites Mal zu fuehren, und schliesst Residual explizit aus, selbst
/// wenn `allowed_next` im selben Schritt zufaellig auch stabil geblieben
/// waere - beide Ausgaenge bleiben getrennt, wie die Definition verlangt.
pub fn is_capsule_fixpoint(before: &CandidateCapsule, after: &CandidateCapsule) -> bool {
    after.phase != Phase::Residual && after.allowed_next == before.allowed_next
}

/// Challenge-Abschlussbedingung (Definition 14.2 (Phasen-Modul-Bindung): "Alle Kapseln im
/// Kapselfixpunkt oder RESIDUAL") fuer eine einzelne Kapsel: ist sie nach
/// diesem `ratchet`-Schritt in einem der beiden zulaessigen Endzustaende?
pub fn is_capsule_resolved(before: &CandidateCapsule, after: &CandidateCapsule) -> bool {
    after.phase == Phase::Residual || is_capsule_fixpoint(before, after)
}

/// Invariante 7.24 (Keine vorzeitige Oeffnung) ueber `status`: eine Kapsel
/// DARF nicht als CLOSED gefuehrt werden, solange sie nicht kristallisiert
/// oder abschliessend residual/quarantaeniert ist.
pub fn check_closure_state(capsule: &CandidateCapsule) -> Result<(), PskError> {
    let may_close = matches!(
        capsule.phase,
        Phase::Crystallized | Phase::Residual | Phase::Quarantined
    );
    if capsule.status == Status::Closed && !may_close {
        Err(PskError::SurfaceInvariantCollapse)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        ClassId, EvidenceObjectStatusKind, EvidenceObjectTypeKind, IRNodeId, LensSpec, MethodRef,
        RealityStatus, ScopeSpec, SourceRef, TickId,
    };

    fn projection(id: &str) -> FieldProjection {
        FieldProjection {
            schema: "psk.field-projection/1.0".into(),
            id: ObjectId::new(SortId::Projection, Digest::sha256(id.as_bytes())),
            field_ref: ObjectId::new(SortId::FieldIdentity, Digest::sha256(b"f")),
            source_refs: vec![],
            lens_ref: LensSpec("lens/1".into()),
            scope: ScopeSpec("s".into()),
            visible: vec![IRNodeId("n1".into())],
            occluded: vec![],
            distinctions: vec![],
            source_provenance: vec![SourceRef("q1".into())],
            reality_view: RealityStatus::Unknown,
            tick: TickId("t".into()),
        }
    }

    fn projection_with_source(id: &str, source: &str) -> FieldProjection {
        FieldProjection {
            source_provenance: vec![SourceRef(source.into())],
            ..projection(id)
        }
    }

    fn requirement(id: &str, artifact: &str, source: &str) -> Requirement {
        Requirement {
            id: id.into(),
            severity: "MUST".into(),
            artifact: artifact.into(),
            precedence: 1,
            statement: "s".into(),
            source: source.into(),
        }
    }

    /// Direktes Struct-Literal statt eines Laufs durch `capsulate`: seit
    /// Regel 7.29 (Eine Kapsel ist Funktion ihrer Klasse) entscheidet `capsulate` SELBST, was in
    /// `allowed_next` kommt (siehe unten) - die Tests hier (Ratchet,
    /// Split, Support, Kontraktion, Fixpunkt) pruefen andere Operatoren
    /// und brauchen nur EINE Kapsel mit frei wählbarem `allowed_next`,
    /// keinen Beleg fuer capsulate's eigene Ableitung. Dieselbe
    /// Rechtfertigung wie bei den EvidenceObject-Fixtures oben: die reale
    /// Herkunft spielt fuer diese Tests keine Rolle.
    fn capsule(next: &[&str]) -> CandidateCapsule {
        CandidateCapsule {
            schema: "psk.candidate-capsule/1.0".to_string(),
            id: ObjectId::new(CAPSULE_SORT, Digest::sha256(b"test-capsule")),
            surface: SurfaceDescriptor("behauptete Rolle".into()),
            invariant_core: Vec::new(),
            phase: Phase::Sealed,
            witnesses: vec![projection("p1").id],
            replay: ReplayDescriptor("replay/1".into()),
            boundary: ScopeExpr("lokal".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
            coupling: vec![],
            allowed_next: next.iter().map(|c| CapsuleId((*c).into())).collect(),
            status: Status::Open,
        }
    }

    /// Direktes Struct-Literal statt `psk_witness::make_evidence`: die
    /// echte, kanonische Identitaet (die `make_evidence` berechnet) spielt
    /// fuer diese Tests keine Rolle - weder `split()` (nimmt seit dem
    /// T-PORT-001-Fix gar kein `EvidenceObject` mehr entgegen) noch
    /// `effective_rank_of` (liest nur `independence_class`) pruefen `id`/
    /// `hash`. Ein Platzhalterdigest genuegt, ohne die psk-witness-
    /// Abhaengigkeit fuer einen einzigen Testwert zu behalten.
    fn evidence(class: &str) -> EvidenceObject {
        EvidenceObject {
            schema: "psk.evidence/1.0".into(),
            id: ObjectId::new(SortId::Witness, Digest::sha256(class.as_bytes())),
            r#type: EvidenceObjectTypeKind::Measurement,
            scope: ScopeExpr("s".into()),
            input: vec![Digest::sha256(b"i")],
            output: Digest::sha256(b"o"),
            method: MethodRef("m".into()),
            trace_ref: TraceRef(Digest::sha256(b"t")),
            hash: Digest::sha256(class.as_bytes()),
            signature: None,
            status: EvidenceObjectStatusKind::Valid,
            independence_class: ClassId(class.into()),
        }
    }

    #[test]
    fn a_new_capsule_is_sealed_with_an_empty_core() {
        // Axiom 12.3 (Oberfläche erzeugt keine Invarianz): Oberflaeche erzeugt keine Invarianz.
        let c = capsule(&["c1", "c2"]);
        assert_eq!(c.phase, Phase::Sealed);
        assert_eq!(c.status, Status::Open);
        assert!(c.invariant_core.is_empty());
    }

    #[test]
    fn claimed_invariants_need_independent_evidence_to_enter_the_core() {
        // Regel 12.4. `has_independent_evidence` ist seit dem T-PORT-001-
        // Fix ein deklarierter Parameter (vom Aufrufer via
        // `psk_witness::has_independent_evidence` entschieden, siehe
        // split()s Modulkopf) - `false` entspricht Evidenz aus derselben
        // Klasse wie der Erzeuger, `true` einer unabhaengigen Klasse.
        let c = capsule(&["c1"]);
        let claimed = vec![InvariantId("I-ARCH-001".into())];

        let self_only = split(&c, &claimed, false);
        assert!(self_only.invariant_core.is_empty());
        assert_eq!(
            self_only.rejected, claimed,
            "Abgewiesenes verschwindet nicht"
        );

        let independent = split(&c, &claimed, true);
        assert_eq!(independent.invariant_core, claimed);
        assert!(independent.rejected.is_empty());
    }

    #[test]
    fn ratchet_can_only_shrink() {
        // Definition 12.5 (Ratchet-Schritt): S_{n+1} subseteq S_n.
        let c = capsule(&["c1", "c2", "c3"]);
        let after = ratchet(
            &c,
            &[
                CapsuleId("c1".into()),
                CapsuleId("c9".into()), // war nie drin
            ],
            1,
            10,
        )
        .unwrap();
        assert_eq!(after.allowed_next, vec![CapsuleId("c1".into())]);
        assert_eq!(after.phase, Phase::Ratcheted);
    }

    #[test]
    fn ratchet_is_monotone_over_repeated_rounds() {
        // Invariante 12.6.
        let mut c = capsule(&["c1", "c2", "c3"]);
        let mut sizes = vec![c.allowed_next.len()];
        for (round, survivors) in [vec!["c1", "c2"], vec!["c1"], vec![]].iter().enumerate() {
            let ids: Vec<CapsuleId> = survivors.iter().map(|s| CapsuleId((*s).into())).collect();
            let next = ratchet(&c, &ids, round as u32, 10).unwrap();
            assert_eq!(check_monotone_contraction(&c, &next), Ok(()));
            sizes.push(next.allowed_next.len());
            c = next;
        }
        assert_eq!(sizes, vec![3, 2, 1, 0]);
    }

    #[test]
    fn growing_the_successor_set_is_rejected() {
        let before = capsule(&["c1"]);
        let after = CandidateCapsule {
            allowed_next: vec![CapsuleId("c1".into()), CapsuleId("c2".into())],
            ..before.clone()
        };
        assert_eq!(
            check_monotone_contraction(&before, &after),
            Err(PskError::MorphogenesisViolation)
        );
    }

    #[test]
    fn exhausting_the_round_budget_makes_the_capsule_residual() {
        // Regel 12.7 (Selektionsdruck), letzter Satz.
        let c = capsule(&["c1"]);
        let after = ratchet(&c, &[CapsuleId("c1".into())], 10, 10).unwrap();
        assert_eq!(after.phase, Phase::Residual);
    }

    #[test]
    fn a_ratchet_step_that_does_not_shrink_the_successor_set_is_a_fixpoint() {
        // Definition 22.2 (Kapselfixpunkt): allowed_next(ratchet(c)) = allowed_next(c).
        let c = capsule(&["c1", "c2"]);
        let after = ratchet(&c, &[CapsuleId("c1".into()), CapsuleId("c2".into())], 1, 10).unwrap();
        assert_eq!(after.allowed_next, c.allowed_next);
        assert!(is_capsule_fixpoint(&c, &after));
        assert!(is_capsule_resolved(&c, &after));
    }

    #[test]
    fn a_ratchet_step_that_still_shrinks_the_successor_set_is_not_yet_a_fixpoint() {
        let c = capsule(&["c1", "c2", "c3"]);
        let after = ratchet(&c, &[CapsuleId("c1".into())], 1, 10).unwrap();
        assert_ne!(after.allowed_next, c.allowed_next);
        assert!(!is_capsule_fixpoint(&c, &after));
        assert!(!is_capsule_resolved(&c, &after));
    }

    #[test]
    fn budget_exhaustion_is_never_a_fixpoint_even_if_the_set_also_happened_to_stabilize() {
        // Definition 22.2 (Kapselfixpunkt), letzter Satz: beide Ausgaenge bleiben getrennt -
        // RESIDUAL gewinnt, selbst wenn allowed_next im selben Schritt
        // zufaellig unveraendert geblieben waere.
        let c = capsule(&["c1"]);
        let after = ratchet(&c, &[CapsuleId("c1".into())], 10, 10).unwrap();
        assert_eq!(after.allowed_next, c.allowed_next, "Vorbedingung des Tests");
        assert_eq!(after.phase, Phase::Residual);
        assert!(!is_capsule_fixpoint(&c, &after));
        // RESIDUAL ist trotzdem einer der beiden zulaessigen Challenge-Ausgaenge.
        assert!(is_capsule_resolved(&c, &after));
    }

    #[test]
    fn support_requires_all_five_paths() {
        // Definition 11.11 (Perkolationssupport): "genau dann, wenn".
        let full = SupportPaths {
            gate: true,
            witness: true,
            replay: true,
            resource: true,
            coupling: true,
        };
        assert!(support(&full));
        for drop in 0..5 {
            let mut p = full;
            match drop {
                0 => p.gate = false,
                1 => p.witness = false,
                2 => p.replay = false,
                3 => p.resource = false,
                _ => p.coupling = false,
            }
            assert!(!support(&p), "ein fehlender Pfad muss Support brechen");
        }
    }

    #[test]
    fn partial_support_makes_the_capsule_residual_not_supported() {
        let c = capsule(&["c1"]);
        let partial = SupportPaths {
            gate: true,
            witness: true,
            replay: true,
            resource: true,
            coupling: false,
        };
        assert_eq!(check_support(&c, &partial).unwrap().phase, Phase::Residual);
    }

    #[test]
    fn closing_only_by_hiding_a_countermodel_is_not_adversarial_closure() {
        // Invariante 12.17 (Nichttrivialität des Überlebens), PSK-E003.
        assert_eq!(
            check_adversarial_closure(true, false),
            Err(PskError::SurfaceInvariantCollapse)
        );
        assert_eq!(check_adversarial_closure(true, true), Ok(()));
    }

    #[test]
    fn evidence_from_one_source_yields_rank_one() {
        // Invariante 12.2 (Kein Selbstwitness): EINE Quelle, egal wie
        // oft, ergibt Rang eins -
        // und zwar einen GEMESSENEN.
        assert_eq!(
            effective_rank_of(&[evidence("qc-0")]),
            EffectiveRank::Measured(1)
        );
        assert_eq!(
            effective_rank_of(&[evidence("qc-0"), evidence("qc-0"), evidence("qc-0")]),
            EffectiveRank::Measured(1)
        );
        assert_eq!(
            effective_rank_of(&[evidence("qc-0"), evidence("qc-1")]),
            EffectiveRank::Measured(2)
        );
    }

    /// Regel 7.52 (Ein Bodenwert ist keine Messung), der Fall, der die
    /// Regel ausgeloest hat.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: eine leere Evidenzmenge
    /// ergibt KEINEN Rang - nicht eins. Und die gemessene Eins aus einer
    /// Quelle ist von ihr unterscheidbar, obwohl beide frueher `1`
    /// hiessen. Der zweite Teil traegt den Test: waeren sie gleich,
    /// haette der Umbau nur den Typ gewechselt und nichts getrennt.
    #[test]
    fn an_empty_evidence_set_yields_no_rank_not_a_floor_of_one() {
        let leer = effective_rank_of(&[]);
        assert_eq!(leer, EffectiveRank::Unmeasured);
        assert!(!leer.is_measured());
        assert_eq!(leer.measured(), None, "es gibt keinen Rang, auch keinen 1");

        let eine_quelle = effective_rank_of(&[evidence("qc-0")]);
        assert_ne!(
            leer, eine_quelle,
            "der Bodenwert und die gemessene Eins muessen unterscheidbar sein"
        );
        assert_eq!(eine_quelle.measured(), Some(1));

        // Und die Kennzeichnung im Bericht trennt sie ebenfalls -
        // "ein Bericht, der den Bodenwert neben gemessenen Werten
        // fuehrt, ohne ihn zu kennzeichnen, behauptet eine Messung, die
        // nicht stattfand".
        assert_eq!(leer.label(), "nicht gemessen (keine Evidenz)");
        assert_eq!(eine_quelle.label(), "1 (gemessen)");
    }

    #[test]
    fn repair_must_be_a_new_branch_not_a_rewrite() {
        // Vertrag 12.10.
        let original = capsule(&["c1"]);
        let rewritten = CandidateCapsule {
            surface: SurfaceDescriptor("umgeschrieben".into()),
            ..original.clone()
        };
        assert_eq!(
            check_repair_is_a_branch(&original, &rewritten),
            Err(PskError::SelfAmendmentWithoutIdentity)
        );

        let branched = seal(CandidateCapsule {
            surface: SurfaceDescriptor("neuer Branch".into()),
            trace_ref: TraceRef(Digest::sha256(b"neue-kette")),
            ..original.clone()
        })
        .unwrap();
        assert_eq!(check_repair_is_a_branch(&original, &branched), Ok(()));
    }

    #[test]
    fn contraction_drops_exhausted_capsules() {
        let alive = capsule(&["c1"]);
        let exhausted = capsule(&[]);
        let crystallized = CandidateCapsule {
            phase: Phase::Crystallized,
            ..capsule(&[])
        };
        let kept = contract(&[alive.clone(), exhausted, crystallized.clone()]);
        assert_eq!(kept.len(), 2);
        assert!(kept.iter().any(|c| c.id == alive.id));
        assert!(kept.iter().any(|c| c.phase == Phase::Crystallized));
    }

    #[test]
    fn residue_flow_follows_the_declared_order() {
        // Definition 12.8 (Residuenfluss): RESIDUE -> Quarantine.
        assert_eq!(residue_flow_next(Phase::Residual), Some(Phase::Quarantined));
        // Recanonicalization ist eine neue Kapsel, kein Phasenschritt.
        assert_eq!(residue_flow_next(Phase::Quarantined), None);
        assert_eq!(residue_flow_next(Phase::Sealed), None);
    }

    #[test]
    fn hardening_outside_the_six_classes_is_rejected() {
        // Regel 12.11 (Zulässige Selbstverhärtung) / Invariante 12.15.
        assert_eq!(HardeningClass::ALL.len(), 6);
        assert_eq!(
            check_hardening_permitted(None, true),
            Err(PskError::SelfAmendmentWithoutIdentity)
        );
        assert_eq!(
            check_hardening_permitted(Some(HardeningClass::DependencyModels), false),
            Err(PskError::SelfAmendmentWithoutIdentity),
            "ohne G-SELF-COMPILE DARF keine Selbstverhaertung wirksam werden"
        );
        assert_eq!(
            check_hardening_permitted(Some(HardeningClass::DependencyModels), true),
            Ok(HardeningClass::DependencyModels)
        );
    }

    #[test]
    fn a_sealed_capsule_may_not_be_closed() {
        // Invariante 7.24 (Keine vorzeitige Oeffnung).
        let premature = CandidateCapsule {
            status: Status::Closed,
            ..capsule(&["c1"])
        };
        assert_eq!(
            check_closure_state(&premature),
            Err(PskError::SurfaceInvariantCollapse)
        );

        let done = CandidateCapsule {
            phase: Phase::Crystallized,
            status: Status::Closed,
            ..capsule(&[])
        };
        assert_eq!(check_closure_state(&done), Ok(()));
    }

    fn base_inputs(offered: Option<OfferedCandidate>) -> CapsuleInputs {
        CapsuleInputs {
            surface: SurfaceDescriptor("behauptete Rolle".into()),
            replay: ReplayDescriptor("replay/1".into()),
            boundary: ScopeExpr("lokal".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
            coupling: vec![],
            offered,
        }
    }

    #[test]
    fn capsulation_is_deterministic() {
        let reqs = vec![requirement("R1", "artifact-a", "q1")];
        let offered = Some(OfferedCandidate {
            id: CapsuleId("c1".into()),
            artifact: "artifact-a".into(),
        });
        let a = capsulate(&[projection("p1")], &reqs, base_inputs(offered.clone())).unwrap();
        let b = capsulate(&[projection("p1")], &reqs, base_inputs(offered)).unwrap();
        assert_eq!(a.id, b.id);
    }

    /// Regel 7.29 (Eine Kapsel ist Funktion ihrer Klasse), der Nachweis, den die Regel verlangt:
    /// nicht dass zwei Klassen im Referenzlauf verschieden ausfallen -
    /// das ist danach eine Messung -, sondern dass verschiedene
    /// Klasseninhalte verschiedene Kapseln ergeben KOENNEN. Zwei Klassen
    /// mit verschiedenen Quellen, dasselbe Angebot: nur die Klasse, deren
    /// Quelle eine Anforderung zum angebotenen Artefakt traegt, nimmt es
    /// in `allowed_next` auf.
    #[test]
    fn allowed_next_can_differ_when_class_sources_differ() {
        let reqs = vec![requirement("R1", "artifact-a", "source-a")];
        let offered = Some(OfferedCandidate {
            id: CapsuleId("candidate-1".into()),
            artifact: "artifact-a".into(),
        });
        let class_a = [projection_with_source("p1", "source-a")];
        let class_b = [projection_with_source("p2", "source-b")];

        let capsule_a = capsulate(&class_a, &reqs, base_inputs(offered.clone())).unwrap();
        let capsule_b = capsulate(&class_b, &reqs, base_inputs(offered)).unwrap();

        assert_eq!(
            capsule_a.allowed_next,
            vec![CapsuleId("candidate-1".into())],
            "Klasse A traegt die Quelle des Angebots - es kommt in ihre Nachfolgemenge"
        );
        assert!(
            capsule_b.allowed_next.is_empty(),
            "Klasse B traegt sie nicht - das Angebot bleibt draussen, kein stiller Ersatz"
        );
        assert_ne!(
            capsule_a.id, capsule_b.id,
            "verschiedene allowed_next -> verschiedene Kapseln, nicht nur verschiedene witnesses"
        );
    }

    /// Die Kehrseite, ausdruecklich getestet: konvergieren zwei Klassen,
    /// weil BEIDE die Quelle tragen, ist das ein Messwert - konvergieren
    /// sie, weil `capsulate` die Klasse gar nicht liest, waere ein Defekt.
    /// Dieser Test unterscheidet die beiden Faelle: source_provenance mit
    /// ZWEI Quellen traegt beide Anforderungen, also kommt das Angebot
    /// bei beiden Klassen an, und das ist hier die geprueft e, gewollte
    /// Konvergenz.
    #[test]
    fn convergence_when_both_classes_share_the_offered_source_is_not_a_defect() {
        let reqs = vec![requirement("R1", "artifact-a", "source-a")];
        let offered = Some(OfferedCandidate {
            id: CapsuleId("candidate-1".into()),
            artifact: "artifact-a".into(),
        });
        let class_a = [projection_with_source("p1", "source-a")];
        let class_b = [projection_with_source("p2", "source-a")];

        let capsule_a = capsulate(&class_a, &reqs, base_inputs(offered.clone())).unwrap();
        let capsule_b = capsulate(&class_b, &reqs, base_inputs(offered)).unwrap();

        assert_eq!(capsule_a.allowed_next, capsule_b.allowed_next);
        assert_eq!(
            capsule_a.allowed_next,
            vec![CapsuleId("candidate-1".into())]
        );
    }
}
