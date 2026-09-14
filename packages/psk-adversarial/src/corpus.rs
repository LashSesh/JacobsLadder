//! Widerspruchsidentifikation und Integrator (M24, Challenge-Phase).
//!
//! Die Rollen aus der Feldfamilienregel haben hier ihr Verhalten: der
//! **Falsifikator** ("sucht Gegenbelege") erzeugt die Gegenmodelle, die
//! die Instruktionsmenge als Vorbedingung der CHALLENGE-Instruktion
//! fuehrt; der **Integrator** ("verklebt oder erzeugt eine Obstruktion")
//! erzeugt aus einem nicht aufloesbaren Widerspruch einen echten
//! ObstructionRecord.
//!
//! Bis zur Taktumverdrahtung (Regel 24.4 (Der Golden Run laeuft unter
//! tick)) lag diese Logik im Konformanzpaket. Sie gehoert hierher, weil
//! die Challenge-Phase sie als Arbeit abwickelt und Definition 14.2 (Phasen-Modul-Bindung)
//! der Challenge-Phase genau M24 zuordnet - der
//! Konformanzlauf DEPONIERT die Anforderungen als Werte im Laufzustand,
//! er identifiziert nicht mehr selbst. Das LESEN des Korpus (Dateipfade,
//! Zeilenform) bleibt Domaenensache und damit im Konformanzpaket.
//!
//! ## Zwei Widerspruchsarten, und warum beide da sein muessen
//!
//! Ein Widerspruch, den eine deklarierte Praezedenz aufloest, und einer,
//! der ohne Aussenrecord offen bleibt. Ein Korpus mit nur einer Art waere
//! das kuenstliche - deshalb traegt `requirements.yaml` beide, und
//! zusaetzlich eine widerspruchsfreie Kontrollmenge, ohne die eine Suche,
//! die ALLES als widerspruechlich meldet, unbemerkt bestuende.
//!
//! ## Nullbefund ueber nichtleerer Arbeitsliste ist Fehlschlag
//!
//! Jede Transformation hier prueft ihre eigene Wirkung: findet sie ueber
//! einem nichtleeren Korpus nichts, gibt sie einen Fehler zurueck und
//! keinen leeren Erfolg. Das ist die verallgemeinerte Lehre aus einer
//! ganzen Reihe von Befunden dieses Projekts - ein deklarierter, nie
//! geschriebener Zaehler; ein gebauter, nie aufgerufener Waechter; ein
//! Ratchet ohne Gegenmodelle; eine Zitatmigration, die "0 ersetzt"
//! meldete. Jedes Mal meldete etwas Erfolg, waehrend es nichts tat.

use std::collections::{BTreeMap, BTreeSet};

use psk_types::objects::{
    CapsuleId, M13Address, ObligationExpr, ObstructionRecord, ObstructionRecordKindKind,
    ObstructionRecordSeverityKind, RecoveryPathId, SortId,
};
use psk_types::{Digest, ObjectId, PskError};

/// Eine Anforderung des Korpus, in der Form von
/// `constitution/requirement_matrix.yaml` plus `precedence`.
///
/// `Serialize`: Anforderungen werden als Werte im Laufzustand Sigma
/// deponiert (Definition 13.1 (Laufzustand)) und gehen damit in I_t ein.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Requirement {
    pub id: String,
    pub severity: String,
    pub artifact: String,
    pub precedence: u32,
    pub statement: String,
    /// Aus WELCHEM Quelldokument diese Anforderung stammt.
    ///
    /// Seit v1.0.45 traegt jede Anforderung ihre Herkunft, weil
    /// Regel 32.6 (Referenzauftrag) "gemeinsame Quellen quotientieren"
    /// verlangt - und ein Quotient ueber einer einzigen Quelle nichts
    /// tut. Ohne dieses Feld waere jede Rangfolge quellenblind, und
    /// genau daraus entstuende die Ordnung, die es nicht gibt.
    pub source: String,
}

/// Warum zwei Anforderungen einander widersprechen und ob die erklaerte
/// Rangfolge das entscheidet.
///
/// ## Drei Faelle, und warum der dritte seit v1.0.45 noetig ist
///
/// Praezedenz ist QUELLENRELATIV. Innerhalb eines Dokuments ist sie die
/// erklaerte Rangfolge seines Verfassers und entscheidet. Zwischen
/// unabhaengigen Dokumenten entscheidet sie nichts: `precedence: 5` in
/// einer Betriebsaufzeichnung und `precedence: 2` in einer Spezifikation
/// sind zwei Zahlen aus zwei Federn, und sie zu vergleichen erfaende
/// eine Ordnung ueber Dingen, die keine gemeinsame haben.
///
/// Das ist derselbe Fehler wie korrelierte Sichten als unabhaengig zu
/// zaehlen (Invariante 12.2 (Kein Selbstwitness)), nur eine Ebene
/// hoeher - dort wird Unabhaengigkeit erfunden, hier eine Rangfolge.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum Geltung {
    /// Dieselbe Quelle, verschiedener Rang: die Praezedenz entscheidet,
    /// genau eine der beiden gilt.
    ResolvedByPrecedence { winner: String, loser: String },
    /// Dieselbe Quelle, gleicher Rang - die Rangfolge entscheidet
    /// nichts. Die Geltung ist ohne eine Beobachtung von aussen nicht
    /// bestimmbar.
    UnresolvableWithoutExternalRecord { left: String, right: String },
    /// VERSCHIEDENE Quellen: die Praezedenzen sind nicht vergleichbar,
    /// unabhaengig davon, wie die Zahlen stehen. Der Befund nennt beide
    /// Quellen, weil "unaufloesbar" ohne sie nicht sagte, warum.
    UnresolvableAcrossSources {
        left: String,
        left_source: String,
        right: String,
        right_source: String,
    },
}

/// Ein identifizierter Widerspruch samt bestimmter (oder eben nicht
/// bestimmbarer) Geltung.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Contradiction {
    pub artifact: String,
    pub geltung: Geltung,
}

impl Contradiction {
    pub fn is_open(&self) -> bool {
        matches!(
            self.geltung,
            Geltung::UnresolvableWithoutExternalRecord { .. }
                | Geltung::UnresolvableAcrossSources { .. }
        )
    }

    /// Ob dieser Widerspruch ueber Quellgrenzen laeuft - die Klasse, die
    /// es vor v1.0.45 nicht gab, weil es nur eine Quelle gab.
    pub fn crosses_sources(&self) -> bool {
        matches!(self.geltung, Geltung::UnresolvableAcrossSources { .. })
    }
}

/// Schritt 2 und 3 des Referenzauftrags: widerspruechliche Anforderungen
/// identifizieren und ihre jeweilige Geltung bestimmen.
///
/// Widerspruch heisst hier: zwei MUST-Anforderungen ueber DASSELBE
/// Artefakt, deren Aussagen einander ausschliessen. Der Kern erfindet
/// dafuer keine Semantik - er vergleicht, was das Korpus selbst als
/// Artefakt und Rang deklariert.
pub fn identify_contradictions(reqs: &[Requirement]) -> Result<Vec<Contradiction>, PskError> {
    let mut by_artifact: BTreeMap<&str, Vec<&Requirement>> = BTreeMap::new();
    for r in reqs.iter().filter(|r| r.severity == "MUST") {
        by_artifact.entry(r.artifact.as_str()).or_default().push(r);
    }

    let mut out = Vec::new();
    for (artifact, group) in &by_artifact {
        for (i, a) in group.iter().enumerate() {
            for b in group.iter().skip(i + 1) {
                if !statements_conflict(&a.statement, &b.statement) {
                    continue;
                }
                // Zuerst die Quellenfrage, DANN die Rangfrage. Die
                // Reihenfolge ist die Aussage: ueber Quellgrenzen wird
                // der Rang gar nicht erst angesehen, weil er dort keine
                // Bedeutung hat.
                let geltung = if a.source != b.source {
                    Geltung::UnresolvableAcrossSources {
                        left: a.id.clone(),
                        left_source: a.source.clone(),
                        right: b.id.clone(),
                        right_source: b.source.clone(),
                    }
                } else if a.precedence == b.precedence {
                    Geltung::UnresolvableWithoutExternalRecord {
                        left: a.id.clone(),
                        right: b.id.clone(),
                    }
                } else {
                    let (w, l) = if a.precedence > b.precedence {
                        (a, b)
                    } else {
                        (b, a)
                    };
                    Geltung::ResolvedByPrecedence {
                        winner: w.id.clone(),
                        loser: l.id.clone(),
                    }
                };
                out.push(Contradiction {
                    artifact: (*artifact).to_string(),
                    geltung,
                });
            }
        }
    }

    // Nullbefund ueber nichtleerem Korpus ist Fehlschlag, nicht Erfolg.
    if !reqs.is_empty() && out.is_empty() {
        return Err(PskError::SurfaceInvariantCollapse);
    }
    Ok(out)
}

/// Ob zwei Aussagen ueber dasselbe Artefakt einander ausschliessen.
///
/// Bewusst eng und wortgebunden statt "klug": zwei Aussagen, die denselben
/// Gegenstand auf verschiedene Werte festlegen ("enthaelt genau X" gegen
/// "enthaelt genau Y"), oder eine Beschraenkung gegen eine Ausweitung
/// ("DARF ausschliesslich innerhalb" gegen "MUSS ... ausserhalb ...
/// spiegeln"). Was diese Form nicht faengt, faengt sie nicht - ein
/// Sprachverstehen waere hier eine Behauptung, keine Pruefung.
fn statements_conflict(a: &str, b: &str) -> bool {
    let exact = |s: &str| s.find("enthaelt genau ").map(|i| s[i + 15..].to_string());
    if let (Some(x), Some(y)) = (exact(a), exact(b)) {
        return x != y;
    }
    let restricts = |s: &str| s.contains("ausschliesslich innerhalb");
    let extends = |s: &str| s.contains("ausserhalb") && s.contains("MUSS");
    (restricts(a) && extends(b)) || (restricts(b) && extends(a))
}

/// Beschraenkt Widersprueche auf eine Quotientenklasse (Regel 7.29 (Eine Kapsel ist Funktion ihrer Klasse)):
/// ein Widerspruch gehoert zu einer Klasse, wenn WENIGSTENS eine seiner
/// beiden Seiten aus einer Quelle stammt, die diese Klasse traegt - die
/// Klasse hat dann eigene Evidenz, gegen die der Widerspruch spricht. Eine
/// Seite ganz ausserhalb bindet die Klasse nicht dazu, die andere zu
/// ignorieren: sie ist Gegenstand des Widerspruchs, nicht Aussenstehende.
///
/// `UnresolvableWithoutExternalRecord` fuehrt nur Anforderungs-IDs, keine
/// Quelle - beide Seiten teilen ohnehin dieselbe (so entsteht diese
/// Geltungsart in `identify_contradictions`); die Quelle kommt ueber die
/// ID aus `requirements` zurueck.
pub fn contradictions_of_class(
    contradictions: &[Contradiction],
    requirements: &[Requirement],
    class_sources: &BTreeSet<String>,
) -> Vec<Contradiction> {
    let source_of: BTreeMap<&str, &str> = requirements
        .iter()
        .map(|r| (r.id.as_str(), r.source.as_str()))
        .collect();
    contradictions
        .iter()
        .filter(|c| match &c.geltung {
            Geltung::UnresolvableAcrossSources {
                left_source,
                right_source,
                ..
            } => {
                class_sources.contains(left_source.as_str())
                    || class_sources.contains(right_source.as_str())
            }
            Geltung::UnresolvableWithoutExternalRecord { left, right } => source_of
                .get(left.as_str())
                .or_else(|| source_of.get(right.as_str()))
                .is_some_and(|s| class_sources.contains(*s)),
            Geltung::ResolvedByPrecedence { .. } => false,
        })
        .cloned()
        .collect()
}

/// Der **Falsifikator** ("sucht Gegenbelege"): jeder Widerspruch, den die
/// Praezedenz NICHT aufloest, ist ein Gegenbeleg gegen den
/// Aenderungsvorschlag - er zeigt eine Lesart, unter der der Vorschlag
/// nicht gilt.
///
/// Die Instruktionsmenge fuehrt Gegenmodelle als Vorbedingung der
/// CHALLENGE-Instruktion. Bis zum Korpusbau gab es dafuer keinen
/// Erzeuger, und genau deshalb fixierte das Ratchet in Runde 1: es hatte
/// nichts zu verkleinern.
pub fn falsifier_countermodels(contradictions: &[Contradiction]) -> Vec<CapsuleId> {
    contradictions
        .iter()
        .filter(|c| c.is_open())
        .map(|c| match &c.geltung {
            Geltung::UnresolvableWithoutExternalRecord { left, right } => {
                CapsuleId(format!("countermodel:{}:{}~{}", c.artifact, left, right))
            }
            // Quellenuebergreifend: dasselbe Gegenmodell, aber die
            // Kennung nennt die QUELLEN mit. Wer es liest, sieht nicht
            // nur, DASS zwei Anforderungen streiten, sondern dass sie
            // aus verschiedenen Federn stammen - und damit, warum keine
            // Rangfolge hilft.
            Geltung::UnresolvableAcrossSources {
                left,
                left_source,
                right,
                right_source,
            } => CapsuleId(format!(
                "countermodel:{}:{}@{}~{}@{}",
                c.artifact, left, left_source, right, right_source
            )),
            Geltung::ResolvedByPrecedence { .. } => unreachable!("nach is_open gefiltert"),
        })
        .collect()
}

/// Ob ein Gegenmodell diesen Nachfolgekandidaten widerlegt. Der
/// Falsifikator benennt in jedem Gegenmodell das Artefakt, ueber dem der
/// Widerspruch steht; ein Kandidat, der genau dieses Artefakt aendern
/// will, faellt darunter. `patch_artifact` ist das Artefakt des
/// Aenderungsvorschlags des Laufs (beim Referenzlauf: der Scope des
/// deponierten Patchplans) - frueher stand hier eine Konstante des
/// Konformanzpakets; als Parameter benennt der Aufrufer den realen
/// Laufwert.
pub fn refutes(countermodel: &CapsuleId, candidate: &CapsuleId, patch_artifact: &str) -> bool {
    countermodel
        .0
        .strip_prefix("countermodel:")
        .and_then(|rest| rest.split(':').next())
        .map(|artifact| {
            candidate.0.contains(artifact)
                || (!patch_artifact.is_empty() && artifact == patch_artifact)
        })
        .unwrap_or(false)
}

/// Der **Integrator** ("verklebt oder erzeugt eine Obstruktion"): fuer
/// einen Widerspruch, den die Rangfolge nicht entscheidet, entsteht ein
/// ObstructionRecord der Art `order` - die Art, die das Objektschema fuer
/// einen Ordnungs-/Praezedenzkonflikt fuehrt - mit `severity: blocking`,
/// weil er ohne Aussenrecord nicht aufloesbar ist. Ein durch die
/// Praezedenz aufloesbarer Widerspruch erzeugt KEINE Obstruktion: er ist
/// entschieden.
pub fn integrator_obstruction(
    contradiction: &Contradiction,
    residue_ref: ObjectId,
    located_at: M13Address,
) -> Result<ObstructionRecord, PskError> {
    // Beide unaufloesbaren Arten erzeugen eine Obstruktion; der
    // Erholungspfad benennt, WORAN sie haengt. Bei der
    // quellenuebergreifenden ist das nicht "gleiche Praezedenz", sondern
    // "verschiedene Quellen" - ein Aussenrecord bleibt in beiden Faellen
    // der Weg, aber der Grund ist ein anderer, und ein gemeinsamer Text
    // verlöre ihn.
    let recovery = match &contradiction.geltung {
        Geltung::UnresolvableWithoutExternalRecord { left, right } => {
            format!("aussenrecord-einholen:{left}~{right}")
        }
        Geltung::UnresolvableAcrossSources {
            left,
            left_source,
            right,
            right_source,
        } => format!(
            "aussenrecord-einholen-quellenuebergreifend:{left}@{left_source}~{right}@{right_source}"
        ),
        Geltung::ResolvedByPrecedence { .. } => {
            return Err(PskError::SurfaceInvariantCollapse);
        }
    };
    let draft = ObstructionRecord {
        id: ObjectId::new(SortId::Residue, Digest::sha256(b"")), // Platzhalter
        kind: ObstructionRecordKindKind::Order,
        located_at: vec![located_at],
        involved: vec![],
        severity: ObstructionRecordSeverityKind::Blocking,
        residue_ref,
        allowed_recovery: vec![RecoveryPathId(recovery)],
    };
    let mut value = serde_json::to_value(&draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let canonical = psk_canon::identity_projection(&bytes, psk_canon::Media::Json)?;
    let id: ObjectId = psk_canon::object_id(SortId::Residue.id(), &canonical)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(ObstructionRecord { id, ..draft })
}

/// Die offene Obligation, die ein nicht aufloesbarer Widerspruch traegt.
pub fn open_obligation_for(contradiction: &Contradiction) -> ObligationExpr {
    match &contradiction.geltung {
        Geltung::UnresolvableWithoutExternalRecord { left, right } => ObligationExpr(format!(
            "Geltung zwischen {left} und {right} ueber {} ist ohne Aussenrecord nicht bestimmbar \
             (gleiche Praezedenz)",
            contradiction.artifact
        )),
        Geltung::UnresolvableAcrossSources {
            left,
            left_source,
            right,
            right_source,
        } => ObligationExpr(format!(
            "Geltung zwischen {left} ({left_source}) und {right} ({right_source}) ueber {} ist \
             ohne Aussenrecord nicht bestimmbar (verschiedene Quellen - die Praezedenzen sind \
             nicht vergleichbar, unabhaengig von ihren Zahlen)",
            contradiction.artifact
        )),
        Geltung::ResolvedByPrecedence { winner, loser } => ObligationExpr(format!(
            "{winner} schlaegt {loser} - keine offene Obligation"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Eine Anforderung aus DERSELBEN Quelle - der Fall, in dem
    /// Praezedenz ueberhaupt etwas entscheidet.
    fn req(id: &str, artifact: &str, prec: u32, st: &str) -> Requirement {
        req_from("eine-quelle", id, artifact, prec, st)
    }

    fn req_from(source: &str, id: &str, artifact: &str, prec: u32, st: &str) -> Requirement {
        Requirement {
            id: id.into(),
            severity: "MUST".into(),
            artifact: artifact.into(),
            precedence: prec,
            statement: st.into(),
            source: source.into(),
        }
    }

    /// Praezedenz ist QUELLENRELATIV - der Fall, der die dritte
    /// Geltungsart traegt.
    ///
    /// ERWARTUNG, vor der Messung ausgesprochen: zwei Anforderungen aus
    /// VERSCHIEDENEN Quellen loesen sich nicht auf, auch wenn eine den
    /// klar hoeheren Rang traegt. Und die Gegenprobe daneben ist die
    /// tragende: DIESELBEN Zahlen innerhalb EINER Quelle loesen sehr
    /// wohl auf. Ohne sie sagte der erste Fall nur, dass irgendetwas
    /// nicht aufloest - nicht, dass die Quellgrenze der Grund ist.
    #[test]
    fn precedence_decides_within_a_source_and_never_across_two() {
        let a = "Die Datei enthaelt genau 'x'.";
        let b = "Die Datei enthaelt genau 'y'.";

        // Ueber Quellgrenzen: 5 gegen 2, und es entscheidet NICHTS.
        let ueber_quellen = vec![
            req_from("spec", "S1", "f.txt", 2, a),
            req_from("release-note", "O1", "f.txt", 5, b),
        ];
        let found = identify_contradictions(&ueber_quellen).expect("Widerspruch");
        assert_eq!(found.len(), 1);
        assert_eq!(
            found[0].geltung,
            Geltung::UnresolvableAcrossSources {
                left: "S1".into(),
                left_source: "spec".into(),
                right: "O1".into(),
                right_source: "release-note".into(),
            },
            "der hoehere Rang aus fremder Quelle entscheidet nicht"
        );
        assert!(found[0].is_open());
        assert!(found[0].crosses_sources());

        // Gegenprobe: dieselben Zahlen, EINE Quelle - jetzt entscheidet
        // die Rangfolge.
        let eine_quelle = vec![
            req_from("spec", "S1", "f.txt", 2, a),
            req_from("spec", "S2", "f.txt", 5, b),
        ];
        let found = identify_contradictions(&eine_quelle).expect("Widerspruch");
        assert_eq!(
            found[0].geltung,
            Geltung::ResolvedByPrecedence {
                winner: "S2".into(),
                loser: "S1".into()
            },
            "innerhalb einer Quelle schlaegt der hoehere Rang"
        );
        assert!(!found[0].is_open());
        assert!(!found[0].crosses_sources());
    }

    /// Der quellenuebergreifende Widerspruch erzeugt eine Obstruktion,
    /// und ihr Erholungspfad NENNT die Quellen.
    ///
    /// ERWARTUNG: die Obstruktion entsteht (blocking, Art `order`), und
    /// ihr Pfad unterscheidet sich von dem des quelleninternen Falls -
    /// sonst waere die neue Klasse gebaut und im Artefakt unsichtbar.
    #[test]
    fn a_cross_source_contradiction_names_both_sources_in_its_recovery_path() {
        let reqs = vec![
            req_from("spec", "S1", "f.txt", 2, "Die Datei enthaelt genau 'x'."),
            req_from(
                "release-note",
                "O1",
                "f.txt",
                5,
                "Die Datei enthaelt genau 'y'.",
            ),
        ];
        let c = &identify_contradictions(&reqs).expect("Widerspruch")[0];
        let obstruction = integrator_obstruction(
            c,
            ObjectId::new(SortId::Residue, Digest::sha256(b"res")),
            M13Address("m13:0/c0".into()),
        )
        .expect("Obstruktion");

        assert_eq!(obstruction.kind, ObstructionRecordKindKind::Order);
        assert_eq!(
            obstruction.severity,
            ObstructionRecordSeverityKind::Blocking
        );
        let pfad = &obstruction.allowed_recovery[0].0;
        assert!(
            pfad.contains("quellenuebergreifend"),
            "der Pfad muss die Art nennen: {pfad}"
        );
        assert!(pfad.contains("spec") && pfad.contains("release-note"));

        // Und die offene Obligation sagt, WARUM keine Rangfolge hilft.
        let ob = open_obligation_for(c).0;
        assert!(
            ob.contains("nicht vergleichbar"),
            "die Obligation muss den Grund nennen: {ob}"
        );
    }

    #[test]
    fn both_contradiction_kinds_are_identified_and_the_control_set_is_not() {
        let reqs = vec![
            req("A1", "f.txt", 1, "Die Datei enthaelt genau 'x'."),
            req("A2", "f.txt", 2, "Die Datei enthaelt genau 'y'."),
            req(
                "B1",
                "g.txt",
                1,
                "Der Patch DARF ausschliesslich innerhalb der Sandbox schreiben.",
            ),
            req(
                "B2",
                "g.txt",
                1,
                "Der Patch MUSS den ausserhalb gefuehrten Stand spiegeln.",
            ),
            req("C1", "h.txt", 1, "Jeder Schritt erzeugt ein TraceSegment."),
            req(
                "C2",
                "i.txt",
                1,
                "Der Anker versiegelt vor der ersten Aenderung.",
            ),
        ];
        let found = identify_contradictions(&reqs).expect("Widersprueche");
        assert_eq!(
            found.len(),
            2,
            "genau die zwei Paare, nicht mehr: {found:?}"
        );

        let resolved: Vec<_> = found.iter().filter(|c| !c.is_open()).collect();
        let open: Vec<_> = found.iter().filter(|c| c.is_open()).collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(open.len(), 1);
        assert_eq!(
            resolved[0].geltung,
            Geltung::ResolvedByPrecedence {
                winner: "A2".into(),
                loser: "A1".into()
            },
            "die hoehere Praezedenz gewinnt"
        );
    }

    /// Die Kontrollmenge ist der Grund, warum der Test oben etwas sagt:
    /// eine Suche, die ALLES als widerspruechlich meldet, faellt hier auf.
    #[test]
    fn a_contradiction_free_corpus_is_a_failure_not_an_empty_success() {
        let reqs = vec![
            req("C1", "h.txt", 1, "Jeder Schritt erzeugt ein TraceSegment."),
            req(
                "C2",
                "i.txt",
                1,
                "Der Anker versiegelt vor der ersten Aenderung.",
            ),
        ];
        // Nullbefund ueber nichtleerer Arbeitsliste: Fehler, kein leerer
        // Erfolg. Ohne diese Wache waere ein kaputter Vergleich von einem
        // widerspruchsfreien Korpus nicht zu unterscheiden.
        assert!(identify_contradictions(&reqs).is_err());
    }

    #[test]
    fn only_open_contradictions_become_countermodels_and_obstructions() {
        let reqs = vec![
            req("A1", "f.txt", 1, "Die Datei enthaelt genau 'x'."),
            req("A2", "f.txt", 2, "Die Datei enthaelt genau 'y'."),
            req(
                "B1",
                "g.txt",
                1,
                "Der Patch DARF ausschliesslich innerhalb der Sandbox schreiben.",
            ),
            req(
                "B2",
                "g.txt",
                1,
                "Der Patch MUSS den ausserhalb gefuehrten Stand spiegeln.",
            ),
        ];
        let found = identify_contradictions(&reqs).unwrap();
        let cms = falsifier_countermodels(&found);
        assert_eq!(
            cms.len(),
            1,
            "nur der offene Widerspruch ist ein Gegenbeleg"
        );

        let open = found.iter().find(|c| c.is_open()).unwrap();
        let resolved = found.iter().find(|c| !c.is_open()).unwrap();
        let rref = ObjectId::new(SortId::Residue, Digest::sha256(b"r"));
        assert!(integrator_obstruction(open, rref, M13Address("m13:0/c0".into())).is_ok());
        assert!(
            integrator_obstruction(resolved, rref, M13Address("m13:0/c0".into())).is_err(),
            "ein entschiedener Widerspruch erzeugt KEINE Obstruktion"
        );
    }
}
