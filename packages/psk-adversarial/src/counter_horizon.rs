//! QPM Struktur 3.6 (CounterHorizon), Profil von S-RES, Eigner M24 -
//! deshalb liegt es hier im adversarialen Kern und nicht bei den
//! Feldern.
//!
//! QPM Regel 3.8 macht den CounterHorizon zum EINZIGEN Erzeuger der
//! Massenklasse Gegenhorizont: "Nullmodell oder begruendeter
//! Ausschluss". Was hier nicht steht, kann dort nicht verbucht werden.

use psk_types::{ObjectId, TraceRef};

/// Eine abgewiesene Deutung, mit Grund (QPM Struktur 3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RejectedReading {
    pub reading: ObjectId,
    pub reason: String,
    pub witness_ref: Option<ObjectId>,
}

/// Ein begruendet ausgeschlossener Bereich - "nicht uebersehen".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfScopeRegion {
    pub region: RegionSpec,
    pub justification: String,
}

/// Bereichsangabe. Wie die uebrigen QPM-Spezifikationstypen ein
/// Newtype: das Werk nennt ihn, gibt ihm aber keinen Innenaufbau.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RegionSpec(pub String);

/// QPM Struktur 3.6 (CounterHorizon), feldgetreu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterHorizon {
    pub schema: String,
    pub id: ObjectId,
    /// Worauf sich der Gegenbefund bezieht.
    pub subject_ref: ObjectId,
    pub null_models: Vec<ObjectId>,
    pub rejected_readings: Vec<RejectedReading>,
    pub out_of_scope: Vec<OutOfScopeRegion>,
    /// Bekannte Fehlermuster, geprueft.
    pub pathologies: Vec<ObjectId>,
    pub trace_ref: TraceRef,
    /// Warum keine Gegenbahn konstruierbar war. QPM Struktur 3.6
    /// (v1.0.4): "Pflicht gdw. null_models UND out_of_scope leer sind;
    /// Leerraum ist keine Begruendung."
    ///
    /// Der v1.0.3-Dokumentbefund - die Struktur kannte kein Feld fuer
    /// die von QPM Regel 3.7 verlangte Begruendung - ist damit an der
    /// Quelle geschlossen. Zweite Instanz derselben Klasse nach
    /// CellReport gegen Regel 9.21: eine Pflicht ohne Feld ist keine.
    pub emptiness_justification: Option<String>,
}

/// Ob ein Gegenhorizont seine Pflicht erfuellt (QPM Regel 3.7).
///
/// `Unjustified` ist kein Fehler des Aufrufers, sondern ein Befund ueber
/// den Gegenhorizont: "macht jeden darauf gestuetzten Befund
/// unvollstaendig". Er wird berichtet, nicht geworfen - wer darauf baut,
/// muss es sehen koennen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterHorizonStanding {
    /// Nullmodelle oder begruendete Ausschluesse liegen vor.
    Constructed,
    /// Leer, aber begruendet, warum keine Gegenbahn konstruierbar war.
    JustifiedEmpty,
    /// Leer ohne Begruendung - die Gegenhorizontpflicht ist nicht
    /// erfuellt.
    Unjustified,
}

impl CounterHorizon {
    /// QPM Regel 3.7, abgeleitet aus dem Objekt.
    pub fn standing(&self) -> CounterHorizonStanding {
        if !self.null_models.is_empty() || !self.out_of_scope.is_empty() {
            return CounterHorizonStanding::Constructed;
        }
        match &self.emptiness_justification {
            Some(j) if !j.trim().is_empty() => CounterHorizonStanding::JustifiedEmpty,
            _ => CounterHorizonStanding::Unjustified,
        }
    }

    /// Die Objekte, die dieser Gegenhorizont als Gegenhorizontmasse
    /// traegt: Nullmodelle, abgewiesene Deutungen, Pathologien.
    ///
    /// Begruendete Ausschluesse (`out_of_scope`) zaehlen NICHT mit: sie
    /// benennen Bereiche, keine Objekte der eingegangenen Masse.
    pub fn carried(&self) -> Vec<ObjectId> {
        self.null_models
            .iter()
            .copied()
            .chain(self.rejected_readings.iter().map(|r| r.reading))
            .chain(self.pathologies.iter().copied())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::SortId;
    use psk_types::Digest;

    fn oid(s: &[u8]) -> ObjectId {
        ObjectId::new(SortId::Residue, Digest::sha256(s))
    }

    fn empty_horizon(justification: Option<&str>) -> CounterHorizon {
        CounterHorizon {
            schema: "psk.qpm.counter-horizon/1.0".to_string(),
            id: oid(b"ch"),
            subject_ref: oid(b"subject"),
            null_models: vec![],
            rejected_readings: vec![],
            out_of_scope: vec![],
            pathologies: vec![],
            trace_ref: TraceRef(Digest::sha256(b"t")),
            emptiness_justification: justification.map(str::to_string),
        }
    }

    #[test]
    fn an_empty_counter_horizon_without_justification_fails_its_duty() {
        assert_eq!(
            empty_horizon(None).standing(),
            CounterHorizonStanding::Unjustified
        );
        // Leerraum ist keine Begruendung.
        assert_eq!(
            empty_horizon(Some("   ")).standing(),
            CounterHorizonStanding::Unjustified
        );
        assert_eq!(
            empty_horizon(Some(
                "die Domaene kennt kein Nullmodell fuer eine Einzelzelle"
            ))
            .standing(),
            CounterHorizonStanding::JustifiedEmpty
        );
    }

    #[test]
    fn a_constructed_horizon_needs_no_justification() {
        let mut ch = empty_horizon(None);
        ch.null_models = vec![oid(b"nm")];
        assert_eq!(ch.standing(), CounterHorizonStanding::Constructed);

        let mut ch = empty_horizon(None);
        ch.out_of_scope = vec![OutOfScopeRegion {
            region: RegionSpec("m13:1".into()),
            justification: "Feinchart ausserhalb max_depth".into(),
        }];
        assert_eq!(ch.standing(), CounterHorizonStanding::Constructed);
    }

    #[test]
    fn carried_mass_is_models_readings_and_pathologies_but_not_regions() {
        let mut ch = empty_horizon(Some("x"));
        ch.null_models = vec![oid(b"nm")];
        ch.rejected_readings = vec![RejectedReading {
            reading: oid(b"rd"),
            reason: "Kalibrierung abgelaufen".into(),
            witness_ref: None,
        }];
        ch.pathologies = vec![oid(b"path")];
        ch.out_of_scope = vec![OutOfScopeRegion {
            region: RegionSpec("r".into()),
            justification: "j".into(),
        }];
        let carried = ch.carried();
        assert_eq!(carried.len(), 3, "Regionen sind keine Masse");
        assert!(carried.contains(&oid(b"nm")));
        assert!(carried.contains(&oid(b"rd")));
        assert!(carried.contains(&oid(b"path")));
    }
}
