//! Das CRA: verdichtet die real vorliegenden seiner sechs Eingaben zu
//! genau einem RevisionProposal (Definition CRA, Kapitel 12; ISA-
//! Instruktion PROPOSE_REVISION: in [Residues, Evidence], out
//! [RevisionProposal]).
//!
//! ## Vier von sechs, gefuehrt statt verschwiegen
//!
//! Die sechs Eingaben sind Residuenledger, Replaymanifest, Fork-Evidenz,
//! Shadow-Witnesses, Gatepolitik und Kanonisierung. Der Referenzlauf hat
//! vier davon real; Fork-Evidenz und Shadow-Witnesses existieren nicht.
//! Regel 12.13: "Ein CRA ueber weniger als alle sechs Eingaben ist
//! zulaessig, aber der Vorschlag DARF NICHT den Eindruck erwecken, ueber
//! mehr verdichtet zu haben, als vorlag." Deshalb nimmt `cra` je Eingabe
//! ein `Option` entgegen und traegt die Aufteilung selbst in
//! `cra_inputs_present`/`cra_inputs_absent` ein - der Aufrufer kann sie
//! nicht behaupten.
//!
//! ## Vorschlag ist kein Vollzug
//!
//! Regel 12.13: der Vorschlag ist ein neues Objekt mit neuer Identitaet
//! und Verweis auf den Ursprung, nie eine In-place-Weisung.
//! `candidate_id` MUSS von der aktiven Instanz verschieden sein (sonst
//! PSK-E012), `hardening_class` MUSS eine der sechs zugelassenen Klassen
//! sein - beides prueft diese Funktion, nicht ihr Aufrufer.

use psk_canon::{identity_projection, object_id, Media};
use psk_types::objects::{
    CRAInputId, DeltaSpec, ParentBinding, RevisionProposal, RevisionProposalHardeningClassKind,
    SortId,
};
use psk_types::{Digest, ObjectId, PskError, TraceRef};

/// Die vier moeglichen realen Traeger der sechs CRA-Eingaben. `None`
/// heisst: diese Eingabe existiert im Lauf nicht - sie wird dann unter
/// `cra_inputs_absent` gefuehrt, nicht stillschweigend uebergangen.
pub struct CraInputs {
    /// LR - Digest des Residuenledgers (nichtleer erwartet: ohne
    /// Residuen gaebe es nichts zu revidieren).
    pub residue_ledger: Option<Digest>,
    /// MR - Digest des Replaymanifests.
    pub replay_manifest: Option<Digest>,
    /// FE - Fork-Evidenz. Im Referenzlauf: existiert nicht.
    pub fork_evidence: Option<Digest>,
    /// WS - Shadow-Witnesses. Im Referenzlauf: existiert nicht.
    pub shadow_witnesses: Option<Digest>,
    /// PG - Gatepolitik (Digest der Gateregister).
    pub gate_policy: Option<Digest>,
    /// Can - Kanonisierungsprofil.
    pub canonicalization: Option<Digest>,
}

pub struct ProposalInputs {
    /// ISA-Eingabe Residues - nichtleer (Struktur 12.12).
    pub source_residues: Vec<ObjectId>,
    /// ISA-Eingabe Evidence - nichtleer.
    pub source_evidence: Vec<ObjectId>,
    pub hardening_class: RevisionProposalHardeningClassKind,
    /// Was sich aendert - domaenengeliefert, hier nur typisiert.
    pub proposed_delta: DeltaSpec,
    /// Ergebnis des getrennten Prozessbaus, falls er stattfand - der
    /// Algorithmus Revisionsvorschlag baut VOR der Emission in Isolation,
    /// also ist der Verweis Teil des versiegelten Inhalts, keine
    /// nachtraegliche Mutation.
    pub isolation_build_ref: Option<ObjectId>,
    /// ParentBound gegen die LAUFENDE Instanz: deren drei Identitaeten.
    pub parent_constitution: Digest,
    pub parent_architecture: Digest,
    pub parent_implementation: Digest,
    pub trace_ref: TraceRef,
}

/// PROPOSE_REVISION. Erzeugt genau EINEN Vorschlag.
pub fn cra(inputs: CraInputs, proposal: ProposalInputs) -> Result<RevisionProposal, PskError> {
    // Struktur 12.12: beide ISA-Eingaben nichtleer.
    if proposal.source_residues.is_empty() || proposal.source_evidence.is_empty() {
        return Err(PskError::SelfAmendmentWithoutIdentity);
    }

    // Die Aufteilung vorhandener/fehlender Eingaben entsteht HIER, aus
    // den tatsaechlich uebergebenen Werten - erschoepfend ueber alle
    // sechs, in Registerreihenfolge.
    let pairs: [(CRAInputId, Option<&Digest>); 6] = [
        (CRAInputId::ResidueLedger, inputs.residue_ledger.as_ref()),
        (CRAInputId::ReplayManifest, inputs.replay_manifest.as_ref()),
        (CRAInputId::ForkEvidence, inputs.fork_evidence.as_ref()),
        (
            CRAInputId::ShadowWitnesses,
            inputs.shadow_witnesses.as_ref(),
        ),
        (CRAInputId::GatePolicy, inputs.gate_policy.as_ref()),
        (
            CRAInputId::Canonicalization,
            inputs.canonicalization.as_ref(),
        ),
    ];
    let cra_inputs_present: Vec<CRAInputId> = pairs
        .iter()
        .filter(|(_, v)| v.is_some())
        .map(|(k, _)| *k)
        .collect();
    let cra_inputs_absent: Vec<CRAInputId> = pairs
        .iter()
        .filter(|(_, v)| v.is_none())
        .map(|(k, _)| *k)
        .collect();
    // Nullbefund ueber nichtleerer Arbeitsliste: ein CRA ganz ohne
    // vorliegende Eingaben verdichtet nichts.
    if cra_inputs_present.is_empty() {
        return Err(PskError::SelfAmendmentWithoutIdentity);
    }

    // candidate_id: aus dem Inhalt des Kandidaten (den verdichteten
    // Eingaben plus Delta), NICHT aus der aktiven Instanz - und
    // anschliessend gegen sie geprueft.
    let mut candidate_material = Vec::new();
    for (k, v) in pairs.iter() {
        candidate_material.extend(format!("{k:?}=").as_bytes());
        if let Some(d) = v {
            candidate_material.extend(d.as_bytes());
        }
    }
    candidate_material.extend(proposal.proposed_delta.0.as_bytes());
    let candidate_id = ObjectId::new(SortId::Branch, Digest::sha256(&candidate_material));

    // Regel 12.13 / PSK-E012: der Kandidat DARF NICHT die aktive Instanz
    // sein. Die aktive Instanz ist ueber ihre Implementierungsidentitaet
    // benannt.
    if candidate_id.digest == proposal.parent_implementation {
        return Err(PskError::SelfAmendmentWithoutIdentity);
    }

    let draft = RevisionProposal {
        schema: "psk.revision-proposal/1.0".to_string(),
        id: ObjectId::new(SortId::Branch, Digest::sha256(b"")), // Platzhalter
        candidate_id,
        hardening_class: proposal.hardening_class,
        source_residues: proposal.source_residues,
        source_evidence: proposal.source_evidence,
        cra_inputs_present,
        cra_inputs_absent,
        proposed_delta: proposal.proposed_delta,
        parent_binding: ParentBinding {
            constitution: proposal.parent_constitution,
            architecture: proposal.parent_architecture,
            implementation: proposal.parent_implementation,
        },
        isolation_build_ref: proposal.isolation_build_ref,
        trace_ref: proposal.trace_ref,
    };

    let mut value = serde_json::to_value(&draft).map_err(|_| PskError::CanonicalizationFailed)?;
    value
        .as_object_mut()
        .ok_or(PskError::CanonicalizationFailed)?
        .remove("id");
    let bytes = serde_json::to_vec(&value).map_err(|_| PskError::CanonicalizationFailed)?;
    let canonical = identity_projection(&bytes, Media::Json)?;
    let id: ObjectId = object_id(SortId::Branch.id(), &canonical)
        .parse()
        .map_err(|_| PskError::CanonicalizationFailed)?;
    Ok(RevisionProposal { id, ..draft })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn four_of_six() -> CraInputs {
        CraInputs {
            residue_ledger: Some(Digest::sha256(b"lr")),
            replay_manifest: Some(Digest::sha256(b"mr")),
            fork_evidence: None,
            shadow_witnesses: None,
            gate_policy: Some(Digest::sha256(b"pg")),
            canonicalization: Some(Digest::sha256(b"can")),
        }
    }

    fn proposal_inputs() -> ProposalInputs {
        ProposalInputs {
            source_residues: vec![ObjectId::new(SortId::Residue, Digest::sha256(b"r"))],
            source_evidence: vec![ObjectId::new(SortId::Branch, Digest::sha256(b"cm"))],
            hardening_class: RevisionProposalHardeningClassKind::TestsAndFalsifiers,
            proposed_delta: DeltaSpec("gegenmodell in die stehende negativsuite".into()),
            isolation_build_ref: None,
            parent_constitution: Digest::sha256(b"ic"),
            parent_architecture: Digest::sha256(b"ia"),
            parent_implementation: Digest::sha256(b"im"),
            trace_ref: TraceRef(Digest::sha256(b"t")),
        }
    }

    #[test]
    fn present_and_absent_are_derived_not_claimed() {
        let p = cra(four_of_six(), proposal_inputs()).unwrap();
        assert_eq!(
            p.cra_inputs_present,
            vec![
                CRAInputId::ResidueLedger,
                CRAInputId::ReplayManifest,
                CRAInputId::GatePolicy,
                CRAInputId::Canonicalization
            ]
        );
        assert_eq!(
            p.cra_inputs_absent,
            vec![CRAInputId::ForkEvidence, CRAInputId::ShadowWitnesses],
            "die fehlenden zwei MUESSEN benannt sein, nicht verschwiegen"
        );
        // Erschoepfend: zusammen genau die sechs.
        assert_eq!(p.cra_inputs_present.len() + p.cra_inputs_absent.len(), 6);
    }

    #[test]
    fn empty_isa_inputs_are_refused() {
        let mut pi = proposal_inputs();
        pi.source_residues.clear();
        assert!(
            cra(four_of_six(), pi).is_err(),
            "Residues nichtleer (Struktur 12.12)"
        );
        let mut pi2 = proposal_inputs();
        pi2.source_evidence.clear();
        assert!(cra(four_of_six(), pi2).is_err(), "Evidence nichtleer");
    }

    #[test]
    fn a_candidate_equal_to_the_active_instance_is_psk_e012() {
        // Erzwinge Gleichheit: parent_implementation = der Digest, den die
        // Kandidatenbildung liefern wird.
        let mut material = Vec::new();
        let inputs = four_of_six();
        let pairs: [(&str, Option<&Digest>); 6] = [
            ("ResidueLedger", inputs.residue_ledger.as_ref()),
            ("ReplayManifest", inputs.replay_manifest.as_ref()),
            ("ForkEvidence", inputs.fork_evidence.as_ref()),
            ("ShadowWitnesses", inputs.shadow_witnesses.as_ref()),
            ("GatePolicy", inputs.gate_policy.as_ref()),
            ("Canonicalization", inputs.canonicalization.as_ref()),
        ];
        for (k, v) in pairs.iter() {
            material.extend(format!("{k}=").as_bytes());
            if let Some(d) = v {
                material.extend(d.as_bytes());
            }
        }
        let mut pi = proposal_inputs();
        material.extend(pi.proposed_delta.0.as_bytes());
        pi.parent_implementation = Digest::sha256(&material);
        assert!(
            cra(four_of_six(), pi).is_err(),
            "candidate_id == aktive Instanz MUSS PSK-E012 ausloesen"
        );
        // Positivkontrolle: mit anderem Elternwert geht derselbe Aufbau durch.
        assert!(cra(four_of_six(), proposal_inputs()).is_ok());
    }

    #[test]
    fn a_cra_with_no_present_inputs_condenses_nothing() {
        let none = CraInputs {
            residue_ledger: None,
            replay_manifest: None,
            fork_evidence: None,
            shadow_witnesses: None,
            gate_policy: None,
            canonicalization: None,
        };
        assert!(cra(none, proposal_inputs()).is_err());
    }
}
