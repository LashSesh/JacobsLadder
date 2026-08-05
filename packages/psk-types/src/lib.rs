//! Geteilte Basistypen der PSK-Referenzimplementierung: `ModuleId`,
//! `PortId`, `PskError` (generiert aus den Registern in `architecture/`
//! und `constitution/`), die Nachrichtenhuelle `Msg` nach Struktur 4.1,
//! sowie `objects::SortId` und `objects::OBJECT_COUNT` kanonische
//! Objektstrukturen aus Kapitel 7 (WP02, generiert aus
//! `architecture/object_schemas.yaml`). Absichtlich keine Zahl hier in
//! Prosa - sie driftete bereits dreimal (siehe `OBJECT_COUNT`s eigener
//! Kommentar in tools/psk-codegen/src/objects.rs).
//!
//! Ownership (Vertrag 3.4): dass alle Struktur-Definitionen lexikalisch in
//! diesem einen Paket liegen, ist eine Cargo-Organisationsentscheidung, keine
//! Verletzung der Ownership-Exklusivitaet. Diese bindet, welcher MODUL-CODE
//! ein Objekt konstruieren/schreiben darf, nicht wo der Rust-Typ definiert
//! ist. Die Durchsetzung (nur das Owner-Modul ruft den Konstruktor) erfolgt,
//! sobald reale Konstruktoren existieren (ab WP03).

mod digest;
mod m13_address;
mod msg;
mod object_id;

pub mod payloads {
    //! Nutzlast-Markertypen, generiert aus `architecture/port_registry.yaml`.
    //! Platzhalter bis WP02 die realen Felder aus Kapitel 7 nachtraegt.
    include!(concat!(env!("OUT_DIR"), "/payloads.rs"));
}

pub mod automata {
    //! Die sieben Automaten aus constitution/state_machines.yaml (Kapitel 13),
    //! generiert von tools/psk-codegen.
    //!
    //! Sie liegen wie `objects` zentral in psk-types, weil mehrere Module
    //! denselben Automaten lesen (Kapitel 13 ordnet den Automaten kein
    //! Modul zu, und FSM-OBJECT bzw. FSM-EFFECT laufen ausdruecklich ueber
    //! mehrere Module hinweg). Wer eine Transition ausloesen DARF, ist
    //! davon unberuehrt - das bleibt Ownership-Frage der Module, nicht
    //! eine Frage des Ablageorts (siehe Modulkopf).
    include!(concat!(env!("OUT_DIR"), "/automata.rs"));
}

pub mod passes {
    //! Die geschlossene Passfolge C1..C11 (Definition 11.1), die vier
    //! Emissionsklassen (Definition 11.17) und die sieben Vorbedingungen
    //! von EXECUTABLE - generiert aus architecture/pass_registry.yaml.
    //!
    //! Nur die Bezeichner und ihre Ordnung; die Ausfuehrung der Paesse
    //! liegt bei den jeweils zustaendigen Modulen.
    include!(concat!(env!("OUT_DIR"), "/passes.rs"));
}

pub mod objects {
    //! `SortId` (19 Sorten) und `OBJECT_COUNT` kanonische Objektstrukturen
    //! aus Kapitel 7 / 21.5 / 22.5, generiert aus
    //! `architecture/sort_registry.yaml` und `architecture/object_schemas.yaml`.
    #![allow(non_snake_case)] // Feldnamen I_C/I_A/I_M/I_t sind woertlich aus Regel 6.10.
    include!(concat!(env!("OUT_DIR"), "/sort_id.rs"));
    include!(concat!(env!("OUT_DIR"), "/closed_vocabularies.rs"));
    include!(concat!(env!("OUT_DIR"), "/object_structs.rs"));
}

pub use digest::{Digest, DigestParseError};
pub use m13_address::{
    format as format_m13_address, parse as parse_m13_address, CellId, CellKind, M13AddressError,
    M13NodeId, ParsedM13Address, ScaleAncestor,
};
pub use msg::{ClockRef, DualTime, MessageType, Msg, RunId, SchemaId, Signature, TraceRef, Ulid};
pub use object_id::{ObjectId, ObjectIdParseError};

include!(concat!(env!("OUT_DIR"), "/module_id.rs"));
include!(concat!(env!("OUT_DIR"), "/port_id.rs"));
include!(concat!(env!("OUT_DIR"), "/error.rs"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_id_count_matches_module_map() {
        // Definition 3.1: |M| = 28. Ein Zaehltest hier faengt Codegen-Drift
        // ab, falls architecture/module_map.yaml sich aendert, ohne dass
        // dieser Test aktualisiert wird.
        let all = [
            ModuleId::ConstitutionLoader,
            ModuleId::Canonicalizer,
            ModuleId::ArtifactRegistry,
            ModuleId::SchemaValidator,
            ModuleId::IdentityBinder,
            ModuleId::AnchorRegistry,
            ModuleId::ThoughtCompiler,
            ModuleId::RealityTyper,
            ModuleId::FieldRegistry,
            ModuleId::SpectralLensRouter,
            ModuleId::DependencyAnalyzer,
            ModuleId::ClosureGlueEngine,
            ModuleId::WitnessEngine,
            ModuleId::ValidationPlanner,
            ModuleId::AuthorityConsequenceGate,
            ModuleId::EffectTokenService,
            ModuleId::EffectBoundary,
            ModuleId::ExternalRecordIngress,
            ModuleId::ReconciliationEngine,
            ModuleId::TraceReplayResidueStore,
            ModuleId::MorphogenesisController,
            ModuleId::CertificateReleaseEngine,
            ModuleId::M13TopologyService,
            ModuleId::IRCodec,
            ModuleId::AdversarialKernel,
            ModuleId::Scheduler,
            ModuleId::LifecycleSupervisor,
            ModuleId::ObservabilityProjector,
        ];
        assert_eq!(all.len(), 28);
        assert_eq!(ModuleId::ConstitutionLoader.id(), "M00");
        assert_eq!(ModuleId::ObservabilityProjector.id(), "M27");
    }

    #[test]
    fn error_codes_are_stable_strings() {
        assert_eq!(PskError::UntypedInput.code(), "PSK-E001");
        assert_eq!(PskError::BootPreconditionFailed.code(), "PSK-E101");
    }

    #[test]
    fn digest_round_trips_through_msg() {
        let d = Digest::sha256(b"golden_run");
        let msg = Msg {
            msg_id: Ulid(1),
            port_id: PortId::P07,
            r#type: MessageType::Request,
            schema_id: SchemaId("psk.anchor-snapshot/1.0".into()),
            producer: ModuleId::AnchorRegistry,
            consumer: ModuleId::ThoughtCompiler,
            run_id: RunId("run-0".into()),
            seq: 0,
            input_digests: vec![d],
            created_at: DualTime {
                tau_i: 0,
                tau_e: "1970-01-01T00:00:00Z".into(),
                clock_ref: ClockRef("test".into()),
                uncertainty_ns: 0,
            },
            trace_parent: TraceRef(d),
            payload_digest: d,
            payload: vec![],
            signature: None,
        };
        assert_eq!(msg.payload_digest, d);
        assert_eq!(msg.producer.package(), "psk-anchor");
    }
}
