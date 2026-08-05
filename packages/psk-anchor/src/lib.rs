//! M05 AnchorRegistry, M17 ExternalRecordIngress.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP05: `external_record` (der Aussenrecord-Typ, Regel 32.7), `anchor`
//! (M05: Versiegelung zu AnchorSnapshot), `ingress` (M17: Provenienzbindung).
//!
//! WP15 (I7): `receipt` (M17 - ExternalReceipt/ObserverAdapter, Struktur
//! 7.34; P24-Ingress nach Vertrag 20.2, Herkunftsbeglaubigung an der
//! Prozessgrenze VOR jeder Deserialisierung).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod external_record;
pub use external_record::{ExternalRecord, FileObservation, ObservedPermissions};

mod anchor;
pub use anchor::{is_fresh, no_declared_uncertainty, seal_anchor, AnchorInputs};

mod ingress;
pub use ingress::{bind_provenance, check_observer_separation};

mod receipt;
pub use receipt::{
    build_receipt, ingress_p24, ObservationInputs, ObserverAdapter, ProcessIdentity,
    RegisteredObserverIdentity,
};
