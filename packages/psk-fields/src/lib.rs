//! M08 FieldRegistry, M09 SpectralLensRouter, M20 MorphogenesisController.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1). Ausimplementierung folgt in der Phase, die das jeweilige
//! Modul realisiert (Regel 32.2).
//!
//! WP07 (I3): `registry` (M08, Regel 32.7 - sechs statische Archetypen,
//! FieldIdentity-Konstruktion, Lebenszyklus ueber FSM-FIELD), `lens_router`
//! (M09, FieldProjection bzw. ResidueRecord(scope)+PSK-E013 bei nicht
//! anwendbarer Linse, Regel 7.17/7.16).
//!
//! WP15 (I7): `morphogenesis` (M20 - G-MORPH/G-EXCISION-Auswertung ueber
//! `psk_gate::evaluate_gate`, ExcisionCertificate). Erst jetzt aktiviert:
//! Regel 32.3 verlangt einen stabilen statischen Feldkern zuerst
//! ("Adaptive Morphogenese (M20) DARF erst nach stabilem statischem
//! Feldkern aktiviert werden") - M08/M09 stehen seit WP07 (I3).

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));

mod registry;
pub use registry::{
    advance, archetype_role, check_activation_requirements, complete_transition, register_field,
    FieldRegistrationInputs, LifecycleStep,
};

mod lens_router;
pub use lens_router::{route_lens, LensOutcome, ProjectionInputs};

mod aperture;
pub use aperture::{
    account_apertures, account_from_pairs, as_psk_error, incoming_mass, visible_bodies,
    AccountingFailure, ApertureAccount, MassClass,
};

mod morphogenesis;
pub use morphogenesis::{
    decide_excision, decide_transition, ExcisionInputs, MorphInputs, MorphogenesisOutcome,
};
