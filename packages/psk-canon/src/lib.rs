//! M01 Canonicalizer.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1).

mod canon;

pub use canon::{
    can, collection_digest, identity_projection, object_id, record_digest, CanonValue,
    CanonicalBytes, Media, VolatileFieldPattern, NON_CANONICAL_FIELDS, NOT_REMOVED,
    VOLATILE_FIELDS, VOLATILE_VIOLATION_ERROR,
};

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
