//! M01 Canonicalizer.
//! Portgrenzen generiert aus architecture/port_registry.yaml (Phase I0,
//! Regel 32.1).

mod canon;

pub use canon::{can, collection_digest, object_id, CanonValue, CanonicalBytes, Media};

include!(concat!(env!("OUT_DIR"), "/port_stubs.rs"));
