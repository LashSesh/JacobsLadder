//! ObjectId nach Definition 6.6: id(o) = psk:s:H(Can(pi_vol(o))). `pi_vol`
//! (Definition 6.5) entfernt volatile Felder (z.B. DualTime.tau_e) vor der
//! Kanonisierung; die eigentliche Berechnung liegt in psk-canon
//! (`identity_projection()`), da psk-types nicht von psk-canon abhaengt.
//! Dieser Typ ist nur der Speicher- und Vergleichstyp fuer das Ergebnis.
//! Inhaltsadressiert; zwei Objekte mit gleicher ID sind identisch.

use crate::objects::SortId;
use crate::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ObjectId {
    pub sort: SortId,
    pub digest: Digest,
}

impl ObjectId {
    pub const fn new(sort: SortId, digest: Digest) -> Self {
        ObjectId { sort, digest }
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "psk:{}:{}", self.sort.id(), self.digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectIdParseError {
    WrongForm,
    UnknownSort,
    BadDigest,
}

impl std::fmt::Display for ObjectIdParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObjectIdParseError::WrongForm => write!(
                f,
                "ObjectId muss die Form psk:<sort>:<digest> haben (Definition 6.6)"
            ),
            ObjectIdParseError::UnknownSort => write!(f, "unbekannte Sorte in ObjectId"),
            ObjectIdParseError::BadDigest => write!(f, "ungueltiger Digest in ObjectId"),
        }
    }
}

impl std::error::Error for ObjectIdParseError {}

impl std::str::FromStr for ObjectId {
    type Err = ObjectIdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(3, ':');
        let (Some("psk"), Some(sort_str), Some(digest_str), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ObjectIdParseError::WrongForm);
        };
        let sort = SortId::from_id(sort_str).ok_or(ObjectIdParseError::UnknownSort)?;
        let digest = digest_str
            .parse::<Digest>()
            .map_err(|_| ObjectIdParseError::BadDigest)?;
        Ok(ObjectId { sort, digest })
    }
}

/// Drahtform: die kanonische Zeichenkette "psk:<sort>:<digest>" selbst
/// (Definition 6.6), nicht eine strukturierte Aufloesung.
impl serde::Serialize for ObjectId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ObjectId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<ObjectId>().map_err(serde::de::Error::custom)
    }
}
