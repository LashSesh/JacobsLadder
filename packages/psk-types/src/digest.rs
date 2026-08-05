//! Digest nach Definition 6.4: H = SHA-256, dargestellt als 64 Zeichen
//! Kleinbuchstaben-Hex.

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Digest([u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestParseError {
    WrongLength(usize),
    NotLowercaseHex,
}

impl std::fmt::Display for DigestParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DigestParseError::WrongLength(n) => {
                write!(f, "Digest muss 64 Hexzeichen haben, hat {n}")
            }
            DigestParseError::NotLowercaseHex => {
                write!(
                    f,
                    "Digest muss aus Kleinbuchstaben-Hex bestehen (Definition 6.4)"
                )
            }
        }
    }
}

impl std::error::Error for DigestParseError {}

impl Digest {
    pub const LEN_BYTES: usize = 32;
    pub const LEN_HEX: usize = 64;

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Digest(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// H(bytes) nach Definition 6.4.
    pub fn sha256(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        Digest(out)
    }

    /// H(...) mod m als grosse vorzeichenlose Ganzzahl (Big-Endian-Faltung
    /// ueber alle 32 Bytes, nicht nur das letzte). Regel 9.10 (Platzierungsregel):
    /// "Der Index k ergibt sich als k = H(Can(node)) mod 6".
    pub fn mod_small(&self, m: u64) -> u64 {
        self.0
            .iter()
            .fold(0u64, |acc, &b| (acc * 256 + b as u64) % m)
    }

    /// Parst eine 64-stellige Kleinbuchstaben-Hex-Darstellung. Grossbuchstaben
    /// werden abgelehnt statt stillschweigend normalisiert: die Norm legt
    /// Kleinbuchstaben als Darstellung fest, nicht als eine von mehreren
    /// akzeptierten Schreibweisen.
    pub fn from_hex(s: &str) -> Result<Self, DigestParseError> {
        if s.len() != Self::LEN_HEX {
            return Err(DigestParseError::WrongLength(s.len()));
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(DigestParseError::NotLowercaseHex);
        }
        let mut out = [0u8; 32];
        for (i, chunk) in out.iter_mut().enumerate() {
            *chunk = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|_| DigestParseError::NotLowercaseHex)?;
        }
        Ok(Digest(out))
    }
}

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::str::FromStr for Digest {
    type Err = DigestParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Digest::from_hex(s)
    }
}

/// Drahtform: die kanonische Hex-Darstellung selbst (Definition 6.4), nicht
/// das Byte-Array — sonst waere ein Digest in JSON ein 32-elementiges
/// Zahlenarray statt der normativen Zeichenkette.
impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Digest::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_is_deterministic_and_input_sensitive() {
        assert_eq!(Digest::sha256(b"psk"), Digest::sha256(b"psk"));
        assert_ne!(Digest::sha256(b"psk"), Digest::sha256(b"PSK"));
        assert_ne!(Digest::sha256(b""), Digest::sha256(b"\0"));
    }

    #[test]
    fn hex_roundtrip() {
        let d = Digest::sha256(b"psk");
        let s = d.to_string();
        assert_eq!(s.len(), Digest::LEN_HEX);
        assert_eq!(Digest::from_hex(&s).unwrap(), d);
    }

    #[test]
    fn rejects_uppercase() {
        // Aus einem echten, gueltigen Kleinbuchstaben-Digest abgeleitet statt
        // von Hand als 64-Zeichen-Literal getippt, um genau die Art von
        // Transkriptionsfehler auszuschliessen, die diese Pruefung selbst
        // aufdecken soll.
        let lower = Digest::sha256(b"psk").to_string();
        assert_eq!(lower.len(), Digest::LEN_HEX);
        let upper = lower.to_uppercase();
        assert!(matches!(
            Digest::from_hex(&upper),
            Err(DigestParseError::NotLowercaseHex)
        ));
    }
}
