//! M13Address (Definition 9.11, Kapitel 9.2): Grammatik-Parser/-Formatter auf
//! der generierten Drahtform `objects::M13Address(String)`.
//!
//! ```text
//! grammar: "m13:" scale_path "/" cell_id [ "/" node_id ]
//! scale_path: level { "." parent_cell_id "." parent_node_id }
//! cell_id: ( "c" | "b" | "o" ) k # k in 0..5
//! node_id: "c" | "i" k | "o" k
//! ```
//!
//! Dieses Modul deckt ausschliesslich die GRAMMATIK ab. Regel 9.9
//! (Wohlgeformtheit einer M13Address) stellt drei zusaetzliche Bedingungen,
//! die die Grammatik allein nicht traegt; zwei davon setzen das Zellregister
//! voraus ("geprueft gegen m13_topology.yaml, nicht gegen die
//! Schreibweise"). Sie sind daher in `psk_topology::check_wellformed`
//! implementiert, dem Modul, das die Topologie besitzt (M22) - nicht hier.
//! Eine grammatisch gueltige, aber nicht wohlgeformte Adresse erzeugt
//! PSK-E011 und DARF NICHT in eine Zelle eintreten.
//!
//! Erledigter Dokumentbefund: das dritte Beispiel lautete bis v1.0.3
//! "m13:0.c2.i2/1/o5" und verletzte die eigene Grammatik (blosse Zahl "1"
//! an der cell_id-Position; zusaetzlich ist o5 kein Knoten einer
//! Zentrumzelle). In v1.0.4 zu "m13:1.c2.i2/b5/o5" korrigiert - der Test
//! `example_3_parses_and_matches_definition_9_8` haelt die korrigierte
//! Fassung fest.

use crate::objects::M13Address;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellKind {
    Center,
    Bridge,
    Boundary,
}

impl CellKind {
    fn to_char(self) -> char {
        match self {
            CellKind::Center => 'c',
            CellKind::Bridge => 'b',
            CellKind::Boundary => 'o',
        }
    }
    fn from_char(c: char) -> Option<CellKind> {
        match c {
            'c' => Some(CellKind::Center),
            'b' => Some(CellKind::Bridge),
            'o' => Some(CellKind::Boundary),
            _ => None,
        }
    }
}

/// cell_id: ("c"|"b"|"o") k, k in 0..5 (Definition 9.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CellId {
    pub kind: CellKind,
    pub k: u8,
}

impl CellId {
    pub fn new(kind: CellKind, k: u8) -> Result<Self, M13AddressError> {
        if k > 5 {
            return Err(M13AddressError::KOutOfRange(k));
        }
        Ok(CellId { kind, k })
    }
}

/// node_id: "c" | "i" k | "o" k (Definition 9.11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M13NodeId {
    Center,
    Inner(u8),
    Outer(u8),
}

/// Ein Glied der Ahnenkette in scale_path: ". parent_cell_id . parent_node_id".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScaleAncestor {
    pub cell: CellId,
    pub node: M13NodeId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedM13Address {
    pub level: u32,
    pub ancestors: Vec<ScaleAncestor>,
    pub cell: CellId,
    pub node: Option<M13NodeId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M13AddressError {
    MissingPrefix,
    WrongSegmentCount,
    BadLevel,
    IncompleteAncestorGroup,
    BadCellId,
    BadNodeId,
    KOutOfRange(u8),
}

impl std::fmt::Display for M13AddressError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            M13AddressError::MissingPrefix => write!(f, "M13Address muss mit \"m13:\" beginnen"),
            M13AddressError::WrongSegmentCount => {
                write!(
                    f,
                    "M13Address muss genau \"/\"-cell_id[/node_id] nach scale_path haben"
                )
            }
            M13AddressError::BadLevel => write!(f, "ungueltiges level in scale_path"),
            M13AddressError::IncompleteAncestorGroup => {
                write!(
                    f,
                    "unvollstaendige Ahnengruppe in scale_path (parent_cell_id.parent_node_id)"
                )
            }
            M13AddressError::BadCellId => write!(f, "ungueltiges cell_id (erwartet (c|b|o)k)"),
            M13AddressError::BadNodeId => write!(f, "ungueltiges node_id (erwartet c|ik|ok)"),
            M13AddressError::KOutOfRange(k) => write!(f, "k={k} ausserhalb 0..5"),
        }
    }
}

impl std::error::Error for M13AddressError {}

fn parse_cell_id(tok: &str) -> Result<CellId, M13AddressError> {
    let mut chars = tok.chars();
    let kind_ch = chars.next().ok_or(M13AddressError::BadCellId)?;
    let kind = CellKind::from_char(kind_ch).ok_or(M13AddressError::BadCellId)?;
    let rest: String = chars.collect();
    let k: u8 = rest.parse().map_err(|_| M13AddressError::BadCellId)?;
    CellId::new(kind, k)
}

fn parse_node_id(tok: &str) -> Result<M13NodeId, M13AddressError> {
    if tok == "c" {
        return Ok(M13NodeId::Center);
    }
    let mut chars = tok.chars();
    let kind_ch = chars.next().ok_or(M13AddressError::BadNodeId)?;
    let rest: String = chars.collect();
    let k: u8 = rest.parse().map_err(|_| M13AddressError::BadNodeId)?;
    if k > 5 {
        return Err(M13AddressError::KOutOfRange(k));
    }
    match kind_ch {
        'i' => Ok(M13NodeId::Inner(k)),
        'o' => Ok(M13NodeId::Outer(k)),
        _ => Err(M13AddressError::BadNodeId),
    }
}

/// Parst eine M13Address woertlich nach Definition 9.8.
pub fn parse(s: &str) -> Result<ParsedM13Address, M13AddressError> {
    let rest = s
        .strip_prefix("m13:")
        .ok_or(M13AddressError::MissingPrefix)?;
    let segments: Vec<&str> = rest.split('/').collect();
    if segments.len() < 2 || segments.len() > 3 {
        return Err(M13AddressError::WrongSegmentCount);
    }
    let scale_path = segments[0];
    let cell_tok = segments[1];
    let node_tok = segments.get(2).copied();

    let scale_segments: Vec<&str> = scale_path.split('.').collect();
    let level: u32 = scale_segments[0]
        .parse()
        .map_err(|_| M13AddressError::BadLevel)?;
    let remainder = &scale_segments[1..];
    if !remainder.len().is_multiple_of(2) {
        return Err(M13AddressError::IncompleteAncestorGroup);
    }
    let mut ancestors = Vec::new();
    for pair in remainder.chunks(2) {
        let cell = parse_cell_id(pair[0])?;
        let node = parse_node_id(pair[1])?;
        ancestors.push(ScaleAncestor { cell, node });
    }

    let cell = parse_cell_id(cell_tok)?;
    let node = match node_tok {
        Some(t) => Some(parse_node_id(t)?),
        None => None,
    };

    Ok(ParsedM13Address {
        level,
        ancestors,
        cell,
        node,
    })
}

fn format_cell_id(c: &CellId) -> String {
    format!("{}{}", c.kind.to_char(), c.k)
}

fn format_node_id(n: &M13NodeId) -> String {
    match n {
        M13NodeId::Center => "c".to_string(),
        M13NodeId::Inner(k) => format!("i{k}"),
        M13NodeId::Outer(k) => format!("o{k}"),
    }
}

/// Formatiert nach Definition 9.11 (Umkehrung von `parse`).
pub fn format(p: &ParsedM13Address) -> String {
    let mut s = format!("m13:{}", p.level);
    for a in &p.ancestors {
        s.push('.');
        s.push_str(&format_cell_id(&a.cell));
        s.push('.');
        s.push_str(&format_node_id(&a.node));
    }
    s.push('/');
    s.push_str(&format_cell_id(&p.cell));
    if let Some(n) = &p.node {
        s.push('/');
        s.push_str(&format_node_id(n));
    }
    s
}

impl M13Address {
    pub fn parse(&self) -> Result<ParsedM13Address, M13AddressError> {
        parse(&self.0)
    }

    pub fn from_parsed(p: &ParsedM13Address) -> Self {
        M13Address(format(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_1_center_cell_at_coarse_scale() {
        // "m13:0/c3 -> Zentrumzelle 3 auf Grobskala"
        let p = parse("m13:0/c3").unwrap();
        assert_eq!(p.level, 0);
        assert!(p.ancestors.is_empty());
        assert_eq!(p.cell, CellId::new(CellKind::Center, 3).unwrap());
        assert_eq!(p.node, None);
        assert_eq!(format(&p), "m13:0/c3");
    }

    #[test]
    fn example_2_boundary_node_in_transition_cell() {
        // "m13:0/b4/o4 -> Boundaryknoten o4 in Uebergangszelle 4"
        let p = parse("m13:0/b4/o4").unwrap();
        assert_eq!(p.level, 0);
        assert_eq!(p.cell, CellId::new(CellKind::Bridge, 4).unwrap());
        assert_eq!(p.node, Some(M13NodeId::Outer(4)));
        assert_eq!(format(&p), "m13:0/b4/o4");
    }

    #[test]
    fn example_3_parses_and_matches_definition_9_8() {
        // v1.0.4: "m13:1.c2.i2/b5/o5 -> Feinskala 1, betreten ueber
        // Zentrumzelle 2 und Innenknoten i2; darin Brueckenzelle 5,
        // Aussenknoten o5". Die Zellzugehoerigkeit (i2 in c2, o5 in b5)
        // pruefen nicht wir, sondern psk_topology::check_wellformed gegen
        // das Zellregister (Regel 9.9 Punkt 2).
        let p = parse("m13:1.c2.i2/b5/o5").unwrap();
        assert_eq!(p.level, 1);
        assert_eq!(
            p.ancestors,
            vec![ScaleAncestor {
                cell: CellId::new(CellKind::Center, 2).unwrap(),
                node: M13NodeId::Inner(2),
            }]
        );
        assert_eq!(p.cell, CellId::new(CellKind::Bridge, 5).unwrap());
        assert_eq!(p.node, Some(M13NodeId::Outer(5)));
        assert_eq!(format(&p), "m13:1.c2.i2/b5/o5");
    }

    #[test]
    fn pre_v104_third_example_is_still_a_grammar_error() {
        // Die bis v1.0.3 gedruckte Fassung "m13:0.c2.i2/1/o5" bleibt
        // grammatisch ungueltig ("1" ist kein (c|b|o)k-Token). Der Test
        // haelt fest, dass die Korrektur die Grammatik nicht aufgeweicht hat.
        assert_eq!(parse("m13:0.c2.i2/1/o5"), Err(M13AddressError::BadCellId));
    }

    #[test]
    fn roundtrip_with_ancestor_chain() {
        let p = ParsedM13Address {
            level: 1,
            ancestors: vec![ScaleAncestor {
                cell: CellId::new(CellKind::Center, 2).unwrap(),
                node: M13NodeId::Inner(2),
            }],
            cell: CellId::new(CellKind::Boundary, 5).unwrap(),
            node: None,
        };
        let s = format(&p);
        assert_eq!(s, "m13:1.c2.i2/o5");
        assert_eq!(parse(&s).unwrap(), p);
    }

    #[test]
    fn rejects_missing_prefix() {
        assert_eq!(parse("0/c3"), Err(M13AddressError::MissingPrefix));
    }

    #[test]
    fn rejects_k_out_of_range() {
        assert_eq!(parse("m13:0/c6"), Err(M13AddressError::KOutOfRange(6)));
    }

    #[test]
    fn m13_address_wire_type_roundtrips_through_parse() {
        let addr = M13Address::from_parsed(&parse("m13:0/b4/o4").unwrap());
        assert_eq!(addr.0, "m13:0/b4/o4");
        assert_eq!(addr.parse().unwrap(), parse("m13:0/b4/o4").unwrap());
    }
}
