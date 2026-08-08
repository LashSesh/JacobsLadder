//! `verify-dependencies`: statische Pruefung von Modul- und Paketabhaengig-
//! keitsgraph, gleiches Werkzeugmuster wie `verify-modtree` (Struktur:
//! eigenstaendiges Binary, kein `syn`, so wenig Parsing wie fuer die
//! tatsaechlichen Registerformen noetig).
//!
//! Deckt zwei registrierte Tests ab:
//!
//! - **T-ARCH-002** (`introduce_cyclic_module_dependency -> build_fail`,
//!   Invariante 2.3: "Der Modulabhaengigkeitsgraph ist azyklisch.") -
//!   Zyklenpruefung ueber den aus `architecture/port_registry.yaml`
//!   gebildeten Modulgraphen, plus Pruefung der in
//!   `architecture/module_map.yaml`s `forbidden_edges` explizit
//!   untersagten Kanten.
//! - **T-PORT-001** (`add_direct_cross_module_call_without_port ->
//!   build_fail`, Invariante 26.3: "Der Paketabhaengigkeitsgraph ist
//!   azyklisch und respektiert die Schichtenordnung.") - Zyklenpruefung
//!   ueber den tatsaechlichen Cargo-Abhaengigkeitsgraphen (jedes
//!   `[dependencies]` in jedem Mitgliedspaket), plus Pruefung, dass jede
//!   Paket-zu-Paket-Abhaengigkeit zwischen zwei modulbesitzenden Paketen
//!   durch einen registrierten Port zwischen ihren Modulen gedeckt ist -
//!   oder eine der vier textlich benannten Ausnahmen ist (siehe
//!   `is_foundational_dependency` unten).
//!
//! ## Was dieses Werkzeug NICHT prueft (ehrlicher Deckungsluecken-Hinweis)
//!
//! Invariante 2.3s Schichtrichtungs-Vergleichsoperator war in der v1.0.13-
//! Quelle nicht sicher rekonstruierbar (siehe Git-Historie dieser Datei
//! fuer die damalige Gegenprobe). PSK-RA v1.0.14 hat das an der Quelle
//! korrigiert: der Fehler lag in der Norm selbst, nicht im Register - die
//! Ungleichung war invertiert und haette woertlich genommen die
//! spezifizierte Vorwaertspipeline (z.B. M11->M12->M13->M14, P18) selbst
//! verboten. Korrigierter Wortlaut: "L(Mb) >= L(Ma) - die Pipeline
//! schreitet zu gleichem oder hoeherem Layer fort - oder [...] eine der
//! [...] benannten Rueckflusskanten." Die Ambiguitaet ist damit
//! aufgeloest; ein GENERISCHER Schichtrichtungs-Check ist trotzdem NICHT
//! Teil dieses Werkzeugs (bewusst nicht scope-erweitert ueber die konkret
//! angeforderte P39-Korrektur hinaus, siehe `is_named_backflow`) - eine
//! separate, spaeter zu entscheidende Erweiterung, kein stillschweigend
//! behaupteter Deckungsgewinn.
//!
//! PSK-RA v1.0.16 ergaenzte die Art-Spalte (`kind`) fuer alle 42 Ports
//! (zuvor nur neun Beispiele, siehe port_registry.yaml Kopfkommentar) und
//! bestaetigte damit den vierten, zuvor offenen Zyklenfund (M08<->M20, P31/
//! P32) als denselben Anruf-Ruecksprung-Fall wie P00/P05. Das machte
//! "request" zum GEWOEHNLICHEN Fall (33 von 42) statt einer neunkoepfigen
//! Ausnahmeliste - `module_graph_edges`s zweite Ausnahmeklasse wurde
//! deshalb von "jeder kind:request-Port" auf eine kleine, an echtem Code
//! verifizierte Aufzaehlung umgestellt (`is_verified_call_return_leg`);
//! die alte, breite Fassung haette sonst 33 von 42 Kanten aus der
//! Zyklenpruefung entfernt und T-ARCH-002 praktisch wirkungslos gemacht.
//! Siehe dessen Kopfkommentar fuer die Einzelheiten.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Deserialize;

const WILDCARD: &str = "*";

fn workspace_root() -> PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    loop {
        if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
            return dir;
        }
        if !dir.pop() {
            panic!("keine Workspace-Wurzel (Cargo.toml + .git) gefunden");
        }
    }
}

/// Liest `Cargo.toml`s `[workspace] members` roh als Zeilenliste - identisch
/// zu `verify-modtree`s eigener Funktion, absichtlich dupliziert statt
/// einer neuen internen Bibliotheksabhaengigkeit zwischen zwei CI-
/// Werkzeugen, die sonst unabhaengig bleiben sollen.
fn workspace_members(root: &Path) -> Vec<PathBuf> {
    let text = fs::read_to_string(root.join("Cargo.toml")).expect("Cargo.toml lesbar");
    let mut members = Vec::new();
    let mut in_members = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("members") && trimmed.contains('[') {
            in_members = true;
            continue;
        }
        if in_members {
            if trimmed.starts_with(']') {
                break;
            }
            let cleaned = trimmed.trim_end_matches(',').trim_matches('"');
            if !cleaned.is_empty() {
                members.push(root.join(cleaned));
            }
        }
    }
    members
}

// ------------------------------------------------------- module_map.yaml

#[derive(Debug, Deserialize)]
struct ModuleMap {
    modules: Vec<ModuleEntry>,
    #[serde(default)]
    forbidden_edges: Vec<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct ModuleEntry {
    id: String,
    package: String,
}

// ----------------------------------------------------- port_registry.yaml

#[derive(Debug, Deserialize)]
struct PortRegistry {
    ports: Vec<PortEntry>,
}

/// `kind` (Regel 4.7: request/event) steht im realen Register, treibt aber
/// KEINE Pruefung mehr in diesem Werkzeug (siehe `is_verified_call_return_leg`s
/// Kopfkommentar fuer den Grund) - deshalb hier bewusst nicht deserialisiert,
/// statt eines gelesenen-aber-nie-benutzten Feldes.
#[derive(Debug, Deserialize, Clone)]
struct PortEntry {
    from: String,
    to: String,
}

// ------------------------------------------------------ pass_registry.yaml

#[derive(Debug, Deserialize)]
struct PassRegistry {
    passes: Vec<PassEntry>,
}

#[derive(Debug, Deserialize, Clone)]
struct PassEntry {
    modules: Vec<String>,
}

// ---------------------------------------------------------- Cargo.toml

#[derive(Debug, Deserialize, Default)]
struct CargoManifest {
    package: Option<CargoPackage>,
    #[serde(default)]
    dependencies: BTreeMap<String, toml::Value>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: String,
}

fn load_manifest(crate_dir: &Path) -> Option<CargoManifest> {
    let text = fs::read_to_string(crate_dir.join("Cargo.toml")).ok()?;
    toml::from_str(&text).ok()
}

/// Alle Registerdaten, einmal geladen, allen Pruefungen gemeinsam.
struct Registers {
    /// Paket -> besessene Modul-IDs. Ein Paket KANN mehrere Module
    /// besitzen (z.B. psk-contract fuer M00/M02/M04).
    modules_of: BTreeMap<String, Vec<String>>,
    all_module_ids: BTreeSet<String>,
    ports: Vec<PortEntry>,
    /// `pass_registry.yaml`s Passen, je nur ihre `modules`-Liste - fuer die
    /// PSK-RA v1.0.15-Ausnahme "gemeinsame Passtraeger" (siehe
    /// `shares_a_pass`).
    passes: Vec<PassEntry>,
    forbidden_edges: Vec<Vec<String>>,
    /// Paket -> Cargo-`[dependencies]`-Namen, die selbst Workspace-Mitglieder
    /// sind (externe Crates wie `serde` sind fuer diese Pruefungen irrelevant).
    package_deps: BTreeMap<String, BTreeSet<String>>,
}

fn load_registers(root: &Path) -> Registers {
    let module_map: ModuleMap = serde_yaml::from_str(
        &fs::read_to_string(root.join("architecture/module_map.yaml")).expect("module_map.yaml"),
    )
    .expect("module_map.yaml parsebar");
    let port_registry: PortRegistry = serde_yaml::from_str(
        &fs::read_to_string(root.join("architecture/port_registry.yaml"))
            .expect("port_registry.yaml"),
    )
    .expect("port_registry.yaml parsebar");
    let pass_registry: PassRegistry = serde_yaml::from_str(
        &fs::read_to_string(root.join("architecture/pass_registry.yaml"))
            .expect("pass_registry.yaml"),
    )
    .expect("pass_registry.yaml parsebar");

    let mut modules_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut all_module_ids = BTreeSet::new();
    for m in &module_map.modules {
        modules_of
            .entry(m.package.clone())
            .or_default()
            .push(m.id.clone());
        all_module_ids.insert(m.id.clone());
    }

    let members = workspace_members(root);
    let member_names: BTreeSet<String> = members
        .iter()
        .filter_map(|dir| load_manifest(dir))
        .filter_map(|m| m.package.map(|p| p.name))
        .collect();

    let mut package_deps = BTreeMap::new();
    for dir in &members {
        let Some(manifest) = load_manifest(dir) else {
            continue;
        };
        let Some(name) = manifest.package.map(|p| p.name) else {
            continue;
        };
        let deps: BTreeSet<String> = manifest
            .dependencies
            .keys()
            .filter(|d| member_names.contains(*d))
            .cloned()
            .collect();
        package_deps.insert(name, deps);
    }

    Registers {
        modules_of,
        all_module_ids,
        ports: port_registry.ports,
        passes: pass_registry.passes,
        forbidden_edges: module_map.forbidden_edges,
        package_deps,
    }
}

// --------------------------------------------------------- Zyklenpruefung

/// Generischer DFS-Zyklenfund ueber eine Kantenliste - dieselbe Aufgabe
/// fuer Modul- und fuer Paketgraph, deshalb ein Algorithmus statt zwei.
/// Gibt den ersten gefundenen Zyklus als Knotenpfad zurueck (leer = azyklisch).
fn find_cycle(nodes: &BTreeSet<String>, edges: &BTreeMap<String, BTreeSet<String>>) -> Vec<String> {
    #[derive(Clone, Copy, PartialEq)]
    enum State {
        Unvisited,
        InProgress,
        Done,
    }

    fn visit(
        node: &str,
        edges: &BTreeMap<String, BTreeSet<String>>,
        state: &mut BTreeMap<String, State>,
        stack: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        state.insert(node.to_string(), State::InProgress);
        stack.push(node.to_string());
        if let Some(targets) = edges.get(node) {
            for t in targets {
                match state.get(t).copied().unwrap_or(State::Unvisited) {
                    State::Unvisited => {
                        if let Some(cycle) = visit(t, edges, state, stack) {
                            return Some(cycle);
                        }
                    }
                    State::InProgress => {
                        let start = stack.iter().position(|n| n == t).unwrap();
                        let mut cycle = stack[start..].to_vec();
                        cycle.push(t.clone());
                        return Some(cycle);
                    }
                    State::Done => {}
                }
            }
        }
        stack.pop();
        state.insert(node.to_string(), State::Done);
        None
    }

    let mut state: BTreeMap<String, State> = BTreeMap::new();
    for n in nodes {
        if state.get(n).copied().unwrap_or(State::Unvisited) == State::Unvisited {
            let mut stack = Vec::new();
            if let Some(cycle) = visit(n, edges, &mut state, &mut stack) {
                return cycle;
            }
        }
    }
    Vec::new()
}

// ------------------------------------------------------------- T-ARCH-002

/// Definition 2.7 (Zulaessige Rueckfluesse), PSK-RA v1.0.14, woertlich:
/// "(i) Residuenrueckfluss: jede Schicht -> M19 (Residue-/Trace-
/// schreibung). (ii) Reanalyserueckfluss: M18 -> M06 als neuer
/// Kompilationsauftrag mit neuer Objektidentitaet. (iii) Reankrierung:
/// M18/M13 -> M05 als Anforderung eines neuen AnchorSnapshot. (iv)
/// Revisionsvorschlag: M24 -> M21 als RevisionProposal, niemals als
/// In-place-Aenderung. (v) Sondierungsrueckfluss: M13 -> M09 als neue
/// ProbeRequest (P39). Erzeugt eine neue FieldProjection mit neuer
/// Objektidentitaet; niemals ein direkter Aufruf in eine bestehende
/// Projektion hinein." Kanal (v) wurde mit v1.0.14 ergaenzt - v1.0.13s
/// Invariante 2.3 hatte die Schichtungleichung invertiert und damit
/// P39 als echten Zyklus (M09->..->M13->M09) gemeldet, obwohl der
/// eigentliche Fehler in der Norm lag, nicht im Register (siehe
/// Modulkopf). Diese fuenf - und NUR diese fuenf - sind per Definition
/// erlaubte Gegenrichtung, keine Zyklusverletzung. Kanal (i) ist "jede
/// Schicht", also JEDE Kante mit Ziel M19, nicht nur die als Wildcard
/// (P28) oder `kind: event` getaggten - P23 (M16->M19) traegt z.B.
/// keins von beidem, ist aber textlich unzweifelhaft derselbe Kanal.
fn is_named_backflow(p: &PortEntry) -> bool {
    p.to == "M19"
        || (p.from == "M18" && p.to == "M06")
        || (p.from == "M18" && p.to == "M05")
        || (p.from == "M13" && p.to == "M05")
        || (p.from == "M24" && p.to == "M21")
        || (p.from == "M13" && p.to == "M09")
}

/// PSK-RA v1.0.15, Invariante 2.3s vierte Ausnahmeklasse: "...oder wenn Ma
/// und Mb laut pass_registry.yaml gemeinsame Traeger derselben Passe sind
/// (Zusammenarbeit innerhalb einer Passe, kein Rueckfluss zwischen
/// Passen)." Grund, real gefunden: der M11<->M22-Zyklus (P16 SeamQuery,
/// P17 CellReport) war KEIN sechster Rueckflusskanal wie zuerst vermutet -
/// Pass C9 (ClosureAndGluing, pass_registry.yaml) fuehrt `modules: [M11,
/// M22]` bereits als GEMEINSAME Traeger derselben Passe. Die Schichtregel
/// war nie dafuer gedacht, Zusammenarbeit INNERHALB einer Passe zu
/// verbieten - nur Rueckfluss ZWISCHEN Pipelinestufen. Symmetrisch (Ma,Mb)
/// und (Mb,Ma), da "gemeinsame Traeger" keine Richtung kennt.
fn shares_a_pass(from: &str, to: &str, passes: &[PassEntry]) -> bool {
    passes
        .iter()
        .any(|p| p.modules.iter().any(|m| m == from) && p.modules.iter().any(|m| m == to))
}

/// PSK-RA v1.0.16, Fehlerkorrektur-Befund (20): Kapitel 4.2 traegt jetzt fuer
/// alle 42 Ports eine Art-Spalte (`kind`), nicht mehr nur fuer neun Beispiele.
/// Regel 4.7 (Synchronitaet) macht "request" damit zum GEWOEHNLICHEN Fall
/// (33 von 42 Ports) - jeder synchrone Pipelineschritt innerhalb eines Ticks
/// ist "request", unabhaengig davon, ob er architektonisch vorwaerts oder
/// rueckwaerts zeigt. `kind` beschreibt Zustellzeitpunkt (Regel 4.7), NICHT
/// Abhaengigkeitsrichtung (Invariante 2.3) - zwei orthogonale Eigenschaften.
///
/// Die FRUEHERE Fassung dieser Funktion behandelte JEDEN `kind: request`-Port
/// als Ausnahme von der Zyklenpruefung - richtig fuer die neun ehemaligen
/// Beispiele (jede Vorwaertskante darunter blieb ohnehin unproblematisch,
/// da sie keine Rueckkante schliesst), aber FALSCH als generelle Regel:
/// mechanisch auf alle 42 angewandt, entfernt sie 33 von 42 Kanten aus dem
/// Graphen - darunter die gesamte gewoehnliche Vorwaertspipeline (P01-P04,
/// P08-P20, P25, P34/P35, P40/P41 usw.) - und macht die Zyklenpruefung
/// PRAKTISCH WIRKUNGSLOS: ein fast leerer Graph ist trivial azyklisch, ganz
/// unabhaengig davon, ob die registrierten Abhaengigkeiten tatsaechlich
/// azyklisch sind. Real beobachtet: nach Ergaenzung der 33 Eintraege meldete
/// dieses Werkzeug PASS - aber nur, weil kaum noch Kanten uebrig waren, nicht
/// weil der Graph gepruefte Azyklizitaet zeigte.
///
/// Modulgraph NUR aus konkreten (nicht-Wildcard-) Ports, ohne Definition
/// 2.7s fuenf benannte Rueckflusskanaele, ohne verifizierte Anruf-
/// Ruecksprung-Kanten und ohne Kanten zwischen gemeinsamen Passtraegern
/// (Invariante 2.3, v1.0.15) - vier getrennt verifizierte Ausnahmeklassen,
/// keine geratenen:
///
/// 1. `"*"`-Ports (P28, P30) sind Fan-in/Fan-out-Sammel-/Streubeziehungen,
///    keine Punkt-zu-Punkt-Pipelinekanten - woertlich entfaltet wuerden
///    sie Scheinzyklen erzeugen (siehe `is_named_backflow` fuer P28s
///    eigentlichen Kanal; P30 hat keine Zielrichtung, die je in einen
///    Zyklus zurueckfuehren koennte, da M25 Schicht L0 ist).
/// 2. Verifizierte Anruf-Ruecksprung-Kanten - siehe
///    `is_verified_call_return_leg`. NICHT laenger "jeder kind:request-Port"
///    (siehe Erklaerung oben), sondern eine explizite, an echtem Code
///    verifizierte Aufzaehlung, genau wie Klasse 3.
/// 3. Definition 2.7s fuenf benannte Rueckflusskanaele - siehe
///    `is_named_backflow`.
/// 4. Gemeinsame Passtraeger (Invariante 2.3, v1.0.15) - siehe
///    `shares_a_pass`.
fn module_graph_edges(regs: &Registers) -> BTreeMap<String, BTreeSet<String>> {
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in &regs.ports {
        if p.from == WILDCARD || p.to == WILDCARD {
            continue;
        }
        if is_named_backflow(p) {
            continue;
        }
        if is_verified_call_return_leg(p) {
            continue;
        }
        if shares_a_pass(&p.from, &p.to, &regs.passes) {
            continue;
        }
        edges
            .entry(p.from.clone())
            .or_default()
            .insert(p.to.clone());
    }
    edges
}

/// Explizit verifizierte Ruecksprung-Haelften synchroner Anruf/Ruecksprung-
/// Grenzen (Regel 4.7: `kind: request` = synchron und blockierend innerhalb
/// desselben Ticks) - Definition 4.4s "Port" bindet Erzeuger und Verbraucher
/// symmetrisch, aber ein Ruecksprungwert, der denselben Aufruf abschliesst,
/// ist keine ZWEITE, unabhaengige Architekturkante im Sinne von Invariante
/// 2.3s Modulabhaengigkeitsgraph - er ist derselbe Aufruf, einmal hin und
/// zurueck. Bewusst eine kleine, benannte Aufzaehlung (wie
/// `is_named_backflow`), NICHT "jeder kind:request-Port" (siehe
/// `module_graph_edges`s Kopfkommentar fuer den Unterschied) - jeder Eintrag
/// hier ist einzeln an echtem Code verifiziert, nicht aus dem Registerfeld
/// allein abgeleitet:
///
/// - (M04, M26): P05 "IdentityBinding", Ruecksprung von P00 "BootRequest".
///   `psk_contract::boot()` (boot.rs, Algorithmus 17.1) ist EIN
///   Funktionsaufruf, der Schritt 1-21 (M00 bis M04, G-BOOT) sequenziell
///   ausfuehrt und EIN `Result<BootReport, _>` zurueckgibt - P00 (M26->M00)
///   und P05 (M04->M26) beschreiben zusammen EINE Aufruf-Ruecksprung-Grenze.
///   Ungeprueft als eigenstaendige Kante behandelt, schliesst P05 den Kreis
///   M00->M01->M02->M03->M04->M26->M00 - real gefunden, an boot.rs
///   verifiziert, nicht angenommen.
/// - (M20, M08): P31 "MorphogenesisDecision", Ruecksprung von P32
///   "SpawnRequest". `psk-fields/src/morphogenesis.rs`s `decide_transition`
///   (M20s eigene Funktion) wertet das Gate aus und ruft bei PASS direkt
///   `complete_transition` - M08s eigene Funktion, SELBES Cargo-Paket
///   (psk-fields, module_map.yaml) - synchron im selben Aufruf auf. Derselbe
///   Anruf-Ruecksprung-Charakter wie P00/P05, PSK-RA v1.0.16 bestaetigt
///   (Fehlerkorrektur-Befund 20: "P31/P32 ... sind damit request - derselbe
///   Aufruf/Ruecksprung-Charakter wie P00/P05 in boot(), nur zuvor nicht
///   gekennzeichnet"). Ungeprueft behandelt, schliesst P31 den Kreis
///   M08->M20->M08.
fn is_verified_call_return_leg(p: &PortEntry) -> bool {
    (p.from == "M04" && p.to == "M26") || (p.from == "M20" && p.to == "M08")
}

fn check_module_cycle(regs: &Registers) -> Option<String> {
    let cycle = find_cycle(&regs.all_module_ids, &module_graph_edges(regs));
    if cycle.is_empty() {
        None
    } else {
        Some(format!(
            "T-ARCH-002: zyklische Modulabhaengigkeit im Portregister: {}",
            cycle.join(" -> ")
        ))
    }
}

/// Prueft nur die UNBEDINGTEN (2-elementigen) `forbidden_edges` - ein
/// 3-elementiger Eintrag wie `["*", M19, delete_or_overwrite]` untersagt
/// eine OPERATION (delete/overwrite), nicht jede Kante zu M19 ueberhaupt
/// (M19 empfaengt legitim ueber P23/P28/P33 - append-artige Ports); diese
/// operationsspezifische Garantie ist bereits durch die Abwesenheit einer
/// `delete`/`overwrite`-Methode auf `TraceStore`/`ResidueLedger` selbst
/// bewiesen (siehe conformance_catalog.rs T-TRACE-001-Befund), nicht
/// nochmal hier dupliziert.
fn check_forbidden_edges(regs: &Registers) -> Vec<String> {
    let mut problems = Vec::new();
    for edge in &regs.forbidden_edges {
        if edge.len() != 2 {
            continue;
        }
        let (src, dst) = (&edge[0], &edge[1]);
        for p in &regs.ports {
            let src_matches = src == WILDCARD || &p.from == src;
            let dst_matches = dst == WILDCARD || &p.to == dst;
            if src_matches && dst_matches {
                problems.push(format!(
                    "verbotene Kante [{src}, {dst}] ist als Port {}->{} registriert",
                    p.from, p.to
                ));
            }
        }
    }
    problems
}

// ------------------------------------------------------------- T-PORT-001

/// Vier textlich benannte, in der REALEN Abhaengigkeitsmatrix gegen-
/// gepruefte Ausnahmen von "jede Paketkante braucht einen deckenden Port":
/// - psk-types: Invariante 26.3, "psk-types ... besitzt keine internen
///   Abhaengigkeiten" - die universelle Objektvokabular-Kiste, die JEDES
///   Modul kennen muss, um Kapitel-7-Objekte ueberhaupt auszutauschen.
/// - psk-canon: Invariante 26.3, gemeinsam mit psk-types genannt - reale
///   Abhaengigkeitspruefung zeigt psk-canons EINZIGE interne Abhaengigkeit
///   ist psk-types selbst, keine andere Modulkante.
/// - psk-trace: Definition 2.7(i), "Residuenrueckfluss: jede Schicht ->
///   M19" - woertlich JEDE Schicht, nicht nur die portregistrierten.
/// - psk-gate: `evaluate_gate` ist laut psk-certify/src/certify.rs
///   Modulkopf ausdruecklich "dieselbe generische evaluate_gate wie M14/
///   M20" - eine geteilte Auswertungsfunktion, kein M14-exklusiver
///   Pipelineschritt.
fn is_foundational_dependency(target_package: &str) -> bool {
    matches!(
        target_package,
        "psk-types" | "psk-canon" | "psk-trace" | "psk-gate"
    )
}

/// `true`, wenn irgendein registrierter Port EIN Modul aus `from_modules`
/// mit EINEM Modul aus `to_modules` verbindet - in JEDER Richtung (die
/// Cargo-Abhaengigkeitsrichtung sagt nicht zuverlaessig voraus, in welcher
/// Richtung der zugehoerige Port lief, siehe Modulkopf).
fn any_port_connects(ports: &[PortEntry], from_modules: &[String], to_modules: &[String]) -> bool {
    ports.iter().any(|p| {
        (from_modules.iter().any(|m| m == &p.from) && to_modules.iter().any(|m| m == &p.to))
            || (to_modules.iter().any(|m| m == &p.from) && from_modules.iter().any(|m| m == &p.to))
    })
}

fn package_graph_edges(regs: &Registers) -> BTreeMap<String, BTreeSet<String>> {
    regs.package_deps
        .iter()
        .map(|(pkg, deps)| (pkg.clone(), deps.clone()))
        .collect()
}

fn check_package_cycle(regs: &Registers) -> Option<String> {
    let packages: BTreeSet<String> = regs.package_deps.keys().cloned().collect();
    let cycle = find_cycle(&packages, &package_graph_edges(regs));
    if cycle.is_empty() {
        None
    } else {
        Some(format!(
            "T-PORT-001 / Invariante 26.3: zyklische Paketabhaengigkeit: {}",
            cycle.join(" -> ")
        ))
    }
}

/// psk-contract implementiert Algorithmus 17.1 (boot(), 21 Schritte) und
/// ist damit - trotz nomineller M00/M02/M04-Ownership in module_map.yaml -
/// ein DRITTER Orchestrator neben psk-conformance/psk-cli, kein reines
/// Pipelinemodul. Direkt an `boot.rs` verifiziert, nicht angenommen: Schritt
/// 8 ruft `psk_topology::nodes/edges/cells` (M22), Schritt 17
/// `psk_effect::register_only_versioned_operators_and_capabilities` (M15/
/// M16), Schritt 18 `psk_certify::compute_release_and_operational_posture`
/// (M21) - alle drei sind die urspruenglich von diesem Werkzeug gemeldeten
/// psk-contract-Funde, alle drei durch eine numerierte Algorithmus-17.1-
/// Stelle im tatsaechlichen Code belegt, keine erratene Ausnahme.
fn is_orchestrator(package: &str) -> bool {
    matches!(package, "psk-contract")
}

/// Kernpruefung von T-PORT-001: fuer jede Paket-zu-Paket-Cargo-Kante
/// zwischen zwei MODULBESITZENDEN Paketen (Orchestratoren/Werkzeuge wie
/// psk-conformance, psk-cli, alle tools/* besitzen KEIN M00-M27-Modul und
/// sind damit automatisch ausgenommen - Definition 3.1s geschlossene
/// Modulmenge, nicht Ratespiel; psk-contract besitzt zwar Module, ist aber
/// laut `is_orchestrator` ebenfalls ausgenommen), die nicht auf eine der
/// vier `is_foundational_dependency`-Ausnahmen zielt, muss ein Port
/// zwischen ihren Modulen bestehen.
fn check_unjustified_package_edges(regs: &Registers) -> Vec<String> {
    let mut problems = Vec::new();
    for (pkg, deps) in &regs.package_deps {
        if is_orchestrator(pkg) {
            continue;
        }
        let Some(from_modules) = regs.modules_of.get(pkg) else {
            continue; // pkg besitzt kein Modul - kein Pipelinemitglied, siehe Doc
        };
        for dep in deps {
            if is_foundational_dependency(dep) {
                continue;
            }
            let Some(to_modules) = regs.modules_of.get(dep) else {
                continue; // dep besitzt kein Modul (Werkzeug/Adapter) - kein Portbezug erwartet
            };
            if !any_port_connects(&regs.ports, from_modules, to_modules) {
                problems.push(format!(
                    "T-PORT-001: {pkg} ({}) haengt von {dep} ({}) ab, aber kein Port verbindet \
                     ihre Module - direkte modulueberschreitende Kante ohne Portdeckung",
                    from_modules.join(","),
                    to_modules.join(",")
                ));
            }
        }
    }
    problems
}

/// Invariante 26.3, woertlich benannte Einzelfaelle, unabhaengig von der
/// generischen Portdeckungspruefung oben verifiziert.
fn check_named_invariant_26_3(regs: &Registers) -> Vec<String> {
    let mut problems = Vec::new();

    if let Some(deps) = regs.package_deps.get("psk-types") {
        if !deps.is_empty() {
            problems.push(format!(
                "Invariante 26.3: psk-types soll keine internen Abhaengigkeiten haben, hat aber {deps:?}"
            ));
        }
    }
    if let Some(deps) = regs.package_deps.get("psk-canon") {
        let extra: Vec<&String> = deps.iter().filter(|d| d.as_str() != "psk-types").collect();
        if !extra.is_empty() {
            problems.push(format!(
                "Invariante 26.3: psk-canons einzige interne Abhaengigkeit soll psk-types sein, \
                 zusaetzlich gefunden: {extra:?}"
            ));
        }
    }
    let observe_dependents: Vec<&String> = regs
        .package_deps
        .iter()
        .filter(|(pkg, deps)| pkg.as_str() != "psk-observe" && deps.contains("psk-observe"))
        .map(|(pkg, _)| pkg)
        .collect();
    if !observe_dependents.is_empty() {
        problems.push(format!(
            "Invariante 26.3: psk-observe wird von keinem anderen Paket referenziert, \
             gefunden: {observe_dependents:?}"
        ));
    }
    if let Some(deps) = regs.package_deps.get("psk-effect") {
        if deps.contains("psk-anchor") {
            problems.push(
                "Invariante 26.3: psk-effect DARF NICHT psk-anchor referenzieren \
                 (Beobachterteil-Trennung)"
                    .to_string(),
            );
        }
    }

    problems
}

fn main() -> ExitCode {
    let root = workspace_root();
    let regs = load_registers(&root);

    let mut problems: Vec<String> = Vec::new();
    problems.extend(check_module_cycle(&regs));
    problems.extend(check_forbidden_edges(&regs));
    problems.extend(check_package_cycle(&regs));
    problems.extend(check_unjustified_package_edges(&regs));
    problems.extend(check_named_invariant_26_3(&regs));

    if problems.is_empty() {
        eprintln!(
            "verify-dependencies: PASS — Modul- und Paketgraph azyklisch, {} verbotene Kanten \
             abwesend, Paketabhaengigkeiten portgedeckt oder begruendet ausgenommen.",
            regs.forbidden_edges.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!("verify-dependencies: FAIL —");
        for p in &problems {
            eprintln!("    - {p}");
        }
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn regs_from_real_workspace() -> Registers {
        load_registers(&workspace_root())
    }

    fn edges(pairs: &[(&str, &str)]) -> Vec<PortEntry> {
        pairs
            .iter()
            .map(|(f, t)| PortEntry {
                from: f.to_string(),
                to: t.to_string(),
            })
            .collect()
    }

    #[test]
    fn find_cycle_detects_a_real_cycle() {
        let nodes: BTreeSet<String> = ["A", "B", "C"].iter().map(|s| s.to_string()).collect();
        let mut e: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        e.entry("A".into()).or_default().insert("B".into());
        e.entry("B".into()).or_default().insert("C".into());
        e.entry("C".into()).or_default().insert("A".into());
        let cycle = find_cycle(&nodes, &e);
        assert!(
            !cycle.is_empty(),
            "A->B->C->A muss als Zyklus gefunden werden"
        );
    }

    #[test]
    fn find_cycle_reports_acyclic_graph_as_empty() {
        let nodes: BTreeSet<String> = ["A", "B", "C"].iter().map(|s| s.to_string()).collect();
        let mut e: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        e.entry("A".into()).or_default().insert("B".into());
        e.entry("B".into()).or_default().insert("C".into());
        assert!(find_cycle(&nodes, &e).is_empty());
    }

    #[test]
    fn the_real_module_graph_is_now_fully_acyclic_all_four_findings_closed() {
        // Vier Funde, jeweils an der Quelle bzw. an echtem Code verifiziert,
        // nicht geraten - keiner durch eine erratene Ausnahme geschlossen:
        // (1) M09/M13 (P39) - PSK-RA v1.0.14 korrigierte Invariante 2.3s
        //     invertierte Schichtungleichung und nahm P39 als fuenften
        //     benannten Rueckflusskanal auf.
        // (2) M11/M22 (P16/P17) - PSK-RA v1.0.15 ergaenzte die Ausnahme
        //     "gemeinsame Passtraeger": Pass C9 (pass_registry.yaml) fuehrt
        //     `modules: [M11, M22]` bereits gemeinsam, siehe `shares_a_pass`.
        // (3) M08/M20 (P31/P32) - PSK-RA v1.0.16 ergaenzte die Art-Spalte
        //     (`kind`) fuer alle 42 Ports und bestaetigte P31 explizit als
        //     denselben Anruf-Ruecksprung-Charakter wie P00/P05
        //     (Fehlerkorrektur-Befund 20) - an echtem Code bereits vorher
        //     verifiziert (morphogenesis.rs: `decide_transition` ruft
        //     `complete_transition`, M08s eigene Funktion, synchron im
        //     selben Cargo-Paket auf), jetzt normativ bestaetigt statt nur
        //     strukturell vermutet. Siehe `is_verified_call_return_leg`.
        // (4) Keine weiteren - siehe die naechsten beiden Tests: die
        //     mechanische Ausbreitung von `kind: request` auf alle 42 Ports
        //     haette (falsch) auch jede gewoehnliche Vorwaertskante entfernt
        //     und eine echte vierte Verletzung stillschweigend verdeckt,
        //     statt sie zu loesen - deshalb die enge, aufgezaehlte Fassung.
        let regs = regs_from_real_workspace();
        assert_eq!(check_module_cycle(&regs), None, "{:?}", check_module_cycle(&regs));
    }

    #[test]
    fn is_verified_call_return_leg_matches_exactly_the_two_verified_pairs() {
        // Bewusst eng: nur die beiden an echtem Code verifizierten
        // Ruecksprung-Kanten, keine generische kind:request-Regel (siehe
        // module_graph_edges' Kopfkommentar).
        assert!(is_verified_call_return_leg(&PortEntry {
            from: "M04".into(),
            to: "M26".into(),
        }));
        assert!(is_verified_call_return_leg(&PortEntry {
            from: "M20".into(),
            to: "M08".into(),
        }));
        // Die dazugehoerigen VORWAERTS-Kanten (P00, P32) brauchen die
        // Ausnahme nicht (sie schliessen keinen Kreis) und sind bewusst
        // NICHT Teil dieser Aufzaehlung.
        assert!(!is_verified_call_return_leg(&PortEntry {
            from: "M26".into(),
            to: "M00".into(),
        }));
        assert!(!is_verified_call_return_leg(&PortEntry {
            from: "M08".into(),
            to: "M20".into(),
        }));
        // Irgendein anderer kind:request-Port (z.B. P18, gewoehnliche
        // Vorwaertspipeline) darf NICHT matchen - das ist genau der Fehler,
        // den die alte, breite Fassung gemacht haette.
        assert!(!is_verified_call_return_leg(&PortEntry {
            from: "M11".into(),
            to: "M12".into(),
        }));
    }

    #[test]
    fn without_the_call_return_exception_m08_m20_would_cycle() {
        // Zeigt, dass die Ausnahme tatsaechlich traegt (nicht wirkungslos
        // ist): P31 und P32 sind REALE, im Register eingetragene Kanten
        // (aus dem echten Workspace gelesen, nicht erfunden) - ungeprueft
        // als gewoehnliche Architekturkanten behandelt, bilden genau sie
        // den Zyklus, den PSK-RA v1.0.16 als Nicht-Verstoss bestaetigt hat.
        // Entfernen aus `regs.ports` waere hier der falsche Test (das
        // entfernt die KANTE selbst, nicht nur ihre Ausnahme) - stattdessen
        // `find_cycle` direkt auf das reale Paar angewandt, ohne jede
        // Ausnahmelogik dazwischen.
        let regs = regs_from_real_workspace();
        let real_pair: BTreeMap<String, BTreeSet<String>> = regs
            .ports
            .iter()
            .filter(|p| (p.from == "M08" && p.to == "M20") || (p.from == "M20" && p.to == "M08"))
            .fold(BTreeMap::new(), |mut edges, p| {
                edges
                    .entry(p.from.clone())
                    .or_default()
                    .insert(p.to.clone());
                edges
            });
        assert_eq!(
            real_pair.values().map(|t| t.len()).sum::<usize>(),
            2,
            "P31 und P32 muessen beide als reale Kanten im Register stehen: {real_pair:?}"
        );
        let nodes: BTreeSet<String> = ["M08".to_string(), "M20".to_string()].into_iter().collect();
        assert!(
            !find_cycle(&nodes, &real_pair).is_empty(),
            "M08<->M20 muss ohne die Ausnahme als Zyklus erkannt werden"
        );
    }

    #[test]
    fn ordinary_forward_pipeline_ports_stay_in_the_cycle_graph_despite_kind_request() {
        // Regressionswache gegen genau den Fehler, den die fruehere, breite
        // "jeder kind:request-Port ist ausgenommen"-Fassung gemacht haette:
        // P18 (M11->M12, ClosureReport) ist seit PSK-RA v1.0.16 `kind:
        // request` wie 32 andere gewoehnliche Vorwaertsports auch - keiner
        // von ihnen ist ein Anruf-Ruecksprung-Fall, alle muessen im
        // Zyklengraphen bleiben, sonst prueft T-ARCH-002 fast nichts mehr.
        let regs = regs_from_real_workspace();
        assert!(
            regs.ports.iter().any(|p| p.from == "M11" && p.to == "M12"),
            "P18 muss im realen Register existieren"
        );
        let graph = module_graph_edges(&regs);
        assert!(
            graph.get("M11").is_some_and(|targets| targets.contains("M12")),
            "P18 (M11->M12) muss trotz kind:request im Zyklengraphen bleiben: {graph:#?}"
        );
    }

    #[test]
    fn shares_a_pass_finds_a_common_carrier_symmetrically() {
        let passes = vec![PassEntry {
            modules: vec!["M11".into(), "M22".into()],
        }];
        assert!(shares_a_pass("M11", "M22", &passes));
        assert!(
            shares_a_pass("M22", "M11", &passes),
            "muss symmetrisch sein"
        );
        assert!(!shares_a_pass("M11", "M08", &passes));
    }

    #[test]
    fn the_real_pass_registry_lists_m11_and_m22_as_joint_carriers_of_c9() {
        // PSK-RA v1.0.15: Pass C9 (ClosureAndGluing) ist der reale Beleg
        // fuer die "gemeinsame Passtraeger"-Ausnahme, nicht nur behauptet.
        let regs = regs_from_real_workspace();
        assert!(shares_a_pass("M11", "M22", &regs.passes));
    }

    #[test]
    fn without_the_shared_pass_exception_m11_m22_would_cycle() {
        // Zeigt, dass die Ausnahme tatsaechlich traegt (nicht wirkungslos
        // ist): ohne passes bildet der M11<->M22-Portpaar wieder den
        // Zyklus, den PSK-RA v1.0.15 als Nicht-Verstoss erklaert hat.
        let mut regs = regs_from_real_workspace();
        regs.passes.clear();
        let cycle = check_module_cycle(&regs);
        assert!(
            cycle
                .as_deref()
                .is_some_and(|c| c.contains("M11") && c.contains("M22")),
            "{cycle:?}"
        );
    }

    #[test]
    fn mutation_introduces_a_second_module_cycle_and_is_caught() {
        // T-ARCH-002s Mutationsszenario: eine kuenstliche Rueckkante fuegt
        // einen ZWEITEN, unabhaengigen Zyklus ein. DFS in BTreeSet-
        // Reihenfolge erreicht M00 vor M09 (alphabetisch), findet den neu
        // eingefuegten M00-Zyklus deshalb zuerst - die bestehende M09/M13-
        // Altlast (siehe Test oben) verdeckt diesen Fund nicht.
        let mut regs = regs_from_real_workspace();
        // M00 -> M01 -> M02 -> M03 -> M04 existiert bereits reihum (P01-P04);
        // eine zusaetzliche M04 -> M00-Kante schliesst den Kreis.
        regs.ports.push(PortEntry {
            from: "M04".into(),
            to: "M00".into(),
        });
        let cycle = check_module_cycle(&regs);
        assert!(
            cycle.as_deref().is_some_and(|c| c.contains("M00")),
            "{cycle:?}"
        );
    }

    #[test]
    fn wildcard_exclusion_removes_wildcard_ports_from_the_cycle_graph() {
        // P28 (*->M19) und P30 (M25->*) woertlich entfaltet wuerden mit
        // dem echten P29 (M19->M25) einen Scheinzyklus bilden - siehe
        // Modulkopf. Direkter Mechanismusnachweis statt Gesamtsauberkeits-
        // annahme (die reale Registerlage hat unabhaengig davon einen
        // offenen Fund, siehe Test oben): keine Wildcard-Kante taucht im
        // gebauten Graphen ueberhaupt auf.
        let regs = regs_from_real_workspace();
        assert!(regs.ports.iter().any(|p| p.from == "*" || p.to == "*"));
        let graph = module_graph_edges(&regs);
        assert!(!graph.contains_key("*"));
        assert!(graph.values().all(|targets| !targets.contains("*")));
    }

    #[test]
    fn forbidden_edge_present_as_a_real_port_is_flagged() {
        let mut regs = regs_from_real_workspace();
        regs.forbidden_edges = vec![vec!["M16".into(), "M15".into()]];
        regs.ports = edges(&[("M16", "M15")]);
        let problems = check_forbidden_edges(&regs);
        assert_eq!(problems.len(), 1);
    }

    #[test]
    fn three_element_forbidden_edge_is_skipped_not_misread_as_unconditional() {
        // ["*", M19, delete_or_overwrite] darf NICHT jede M19-Kante
        // (z.B. das reale, legitime P23 M16->M19) als Verstoss melden.
        let mut regs = regs_from_real_workspace();
        regs.forbidden_edges = vec![vec!["*".into(), "M19".into(), "delete_or_overwrite".into()]];
        regs.ports = edges(&[("M16", "M19")]);
        assert!(check_forbidden_edges(&regs).is_empty());
    }

    #[test]
    fn the_real_forbidden_edges_are_absent_from_the_real_port_registry() {
        let regs = regs_from_real_workspace();
        assert!(
            check_forbidden_edges(&regs).is_empty(),
            "{:?}",
            check_forbidden_edges(&regs)
        );
    }

    #[test]
    fn the_real_package_graph_is_acyclic() {
        let regs = regs_from_real_workspace();
        assert_eq!(check_package_cycle(&regs), None);
    }

    #[test]
    fn mutation_introduces_a_package_cycle_and_is_caught() {
        // T-PORT-001-benachbarte Mutation auf Paketebene: eine
        // kuenstliche Rueckkante schliesst einen Kreis.
        let mut regs = regs_from_real_workspace();
        let target = regs
            .package_deps
            .get("psk-types")
            .cloned()
            .unwrap_or_default();
        assert!(
            target.is_empty(),
            "psk-types haengt real von nichts ab - Vorbedingung fuer diesen Test"
        );
        regs.package_deps
            .entry("psk-types".to_string())
            .or_default()
            .insert("psk-canon".to_string()); // psk-canon haengt bereits von psk-types ab
        assert!(check_package_cycle(&regs).is_some());
    }

    #[test]
    fn the_real_package_dependencies_are_all_port_justified_or_exempt() {
        // psk-contracts drei urspruenglich gemeldeten Funde sind an
        // boot.rs verifiziert (Algorithmus 17.1 Schritt 8/17/18) und ueber
        // `is_orchestrator` ausgenommen - siehe deren Modulkopf.
        // psk-adversarials frueherer Fund (M24::split() rief real
        // `psk_witness::has_independent_evidence` auf) ist behoben:
        // `split()` nimmt seither `has_independent_evidence: bool` als
        // deklarierten Parameter entgegen (kernel.rs), die
        // psk-witness-Abhaengigkeit ist aus psk-adversarial/Cargo.toml
        // vollstaendig entfernt, nicht nur zu dev-dependencies verschoben
        // (die Tests brauchten sie ohnehin nur fuer einen Platzhalterwert,
        // jetzt per Struct-Literal statt `make_evidence`). T-PORT-001 ist
        // damit real gruen - alle Paketkanten sind portgedeckt oder
        // begruendet ausgenommen.
        let regs = regs_from_real_workspace();
        let problems = check_unjustified_package_edges(&regs);
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn mutation_adds_an_unjustified_cross_module_dependency() {
        // T-PORT-001s eigenes Mutationsszenario: eine neue, nicht
        // portgedeckte Paketkante zwischen zwei modulbesitzenden Paketen.
        // Delta statt absoluter Zahl: die reale Registerlage hat bereits
        // einen unabhaengigen offenen Fund (psk-adversarial/psk-witness,
        // siehe Test oben) - die Mutation muss GENAU EINEN zusaetzlichen
        // Fund erzeugen, nicht den Gesamtzustand auf 1 zuruecksetzen.
        let mut regs = regs_from_real_workspace();
        let before = check_unjustified_package_edges(&regs).len();
        // psk-observe (M27) und psk-scheduler (M25): kein Port verbindet
        // sie (M27 hat laut forbidden_edges gar keine ausgehende Kante).
        regs.package_deps
            .entry("psk-observe".to_string())
            .or_default()
            .insert("psk-scheduler".to_string());
        let problems = check_unjustified_package_edges(&regs);
        assert_eq!(problems.len(), before + 1, "{problems:#?}");
        assert!(problems
            .iter()
            .any(|p| p.contains("psk-observe") && p.contains("psk-scheduler")));
    }

    #[test]
    fn foundational_dependencies_are_never_flagged_even_without_a_port() {
        let regs = regs_from_real_workspace();
        // psk-gate (M14) haengt von psk-trace (M19) ab - kein M14<->M19-Port
        // existiert, das ist die ausdrueckliche psk-trace-Ausnahme.
        assert!(regs
            .package_deps
            .get("psk-gate")
            .map(|d| d.contains("psk-trace"))
            .unwrap_or(false));
        let problems = check_unjustified_package_edges(&regs);
        assert!(
            !problems
                .iter()
                .any(|p| p.contains("psk-gate") && p.contains("psk-trace")),
            "{problems:#?}"
        );
    }

    #[test]
    fn the_real_workspace_satisfies_invariant_26_3() {
        let regs = regs_from_real_workspace();
        let problems = check_named_invariant_26_3(&regs);
        assert!(problems.is_empty(), "{problems:#?}");
    }

    #[test]
    fn mutation_makes_psk_observe_a_dependency_of_another_package() {
        let mut regs = regs_from_real_workspace();
        regs.package_deps
            .entry("psk-fields".to_string())
            .or_default()
            .insert("psk-observe".to_string());
        let problems = check_named_invariant_26_3(&regs);
        assert_eq!(problems.len(), 1, "{problems:#?}");
    }

    #[test]
    fn mutation_makes_psk_effect_depend_on_psk_anchor() {
        let mut regs = regs_from_real_workspace();
        regs.package_deps
            .entry("psk-effect".to_string())
            .or_default()
            .insert("psk-anchor".to_string());
        let problems = check_named_invariant_26_3(&regs);
        assert_eq!(problems.len(), 1, "{problems:#?}");
    }
}
