//! Vertrag 9.7 ueber dem realen Graphen des Golden Run - und die
//! EXECUTABLE-Frage, ehrlich beantwortet.
//!
//! Bis v1.0.34 war `close_all_18` ein Stub und `glue` bekam ein
//! hartkodiertes `cells_closed: true`. Jetzt misst der Lauf: alle 18
//! Zellen schliessen, ein Teil davon VAKUUM (Regel 9.9 verlangt, genau
//! das auszuweisen: "18 geschlossen, davon N vakuum", nicht "18
//! geschlossen"), und EXECUTABLE scheitert nicht mehr an der Topologie,
//! sondern am blockierenden Residuum des offen gebliebenen
//! Korpuswiderspruchs - der Referenzkorpus enthaelt beide
//! Widerspruchsarten absichtlich.

#[test]
fn all_18_cells_close_and_the_vacuum_ones_are_disclosed() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-cells-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let report = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    let reports = &report.cell_reports;
    assert_eq!(reports.len(), 18, "Definition 9.4: |Delta| = 18");
    assert!(
        psk_topology::all_18_closed(reports),
        "Vertrag 9.7 ueber dem realen Graphen"
    );

    // Regel 9.9, Zaehlpflicht. Die genaue Zahl ist inhaltsadressiert
    // (H(Can(node)) mod 6) und wandert mit jedem Normdokumenttausch -
    // gepinnt wird deshalb die STRUKTUR, nicht der Zufallswert:
    let vacuum = psk_topology::vacuum_closed_count(reports);
    let empty = reports
        .iter()
        .filter(|r| r.occupancy == psk_topology::Occupancy::Empty)
        .count();
    assert_eq!(
        vacuum, empty,
        "vakuum geschlossen == leer (alle schliessen)"
    );
    // Der Lauf traegt genau EINEN Knoten einer Zentrumssorte (den
    // ThoughtBody-Kontext) - mindestens fuenf der sechs Zentrumszellen
    // sind also strukturell leer, egal wohin der Hash ihn legt.
    assert!(vacuum >= 5, "gemessen: {vacuum}");
    assert!(vacuum < 18, "der Graph ist nicht leer");
    println!("18 geschlossen, davon {vacuum} vakuum");

    for r in reports {
        // Regel 9.19: max_depth = 0 -> als trivial ausgewiesen.
        assert_eq!(
            r.closure_mode,
            psk_topology::ClosureMode::TrivialSingleChart
        );
        match r.occupancy {
            // Kein Knoten des Referenzlaufs traegt Witnessverweise -
            // die Aufloesung ist VAKUUM wahr und steht auch so da.
            psk_topology::Occupancy::Occupied => assert_eq!(
                r.refs_resolvable,
                psk_topology::RefsResolution::VacuousWitnesses
            ),
            psk_topology::Occupancy::Empty => {
                assert_eq!(r.refs_resolvable, psk_topology::RefsResolution::Vacuous)
            }
        }
        // EdgeContext::default() sondiert nicht (Zellen sind nicht
        // exklusiv) - Konfliktvermerke waeren hier ein Fehler.
        assert!(r.probe_notes.is_empty());
    }
}

#[test]
fn executable_fails_on_the_blocking_residue_not_on_topology() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-exec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let report = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    let x = &report.executable;
    // Die Topologieseite ist seit v1.0.34 KEIN Blocker mehr:
    assert!(x.fully_typed);
    assert!(x.anchor_bound_or_declared_unanchored);
    assert!(x.all_18_cells_closed);
    assert!(
        x.unique_global_section,
        "glue mit ABGELEITETEM cells_closed"
    );
    assert!(x.all_blocking_gates_pass);
    assert!(x.close720_phi_squared_trivially && x.close720_holonomy_trivially);

    // Was EXECUTABLE tatsaechlich verhindert: der offen gebliebene
    // Korpuswiderspruch residualisiert BLOCKIEREND (er ist ohne
    // Aussenrecord nicht aufloesbar) - und genau er steht namentlich da.
    assert!(!x.no_blocking_residue);
    assert!(
        x.blockers
            .iter()
            .any(|b| b.contains("golden-run-patch.txt")),
        "der Blocker traegt seinen Namen: {:?}",
        x.blockers
    );

    // Im Einzellauf bleibt der Replayschenkel offen (Definition 22.1:
    // Replayklasse ist eine Eigenschaft eines VERGLEICHS) - also ist
    // die EXECUTABLE-Frage hier UNENTSCHIEDEN, nicht "nein".
    assert_eq!(x.close720_replay_canon_eq, None);
    assert_eq!(x.executable_reachable(), None);
}

fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
        assert!(dir.pop(), "keine Workspace-Wurzel");
    }
    dir
}
