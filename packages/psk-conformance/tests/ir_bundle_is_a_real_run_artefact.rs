//! FC2: der IRBundle-Kandidat entsteht IM Lauf, nicht im Test.
//!
//! Bis v1.0.23 war `psk_ir::compile_ir_bundle` ein Stub mit Rueckgabetyp
//! `!`; kein Lauf brachte je ein IRBundle hervor, also war auch kein
//! Round-Trip messbar, also fehlte FC2 der Beleg und die Konformanzklasse
//! blieb bei C0. Dieser Test misst, was jetzt entsteht.

#[test]
fn the_golden_run_produces_an_ir_bundle_that_round_trips() {
    let root = {
        let mut dir = std::env::current_dir().expect("cwd");
        while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
            assert!(dir.pop(), "keine Workspace-Wurzel");
        }
        dir
    };
    let sandbox = std::env::temp_dir().join(format!("psk-ir-run-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);

    let report = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let bundle = &report.ir_bundle;

    println!("=== IRBundle-Kandidat des Referenzlaufs ===");
    println!("  Knoten          = {}", bundle.graph.nodes.len());
    println!("  Kanten          = {}", bundle.graph.edges.len());
    println!("  emission_class  = {:?}", bundle.emission_class);
    println!("  digest          = {}", bundle.digest);
    println!(
        "  Kantenzensus    = {:?}",
        psk_conformance::edge_census(bundle)
    );
    println!("  scope-Residuen  = {}", report.ir_scope_residues.len());
    println!("  Auslassungen    = {}", report.ir_omissions.len());
    for o in &report.ir_omissions {
        println!("     {o:?}");
    }

    // Round-Trip-Pflicht (Algorithmus 10.3) am LAUFARTEFAKT, nicht an
    // einem Fixture: ir_encode(ir_decode(x)) == x.
    let encoded = psk_ir::ir_encode(bundle).expect("encode");
    let decoded = psk_ir::ir_decode(&encoded).expect("decode");
    let reencoded = psk_ir::ir_encode(&decoded).expect("re-encode");
    assert_eq!(
        encoded, reencoded,
        "der Round-Trip MUSS verlustfrei sein (Algorithmus 10.3)"
    );

    // Invariante 10.7: keine Kante ohne Bedingungen - und Regel 10.9: keine
    // davon stets wahr. Das ist der Punkt der ganzen Uebung.
    for e in &bundle.graph.edges {
        assert!(
            !e.preconditions.is_empty() && !e.postconditions.is_empty(),
            "Invariante 10.7: Kante {:?} ohne Bedingungen",
            e.relation_sort
        );
        for p in e.preconditions.iter().chain(e.postconditions.iter()) {
            assert!(
                !p.0.trim().eq_ignore_ascii_case("true") && !p.0.trim().is_empty(),
                "Regel 10.9: stets wahres Praedikat an Kante {:?}",
                e.relation_sort
            );
        }
    }

    // Der Kandidat DARF nicht EXECUTABLE sein: executable_requires
    // verlangt all_18_cells_closed, und close_all_18 ist ein Stub.
    assert_eq!(
        bundle.emission_class,
        psk_types::objects::IRBundleEmissionClassKind::Hold,
        "ein EXECUTABLE vor geschlossenen Zellen waere ein Konformitaetsdefekt"
    );

    // Nicht leer: sonst wuerde der Test einen kaputten Zusammenbau als
    // 'ehrlich duenn' durchgehen lassen.
    assert!(!bundle.graph.nodes.is_empty(), "der Lauf hat reale Objekte");
    assert!(
        !bundle.graph.edges.is_empty(),
        "mindestens die deklarierten Relationen mit belegten Endpunkten MUESSEN Kanten tragen"
    );

    let _ = std::fs::remove_dir_all(&sandbox);
}
