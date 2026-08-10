//! QPM-0 und QPM-1 ueber dem Referenzlauf - der erste QPM-Lauf gegen
//! einen echten Messgegenstand statt gegen handgebaute Eingaben.
//!
//! Dieselbe Linie wie FC2, FC5 und FC7: was das System HERVORBRINGT
//! zaehlt, was ein Test ZEIGT nicht.

#[test]
fn the_reference_run_is_observed_and_the_books_balance() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let qpm = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");

    let mass = run.ir_bundle.graph.nodes.len();
    assert_eq!(qpm.total_mass, mass, "die ganze Masse ist verbucht");
    assert!(
        psk_conformance::books_balanced(&qpm, mass),
        "QPM Axiom 3.1 (Kein stiller Ausschluss): die Buchfuehrung geht auf"
    );

    println!("=== QPM-Beobachtung des Referenzlaufs ===");
    println!("Masse: {mass} IR-Knoten");
    for line in psk_conformance::census_lines(&qpm) {
        println!("  {line}");
    }

    // Alle vier Klassen erscheinen, auch die leeren - dieselbe Haltung
    // wie Regel 9.11 (Vakuum ist kein Beleg) auf der PSK-RA-Seite: eine
    // Null ist eine Aussage, kein Weglassen.
    assert_eq!(qpm.census.len(), 4);
    let visible = qpm.census[&psk_fields::MassClass::VisibleBody];
    let shadow = qpm.census[&psk_fields::MassClass::Shadow];
    let residue = qpm.census[&psk_fields::MassClass::Residue];
    let counter = qpm.census[&psk_fields::MassClass::CounterHorizon];
    assert_eq!(visible + shadow + residue + counter, mass);

    // DREI der vier Klassen sind real belegt. Die Residuenklasse wurde
    // erst mit v1.0.6 erreichbar: der Lauf oeffnet ein blockierendes
    // Residuum auf den Anker, und der Anker IST ein IR-Knoten - was
    // fehlte, war der Rueckverweis in `residue_refs`.
    assert!(visible > 0, "das Instrument erreicht etwas");
    assert!(shadow > 0, "und es erreicht nicht alles - echte Schatten");
    assert!(residue > 0, "und ein Teil der Masse ist residualisiert");
    // Gegenhorizont bleibt null: die Nullmodelle des Laufs sind
    // Aussagen UEBER ihn, keine Knoten IN ihm - das braucht die
    // reichere Domaene und wird nicht erzwungen.
    assert_eq!(counter, 0);
    println!("sichtbar {visible}, Schatten {shadow}, Residuum {residue}");

    // QPM Regel 3.9 (Präzedenz unter den Erzeugern): die Praezedenz wurde AUSGEUEBT, nicht nur
    // deklariert - und die verdraengte Klasse ist erhalten.
    assert!(
        !qpm.displaced.is_empty(),
        "die Praezedenz muss an dieser Masse greifen"
    );
    for (node, classes) in &qpm.displaced {
        // Residuum sticht Schatten: der Knoten zaehlt als Residuum ...
        assert_eq!(
            qpm.census_class_of(node),
            Some(psk_fields::MassClass::Residue)
        );
        // ... und fuehrt seinen Schattenbeleg weiter mit.
        assert!(classes.contains(&psk_fields::MassClass::Shadow));
        assert!(
            qpm.shadows.iter().any(|(n, _)| n == node),
            "der ShadowRecord bleibt bestehen: {node:?}"
        );
        println!("  verdraengt bei {}: {:?}", node.0, classes);
    }

    // QPM Regel 3.5 (Eine Apertur erzeugt Schatten, keine Abwesenheit): JEDER Schattenbeleg traegt seine Apertur - auch
    // der eines Knotens, den die Praezedenz woanders zaehlt.
    assert_eq!(qpm.shadows.len(), shadow + qpm.displaced.len());
    for (node, aperture) in &qpm.shadows {
        assert!(
            qpm.bank.aperture(aperture).is_some(),
            "die Apertur {aperture:?} von {node:?} steht in der Bank"
        );
    }

    // QPM Regel 3.5 (Eine Apertur erzeugt Schatten, keine Abwesenheit): eine Apertur, die alles durchlaesst, ist keine.
    qpm.bank
        .check_predicates()
        .expect("kein stets wahres pass_predicate");
}

#[test]
fn the_verdict_is_unknown_because_no_catalog_is_registered() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-v-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let qpm = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");

    // QPM-OBL-002, ueber QPM Regel 3.3 (Scope ist explizit, nie universell): "Fehlt catalog_ref, so endet
    // jeder Lauf in UNKNOWN, nicht in FAIL."
    assert_eq!(qpm.verdict, psk_conformance::IdentityVerdict::Unknown);
    assert_ne!(qpm.verdict, psk_conformance::IdentityVerdict::Invalid);
    assert!(qpm.verdict_reason.contains("catalog_ref"));
    assert_eq!(qpm.scope.ceiling(), psk_fields::ScopeCeiling::ForcedUnknown);

    // QPM Regel 4.3 (Zwei orthogonale Statusachsen): die beiden Achsen sind unabhaengig. Der Lauf ist
    // valide gemessen (RunGate PASS) UND das Verdikt ist UNKNOWN -
    // "diese Kombination ist ausdruecklich erwuenscht".
    assert_eq!(qpm.run_gate, psk_conformance::RunGate::Pass);
    println!("Verdikt: {:?} ({})", qpm.verdict, qpm.verdict_reason);
    println!("RunGate: {:?}", qpm.run_gate);
}

#[test]
fn undeclared_channels_are_named_never_treated_as_absent() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-c-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let qpm = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");

    // QPM Struktur 3.19 (SignatureAtlas) nennt neun Kanaele; der Lauf
    // deklariert vier. Der Titel ist kein Schmuck: dieselbe Tatsache
    // stand hier eine Runde lang OHNE ihn unter der damaligen Nummer,
    // die v1.0.5 neu besetzte - die Stelle zeigte danach stumm auf ein
    // fremdes Objekt, waehrend die getitelte Zwillingsstelle im
    // Domaenenprofil laut durchfiel. Gleicher Fehler, gleiche Edition,
    // ein Unterschied.
    assert_eq!(qpm.scope.declared_channels.len(), 4);
    // Die uebrigen fuenf stehen BENANNT und BEGRUENDET da (QPM Regel
    // 3.3) - nicht als Abwesenheit, nicht als Luecke.
    assert_eq!(qpm.undeclared_channels.len(), 5);
    for (channel, reason) in &qpm.undeclared_channels {
        assert!(
            !reason.trim().is_empty(),
            "Kanal {channel:?} ohne Begruendung"
        );
        println!("  nicht deklariert: {} - {}", channel.0, reason);
    }

    // QPM Regel 3.7 (Gegenhorizont ist konstruiert oder begründet leer): der Gegenhorizont ist leer, aber begruendet - seit
    // v1.0.4 traegt die Struktur dafuer ein Feld.
    assert_eq!(
        qpm.counter_horizon_standing,
        psk_adversarial::CounterHorizonStanding::JustifiedEmpty
    );
    assert!(psk_conformance::findings_admissible(&qpm));
    println!(
        "{}",
        psk_conformance::counter_horizon_note(qpm.counter_horizon_standing)
    );
}

/// Die Zirkelfrage, als Test statt als Zusage.
///
/// PSK-RAs Klassenberechnung hat genau zwei Eingaenge: den abgeleiteten
/// Deckungsvektor und die sechs Abnahmeflaggen. Der Vektor kommt aus
/// `collect_feature_evidence`, die AUSSCHLIESSLICH
/// `GoldenRunCertification` und `BaselineComparison` liest.
///
/// Ein Rueckflusspfad entstuende also genau dann, wenn eine QPM-Ausgabe
/// in einem dieser Typen laege. Dieser Test haelt fest, dass die
/// QPM-Beobachtung den Lauf nicht veraendert - weder seinen Inhalt noch
/// seine Identitaeten.
#[test]
fn qpm_findings_cannot_reach_the_conformance_class() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-x-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");

    // Alles, was in die Klassenberechnung fliessen koennte, VOR der
    // Beobachtung festgehalten.
    let before = (
        run.ir_bundle.digest,
        run.trace_head,
        run.boot_report.identity.I_C,
        run.boot_report.identity.I_A,
        run.residues.len(),
        run.cell_reports.len(),
        run.executable.clone(),
    );

    let qpm = psk_conformance::observe_golden_run(&run, &root).expect("QPM-Beobachtung");
    // Das Verdikt ist UNKNOWN - der schaerfste Fall: WENN es
    // zurueckflosse, muesste es hier etwas veraendern.
    assert_eq!(qpm.verdict, psk_conformance::IdentityVerdict::Unknown);

    let after = (
        run.ir_bundle.digest,
        run.trace_head,
        run.boot_report.identity.I_C,
        run.boot_report.identity.I_A,
        run.residues.len(),
        run.cell_reports.len(),
        run.executable.clone(),
    );
    assert_eq!(before, after, "die Beobachtung veraendert den Lauf nicht");

    // Und die Signaturseite: `observe_golden_run` nimmt `&GoldenRunReport`
    // und gibt einen EIGENEN Typ zurueck. Waere `QpmRunReport` ein Feld
    // von `GoldenRunReport` oder `GoldenRunCertification`, koennte
    // `collect_feature_evidence` es lesen - es ist keines, und der
    // Compiler haelt das fest, weil dieser Test den Lauf unveraendert
    // weiterreicht.
    let evidence = psk_conformance::collect_feature_evidence(
        &psk_conformance::run_golden_run_with_certificate(&root, &sandbox).expect("Zertifizierung"),
        None,
    );
    let derived = psk_certify::derive_feature_coverage(&evidence);
    assert_eq!(
        derived.findings.len(),
        9,
        "der Deckungsvektor wird aus neun Stufen abgeleitet - keine davon ist QPM"
    );
}

fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
        assert!(dir.pop(), "keine Workspace-Wurzel");
    }
    dir
}

/// QPM-2: der effektive Witnessrang, gebunden statt neu gebaut - und
/// der blockierende Negativtest `correlated-views-counted-as-independent`
/// an genau diesem Lauf GEMESSEN.
///
/// Der Referenzlauf ist dafuer der richtige Fall: sechs Projektionen,
/// die alle dieselbe eine Ankerquelle teilen. Wer sie als unabhaengig
/// zaehlte, kaeme auf Rang sechs; der Abhaengigkeitsquotient sagt eins.
#[test]
fn correlated_views_are_not_counted_as_independent() {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm-r-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);
    let run = psk_conformance::run_golden_run(&root, &sandbox).expect("Golden Run");
    let rank = psk_conformance::witness_rank(&run);

    println!(
        "Sichten {}, unabhaengige Klassen {}, effective_rank {} ({})",
        rank.views, rank.independent_classes, rank.effective_rank, rank.method
    );

    // Der Rang kommt aus PSK-RAs Abhaengigkeitsquotienten, unveraendert.
    assert_eq!(rank.effective_rank, rank.independent_classes as i64);

    // Der Fall wird WIRKLICH geuebt: es gibt mehr Sichten als Klassen.
    // Ohne diese Zeile waere der Test gruen, auch wenn der Lauf gar
    // keine korrelierten Sichten haette - dieselbe Ueberlegung wie bei
    // den vakuum geschlossenen Zellen.
    assert!(
        rank.absorbed_by_correlation() > 0,
        "ohne korrelierte Sichten prueft dieser Test nichts: {rank:?}"
    );
    assert_eq!(rank.views, 6);
    assert_eq!(
        rank.sources, 1,
        "eine gemeinsame Quelle - das IST die Korrelation"
    );

    // Und der Negativtest selbst.
    assert!(
        rank.correlated_views_not_counted_as_independent(),
        "correlated-views-counted-as-independent: {rank:?}"
    );

    // Gegenprobe, damit das Bestehen nicht Zufall ist: haette der Lauf
    // die Sichten als unabhaengig gezaehlt, MUESSTE der Test fallen.
    let inflated = psk_conformance::WitnessRank {
        effective_rank: rank.views as i64,
        ..rank.clone()
    };
    assert!(
        !inflated.correlated_views_not_counted_as_independent(),
        "der Test muss den aufgeblaehten Rang zurueckweisen"
    );
}
