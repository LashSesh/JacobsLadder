//! QPM-3 (lineare Zeit, Phasenlift, Zyklusindex, Channel-Switch-Witness)
//! ueber dem realen, getakteten Referenzlauf.
//!
//! Jeder Test hier misst; keiner setzt. Die Gegenproben sind der Teil,
//! der die Positivbefunde tragfaehig macht - ohne sie waere "0 Luecken"
//! nicht von "das Lueckenregister ist nicht fuellbar" zu unterscheiden.

use psk_conformance::{
    cycle_index_matches_ticks, observe_cycle, run_golden_run, BoundaryKind, ChannelId, LeakStatus,
    Orientation, SamplingRate, TWELFTHS_PER_TURN,
};

fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
        assert!(dir.pop(), "keine Workspace-Wurzel");
    }
    dir
}

/// Je Test eine eigene Sandbox: `psk_contract::boot` nimmt einen
/// Store-Lock auf `store_root`, und die Tests dieses Binaries laufen
/// nebenlaeufig. Ein geteilter Pfad ergaebe BootPreconditionFailed am
/// Lock - richtig gesperrt, nur falsch aufgerufen.
fn run(name: &str) -> psk_conformance::GoldenRunReport {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-qpm3-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&sandbox);
    let r = run_golden_run(&root, &sandbox).expect("Referenzlauf");
    std::fs::remove_dir_all(&sandbox).ok();
    r
}

fn channel() -> ChannelId {
    ChannelId("topology".into())
}

/// Der Grund, aus dem QPM-3 bisher domaenenblockiert war, faellt weg:
/// der Lauf taktet real, und der Zyklusindex ist damit ABGELESEN statt
/// konstruiert. Die eigentliche Aussage steckt in der Gegenprobe: n_k
/// entsteht aus der Formel ueber den Siegeln, `ticks` aus
/// `Sigma.tick_no` - zwei unabhaengige Wege auf denselben Wert.
#[test]
fn the_cycle_index_is_read_off_the_seals_and_matches_the_tick_count() {
    let report = observe_cycle(
        &run("the_cycle_index_is_read_"),
        channel(),
        SamplingRate::EveryBoundary,
    )
    .expect("QPM-3");

    assert!(report.ticks > 0, "ohne Takte gaebe es keinen Umlauf");
    assert!(
        cycle_index_matches_ticks(&report),
        "n_k ({:?}) und tick_no ({}) muessen uebereinstimmen",
        report.roll_states.last().map(|r| r.n),
        report.ticks
    );
    assert_eq!(
        report.closed_turns, report.ticks,
        "jeder Takt MUSS als geschlossener Umlauf erscheinen"
    );
}

/// QPM Definition 2.3 (Angehobener Phasor): der Lift schreitet monoton fort,
/// die sichtbare Phase kehrt zurueck. Beides an denselben Rollzustaenden
/// geprueft - eine sichtbare Phase, die NICHT zurueckkehrt, waere kein
/// Phasor, und ein Lift, der zurueckkehrt, kein Lift.
#[test]
fn the_lift_advances_monotonically_while_the_visible_phase_returns() {
    let report = observe_cycle(
        &run("the_lift_advances_monoto"),
        channel(),
        SamplingRate::EveryBoundary,
    )
    .expect("QPM-3");
    let states = &report.roll_states;
    assert!(
        states.len() > 12,
        "mehr als ein Umlauf, sonst kehrt nichts zurueck"
    );

    for w in states.windows(2) {
        assert!(
            w[1].theta_hat_twelfths >= w[0].theta_hat_twelfths,
            "der Lift DARF nicht zurueckgehen"
        );
    }
    assert!(
        states.last().unwrap().theta_hat_twelfths > TWELFTHS_PER_TURN,
        "nach mehr als einem Umlauf steht der Lift jenseits von 2pi"
    );

    // Die sichtbare Phase kehrt zurueck: derselbe Wert tritt in
    // verschiedenen Umlaeufen auf.
    let first_turn: Vec<u64> = states
        .iter()
        .filter(|s| s.n == 0)
        .map(|s| s.theta_twelfths)
        .collect();
    let second_turn: Vec<u64> = states
        .iter()
        .filter(|s| s.n == 1)
        .map(|s| s.theta_twelfths)
        .collect();
    assert!(!first_turn.is_empty() && !second_turn.is_empty());
    assert!(
        second_turn.iter().any(|v| first_turn.contains(v)),
        "theta MUSS nach 2pi zurueckkehren: {first_turn:?} / {second_turn:?}"
    );

    // Und die Formel selbst, an jedem Zustand.
    for s in states {
        assert_eq!(s.theta_twelfths, s.theta_hat_twelfths % TWELFTHS_PER_TURN);
        assert_eq!(s.n, s.theta_hat_twelfths / TWELFTHS_PER_TURN);
    }
}

/// Regel "Keine Ablesung auf halber Rueckkehr" (QPM v1.0.7): jede
/// Beobachtung haengt an einem Siegel. Geprueft wird beides - dass jeder
/// Rollzustand einen Siegelbezug traegt UND dass dieser Bezug auf ein
/// echtes Segment des Laufs zeigt (ein erfundener Digest bestuende den
/// ersten Teil allein).
#[test]
fn every_reading_hangs_on_a_real_seal() {
    let r = run("every_reading_hangs_on_a");
    let report = observe_cycle(&r, channel(), SamplingRate::EveryBoundary).expect("QPM-3");
    let real_seals: std::collections::HashSet<_> = r
        .trace_segments
        .iter()
        .filter(|s| s.event_type.0.starts_with("phase.sealed.") || s.event_type.0 == "tick.closed")
        .map(|s| s.segment_digest)
        .collect();

    assert!(!report.roll_states.is_empty());
    for s in &report.roll_states {
        assert!(
            real_seals.contains(&s.seal_ref),
            "Ablesung ohne echtes Siegel: {:?}",
            s.machine_state
        );
        assert!(matches!(
            s.machine_state,
            BoundaryKind::PhaseSeal { .. } | BoundaryKind::CycleBoundary
        ));
    }
}

/// Regel "Die Abtastrate bestimmt die aufzeichnende Seite" (QPM v1.0.7):
/// tastet das Instrument jede Grenze ab, entsteht keine Luecke. Der
/// Negativnachweis daneben ist der eigentliche Test - eine gedrosselte
/// Rate MUSS die Differenz registrieren, und zwar GETRENNT vom
/// Massenzensus.
#[test]
fn a_reduced_sampling_rate_registers_the_difference_as_gaps() {
    let r = run("a_reduced_sampling_rate_");

    let full = observe_cycle(&r, channel(), SamplingRate::EveryBoundary).expect("QPM-3 voll");
    assert!(
        full.sampling_gaps.is_empty(),
        "wer jede Grenze abtastet, laesst keine aus"
    );
    assert_eq!(full.boundaries_sampled, full.seals_in_run);

    let thin =
        observe_cycle(&r, channel(), SamplingRate::CycleBoundariesOnly).expect("QPM-3 gedrosselt");
    assert_eq!(
        thin.seals_in_run, full.seals_in_run,
        "der LAUF versiegelt gleich viel - die Abtastrate aendert ihn nicht"
    );
    assert!(
        !thin.sampling_gaps.is_empty(),
        "die ausgelassenen Phasensiegel MUESSEN als Luecken erscheinen"
    );
    assert_eq!(
        thin.boundaries_sampled + thin.sampling_gaps.len(),
        thin.seals_in_run,
        "abgetastet plus Luecken MUSS die Siegel des Laufs ergeben"
    );

    // Getrennt vom Massenzensus: die Luecken beruehren die Massenklassen
    // nicht. Eine ausgelassene Grenze erzeugt keine Masse.
    let census = psk_conformance::observe_golden_run(&r, &workspace_root()).expect("QPM-1");
    let mass: usize = census.census.values().sum();
    assert_eq!(
        mass, census.total_mass,
        "der Zensus bleibt vollstaendig, egal wie fein QPM-3 abtastet"
    );
    assert!(
        thin.sampling_gaps.len() > mass,
        "die Luecken sind eine eigene Groesse, nicht eine Teilmenge der Masse: \
         {} Luecken gegen {} Masse",
        thin.sampling_gaps.len(),
        mass
    );
}

/// QPM Invariante 2.4 (Keine stille Millisekunde) und die vom Auftraggeber
/// verlangte Leerlauf/Belegung-Unterscheidung: BEIDE Arten kommen im
/// Lauf vor, und beide sind protokolliert - das Siegel IST der Nachweis
/// (Regel 24.4 (Der Golden Run läuft unter tick)). Kaeme nur eine Art
/// vor, waere die Unterscheidung nicht gemessen, sondern behauptet.
#[test]
fn idle_and_occupied_phases_both_occur_and_both_are_sealed() {
    let report = observe_cycle(
        &run("idle_and_occupied_phases"),
        channel(),
        SamplingRate::EveryBoundary,
    )
    .expect("QPM-3");

    assert!(
        report.occupied_boundaries > 0,
        "ein Lauf ohne belegte Phase haette nichts getan"
    );
    assert!(
        report.idle_boundaries > 0,
        "ein Lauf ohne Leerlaufphase koennte die Unterscheidung nicht belegen"
    );
    assert_eq!(
        report.occupied_boundaries + report.idle_boundaries,
        report.boundaries_sampled,
        "jede abgetastete Grenze ist genau eines von beidem"
    );
    // Keine stille Millisekunde: jede Grenze traegt ihr Siegel, auch die
    // leere - deshalb ist die Zahl der Siegel die Zahl der Grenzen.
    assert_eq!(report.seals_in_run, report.boundaries_sampled);
}

/// Die uebrigen Felder des Rollzustands (QPM Definition 2.7 (Rollzustand)), ehrlich
/// gefuehrt: Orientierung abgeleitet, Leckstatus AUSGEWIESEN nicht
/// behauptet.
#[test]
fn the_roll_state_carries_orientation_and_an_honest_leak_status() {
    let report = observe_cycle(
        &run("the_roll_state_carries_o"),
        channel(),
        SamplingRate::EveryBoundary,
    )
    .expect("QPM-3");
    for s in &report.roll_states {
        assert_eq!(
            s.orientation,
            Orientation::Forward,
            "die Kette laeuft vorwaerts"
        );
        assert_eq!(
            s.leak,
            LeakStatus::NotInstrumented,
            "QPM-7 ist nicht gebaut - 'kein Leck' waere eine Erfindung"
        );
        assert_eq!(s.channel, channel());
    }
}

/// Der Kanalwechsel: KEINER im Referenzlauf. Der Befund gehoert dem
/// LAUF, nicht dem Instrument - nachgewiesen dadurch, dass die
/// Zyklusgrenzen vorliegen, an denen ein Wechsel ueberhaupt zulaessig
/// waere (QPM Algorithmus 2.8 (Zyklusschnitt und Kanalwechsel)s `Seam_2pi`). Ein Instrument ohne
/// Zyklusgrenzen koennte den Unterschied nicht behaupten.
#[test]
fn no_channel_switch_occurs_and_the_run_is_why_not_the_instrument() {
    let report = observe_cycle(
        &run("no_channel_switch_occurs"),
        channel(),
        SamplingRate::EveryBoundary,
    )
    .expect("QPM-3");

    assert!(report.channel_switches.is_empty());
    assert!(
        report.closed_turns > 0,
        "es GIBT geschlossene Umlaeufe - an ihnen waere ein Wechsel zulaessig"
    );
    let boundaries = report
        .roll_states
        .iter()
        .filter(|s| s.machine_state == BoundaryKind::CycleBoundary)
        .count();
    assert_eq!(
        boundaries as u64, report.ticks,
        "je Takt eine Zyklusgrenze, an der das Instrument ablesen wuerde"
    );
}

/// QPM-OBL-002 deckelt auch diese Stufe: solange der Scope keinen
/// Katalog nennt, ist das Verdikt UNKNOWN - der richtige Ausgang, nicht
/// ein Fehlschlag.
#[test]
fn the_verdict_is_capped_at_unknown_for_the_declared_reason() {
    let report = observe_cycle(
        &run("the_verdict_is_capped_at"),
        channel(),
        SamplingRate::EveryBoundary,
    )
    .expect("QPM-3");
    assert_eq!(report.verdict, psk_conformance::IdentityVerdict::Unknown);
    assert!(report.verdict_reason.contains("QPM-OBL-002"));
}
