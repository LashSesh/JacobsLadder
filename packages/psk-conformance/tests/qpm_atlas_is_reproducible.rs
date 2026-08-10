//! QPM-4 (kanonische Signaturgrammatik, reproduzierbarer Multiview-Atlas)
//! ueber dem realen, getakteten Referenzlauf.
//!
//! Die Vorgabe des Auftraggebers: "zwei Laeufe, gleicher RunDescriptor,
//! gleicher Atlas - und nach v1.0.7 haengt jede Ablesung an einem
//! Siegel. Beide Laeufe takten identisch (R3 steht), der Atlas muss also
//! bitgleich sein. Faellt er das nicht, ist der Grund der Befund -
//! vermutlich eine Stelle, an der eine Messung an etwas anderem haengt
//! als am Siegel."

use psk_conformance::{
    atlas_digest, build_atlas, compare_atlases, load_qpm_profile, run_golden_run_with_certificate,
    seal_reproducibility,
};

fn workspace_root() -> std::path::PathBuf {
    let mut dir = std::env::current_dir().expect("cwd");
    while !(dir.join("Cargo.toml").is_file() && dir.join(".git").exists()) {
        assert!(dir.pop(), "keine Workspace-Wurzel");
    }
    dir
}

/// Je Test eine eigene Sandbox (Store-Lock, nebenlaeufige Tests).
fn certified(name: &str) -> psk_conformance::GoldenRunCertification {
    let root = workspace_root();
    let sandbox = std::env::temp_dir().join(format!("psk-a4-{}-{}", std::process::id(), name));
    let _ = std::fs::remove_dir_all(&sandbox);
    let c = run_golden_run_with_certificate(&root, &sandbox).expect("Zertifizierung");
    std::fs::remove_dir_all(&sandbox).ok();
    c
}

/// Das Stufenkriterium selbst. Die beiden Laeufe der Zertifizierung
/// teilen den RunDescriptor und takten identisch (R3), also MUSS der
/// Atlas bitgleich sein.
#[test]
fn two_runs_with_the_same_run_descriptor_yield_a_bit_identical_atlas() {
    let c = certified("repro");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");

    // Vorbedingung, gemessen statt angenommen: die beiden Laeufe SIND
    // replaygleich. Ohne sie prueefte der Vergleich unten nichts ueber
    // den Atlas, sondern ueber den Determinismus des Laufes.
    assert!(
        c.replay_check.canonical_digest_match && c.replay_check.gate_sequence_match,
        "Vorbedingung: R3 - beide Laeufe sind kanonisch gleich"
    );
    assert_eq!(c.first.ticks, c.second.ticks, "beide takten gleich");

    let a = build_atlas(&c.first, &profile).expect("Atlas 1");
    let b = build_atlas(&c.second, &profile).expect("Atlas 2");
    let cmp = compare_atlases(&a, &b).expect("Vergleich");

    assert!(
        cmp.reproducible,
        "der Atlas ist nicht bitgleich - Abweichungen: {:?}",
        cmp.divergences
    );
    assert!(
        cmp.divergences.is_empty(),
        "bitgleich, aber Stellen gemeldet: {:?}",
        cmp.divergences
    );
    assert_eq!(cmp.digest_a, cmp.digest_b);
}

/// `reproducible` ist eine Eigenschaft des VERGLEICHS, nicht eines
/// Laufes - und der einzige Schreibpfad ist `seal_reproducibility`.
/// Ohne diesen Test bliebe unbelegt, dass ein Einzellauf das Feld
/// wirklich offen laesst statt es stillschweigend zu setzen.
#[test]
fn a_single_run_leaves_reproducibility_open_with_a_stated_reason() {
    let c = certified("single");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");
    let mut a = build_atlas(&c.first, &profile).expect("Atlas");

    assert!(
        a.reproducible.is_none(),
        "ein Lauf kann keinen Vergleich bezeugen"
    );
    assert!(
        a.reproducibility_absent_reason
            .as_deref()
            .unwrap_or("")
            .contains("zweier Laeufe"),
        "der Nullstand MUSS erklaert sein"
    );

    let b = build_atlas(&c.second, &profile).expect("Atlas 2");
    let cmp = compare_atlases(&a, &b).expect("Vergleich");
    seal_reproducibility(&mut a, &cmp);
    assert_eq!(a.reproducible, Some(true));
    assert!(
        a.reproducibility_absent_reason.is_none(),
        "nach der Ableitung gibt es nichts mehr zu erklaeren"
    );
}

/// QPM Regel 2.9 (Keine Ablesung auf halber Rückkehr): jeder
/// SignatureVector haengt an einem Siegel des Laufes - und zwar an
/// einer ZYKLUSGRENZE, dem Punkt, an dem der Umlauf geschlossen ist.
/// Geprueft gegen die echten Segmente: ein erfundener Digest bestuende
/// die Existenzpruefung, nicht diese.
#[test]
fn every_signature_vector_hangs_on_a_real_cycle_boundary() {
    let c = certified("seal");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");
    let a = build_atlas(&c.first, &profile).expect("Atlas");

    let boundaries: std::collections::HashSet<_> = c
        .first
        .trace_segments
        .iter()
        .filter(|s| s.event_type.0 == "tick.closed")
        .map(|s| s.segment_digest)
        .collect();
    assert!(
        !boundaries.is_empty(),
        "Vorbedingung: der Lauf schliesst Umlaeufe"
    );

    assert!(!a.vectors.is_empty(), "der Atlas ist nicht leer");
    for v in &a.vectors {
        assert!(
            boundaries.contains(&v.trace_ref.0),
            "Kanal {} liest nicht an einer Zyklusgrenze",
            v.channel_ref.0
        );
    }
}

/// QPM Struktur 2.6 (Kanal): "Nicht deklarierte Kanaele werden nicht
/// als uebersehen gezaehlt." Der Atlas fuehrt die vier deklarierten und
/// KEINE Nullkomponente fuer die fuenf uebrigen - eine Null waere eine
/// Messung, die nicht stattfand.
#[test]
fn undeclared_channels_are_absent_not_zero() {
    let c = certified("channels");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");
    let a = build_atlas(&c.first, &profile).expect("Atlas");

    let names: Vec<&str> = a.vectors.iter().map(|v| v.channel_ref.0.as_str()).collect();
    assert_eq!(names.len(), 4, "vier deklarierte Kanaele: {names:?}");
    for undeclared in ["spectrum", "phase", "symmetry", "rank", "entropy"] {
        assert!(
            !names.contains(&undeclared),
            "{undeclared} ist nicht deklariert und DARF nicht mit null erscheinen"
        );
    }
    // Und jeder gefuehrte Kanal traegt wirklich Messwerte.
    for v in &a.vectors {
        assert!(
            !v.components.is_empty(),
            "Kanal {} ohne Komponente waere ein leerer Eintrag",
            v.channel_ref.0
        );
    }
}

/// QPM Regel 3.18 (Splitbild und Parallaxe): der effektive Witnessrang
/// folgt dem Abhaengigkeitsquotienten, nicht der Zahl der Sichten.
/// Sechs Sichten, eine Quotientenklasse - der Rang DARF nicht sechs
/// sein. Das ist derselbe Negativnachweis, den QPM-2 als
/// "correlated-views-counted-as-independent" fuehrt, hier am Atlas.
#[test]
fn the_rank_follows_the_quotient_not_the_number_of_views() {
    let c = certified("rank");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");
    let a = build_atlas(&c.first, &profile).expect("Atlas");

    assert_eq!(a.views.len(), 6, "sechs gebundene Projektionen");
    assert!(
        a.effective_witness_rank < a.views.len() as i64,
        "korrelierte Sichten DUERFEN den Rang nicht kuenstlich erhoehen: \
         Rang {} bei {} Sichten",
        a.effective_witness_rank,
        a.views.len()
    );
    assert_eq!(
        a.effective_witness_rank,
        psk_conformance::witness_rank(&c.first).effective_rank,
        "der Atlas uebernimmt den Rang, er rechnet ihn nicht neu"
    );
}

/// BEFUND, als erklaerter Nullstand gefuehrt: `calibration_ref` ist
/// laut QPM Struktur 3.13 (SignatureVector) pflichtig, und die Referenzdomaene fuehrt
/// kein Kalibrierungsobjekt (catalog_ref: null, QPM-OBL-002). Der Test
/// haelt beides fest - dass der Verweis fehlt UND dass der Grund
/// benannt ist. Ein erfundener Verweis bestuende ihn nicht.
#[test]
fn the_missing_calibration_is_a_declared_null_state() {
    let c = certified("calib");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");
    let a = build_atlas(&c.first, &profile).expect("Atlas");

    for v in &a.vectors {
        assert!(
            v.calibration_ref.is_none(),
            "es gibt kein Kalibrierungsobjekt, auf das verwiesen werden koennte"
        );
        assert!(
            v.calibration_absent_reason
                .as_deref()
                .unwrap_or("")
                .contains("QPM-OBL-002"),
            "der Nullstand MUSS seinen Grund nennen"
        );
    }
    // Die Bedingung, unter der das so bleibt: der Scope nennt keinen
    // Katalog. Bekommt er einen, faellt dieser Test - und das ist die
    // Aufforderung, die Kalibrierung zu verdrahten.
    assert!(
        profile.scope().policies.catalog_ref.is_none(),
        "sobald ein Katalog deklariert ist, MUSS calibration_ref zeigen"
    );
}

/// Die Gegenprobe zum Reproduzierbarkeitstest: der Vergleich kann
/// ueberhaupt Abweichungen finden. Ohne sie bliebe unbelegt, dass
/// `reproducible: true` etwas anderes ist als ein Vergleich, der nie
/// hinsieht.
#[test]
fn the_comparison_really_detects_a_difference() {
    let c = certified("negative");
    let profile = load_qpm_profile(&workspace_root()).expect("QPM-Profil");
    let a = build_atlas(&c.first, &profile).expect("Atlas");
    let mut b = a.clone();

    // Eine einzige Komponente veraendern - so wenig wie moeglich.
    let v = b.vectors.first_mut().expect("mindestens ein Vektor");
    let key = v.components.keys().next().cloned().expect("Komponente");
    v.components.insert(
        key.clone(),
        psk_types::objects::Scaled {
            schema: "psk.scaled/1.0".into(),
            numerator: 9_999,
            scale: 0,
        },
    );

    let cmp = compare_atlases(&a, &b).expect("Vergleich");
    assert!(
        !cmp.reproducible,
        "eine geaenderte Komponente MUSS auffallen"
    );
    assert!(
        cmp.divergences.iter().any(|d| d.contains("Komponenten")),
        "die Stelle MUSS benannt sein, nicht nur die Ungleichheit: {:?}",
        cmp.divergences
    );
    assert_ne!(cmp.digest_a, cmp.digest_b);
    // Und der Digest allein traegt das Urteil: auch ohne die
    // Stellenliste waere es erkannt.
    assert_ne!(atlas_digest(&a).unwrap(), atlas_digest(&b).unwrap());
}
