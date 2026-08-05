//! I8 (Phasentabelle 32.1, Klasse C5: "Independent Replay ... Zweiter
//! Prozess oder Rechner reproduziert die kanonischen Resultate.") als
//! Blackbox-Test ueber das tatsaechlich kompilierte `psk-cli`-Binary.
//! `CARGO_BIN_EXE_psk-cli` ist nur in einem Integrationstest wie diesem
//! (unter `tests/`) zuverlaessig gesetzt, nicht innerhalb des Binaries
//! selbst (Cargo kann waehrend des eigenen Testbuilds nicht auf sich
//! selbst verweisen). Dieser Prozess ruft `psk-cli golden-run
//! --independent` auf, der seinerseits einen zweiten, echten Kindprozess
//! startet - zwei tatsaechliche Betriebssystemprozesse insgesamt (dieser
//! Testprozess zaehlt nicht mit), kein simulierter Vergleich.

use std::process::Command;

#[test]
fn i8_independent_replay_reproduces_the_same_canonical_digest() {
    let sandbox = std::env::temp_dir().join(format!("psk-cli-i8-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&sandbox);

    let output = Command::new(env!("CARGO_BIN_EXE_psk-cli"))
        .arg("golden-run")
        .arg(&sandbox)
        .arg("--independent")
        .output()
        .expect("psk-cli sollte startbar sein");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "psk golden-run --independent sollte erfolgreich sein:\n{stderr}"
    );
    assert!(
        stderr.contains("PASS (I8)"),
        "Ausgabe sollte den I8-Erfolg explizit vermelden:\n{stderr}"
    );
    assert!(
        !stderr.contains("Digests weichen ab"),
        "zwei unabhaengige Prozesse duerfen nicht abweichen:\n{stderr}"
    );

    std::fs::remove_dir_all(&sandbox).ok();
}
