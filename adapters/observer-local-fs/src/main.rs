//! Beobachterprozess (Regel Einzelrechnerbetrieb: M17 plus
//! ObserverAdapter) - P24a-Realisierung. Liest laengenpraefigierte `Msg`-
//! Rahmen (psk-ipc) von stdin, wertet sie ueber `psk_anchor::serve_request`
//! gegen die echte `observe()`-Funktion aus, schreibt die Antwort auf
//! stdout. Beendet sich sauber bei EOF (Elternprozess - M26,
//! `proc.control` - hat die Pipe geschlossen).
//!
//! Diese eine Pipe - von M26 exklusiv fuer genau diesen Kindprozess
//! angelegt - ist die Prozessisolation, auf die sich die v1.0.13-
//! Praezisierung von Vertrag Herkunftsbeglaubigung an der Prozessgrenze
//! stuetzt (kein weiterer Codepfad in diesem Prozess schreibt auf
//! stdout).
//!
//! `root` kommt als Kommandozeilenargument (Argument 1), analog zu
//! `effect-local-fs`s `sandbox_root`.

use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use observer_local_fs::ObserverConfig;
use psk_types::objects::AdapterId;

fn main() -> ExitCode {
    let root: PathBuf = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("observer-local-fs: erwarte root als Argument 1");
            return ExitCode::FAILURE;
        }
    };
    let config = ObserverConfig::new(root);
    let observer_id = AdapterId("observer-local-fs".into());

    let mut input = stdin().lock();
    let mut output = stdout().lock();

    loop {
        let request = match psk_ipc::read_frame(&mut input) {
            Ok(None) => return ExitCode::SUCCESS,
            Ok(Some(msg)) => msg,
            Err(e) => {
                eprintln!("observer-local-fs: Rahmenfehler beim Lesen: {e}");
                return ExitCode::FAILURE;
            }
        };

        let response = psk_anchor::serve_request(
            |observed_at| {
                observer_local_fs::observe(&config, observed_at).map_err(|e| e.to_string())
            },
            observer_id.clone(),
            &request,
        );

        if let Err(e) = psk_ipc::write_frame(&mut output, &response) {
            eprintln!("observer-local-fs: Rahmenfehler beim Schreiben: {e}");
            return ExitCode::FAILURE;
        }
        if let Err(e) = output.flush() {
            eprintln!("observer-local-fs: Flush fehlgeschlagen: {e}");
            return ExitCode::FAILURE;
        }
    }
}
