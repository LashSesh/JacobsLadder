//! Effektprozess (Regel Einzelrechnerbetrieb: M16 plus EffectAdapter) -
//! P24a-Realisierung. Liest laengenpraefigierte `Msg`-Rahmen (psk-ipc)
//! von stdin, wertet sie ueber `psk_effect::serve_request` gegen den
//! echten `LocalFsAdapter` aus, schreibt die Antwort auf stdout. Beendet
//! sich sauber bei EOF (Elternprozess - M26, `proc.control` - hat die
//! Pipe geschlossen).
//!
//! `sandbox_root` kommt als Kommandozeilenargument (Argument 1): der
//! Effektprozess hat keine eigene Konfigurationsquelle jenseits dessen,
//! was der spawnende Kernprozess ihm mitgibt - dieselbe Begruendung wie
//! bei `EffectAdapter::apply`s `started_at`-Parameter (M16 fuehrt keine
//! eigene Uhr, siehe psk-effect::boundary Modulkopf; hier: M16 fuehrt
//! auch keine eigene Konfiguration).

use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use effect_local_fs::LocalFsAdapter;

fn main() -> ExitCode {
    let sandbox_root: PathBuf = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("effect-local-fs: erwarte sandbox_root als Argument 1");
            return ExitCode::FAILURE;
        }
    };
    let mut adapter = LocalFsAdapter { sandbox_root };

    let mut input = stdin().lock();
    let mut output = stdout().lock();

    loop {
        let request = match psk_ipc::read_frame(&mut input) {
            Ok(None) => return ExitCode::SUCCESS,
            Ok(Some(msg)) => msg,
            Err(e) => {
                eprintln!("effect-local-fs: Rahmenfehler beim Lesen: {e}");
                return ExitCode::FAILURE;
            }
        };

        let response = psk_effect::serve_request(&mut adapter, &request);

        if let Err(e) = psk_ipc::write_frame(&mut output, &response) {
            eprintln!("effect-local-fs: Rahmenfehler beim Schreiben: {e}");
            return ExitCode::FAILURE;
        }
        if let Err(e) = output.flush() {
            eprintln!("effect-local-fs: Flush fehlgeschlagen: {e}");
            return ExitCode::FAILURE;
        }
    }
}
