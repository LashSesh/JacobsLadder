//! Liest den tatsaechlichen Dateisystemzustand einer lokalen Projektwurzel
//! (Regel 32.5, Erste Domaene: "isolierter, versionierter lokaler
//! Projektordner. Der Kern arbeitet zunaechst read-only") und baut daraus
//! einen ExternalRecord (Regel 32.8 (Anker der Referenzdomäne): "Der AnchorSnapshot bindet
//! Dateihashes, Git-Commit, Zeitstempel, Rechte, Konfiguration und
//! erlaubten Scope. Der Aussenrecord entsteht nach Ausfuehrung durch einen
//! unabhaengigen Adapter, der den tatsaechlichen Dateisystemzustand
//! liest.").
//!
//! Git-Commit-Erkennung liest ausschliesslich Dateien (.git/HEAD,
//! .git/refs/..., .git/packed-refs) statt einen `git`-Prozess aufzurufen -
//! deterministischer und ohne Umgebungsabhaengigkeit von einem installierten
//! Git-Binary.

use std::fs;
use std::path::{Path, PathBuf};

use psk_anchor::{ExternalRecord, FileObservation, HistoryPoint, ObservedPermissions};
use psk_types::{Digest, DualTime};

/// Konfiguration eines Beobachtungslaufs. Ihr Digest geht als
/// "Konfiguration" (Regel 32.8 (Anker der Referenzdomäne)) in den ExternalRecord ein, damit zwei
/// Laeufe mit unterschiedlicher Ausschlussliste nicht denselben Record
/// vortaeuschen.
#[derive(Debug, Clone)]
pub struct ObserverConfig {
    pub root: PathBuf,
    /// Verzeichnisnamen, die nicht betreten werden.
    pub excluded_dirs: Vec<String>,
}

impl ObserverConfig {
    /// `.git` ist immer ausgeschlossen: sein Zustand geht bereits gesondert
    /// als `git_commit` ein, nicht nochmal dateiweise.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        ObserverConfig {
            root: root.into(),
            excluded_dirs: vec![".git".to_string()],
        }
    }

    fn digest(&self) -> Digest {
        let mut buf = self.root.to_string_lossy().into_owned();
        for d in &self.excluded_dirs {
            buf.push('\0');
            buf.push_str(d);
        }
        Digest::sha256(buf.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObserveError {
    RootNotFound(PathBuf),
    Io(String),
}

impl std::fmt::Display for ObserveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ObserveError::RootNotFound(p) => {
                write!(f, "Beobachtungswurzel {} existiert nicht", p.display())
            }
            ObserveError::Io(e) => write!(f, "Dateisystemfehler: {e}"),
        }
    }
}

impl std::error::Error for ObserveError {}

/// Regel 32.8 (Anker der Referenzdomäne): liest den tatsaechlichen Dateisystemzustand unter
/// `config.root` read-only (Regel 32.5) und baut daraus einen
/// ExternalRecord. `observed_at` wird vom Aufrufer gestellt, nicht hier
/// erzeugt - dieser Adapter macht die Wanduhr nicht selbst verbindlich
/// (Invariante 6.14, Replayneutralitaet der Wanduhr).
pub fn observe(
    config: &ObserverConfig,
    observed_at: DualTime,
) -> Result<ExternalRecord, ObserveError> {
    if !config.root.is_dir() {
        return Err(ObserveError::RootNotFound(config.root.clone()));
    }
    let mut file_hashes = Vec::new();
    walk(
        &config.root,
        &config.root,
        &config.excluded_dirs,
        &mut file_hashes,
    )?;
    // Ordnungssemantik: file_hashes ist hier kein Register-Feld mit eigener
    // Vorschrift, aber deterministische Reihenfolge ist Voraussetzung fuer
    // einen reproduzierbaren ExternalRecord.
    file_hashes.sort_by(|a, b| a.relative_path.cmp(&b.relative_path));

    let permissions = ObservedPermissions {
        read_only: fs::metadata(&config.root)
            .map(|m| m.permissions().readonly())
            .unwrap_or(false),
    };

    Ok(ExternalRecord {
        file_hashes,
        git_commit: read_git_commit(&config.root),
        observed_at,
        permissions,
        configuration_digest: config.digest(),
        allowed_scope: config.root.to_string_lossy().into_owned(),
    })
}

fn walk(
    root: &Path,
    dir: &Path,
    excluded: &[String],
    out: &mut Vec<FileObservation>,
) -> Result<(), ObserveError> {
    for entry in fs::read_dir(dir).map_err(|e| ObserveError::Io(e.to_string()))? {
        let entry = entry.map_err(|e| ObserveError::Io(e.to_string()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| ObserveError::Io(e.to_string()))?;
        if file_type.is_dir() {
            let name = entry.file_name();
            if excluded
                .iter()
                .any(|e| e.as_str() == name.to_string_lossy())
            {
                continue;
            }
            walk(root, &path, excluded, out)?;
        } else if file_type.is_file() {
            let content = fs::read(&path).map_err(|e| ObserveError::Io(e.to_string()))?;
            let relative = path.strip_prefix(root).unwrap_or(&path);
            out.push(FileObservation {
                relative_path: relative.to_string_lossy().replace('\\', "/"),
                content_digest: Digest::sha256(&content),
            });
        }
    }
    Ok(())
}

/// Liest den aktuellen Git-Commit ueber reine Dateizugriffe (kein
/// Prozessaufruf): .git/HEAD, ggf. aufgeloest ueber .git/refs/... oder
/// .git/packed-refs. `None`, wenn die Wurzel kein Git-Repository ist oder
/// der Commit nicht aufloesbar ist (z.B. frisch initialisiertes Repo ohne
/// Commit) - beides ist kein Fehler, sondern ein zulaessiger Zustand.
fn read_git_commit(root: &Path) -> Option<String> {
    let git_dir = root.join(".git");
    let head = fs::read_to_string(git_dir.join("HEAD")).ok()?;
    let head = head.trim();
    match head.strip_prefix("ref: ") {
        Some(ref_path) => {
            if let Ok(commit) = fs::read_to_string(git_dir.join(ref_path)) {
                return Some(commit.trim().to_string());
            }
            let packed = fs::read_to_string(git_dir.join("packed-refs")).ok()?;
            packed.lines().find_map(|line| {
                let (commit, r) = line.split_once(' ')?;
                (r == ref_path).then(|| commit.to_string())
            })
        }
        // Detached HEAD: zeigt direkt auf einen Commit.
        None => Some(head.to_string()),
    }
}

/// Folgenbeobachtung statt Punktbeobachtung (Regel 32.7 (Feldfamilie der Referenzdomäne): "Historiker
/// rekonstruiert Versionen" braucht einen Gegenstand, `read_git_commit`
/// liefert nur die aktuelle Spitze). Liest `.git/logs/HEAD` vollstaendig -
/// dieselbe Disziplin wie `read_git_commit`: reine Dateizugriffe, kein
/// Git-Prozessaufruf. `None`, wenn die Wurzel kein Git-Repository ist oder
/// keine Reflog-Datei fuehrt (z.B. ein Shallow-Klon ohne Historie) - beides
/// ist kein Fehler, sondern derselbe zulaessige Zustand wie bei
/// `read_git_commit`. Aeltester Eintrag zuerst (Dateireihenfolge des Logs).
fn read_git_history(root: &Path) -> Option<Vec<HistoryPoint>> {
    let text = fs::read_to_string(root.join(".git").join("logs").join("HEAD")).ok()?;
    Some(text.lines().filter_map(parse_reflog_line).collect())
}

/// Eine Reflog-Zeile: `<alte-sha> <neue-sha> <name> <email> <ts> <tz>\t<nachricht>`.
/// Name und E-Mail koennen intern Leerzeichen tragen (Namen jedenfalls);
/// deshalb wird NICHT von vorn positionsweise gelesen, sondern die letzten
/// zwei wortweisen Felder vor dem Tabulator (Zeitzone, dann Zeitstempel)
/// bestimmen die Grenze - robust gegen die Wortzahl von Name/E-Mail.
fn parse_reflog_line(line: &str) -> Option<HistoryPoint> {
    let (header, message) = line.split_once('\t')?;
    let mut fields = header.split_whitespace();
    let _old_sha = fields.next()?;
    let new_sha = fields.next()?;
    let rest: Vec<&str> = fields.collect();
    if rest.len() < 2 {
        return None;
    }
    let observed_at_unix: i64 = rest[rest.len() - 2].parse().ok()?;
    Some(HistoryPoint {
        commit: new_sha.to_string(),
        observed_at_unix,
        message: message.to_string(),
    })
}

/// Oeffentlicher Einstieg, Gegenstueck zu `observe()`: EINE Folgenbeobachtung
/// statt eines ExternalRecord. `config.root` traegt bereits alles Noetige
/// (dieselbe Wurzel, aus der auch `observe()` liest).
pub fn observe_history(config: &ObserverConfig) -> Option<Vec<HistoryPoint>> {
    read_git_history(&config.root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::ClockRef;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "psk-observer-local-fs-test-{}-{}",
                std::process::id(),
                n
            ));
            fs::create_dir_all(&path).unwrap();
            TempDir(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 1,
            tau_e: "2026-01-01T00:00:00Z".into(),
            clock_ref: ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    #[test]
    fn missing_root_is_an_error() {
        let config = ObserverConfig::new("this-path-does-not-exist-anywhere");
        assert_eq!(
            observe(&config, sample_time()),
            Err(ObserveError::RootNotFound(PathBuf::from(
                "this-path-does-not-exist-anywhere"
            )))
        );
    }

    #[test]
    fn hashes_every_file_and_sorts_by_relative_path() {
        let dir = TempDir::new();
        fs::write(dir.0.join("b.txt"), b"second").unwrap();
        fs::write(dir.0.join("a.txt"), b"first").unwrap();
        fs::create_dir_all(dir.0.join("sub")).unwrap();
        fs::write(dir.0.join("sub").join("c.txt"), b"third").unwrap();

        let config = ObserverConfig::new(&dir.0);
        let record = observe(&config, sample_time()).unwrap();

        let paths: Vec<&str> = record
            .file_hashes
            .iter()
            .map(|f| f.relative_path.as_str())
            .collect();
        assert_eq!(paths, vec!["a.txt", "b.txt", "sub/c.txt"]);
        assert_eq!(
            record.file_hashes[0].content_digest,
            Digest::sha256(b"first")
        );
    }

    #[test]
    fn git_directory_itself_is_never_hashed_as_a_file() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.0.join(".git")).unwrap();
        fs::write(dir.0.join(".git").join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(dir.0.join("real.txt"), b"content").unwrap();

        let config = ObserverConfig::new(&dir.0);
        let record = observe(&config, sample_time()).unwrap();

        assert_eq!(record.file_hashes.len(), 1);
        assert_eq!(record.file_hashes[0].relative_path, "real.txt");
    }

    #[test]
    fn reads_git_commit_from_loose_ref() {
        let dir = TempDir::new();
        let git_dir = dir.0.join(".git");
        fs::create_dir_all(git_dir.join("refs").join("heads")).unwrap();
        fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(
            git_dir.join("refs").join("heads").join("main"),
            b"abc123deadbeef\n",
        )
        .unwrap();

        assert_eq!(read_git_commit(&dir.0), Some("abc123deadbeef".to_string()));
    }

    #[test]
    fn reads_git_commit_from_packed_refs_when_loose_ref_absent() {
        let dir = TempDir::new();
        let git_dir = dir.0.join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
        fs::write(
            git_dir.join("packed-refs"),
            b"# pack-refs\nfeedface refs/heads/main\n",
        )
        .unwrap();

        assert_eq!(read_git_commit(&dir.0), Some("feedface".to_string()));
    }

    #[test]
    fn detached_head_is_read_directly() {
        let dir = TempDir::new();
        let git_dir = dir.0.join(".git");
        fs::create_dir_all(&git_dir).unwrap();
        fs::write(git_dir.join("HEAD"), b"cafebabe1234\n").unwrap();

        assert_eq!(read_git_commit(&dir.0), Some("cafebabe1234".to_string()));
    }

    #[test]
    fn non_git_directory_yields_no_commit() {
        let dir = TempDir::new();
        assert_eq!(read_git_commit(&dir.0), None);
    }

    #[test]
    fn a_reflog_line_parses_commit_timestamp_and_message() {
        let line = "6795144e681247fb4080fec31daf8ea58b8eb1ae 18ab9c285d4b9715621941ab3bf6bdf005253481 LashSesh <sebastianklemm5@gmail.com> 1785768042 +0200\tcommit: Implement phase I2";
        let point = parse_reflog_line(line).unwrap();
        assert_eq!(point.commit, "18ab9c285d4b9715621941ab3bf6bdf005253481");
        assert_eq!(point.observed_at_unix, 1785768042);
        assert_eq!(point.message, "commit: Implement phase I2");
    }

    /// Ein Name mit eigenem Leerzeichen ("Jane Doe" statt "LashSesh") darf
    /// die von-hinten-Grenze nicht verschieben - genau der Fall, den eine
    /// positionsweise Lesart von vorn brechen wuerde.
    #[test]
    fn a_reflog_line_with_a_multi_word_name_still_parses() {
        let line = "0000000000000000000000000000000000000000 abc123 Jane Doe <jane@example.com> 1700000000 -0500\tclone: from https://example.invalid/repo.git";
        let point = parse_reflog_line(line).unwrap();
        assert_eq!(point.commit, "abc123");
        assert_eq!(point.observed_at_unix, 1700000000);
        assert_eq!(
            point.message,
            "clone: from https://example.invalid/repo.git"
        );
    }

    #[test]
    fn a_line_without_a_tab_separated_message_does_not_parse() {
        assert_eq!(parse_reflog_line("not a reflog line at all"), None);
    }

    #[test]
    fn history_reads_every_reflog_entry_in_file_order() {
        let dir = TempDir::new();
        let logs_dir = dir.0.join(".git").join("logs");
        fs::create_dir_all(&logs_dir).unwrap();
        fs::write(
            logs_dir.join("HEAD"),
            "0000000000000000000000000000000000000000 aaa111 X <x@example.invalid> 100 +0000\tclone: from origin\n\
             aaa111 bbb222 X <x@example.invalid> 200 +0000\tcommit: first\n\
             bbb222 ccc333 X <x@example.invalid> 300 +0000\tcommit: second\n",
        )
        .unwrap();

        let config = ObserverConfig::new(&dir.0);
        let history = observe_history(&config).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history[0].commit, "aaa111");
        assert_eq!(history[1].commit, "bbb222");
        assert_eq!(history[2].commit, "ccc333");
        assert_eq!(history[2].observed_at_unix, 300);
    }

    #[test]
    fn a_repository_without_a_reflog_yields_no_history() {
        let dir = TempDir::new();
        fs::create_dir_all(dir.0.join(".git")).unwrap();
        fs::write(dir.0.join(".git").join("HEAD"), b"cafebabe1234\n").unwrap();
        // Kein .git/logs/HEAD angelegt - ein Shallow-Klon ohne Reflog.
        let config = ObserverConfig::new(&dir.0);
        assert_eq!(observe_history(&config), None);
    }

    #[test]
    fn a_non_git_directory_yields_no_history_either() {
        let dir = TempDir::new();
        let config = ObserverConfig::new(&dir.0);
        assert_eq!(observe_history(&config), None);
    }

    #[test]
    fn observation_is_deterministic_across_repeated_reads() {
        let dir = TempDir::new();
        fs::write(dir.0.join("x.txt"), b"stable content").unwrap();
        let config = ObserverConfig::new(&dir.0);

        let a = observe(&config, sample_time()).unwrap();
        let b = observe(&config, sample_time()).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn different_excluded_dirs_change_configuration_digest() {
        let dir = TempDir::new();
        let cfg_a = ObserverConfig::new(&dir.0);
        let mut cfg_b = ObserverConfig::new(&dir.0);
        cfg_b.excluded_dirs.push("node_modules".to_string());

        let a = observe(&cfg_a, sample_time()).unwrap();
        let b = observe(&cfg_b, sample_time()).unwrap();
        assert_ne!(a.configuration_digest, b.configuration_digest);
    }
}
