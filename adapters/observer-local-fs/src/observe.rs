//! Liest den tatsaechlichen Dateisystemzustand einer lokalen Projektwurzel
//! (Regel 32.4, Erste Domaene: "isolierter, versionierter lokaler
//! Projektordner. Der Kern arbeitet zunaechst read-only") und baut daraus
//! einen ExternalRecord (Regel 32.7: "Der AnchorSnapshot bindet
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

use psk_anchor::{ExternalRecord, FileObservation, ObservedPermissions};
use psk_types::{Digest, DualTime};

/// Konfiguration eines Beobachtungslaufs. Ihr Digest geht als
/// "Konfiguration" (Regel 32.7) in den ExternalRecord ein, damit zwei
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

/// Regel 32.7: liest den tatsaechlichen Dateisystemzustand unter
/// `config.root` read-only (Regel 32.4) und baut daraus einen
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
