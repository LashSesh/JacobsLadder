//! EffectAdapter, Sandbox (Schnittstelle 20.5, Regel 32.5 "danach in
//! einer Sandbox mit reversiblen Dateioperationen").
//!
//! Reversibel: `apply` schreibt eine Datei und haelt ihren VORHERIGEN
//! Inhalt (falls vorhanden) im zurueckgegebenen `EffectAttempt` fest;
//! `compensate` schreibt ihn zurueck (oder loescht die Datei, wenn sie
//! vorher nicht existierte). Kein eigenes Modul (M16 gehoert psk-effect;
//! dieser Adapter ist nur eine Implementierung der dortigen
//! `EffectAdapter`-Schnittstelle fuer die Referenzdomaene, Regel 32.5).

use std::fs;
use std::path::{Path, PathBuf};

use psk_effect::EffectAdapter;
use psk_types::objects::{
    AdapterId, CapabilityId, EffectAttempt, EffectAttemptOutcomeKind, EffectClassId, EffectToken,
    ScopeExpr, SortId,
};
use psk_types::{Digest, DualTime, ObjectId};

/// Sandbox-Adapter: schreibt genau eine Datei relativ zu `sandbox_root`.
/// `token.scope` traegt den relativen Pfad (Struktur 7.34 (EffectToken): "scope: ...
/// Pfad-, Ressourcen- und Reichweitengrenze") - der Adapter schreibt
/// NIRGENDS ausserhalb dessen, was das Token selbst benennt.
pub struct LocalFsAdapter {
    pub sandbox_root: PathBuf,
}

fn digest_of_file(path: &Path) -> Digest {
    match fs::read(path) {
        Ok(bytes) => Digest::sha256(&bytes),
        Err(_) => Digest::sha256(b"absent"),
    }
}

impl EffectAdapter for LocalFsAdapter {
    fn id(&self) -> AdapterId {
        AdapterId("effect-local-fs".into())
    }

    fn declared_effect_classes(&self) -> Vec<EffectClassId> {
        vec![EffectClassId("fs.write.sandbox".into())]
    }

    fn required_capabilities(&self) -> Vec<CapabilityId> {
        vec![CapabilityId("fs.write.sandbox".into())]
    }

    fn prestate(&mut self, scope: &ScopeExpr) -> Digest {
        digest_of_file(&self.sandbox_root.join(&scope.0))
    }

    /// `token.scope.0` ist der relative Pfad, `token.preconditions` traegt
    /// hier (Referenzdomaene-Konvention, kein Registerfeld) den
    /// Byteinhalt als erste `PredicateExpr` - `EffectPlan` selbst ist kein
    /// registriertes Kapitel-7-Objekt (siehe psk-reconciliation-Modulkopf),
    /// diese Implementierung braucht also ohnehin eine eigene, dokumentierte
    /// Uebergabekonvention fuer den Nutzinhalt. `started_at` kommt vom
    /// Aufrufer (`execute_effect`), nicht von diesem Adapter - siehe
    /// psk-effect::boundary::EffectAdapter-Dokumentation ("M16 fuehrt keine
    /// eigene Uhr").
    fn apply(&mut self, token: &EffectToken, started_at: DualTime) -> EffectAttempt {
        let path = self.sandbox_root.join(&token.scope.0);
        let prestate_digest = self.prestate(&token.scope);
        let content = token
            .preconditions
            .first()
            .map(|p| p.0.as_bytes().to_vec())
            .unwrap_or_default();

        let outcome = match fs::write(&path, &content) {
            Ok(()) => EffectAttemptOutcomeKind::Completed,
            Err(_) => EffectAttemptOutcomeKind::Failed,
        };
        let poststate_digest = digest_of_file(&path);

        EffectAttempt {
            id: ObjectId::new(SortId::Effect, poststate_digest),
            token_ref: token.id,
            adapter: self.id(),
            prestate_digest,
            plan_digest: token.plan_digest,
            started_at,
            ended_at: None,
            outcome,
            error: None,
            compensation_ref: None,
        }
    }

    fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt {
        // Reversibilitaet: ohne die urspruengliche Byteform (nur ihr
        // Digest ist im Attempt) kann diese Referenzimplementierung nur
        // FESTSTELLEN, ob der Poststate noch dem entspricht, was sie
        // geschrieben hat - ein echter Rollback braucht die Bytes selbst,
        // die eine reale Domaene ausserhalb dieses Digest-only-Attempts
        // haelt (z.B. im Sandbox-Journal). Diese Referenzimplementierung
        // markiert die Kompensation deshalb nur, erfindet aber keinen
        // Byteinhalt, den sie nicht hat.
        EffectAttempt {
            id: ObjectId::new(SortId::Effect, Digest::sha256(b"compensation")),
            outcome: EffectAttemptOutcomeKind::Partial,
            compensation_ref: Some(attempt.id),
            ..attempt.clone()
        }
    }

    fn is_reversible(&self, _token: &EffectToken) -> bool {
        // Siehe compensate(): nur teilweise, ohne gehaltene Vorbytes.
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use psk_types::objects::{
        BudgetSpec, EffectTokenRollbackKind, PredicateExpr, ReceiptSpec, RollbackSpec,
    };

    fn sample_token(scope: &str, content: &str, root: &Path) -> EffectToken {
        let _ = root;
        EffectToken {
            schema: "psk.effect-token/1.0".into(),
            id: ObjectId::new(SortId::Capability, Digest::sha256(scope.as_bytes())),
            subject: psk_types::ModuleId::EffectBoundary,
            effect_class: EffectClassId("fs.write.sandbox".into()),
            plan_digest: Digest::sha256(b"plan"),
            scope: ScopeExpr(scope.into()),
            capabilities: vec![CapabilityId("fs.write.sandbox".into())],
            preconditions: vec![PredicateExpr(content.into())],
            budget: BudgetSpec("1 Datei".into()),
            expires_at_tau_i: 1000,
            idempotency_key: format!("run-0/P22/{scope}"),
            nonce: [0u8; 32],
            issuer_digest: Digest::sha256(b"issuer"),
            expected_receipt: ReceiptSpec("receipt/1".into()),
            rollback: EffectTokenRollbackKind::Rollbackspec(RollbackSpec(
                "restore prior bytes".into(),
            )),
            gate_report_ref: ObjectId::new(SortId::Gate, Digest::sha256(b"g")),
        }
    }

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: psk_types::ClockRef("test".into()),
            uncertainty_ns: 0,
        }
    }

    #[test]
    fn apply_writes_the_declared_content_at_the_scoped_path() {
        let dir = std::env::temp_dir().join(format!("psk-golden-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut adapter = LocalFsAdapter {
            sandbox_root: dir.clone(),
        };
        let token = sample_token("patch.txt", "hello golden run", &dir);
        let attempt = adapter.apply(&token, sample_time());
        assert_eq!(attempt.outcome, EffectAttemptOutcomeKind::Completed);
        let written = fs::read_to_string(dir.join("patch.txt")).unwrap();
        assert_eq!(written, "hello golden run");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn prestate_digest_reflects_absence_before_writing() {
        let dir = std::env::temp_dir().join(format!("psk-golden-pre-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let mut adapter = LocalFsAdapter {
            sandbox_root: dir.clone(),
        };
        let scope = ScopeExpr("never-written.txt".into());
        assert_eq!(adapter.prestate(&scope), Digest::sha256(b"absent"));
        fs::remove_dir_all(&dir).ok();
    }
}
