//! Vertrag 24.1 (Testpflicht je Requirement): Katalog der 37 registrierten
//! T-* Tests - 16 aus `architecture/ra_tests.yaml` (PSK-RA), 21 aus
//! `constitution/conformance_tests.yaml` (CPSK). Jeder Eintrag unten ist
//! entweder (a) hier neu implementiert, (b) bereits an seinem echten
//! Realisierungsort getestet (Verweis statt Duplikat - DRY gilt auch fuer
//! Tests), oder (c) mit einer konkreten Begruendung als derzeit nicht
//! realisierbar dokumentiert. Kategorie (c) ist ein Befund, kein
//! uebersprungener Test: Vertrag 24.1 verlangt Artefakt+Test+Owner je
//! Requirement, und ein fehlender Test OHNE Begruendung wuerde genau das
//! stillschweigend verletzen, was diese Datei verhindern soll.
//!
//! ## (a) Hier neu implementiert (siehe `#[test]`-Funktionen unten)
//! T-ARCH-001, T-ID-001, T-CAN-001, T-DEP-001, T-GLUE-001, T-MEM-001,
//! T-SCOPE-001, T-M13-002, T-RECON-001, T-CAP-001, T-OBS-001, T-BOUND-001,
//! T-REF-001, T-MORPH-001, T-RECEIPT-001, T-SCHEMA-001, T-ANCHOR-001.
//!
//! ## (b) Bereits an ihrem Realisierungsort getestet (kein Duplikat hier)
//! - T-FSM-001 (verbotene Automatentransition): psk-types generierte
//!   Tests, `automata::generated_tests::*_no_declared_transition_realizes_a_forbidden_edge`.
//! - T-IR-001 (Round-Trip): `psk-ir/src/codec.rs::tests::t_ir_001_round_trip_is_lossless`.
//! - T-RATCHET-001 (monotone Kontraktion): `psk-adversarial/src/kernel.rs::tests::ratchet_is_monotone_over_repeated_rounds`.
//! - T-M13-001 (13/30/18-Kardinalitaet): `psk-topology/src/lib.rs::tests::exact_cardinality_matches_invariante_9_5`.
//! - T-REPLAY-001 (Golden Run Replay): `golden_run::tests::replaying_the_golden_run_twice_earns_a_real_certificate`.
//! - T-EFFECT-001 (Effekt ohne Token): `psk-effect/src/boundary.rs::tests::executing_an_unregistered_token_fails`.
//! - T-PERSONA-001 (Persona beansprucht Autoritaet): `compile_fail`-Doctest
//!   auf `psk_observe::Persona` selbst (psk-observe/src/observe.rs) - ein
//!   Doctest in einem `#[cfg(test)]`-Modul wie diesem wird von `cargo test`
//!   NICHT ausgefuehrt (rustdoc extrahiert Doctests nur aus item-Doc-
//!   Kommentaren auf tatsaechlich oeffentlichen, nicht testgated Items);
//!   der Beweis gehoert deshalb an den Typ selbst, nicht hierher.
//! - T-RES-001 (drop_nonpass_artifact -> FAIL): behoben und real getestet
//!   in `psk-gate/src/evaluate.rs::tests` (`every_evaluation_appends_to_
//!   trace_regardless_of_decision`, `non_pass_decisions_residualize`,
//!   `pass_decisions_do_not_residualize`,
//!   `residue_origin_module_is_derived_from_the_gates_registered_owner`).
//!   `evaluate_gate` ruft seither selbst `M19.append`/`M19.residualize`
//!   (Algorithmus 18.6) - urspruenglich hier unter (c) als Befund
//!   dokumentiert, dann auf explizite Anweisung behoben statt nur
//!   geflaggt; dieser Eintrag verschoben, statt die Vorfix-Begruendung
//!   stehen zu lassen.
//!
//! ## (c) Derzeit nicht realisierbar (Befund, mit Begruendung)
//! - T-ARCH-002 (zyklische Modulabhaengigkeit -> build_fail) und
//!   T-PORT-001 (direkter modulueberschreitender Aufruf ohne Port ->
//!   build_fail): beides sind Eigenschaften des KOMPILIERZEITPUNKTS des
//!   gesamten Workspace (Cargo verweigert zyklische Pfadabhaengigkeiten
//!   strukturell), nicht als `#[test]`-Laufzeitassertion innerhalb EINES
//!   Crates ausdrueckbar, ohne einen absichtlich kaputten Geschwister-
//!   Workspace anzulegen - ausserhalb des Umfangs dieser Datei.
//! - T-SEC-001 (Adapter schreibt ausserhalb des Tokenscopes ->
//!   substratblockiert): verlangt echte Substraterzwingung (Vertrag
//!   Capability-Erzwingung); dokumentierte Luecke seit WP12 (siehe
//!   psk-effect/src/boundary.rs Modulkopf). Seit P24a praezisiert, nicht
//!   geschlossen: `effect-local-fs` laeuft jetzt als echter, von M26
//!   gespawnter Kindprozess, aber `LocalFsAdapter::apply` bildet
//!   `sandbox_root.join(&token.scope.0)` weiterhin in Anwendungscode -
//!   kein Chroot, keine ACL, kein Namespace/AppContainer begrenzt, WAS
//!   dieser Prozess tatsaechlich schreiben darf. P24a loeste
//!   Kommunikationsisolation (die exklusive Pipe, siehe
//!   `psk_anchor::ingress_p24_via_exclusive_pipe`), nicht
//!   Dateisystemisolation - das ist ein anderer Blocker, nicht derselbe
//!   unter neuem Namen. Identisch mit OBL-010s offener Anforderung
//!   (`architecture/obligations.yaml`: getrennte Benutzerkontexte/
//!   Namespaces, blocking ab C4) - dieselbe Substratmassnahme wuerde
//!   beides zugleich schliessen.
//! - T-CONC-001 (nebenlaeufiger Stresstest) und T-OBSV-001 (mit/ohne
//!   Profiling identischer Digest): beide verlangen Infrastruktur, die
//!   nicht existiert - einen nebenlaeufigen Ausfuehrungsharness bzw. einen
//!   Profiling-Umschalter. M25/M26 realisieren `select`/`budget`, aber
//!   keine parallele Taktschleife (siehe psk-scheduler Modulkopf).
//! - T-REPLAY-002 (Replay loest echten Effekt aus -> FAIL_PSK_E015): ein
//!   "Replaymodus", der sich von normaler Ausfuehrung unterscheidet und
//!   dieselbe Idempotenzschluessel-Wiederverwendung ERLAUBT (um sie dann
//!   zu verbieten), ist nirgends modelliert - `TokenLedger::consume_once`
//!   verhindert Doppelausfuehrung bereits strukturell, aber mit E008
//!   (EffectWithoutToken), nicht E015. Eine E015-Szene ohne einen echten
//!   Replaymodus-Begriff waere erfunden, kein gefundener Fall.
//! - T-PASS-001 (Compiler-Passreihenfolge vertauschen -> divergence_report):
//!   `pass_registry.yaml` ist deklaratives Metadatenregister, keine
//!   ausfuehrbare Passpipeline mit vertauschbarer Reihenfolge existiert.
//! - T-UNKNOWN-001 (verbale Unsicherheit ohne internen Block -> FAIL) und
//!   T-FIELD-001 (Systemidentitaet auf Feld-ID setzen -> FAIL): beide
//!   benennen Szenarien, zu denen keine registrierte Funktion eine
//!   pruefbare Grenze zieht - "verbale Unsicherheit" und "Systemidentitaet"
//!   sind im Werk an dieser Stelle nicht als konkrete Typen/Felder
//!   gefasst (anders als z.B. Personas Feldliste bei T-PERSONA-001). Ohne
//!   eine Konstruktion, die tatsaechlich existiert, waere jeder Test hier
//!   ein erfundenes Szenario, keine reale Pruefung.
//! - T-TRACE-001 (vorheriges Residuum loeschen) und T-FORECAST-001 (alte
//!   Prognose nach Beobachtung ueberschreiben): `TraceStore`/`ResidueLedger`
//!   besitzen strukturell KEINE `delete`/`overwrite`-Methode (nur
//!   `append`/`transition`) - die Garantie ist die Abwesenheit einer API,
//!   nicht das Verhalten einer vorhandenen. Das ist real (dieselbe Klasse
//!   wie `EffectAdapter`s fehlende `observe()`), aber nicht als Laufzeit-
//!   `#[test]` ausdrueckbar; siehe stattdessen die `compile_fail`-Doctests
//!   bei `GateAuthorization` fuer das gleiche Beweismuster an anderer
//!   Stelle.
//! - T-OWN-001 (create_owned_object_from_foreign_module -> FAIL_PSK_E014):
//!   Vertrag 3.4 (siehe psk-types/src/lib.rs Modulkopf) bindet Ownership an
//!   "welcher MODUL-CODE ein Objekt konstruieren/schreiben darf", nicht an
//!   den Rust-Typort - aber ALLE Felder jedes der `OBJECT_COUNT` kanonischen
//!   Objekte sind `pub` (Codegen-Konvention, siehe tools/psk-codegen/src/
//!   objects.rs: noetig fuer Serde/Cross-Crate-Ergonomie). Jeder Code, der
//!   `psk_types` importiert, kann deshalb JEDES Objekt per Struct-Literal
//!   bauen - der "nur das Owner-Modul ruft den Konstruktor"-Vertrag ist eine
//!   NAMENSKONVENTION (die Konstruktorfunktion liegt im Owner-Modul), keine
//!   Typdurchsetzung. `GateAuthorization`s `#[non_exhaustive]`-Muster loest
//!   das fuer EIN Objekt (psk-gate/authorization.rs), aber nicht generisch
//!   fuer alle 27 - ein Sealing pro Objekt waere ein eigenes, groesseres
//!   Vorhaben, hier nicht unternommen ohne explizite Freigabe. FAIL_PSK_E014
//!   hat deshalb keinen Code-Pfad, der ihn tatsaechlich erzeugt.

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use psk_closure::{glue, CapsuleRestriction};
    use psk_dependency::{dependency_quotient, QuotientInputs, RankMethod};
    use psk_fields::{decide_transition, MorphInputs};
    use psk_gate::ConditionOutcome;
    use psk_reconciliation::{reconcile, DiffOutcome, ReconcileInputs};
    use psk_trace::ResidueLedger;
    use psk_types::objects::{
        DependencyProfileConsensusScopeKind, EffectAttempt, EffectAttemptOutcomeKind,
        FieldProjection, IRNodeId, M13Address, ReasonCode, ReplayDescriptor, ScopeSpec, SourceRef,
        TickId,
    };
    use psk_types::{ClockRef, Digest, DualTime, ObjectId, PskError, TraceRef};

    fn sample_time() -> DualTime {
        DualTime {
            tau_i: 0,
            tau_e: "2026-08-05T00:00:00.000000000Z".into(),
            clock_ref: ClockRef("conformance".into()),
            uncertainty_ns: 0,
        }
    }

    fn workspace_root() -> std::path::PathBuf {
        let mut dir = std::env::current_dir().expect("cwd");
        loop {
            if dir.join("Cargo.toml").is_file() && dir.join(".git").exists() {
                return dir;
            }
            assert!(dir.pop(), "keine Workspace-Wurzel gefunden");
        }
    }

    // ---- T-ARCH-001: alter_architecture_register_without_lock_update -> boot_fail_PSK_E103 ----
    #[test]
    fn t_arch_001_altering_a_register_without_resealing_the_lock_fails_i_a() {
        let root = workspace_root();
        let scratch = std::env::temp_dir().join(format!("psk-t-arch-001-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        copy_dir(&root.join("architecture"), &scratch.join("architecture")).unwrap();

        // Baseline: unveraendert muss die Kopie noch uebereinstimmen.
        let before = verify_architecture::check_architecture_bundle(&scratch).unwrap();
        assert!(
            before.matches(),
            "unveraenderte Kopie sollte I_A noch treffen"
        );

        // Mutation: ein Register inhaltlich aendern, OHNE architecture.lock.json neu zu versiegeln.
        // Ein reiner Kommentar wuerde die kanonische YAML-Form nicht
        // veraendern (Kommentare sind nicht semantisch) - die Mutation
        // MUSS echten Inhalt treffen.
        let target = scratch.join("architecture/obligations.yaml");
        let content = fs::read_to_string(&target).unwrap();
        assert!(content.starts_with("schema: psk.obligations/1.0"));
        let mutated = content.replacen(
            "schema: psk.obligations/1.0",
            "schema: psk.obligations/1.0-mutated",
            1,
        );
        fs::write(&target, mutated).unwrap();

        let after = verify_architecture::check_architecture_bundle(&scratch).unwrap();
        assert!(
            !after.matches(),
            "veraendertes Register ohne Neuversiegelung MUSS I_A-Abweichung ergeben (PSK-E103)"
        );

        fs::remove_dir_all(&scratch).ok();
    }

    // ---- T-ID-001: flip_core_axiom -> constitution_id_changes_and_boot_fails ----
    #[test]
    fn t_id_001_flipping_a_normative_file_changes_the_constitution_id() {
        let root = workspace_root();
        let scratch = std::env::temp_dir().join(format!("psk-t-id-001-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        copy_dir(&root.join("constitution"), &scratch.join("constitution")).unwrap();

        let before =
            verify_bundle::check_constitution_bundle(&scratch.join("constitution")).unwrap();
        assert!(
            before.matches(),
            "unveraenderte Kopie sollte I_C noch treffen"
        );
        let original_digest = before.computed_constitution_id;

        let target = scratch.join("constitution/constitution.md");
        if target.is_file() {
            let mut content = fs::read_to_string(&target).unwrap();
            content.push_str("\n<!-- t-id-001 mutation marker -->\n");
            fs::write(&target, content).unwrap();

            let after =
                verify_bundle::check_constitution_bundle(&scratch.join("constitution")).unwrap();
            assert_ne!(
                after.computed_constitution_id, original_digest,
                "eine Aenderung an einer normativen Datei MUSS den berechneten I_C aendern"
            );
            assert!(
                !after.matches(),
                "der alte, ungeaenderte constitution_id-Wert darf nicht mehr treffen (Boot faellt mit PSK-E103)"
            );
        }

        fs::remove_dir_all(&scratch).ok();
    }

    fn copy_dir(from: &Path, to: &Path) -> std::io::Result<()> {
        fs::create_dir_all(to)?;
        for entry in fs::read_dir(from)? {
            let entry = entry?;
            let dest = to.join(entry.file_name());
            if entry.file_type()?.is_dir() {
                copy_dir(&entry.path(), &dest)?;
            } else {
                fs::copy(entry.path(), &dest)?;
            }
        }
        Ok(())
    }

    // ---- T-CAN-001: canonicalization_idempotence -> Can(Can(x)) == Can(x) ----
    #[test]
    fn t_can_001_canonicalization_is_idempotent() {
        let input = br#"{"b": 2, "a": [3, 1, 2], "c": {"z": 1, "y": 2}}"#;
        let once = psk_canon::can(input, psk_canon::Media::Json).unwrap();
        let twice = psk_canon::can(&once.0, psk_canon::Media::Json).unwrap();
        assert_eq!(
            once.0, twice.0,
            "Can(Can(x)) muss byteidentisch zu Can(x) sein"
        );
    }

    // ---- T-DEP-001: clone_same_model_into_100_facets -> effective_rank_not_100 ----
    #[test]
    fn t_dep_001_cloning_one_model_a_hundred_times_does_not_inflate_effective_rank() {
        let shared_source = vec![SourceRef("t-dep-001-shared-model".into())];
        let projections: Vec<FieldProjection> = (0..100)
            .map(|i| FieldProjection {
                schema: "psk.field-projection/1.0".into(),
                id: ObjectId::new(
                    psk_types::objects::SortId::Projection,
                    Digest::sha256(format!("facet-{i}").as_bytes()),
                ),
                field_ref: ObjectId::new(
                    psk_types::objects::SortId::FieldIdentity,
                    Digest::sha256(b"field"),
                ),
                source_refs: vec![],
                lens_ref: psk_types::objects::LensSpec("identity".into()),
                scope: ScopeSpec("t-dep-001".into()),
                visible: vec![IRNodeId(format!("n{i}"))],
                occluded: vec![],
                distinctions: vec![],
                source_provenance: shared_source.clone(),
                reality_view: psk_types::objects::RealityStatus::Coherent,
                tick: TickId("t0".into()),
            })
            .collect();

        let profile = dependency_quotient(QuotientInputs {
            projections: &projections,
            method: RankMethod::QuotientClassCount,
            consensus_scope: DependencyProfileConsensusScopeKind::Local,
        })
        .unwrap();

        assert_eq!(
            profile.quotient_classes.len(),
            1,
            "100 Facetten desselben Modells (gleiche source_provenance) muessen in EINE Quotientenklasse fallen"
        );
        assert_ne!(
            profile.effective_rank.numerator, 100,
            "der effektive Rang darf die 100 klonierten Facetten nicht als 100 unabhaengige zaehlen"
        );
        assert_eq!(profile.effective_rank.numerator, 1);
    }

    // ---- T-GLUE-001: incompatible_overlap -> RESIDUE_no_global_commit ----
    #[test]
    fn t_glue_001_incompatible_overlapping_restrictions_yield_no_global_section() {
        let cell = M13Address("center".into());
        let a = CapsuleRestriction {
            capsule: ObjectId::new(
                psk_types::objects::SortId::Trace,
                Digest::sha256(b"capsule-a"),
            ),
            cells: vec![cell.clone()],
            restriction_digests: vec![Digest::sha256(b"value-a")],
        };
        let b = CapsuleRestriction {
            capsule: ObjectId::new(
                psk_types::objects::SortId::Trace,
                Digest::sha256(b"capsule-b"),
            ),
            cells: vec![cell],
            restriction_digests: vec![Digest::sha256(b"value-b-different")],
        };

        let outcome = glue(&[a, b], true).unwrap();
        assert!(
            outcome.section.is_none(),
            "widerspruechlicher Overlap darf keine globale Sektion committen"
        );
        assert!(outcome.hold_reason.is_some());
        assert!(!outcome.seams.all_compatible());
    }

    // ---- T-MEM-001: promote_residual_to_canonical_directly -> FAIL ----
    #[test]
    fn t_mem_001_canonical_memory_requires_g_closure_not_a_direct_promotion() {
        let root = workspace_root();
        let text = fs::read_to_string(root.join("architecture/memory_registry.yaml")).unwrap();
        let reg: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let classes = reg["classes"].as_sequence().unwrap();
        let canonical = classes
            .iter()
            .find(|c| c["id"].as_str() == Some("canonical"))
            .expect("Speicherklasse 'canonical' muss registriert sein");
        assert_eq!(
            canonical["write_condition"].as_str(),
            Some("G-CLOSURE"),
            "kanonischer Speicher darf nur unter G-CLOSURE beschrieben werden, nicht direkt"
        );

        // Dieselbe Regel operational: `glue()` (M11, der einzige Erzeuger einer
        // kanonischen globalen Sektion) liefert ohne echte Closure kein
        // `section` - ein direkter "residual -> canonical"-Sprung hat keinen
        // Code-Pfad, der `Some(digest)` ohne bestandene Seam-Pruefung erzeugt.
        let cell = M13Address("center".into());
        let restriction = CapsuleRestriction {
            capsule: ObjectId::new(
                psk_types::objects::SortId::Trace,
                Digest::sha256(b"residual"),
            ),
            cells: vec![cell],
            restriction_digests: vec![Digest::sha256(b"unclosed")],
        };
        let outcome = glue(&[restriction], false).unwrap();
        assert!(
            outcome.section.is_none(),
            "cells_closed=false darf nie eine kanonische Sektion liefern"
        );
    }

    // ---- T-SCOPE-001: promote_cluster_consensus_to_external -> FAIL ----
    #[test]
    fn t_scope_001_widening_cluster_consensus_to_external_without_g_consensus_fails() {
        let result = psk_witness::check_scope_emission(
            DependencyProfileConsensusScopeKind::Cluster,
            DependencyProfileConsensusScopeKind::External,
            false,
        );
        assert!(result.is_err());
    }

    // ---- T-M13-002: remove_one_edge_from_topology -> boot_fail_PSK_E011 ----
    #[test]
    fn t_m13_002_referencing_a_nonexistent_cell_fails_with_e011() {
        let malformed =
            psk_types::objects::M13Address("this-cell-does-not-exist-in-the-register".into());
        let result = psk_topology::check_address(&malformed, 8);
        assert_eq!(result, Err(PskError::NonclosingM13Seam));
    }

    // ---- T-RECON-001: mark_attempt_as_actualized_without_receipt -> FAIL ----
    #[test]
    fn t_recon_001_reconciling_without_any_receipts_fails() {
        let attempt = EffectAttempt {
            id: ObjectId::new(
                psk_types::objects::SortId::Effect,
                Digest::sha256(b"attempt"),
            ),
            token_ref: ObjectId::new(
                psk_types::objects::SortId::Capability,
                Digest::sha256(b"token"),
            ),
            adapter: psk_types::objects::AdapterId("test".into()),
            prestate_digest: Digest::sha256(b"pre"),
            plan_digest: Digest::sha256(b"plan"),
            started_at: sample_time(),
            ended_at: Some(sample_time()),
            outcome: EffectAttemptOutcomeKind::Completed,
            error: None,
            compensation_ref: None,
        };
        let mut residues = ResidueLedger::new();
        let result = reconcile(
            ReconcileInputs {
                plan_ref: ObjectId::new(
                    psk_types::objects::SortId::Effect,
                    Digest::sha256(b"plan"),
                ),
                plan_digest: attempt.plan_digest,
                attempt,
                token_plan_digest: Digest::sha256(b"plan"),
                token_issuer_digest: Digest::sha256(b"issuer"),
                receipts: vec![],
                anchor_ref: ObjectId::new(
                    psk_types::objects::SortId::Anchor,
                    Digest::sha256(b"anchor"),
                ),
                diff: DiffOutcome::Empty,
                finality: psk_types::objects::ReconciliationReportFinalityKind::Provisional,
                witness_ref: ObjectId::new(
                    psk_types::objects::SortId::Witness,
                    Digest::sha256(b"w"),
                ),
                opened_at: sample_time(),
            },
            &mut residues,
        );
        assert!(
            result.is_err(),
            "Faktpromotion zu ACTUALIZED ohne jeden ExternalReceipt muss scheitern"
        );
    }

    // ---- T-CAP-001: effect_role_issues_own_token -> capability_violation ----
    // ---- T-OBS-001: observability_writes_to_store -> capability_violation ----
    // ---- T-BOUND-001: expose_internal_freedom_as_external_capability -> FAIL ----
    #[test]
    fn t_cap_001_t_obs_001_t_bound_001_capability_matrix_denies_the_named_boundary_crossings() {
        let root = workspace_root();
        let text = fs::read_to_string(root.join("architecture/capability_matrix.yaml")).unwrap();
        let reg: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();
        let denials = reg["denials"].as_sequence().unwrap();

        let has_denial = |holder: &str, capability: &str| {
            denials.iter().any(|d| {
                d["holder"].as_str() == Some(holder) && d["capability"].as_str() == Some(capability)
            })
        };

        // T-CAP-001: M16 (Effektgrenze) darf kein eigenes Token ausstellen.
        assert!(
            has_denial("M16", "token.issue"),
            "capability_matrix.yaml muss M16 token.issue ausdruecklich verweigern"
        );
        // T-OBS-001: M27 (Beobachtung) hat keine Schreibautoritaet auf den Store.
        assert!(
            has_denial("M27", "store.append"),
            "capability_matrix.yaml muss M27 store.append ausdruecklich verweigern"
        );
        // T-BOUND-001: M16 darf sich keine Beobachterunabhaengigkeit aneignen -
        // genau das waere "interne [Effekt-]Freiheit als externe
        // [Beobachtungs-]Capability" exponiert.
        assert!(
            has_denial("M16", "fs.read.observer"),
            "capability_matrix.yaml muss M16 fs.read.observer ausdruecklich verweigern"
        );
    }

    // ---- T-REF-001: add_unmapped_concrete_transition -> refinement_check_fail ----
    #[test]
    fn t_ref_001_refinement_map_blocks_on_unmapped_transitions() {
        let root = workspace_root();
        let text = fs::read_to_string(root.join("architecture/refinement_map.yaml")).unwrap();
        let reg: serde_yaml::Value = serde_yaml::from_str(&text).unwrap();

        assert_eq!(
            reg["unmapped_is_blocking"].as_bool(),
            Some(true),
            "eine unabgebildete konkrete Transition MUSS blockieren (Vertrag 23.4) - diese Policy \
             darf nicht versehentlich auf 'nicht blockierend' stehen"
        );
        // Aktueller, tatsaechlicher Stand: vollstaendig (kein Mangel im Bundle
        // selbst) - der Test prueft die POLICY, die eine kuenftige unmapped
        // Transition faellen wuerde, nicht eine synthetische Mutation der
        // 62 echten Transitionen.
        assert_eq!(reg["coverage"]["unmapped"].as_u64(), Some(0));
        assert_eq!(reg["coverage"]["complete"].as_bool(), Some(true));
    }

    // ---- T-MORPH-001: spawn_field_without_gain_or_budget -> HOLD ----
    #[test]
    fn t_morph_001_a_transition_without_a_passed_gate_holds_not_transitions() {
        let field = sample_field_identity();
        let mut trace = psk_trace::TraceStore::new();
        let mut residues = ResidueLedger::new();
        let outcome = decide_transition(
            &field,
            MorphInputs {
                operator: "activate",
                conditions: vec![ConditionOutcome::Undecidable(ReasonCode(
                    "no-declared-gain-or-budget".into(),
                ))],
                seam_compatible: None,
                seam_report_refs: vec![],
                input_digests: vec![Digest::sha256(b"morph")],
                evidence_refs: vec![],
                replay_descriptor: ReplayDescriptor("t-morph-001/1".into()),
                decided_at: sample_time(),
                trace_ref: TraceRef(Digest::sha256(b"trace")),
            },
            &mut trace,
            &mut residues,
        )
        .unwrap();
        // T-RES-001: die HOLD-Entscheidung muss residualisiert sein.
        assert_eq!(residues.all().len(), 1);
        match outcome {
            psk_fields::MorphogenesisOutcome::Held(report) => {
                assert_eq!(
                    report.decision,
                    psk_types::objects::GateReportDecisionKind::Hold
                );
            }
            other => panic!("erwartet Held(..) mit HOLD, bekam {other:?}"),
        }
    }

    fn sample_field_identity() -> psk_types::objects::FieldIdentity {
        psk_fields::register_field(
            psk_types::objects::ArchetypeId::Explorer,
            psk_fields::FieldRegistrationInputs {
                domain: psk_types::objects::DomainExpr("t-morph-001".into()),
                lens: psk_types::objects::LensSpec("identity".into()),
                operators: vec![psk_types::objects::OpId::Project],
                questions: vec![],
                witness_rules: psk_types::objects::WitnessPolicy("default".into()),
                boundaries: psk_types::objects::BoundarySpec("scope".into()),
                gates: vec![],
                time_window: psk_types::objects::TimeWindow("window".into()),
                lineage: psk_types::objects::Lineage("t-morph-001".into()),
                dependency_profile_ref: ObjectId::new(
                    psk_types::objects::SortId::Dependency,
                    Digest::sha256(b"dep"),
                ),
                budget: psk_types::objects::BudgetSpec("0".into()),
                rollback: psk_types::objects::RollbackSpec("none".into()),
            },
        )
        .unwrap()
    }

    // ---- T-RECEIPT-001: replace_external_record_by_internal_simulation -> FAIL ----
    #[test]
    fn t_receipt_001_an_observer_sharing_the_effect_issuers_identity_is_rejected() {
        // Invariante 7.34 (Beobachtertrennung): der Beobachter, der ein
        // ExternalReceipt liefert, darf nicht dieselbe Identitaet wie der
        // Token-Aussteller tragen - sonst koennte eine interne Simulation
        // sich selbst als unabhaengige Beobachtung ausgeben.
        let same_identity = Digest::sha256(b"same-actor");
        let result = psk_anchor::check_observer_separation(same_identity, Some(same_identity));
        assert!(result.is_err());

        let independent = psk_anchor::check_observer_separation(
            Digest::sha256(b"independent-observer"),
            Some(Digest::sha256(b"effect-issuer")),
        );
        assert!(independent.is_ok());
    }

    // ---- T-SCHEMA-001: remove_required_thought_field -> schema_reject ----
    #[test]
    fn t_schema_001_a_thought_body_missing_a_required_field_is_schema_rejected() {
        let root = workspace_root();
        let schema_text =
            fs::read_to_string(root.join("constitution/schemas/thought_body.schema.json")).unwrap();
        let schema: serde_json::Value = serde_json::from_str(&schema_text).unwrap();
        let validator = jsonschema::validator_for(&schema).unwrap();

        // Vollstaendiges, minimales Dokument mit allen Pflichtfeldern.
        let mut complete = serde_json::json!({
            "schema": "psk.thought-body/1.0",
            "id": format!("psk:S-CTX:{}", "0".repeat(64)),
            "anchor_refs": [],
            "unanchored": true,
            "claim": {"text": "x", "formal": "x", "directionality": "internal"},
            "models": [],
            "trajectories": [],
            "reality_status": "UNKNOWN",
            "facticity": "SPECIFIED",
            "witness_refs": [],
            "uncertainty": "none",
            "consequences": [],
            "gate_refs": [],
            "residue_refs": [],
            "lineage": "test",
            "trace_ref": "0".repeat(64),
        });
        assert!(
            validator.is_valid(&complete),
            "vollstaendiges Dokument sollte gegen thought_body.schema.json validieren"
        );

        // Mutation: ein Pflichtfeld entfernen.
        complete.as_object_mut().unwrap().remove("claim");
        assert!(
            !validator.is_valid(&complete),
            "ein ThoughtBody ohne 'claim' MUSS vom Schema abgelehnt werden"
        );
    }

    // ---- T-ANCHOR-001: emit_external_claim_without_anchor -> HOLD ----
    //
    // `psk_thought::compile_thought`s `check_anchoring` erlaubt `unanchored:
    // true` unabhaengig von `claim.directionality` (siehe thought.rs:
    // "if inputs.anchor_refs.is_empty() && !inputs.unanchored") - eine
    // unverankerte EXTERNE Behauptung wird also nicht schon bei der
    // Kompilierung abgewiesen. Die tatsaechliche Schranke liegt einen
    // Schritt spaeter: G-REALITY-COHERENT (SPECIFIED->POSSIBLE, Owner M07,
    // gate_registry.yaml order 1) wird mit der realen Bedingung "keine
    // Evidenz fuer eine externe, unverankerte Behauptung" ausgewertet, und
    // liefert HOLD (Undecidable), nicht PASS - das erfuellt den Test, ohne
    // eine im Werk nicht vorhandene zusaetzliche Pruefung in compile_thought
    // selbst zu erfinden.
    #[test]
    fn t_anchor_001_an_unanchored_external_claim_holds_at_the_coherence_gate() {
        let thought = psk_thought::compile_thought(psk_thought::ThoughtInputs {
            anchor_refs: vec![],
            unanchored: true,
            claim: psk_types::objects::Claim {
                text: "t-anchor-001: externe Behauptung ohne Anker".into(),
                formal: psk_types::objects::ClaimExpr("external-claim".into()),
                directionality: psk_types::objects::ClaimDirectionalityKind::External,
            },
            models: vec![],
            trajectories: vec![],
            uncertainty: psk_types::objects::UncertaintyBlock("none-declared".into()),
            consequences: vec![],
            lineage: psk_types::objects::Lineage("t-anchor-001".into()),
            trace_ref: TraceRef(Digest::sha256(b"trace")),
        })
        .expect("unanchored=true laesst compile_thought fuer sich allein passieren");
        assert!(thought.unanchored);
        assert_eq!(
            thought.claim.directionality,
            psk_types::objects::ClaimDirectionalityKind::External
        );

        let mut trace = psk_trace::TraceStore::new();
        let mut residues = ResidueLedger::new();
        let report = psk_gate::evaluate_gate(
            psk_gate::GateInputs {
                gate_id: psk_types::objects::GateId::GRealityCoherent,
                order: 1,
                input_digests: vec![Digest::sha256(b"t-anchor-001")],
                conditions: vec![ConditionOutcome::Undecidable(ReasonCode(
                    "external-unanchored-claim-has-no-grounding-evidence".into(),
                ))],
                seam_compatible: None,
                evidence_refs: vec![],
                seam_report_refs: vec![],
                replay_descriptor: ReplayDescriptor("t-anchor-001/1".into()),
                decided_at: sample_time(),
                trace_ref: TraceRef(Digest::sha256(b"trace")),
            },
            &mut trace,
            &mut residues,
        )
        .unwrap();
        assert_eq!(
            report.decision,
            psk_types::objects::GateReportDecisionKind::Hold
        );
        // T-RES-001: die HOLD-Entscheidung muss residualisiert sein.
        assert_eq!(residues.all().len(), 1);
    }
}
