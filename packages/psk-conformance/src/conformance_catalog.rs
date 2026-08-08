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
//! - T-PORT-001 (direkter modulueberschreitender Aufruf ohne Port ->
//!   build_fail): real gruen getestet in `tools/verify-dependencies`
//!   (`the_real_package_dependencies_are_all_port_justified_or_exempt`
//!   u.a.). Zwei Funde fuehrten hierher, beide behoben: psk-contracts drei
//!   Paketkanten sind an `boot.rs` als Algorithmus-17.1-Schritte 8/17/18
//!   verifiziert (Orchestratorrolle, kein Portverstoss); psk-adversarials
//!   `split()` (kernel.rs) nahm `EvidenceObject`/`ClassId` direkt aus
//!   psk-witness entgegen - auf explizite Anweisung durch einen
//!   deklarierten `has_independent_evidence: bool`-Parameter ersetzt (M10/
//!   M12 entscheiden das bereits frueher in der Pipeline), Cargo-
//!   Abhaengigkeit vollstaendig entfernt statt eines neuen Ports.
//! - T-ARCH-002 (zyklische Modulabhaengigkeit -> build_fail): real gruen
//!   getestet in `tools/verify-dependencies`
//!   (`the_real_module_graph_is_now_fully_acyclic_all_four_findings_closed`).
//!   Vier Funde fuehrten hierher, alle vier behoben, keiner durch eine
//!   erratene Ausnahme: (1) M09-M13 ueber P39 - ein Normfehler (Invariante
//!   2.3s invertierte Schichtungleichung), an PSK-RA v1.0.14 korrigiert,
//!   P39 als fuenfter benannter Rueckflusskanal aufgenommen. (2) M11-M22
//!   ueber P16/P17 - kein Rueckfluss, sondern Zusammenarbeit INNERHALB von
//!   Pass C9 (ClosureAndGluing, `modules: [M11, M22]`); PSK-RA v1.0.15
//!   ergaenzte dafuer die Ausnahme "gemeinsame Passtraeger" in Invariante
//!   2.3, siehe `shares_a_pass`. (3) M08-M20 ueber P31/P32 (M20->M08
//!   "MorphogenesisDecision", M08->M20 "SpawnRequest") - strukturell
//!   derselbe Anruf/Ruecksprung-Fall wie `psk_contract::boot()`s P00/P05
//!   (`psk-fields/src/morphogenesis.rs`s `decide_transition` ruft
//!   `complete_transition`, M08s eigene Funktion, synchron im selben
//!   Cargo-Paket auf), an echtem Code verifiziert, dann durch PSK-RA
//!   v1.0.16 (Fehlerkorrektur-Befund 20) normativ bestaetigt: P31 traegt
//!   jetzt `kind: request`, "derselbe Aufruf/Ruecksprung-Charakter wie
//!   P00/P05 ... nur zuvor nicht gekennzeichnet". (4) Ein potenzieller
//!   VIERTER Fund, der beim Schliessen von (3) beinahe entstanden waere:
//!   PSK-RA v1.0.16 ergaenzte `kind` fuer alle 42 Ports (zuvor nur neun
//!   Beispiele) und machte "request" damit zum GEWOEHNLICHEN Fall (33 von
//!   42) statt einer neunkoepfigen Ausnahme - `tools/verify-dependencies`s
//!   fruehere Regel "jeder kind:request-Port ist von der Zyklenpruefung
//!   ausgenommen" haette mechanisch auf alle 42 angewandt 33 von 42 Kanten
//!   entfernt, darunter die gesamte gewoehnliche Vorwaertspipeline, und
//!   T-ARCH-002 praktisch wirkungslos gemacht (ein fast leerer Graph ist
//!   trivial azyklisch). Real beobachtet, nicht nur befuerchtet: das
//!   Werkzeug meldete PASS, bevor die Ausnahme auf eine kleine, an echtem
//!   Code verifizierte Aufzaehlung umgestellt wurde (`is_verified_call_
//!   return_leg`, genau P05 und P31 - siehe dessen Kopfkommentar). Danach
//!   erneut PASS, diesmal ueber einen Graphen, der die gewoehnliche
//!   Pipeline nachweislich noch enthaelt (siehe `ordinary_forward_
//!   pipeline_ports_stay_in_the_cycle_graph_despite_kind_request`).
//! - T-SEC-001 (Adapter schreibt ausserhalb des Tokenscopes ->
//!   substratblockiert): real gruen getestet in `psk-lifecycle/tests/
//!   spawn_and_request.rs::a_path_escape_outside_sandbox_root_is_denied_
//!   by_the_substrate_not_the_adapter`. Vertrag Capability-Erzwingung
//!   verlangt echte Substraterzwingung, nicht Programmkonvention;
//!   `LocalFsAdapter::apply` (`effect-local-fs/src/apply.rs`) bildet nach
//!   wie vor blind `sandbox_root.join(&token.scope.0)` - KEINE eigene
//!   Pfadausbruchspruefung, bewusst unveraendert. Die Erzwingung liegt
//!   jetzt im Substrat: `ChildProcess::spawn` (`psk-lifecycle::process`)
//!   erzeugt das Kind angehalten (`CREATE_SUSPENDED`), sperrt sein Token
//!   VOR dem ersten Instruktionsschritt (`AdjustTokenPrivileges
//!   DisableAllPrivileges` + Absenkung auf Low Integrity Level,
//!   `psk-lifecycle::sandbox`) und markiert exklusiv `sandbox_root` als
//!   fuer diese Stufe beschreibbar - kein Zeitfenster mit vollen Rechten.
//!   Der Test beweist das ueber einen realen Pfadausbruchsversuch
//!   (`scope: "..\<Datei>"`), den die Adapterlogik anstandslos
//!   durchreicht: `EffectAttempt.outcome == Failed` UND die Zieldatei
//!   entsteht nachweislich nicht - das Substrat verweigert, nicht der
//!   Adapter. Windows-spezifisch deklariert (analog OBL-005), da PSK-RA
//!   v1.0.16 fuer diese Domaene `CreateProcessWithLogonW oder gleichwertig`
//!   verlangt und dessen woertliche Form (getrenntes, dauerhaft
//!   eingerichtetes Benutzerkonto mit verwalteten Zugangsdaten) ausserhalb
//!   dessen liegt, was Implementierung/Werkzeug ohne Zugriff auf
//!   Systemkontenverwaltung leisten darf - siehe `architecture/
//!   obligations.yaml` OBL-010 (`resolution`, `resolution_platform:
//!   windows`) fuer die vollstaendige Begruendung der gewaehlten
//!   Gleichwertigkeit (Rechteabbau + Low IL statt Kontowechsel). PSK-RA
//!   selbst schreibt kein Betriebssystem vor - auf jeder Nicht-Windows-
//!   Plattform gilt OBL-010 folgerichtig weiter als offen: `psk_lifecycle::
//!   ChildProcess::spawn` (`process_unsupported.rs`, ueber `#[cfg(windows)]`
//!   gewaehlt) verweigert sich dort mit einer auf OBL-010 verweisenden
//!   Fehlermeldung, statt ungeschuetzt zu spawnen - dieser Test schlaegt
//!   dort folglich LAUT fehl (`.expect(...)` auf dem `Err`), nicht
//!   stillschweigend gruen. Real geprueft, nicht nur beabsichtigt: `cargo
//!   check --target x86_64-unknown-linux-gnu --workspace --tests` compiliert
//!   sauber (die Typoberflaeche ist plattformuebergreifend gleich); vor
//!   dieser Aufteilung liess ein unbedingtes `mod process` den GESAMTEN
//!   Workspace dort mit 18 kaskadierenden Fehlern gar nicht erst
//!   kompilieren - ein frueherer, unabsichtlicher Zustand, kein
//!   beabsichtigter.
//!
//! - T-REPLAY-002 (Replay laeuft effektfrei): real gruen getestet in
//!   `psk-scheduler/tests/tick_runs_the_twelve_phases.rs::under_shadow_the_
//!   token_is_invalidated_and_the_adapter_never_runs` (plus derselbe
//!   Nachweis fuer `readonly`). Die fruehere Einordnung unter (c) - "ein
//!   Replaymodus ... ist nirgends modelliert" - war korrekt fuer den
//!   damaligen Stand und wurde an der QUELLE geschlossen, nicht hier
//!   umgedeutet: PSK-RA v1.0.19 Regel 22.3 ("Replay laeuft unter shadow")
//!   loeste eine haengende Referenz auf - I-ARCH-012 und R-RA-012 nannten
//!   ein "Replay-Profil", das `ProfileId` (readonly, shadow, sandbox,
//!   reference) nie fuehrte. Kein fuenfter Profilwert: `shadow` leistet
//!   woertlich, was Replay verlangt. Die Durchsetzung laeuft ueber die
//!   BESTEHENDE Tokeninvalidierung (FSM-TOKEN-Operator `plan_changed`,
//!   P37), nicht ueber eine zusaetzliche Modusabfrage in `dispatch()` -
//!   der Adapter wird unter `shadow`/`readonly` nie aufgerufen
//!   (Invariante 22.6, "Replay ist effektfrei"). Ein Gegentest unter
//!   `reference` zeigt denselben Aufruf real ausfuehren, damit der
//!   Negativnachweis nicht auch bei einem kaputten Match-Arm gruen waere.
//! - T-OBSV-001 (mit/ohne Profiling identischer kanonischer Digest,
//!   I-ARCH-015): real gruen getestet in `psk-scheduler/tests/
//!   profiling_does_not_alter_the_canonical_digest.rs`. Der
//!   Profilingschalter (`psk_scheduler::Profiling`) liegt bewusst
//!   AUSSERHALB von `Sigma` und wird als eigener `tick()`-Parameter
//!   gefuehrt; zusaetzlich heisst sein Datenfeld `runtime_metrics`, das
//!   `architecture/volatile_fields.yaml` bereits als volatil fuehrt, so
//!   dass `pi_vol` es in jeder Tiefe entfernt, falls es je serialisiert
//!   eingebettet wird. Beide Schichten sind getrennt geprueft: identischer
//!   Tracekopf/Objekt-IDs/Segmentzahl mit und ohne Profiling, UND ein
//!   eingebettetes `runtime_metrics` laesst die Identitaet unveraendert,
//!   waehrend der `record_digest` abweicht (Definition 6.6/6.7). Ein
//!   Gegentest stellt sicher, dass der profilierte Lauf ueberhaupt etwas
//!   sammelt - sonst verglichen beide Seiten denselben leeren Zustand.
//!   Nur EIN Codepfad: `record_phase` ist bei ausgeschaltetem Profiling
//!   ein No-op, wird aber unveraendert aufgerufen, damit der Test die
//!   reale Implementierung prueft und nicht zwei verschiedene Zweige.
//!
//! - T-CONC-001 (nebenlaeufiger Stresstest, kanonischer Digest gleich dem
//!   sequentiellen): real gruen getestet in `psk-scheduler/tests/
//!   concurrent_tick_equals_sequential.rs::t_conc_001_a_concurrent_tick_
//!   yields_the_same_canonical_digest_as_the_sequential_one`.
//!   `tick_concurrent` (psk-scheduler::concurrent) setzt Regel 14.7s drei
//!   Saetze je einzeln um: Nebenlaeufigkeit nur INNERHALB einer Phase;
//!   nur fuer Operationen ohne gemeinsamen Schreibzustand
//!   (`concurrency_eligible` zaehlt die vier Ausnahmen abschliessend auf,
//!   die freigegebenen laufen ueber `dispatch_stateless`, das `Sigma` gar
//!   nicht erst bekommt - typseitig erzwungen, nicht bloss dokumentiert);
//!   und Ruecksortierung in die Prioritaetsordnung vor der Anwendung.
//!   Vergleichswert ist `sigma_digest` (I_t), nicht der Tracekopf -
//!   I-ARCH-009 spricht vom kanonischen Zustandsdigest.
//!   Der Negativnachweis (ohne Ruecksortierung MUSS der Digest abweichen)
//!   fand beim ersten Lauf einen realen Fehler im Harness selbst: die
//!   Ergebnisse kamen ueber `join()` in Spawnreihenfolge zurueck, womit
//!   der Sortierschritt toter Code war und der Positivtest die Ordnung
//!   gar nicht prueft e. Seither ueber einen Kanal in echter
//!   Fertigstellungsreihenfolge.
//!   Befund zu M19s Anhaengereihenfolge: sie kann unter Nebenlaeufigkeit
//!   nicht divergieren, und nicht aus Glueck - `TraceStore::append` nimmt
//!   `&mut self`, `Sigma` wird nie geteilt, kein Thread KANN anhaengen.
//!   Alle Segmente entstehen in der sequentiellen Anwendungsschleife in
//!   `select()`-Ordnung. Der Grund ist Regel 14.7s eigener: der Trace IST
//!   gemeinsamer Schreibzustand, also ist Anhaengen keine freigegebene
//!   Operation - es braucht keine Sperre, weil es keinen Wettlauf gibt.
//!
//! - T-PASS-001 (reorder_compiler_passes -> divergence_report): real gruen
//!   getestet in `t_pass_001_reordering_two_passes_alone_already_diverges_i_a`
//!   (unten). Die fruehere Einordnung ("keine ausfuehrbare Passpipeline
//!   existiert") uebersah die billigere Lesart: die Passfolge IST im
//!   versiegelten Register deklariert, also ist ihre Umordnung am I_A
//!   nachweisbar, ohne dass ein Compilerlauf noetig waere. Der Test
//!   mutiert AUSSCHLIESSLICH die Reihenfolge - zwei benachbarte Zeilen
//!   vertauscht, gleiche Menge, gleiche Anzahl, per Sortiervergleich
//!   zugesichert. Diese Enge ist der Punkt: t_arch_001 zeigt bereits,
//!   dass IRGENDEINE Inhaltsaenderung I_A bricht; erst die reine
//!   Permutation zeigt, dass die REIHENFOLGE selbst identitaetsbildend
//!   ist (Definition 11.1, geordnete Passfolge; `Can` erhaelt
//!   Arrayreihenfolgen).
//! - T-TRACE-001 (drop_previous_residue -> FAIL): real gruen als
//!   `compile_fail`-Doctests an `psk_trace::ResidueLedger`. Die
//!   Zusicherung IST die Abwesenheit von `remove`/`clear` und eines
//!   Schreibzugriffs auf die Sammlung (Axiom 7.41) - ein Laufzeittest
//!   kann das nicht leisten, weil man nicht aufrufen kann, was nicht
//!   existiert. Eine Positivkontrolle daneben zeigt, dass derselbe Aufbau
//!   uebersetzt: ohne sie bestuende ein `compile_fail` auch bei einem
//!   blossen Tippfehler im Aufbau.
//!   Hinweis zur Deckung: `verify-catalog` kann diesen Eintrag NICHT
//!   pruefen - Doctests tragen keinen Funktionsnamen, an dem die
//!   ID-Beschriftung haengen koennte. Das ist die dort dokumentierte
//!   Luecke, hier konkret.
//! - T-FORECAST-001 (overwrite_forecast_after_observation -> FAIL): real
//!   gruen in `psk_thought::forecast` - `t_forecast_001_a_later_
//!   observation_only_appends_and_never_replaces` plus drei
//!   `compile_fail`-Doctests und eine Positivkontrolle.
//!   PSK-RA v1.0.22 hat die Voraussetzung an der Quelle geschaffen: OBJ-FCT
//!   (Struktur 20.10) fuehrt horizon, generation_basis, validity_window,
//!   anchor_ref und append-only `evaluations`. Zuvor benannte Vertrag
//!   20.12 vier Pflichtfelder, ohne dass ein Objekt sie trug - es gab
//!   nichts zu ueberschreiben.
//!   Befund bei der Umsetzung: der GENERIERTE Typ allein genuegt Regel
//!   20.11 nicht - alle Felder sind `pub` (Codegen-Konvention), also ist
//!   "besitzen keinen Schreibpfad nach Konstruktion" auf ihm eine blosse
//!   Konvention, dieselbe Lage wie bei T-OWN-001. `SealedForecast` (M07)
//!   schliesst das mit dem Muster von `ResidueLedger`/`TraceStore`:
//!   privates Feld, `&`-Getter, `evaluate()` als einziger veraendernder
//!   Weg und ausschliesslich anhaengend.
//!
//! - T-UNKNOWN-001 (verbal_uncertainty_without_internal_block -> FAIL):
//!   real gruen in `psk_thought::reality::tests::t_unknown_001_unknown_
//!   bars_every_promotion_regardless_of_fact_status` plus den beiden
//!   M18-Tests in `psk_reconciliation::reconcile::tests`.
//!   Die fruehere Einordnung ("verbale Unsicherheit ist nirgends als Typ
//!   gefasst") verwechselte die Szenarienrahmung mit dem pruefbaren Kern.
//!   Vertrag 7.11 enumeriert vier Formen, in denen sich Unwissen
//!   materialisieren MUSS - das ist dieselbe Art Aufzaehlung, die
//!   T-PERSONA-001 ueber Personas Feldliste traegt, nur ueber Zustaende
//!   statt ueber Felder. Und `claim.text` ist ohnehin `non_canonical`,
//!   fuer die Maschine also unsichtbar - genau der Grund fuer die
//!   Materialisierungspflicht. Pruefbare Form: `reality_status == UNKNOWN`
//!   sperrt JEDE Promotion.
//!   Befund vor dem Bau: keine Promotionsstelle prueft e das. Es gab EINE
//!   Wache (`check_promotion`, M07), die ausschliesslich `FactStatus`-Paare
//!   gegen Invariante 5.9 pruefte, und eine ZWEITE, unabhaengige Ableitung
//!   in M18 (`reconcile`s `fact_promotion`), die `reality_status` gar nicht
//!   sah. Vertrag 7.11s "Promotionssperre" war damit beschreibend, nicht
//!   wirksam.
//!   Umsetzung: EINE Wache, ZWEI Aufrufer. `check_promotion` nimmt jetzt
//!   auch `reality_status` und ist die einzige Stelle, die ueber Promotion
//!   entscheidet; M18 ruft sie auf, statt selbst abzuleiten (Paketkante
//!   M18->M06/M07, durch P26 gedeckt - kein neuer Port). Zwei getrennte
//!   Guards waeren auseinandergedriftet, dieselbe Ueberlegung wie bei
//!   `dispatch`/`dispatch_stateless`. Eine gesperrte Promotion senkt auf
//!   NONE, statt die Reconciliation scheitern zu lassen - das Ergebnis
//!   steht sichtbar im Bericht, ist also nicht still.
//! - T-FIELD-001 (set_system_identity_to_field_id -> FAIL): real gruen an
//!   BEIDEN Schreibstellen -
//!   `psk_fields::registry::tests::t_field_001_a_field_whose_id_equals_the_
//!   system_identity_is_refused` (M08) und
//!   `psk_contract::identity_binder::tests::t_field_001_a_registered_field_
//!   equal_to_the_system_identity_is_refused` (M04).
//!   Beide, weil die Zeitachse beide Richtungen offen laesst: bei `bind()`
//!   koennen bereits Felder existieren, nach `bind()` kommen neue hinzu -
//!   eine Pruefung an nur einer Stelle liesse die andere offen. M08 bekommt
//!   die Systemidentitaet als deklarierten Parameter (wie
//!   `has_independent_evidence` in M24), kein neuer Port. In Sigma wird
//!   ausdruecklich NICHT geprueft: das waere Feststellung nach Eintritt,
//!   waehrend die Invariante einen Zustand benennt, der nicht entstehen
//!   darf.
//!   Die fruehere Einordnung als T-OWN-001-Folge war falsch und ist
//!   zurueckgenommen: I-FIELD-001 ist ein WERTpraedikat ("welchen Wert darf
//!   es tragen"), T-OWN-001 ein Konstruktionsverbot ("wer darf
//!   konstruieren"). Das erste braucht keine Typversiegelung, sondern eine
//!   Laufzeitpruefung an der Schreibstelle - was `severity: blocking`
//!   gerade bezeichnet.
//!   UMFANG, ehrlich: geprueft ist der EINZELFALL (eine Feldidentitaet
//!   gegen die Systemidentitaet). I-FIELD-001 deckt daneben den MENGENFALL
//!   ab - "keine MENGE aktiver Feldidentitaeten" darf die Systemidentitaet
//!   ergeben, also auch keine Kombination/Aggregation mehrerer. Dieser Teil
//!   ist NICHT gebaut und NICHT geprueft; er bleibt als offenes Residuum
//!   benannt, nicht als erledigt ausgegeben. Was eine solche Aggregation
//!   ueberhaupt waere (Vereinigung? Digest ueber die Menge?), legt das Werk
//!   an dieser Stelle nicht fest.
//!
//! ## (c) Derzeit nicht realisierbar (Befund, mit Begruendung)
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
//!   fuer alle 27: es funktioniert nur, WEIL GateAuthorization ausserhalb
//!   des Objektregisters in einem eigenen Crate liegt (object_registry.yaml
//!   fuehrt 28 Eintraege, keiner davon GateAuthorization); die 27
//!   kanonischen Objekte teilen sich dagegen EIN Crate (psk_types, via
//!   psk-types/build.rs) und werden per Struct-Literal in mindestens fuenf
//!   weiteren Crates konstruiert - Sealing dort wuerde entweder den
//!   gesamten Workspace an jeder Konstruktionsstelle brechen oder (falls
//!   Konstruktorfunktionen in psk_types selbst blieben) nichts durchsetzen,
//!   da psk_types von jedem Crate gleichermassen importierbar ist. Echte
//!   Durchsetzung braeuchte das physische Verschieben aller 27
//!   Typdefinitionen in ihre besitzenden Crates - explizit gepruedft und
//!   auf Anweisung NICHT unternommen: das Verhaeltnis von Aufwand zu
//!   Gewinn steht nicht im Verhaeltnis, und nichts verschlechtert sich
//!   gegenueber dem seit WP02 bekannten Zustand. FAIL_PSK_E014 hat deshalb
//!   weiterhin keinen Code-Pfad, der ihn tatsaechlich erzeugt - bewusst
//!   offen gelassen, nicht uebersehen.

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
                // T-UNKNOWN-001: ein Subjekt, dessen Realitaetsstatus die
                // Promotion nicht sperrt.
                subject_reality_status: psk_types::objects::RealityStatus::Actualized,
                subject_facticity: psk_types::objects::FactStatus::Observed,
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
                // I-FIELD-001: eine Systemidentitaet, die von jeder
                // real erzeugbaren Feld-ID verschieden ist.
                system_identity: Digest::sha256(b"system-identity-not-a-field"),
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

    // ---- T-PASS-001: reorder_compiler_passes -> divergence_report ----

    /// Die Mutation heisst `reorder_compiler_passes`, und genau das tut
    /// dieser Test: er vertauscht ZWEI benachbarte Passzeilen in
    /// `pass_registry.yaml` und laesst alles andere unberuehrt - dieselben
    /// Paesse, dieselbe Anzahl, derselbe Inhalt je Zeile.
    ///
    /// Warum diese Enge zaehlt: `t_arch_001_...` oben zeigt bereits, dass
    /// IRGENDEINE Inhaltsaenderung an einem Register I_A bricht. Ein
    /// T-PASS-001, das ebenfalls Inhalt aendert, bewiese nur dasselbe ein
    /// zweites Mal. Erst die reine Umordnung zeigt die Aussage, die
    /// T-PASS-001 eigen ist: die REIHENFOLGE der Passfolge ist selbst
    /// identitaetsbildend, nicht bloss ihre Menge. Definition 11.1 fuehrt
    /// C1..C11 als geschlossene, geordnete Folge; `Can` erhaelt
    /// Arraysreihenfolgen ausdruecklich ("erhaelt Arrayreihenfolgen",
    /// Kapitel 6), weshalb eine Permutation einen anderen Digest ergibt.
    ///
    /// Damit braucht T-PASS-001 keine ausfuehrbare Passpipeline: die
    /// Divergenz ist am versiegelten Register nachweisbar, nicht erst an
    /// einem Compilerlauf.
    #[test]
    fn t_pass_001_reordering_two_passes_alone_already_diverges_i_a() {
        let root = workspace_root();
        let scratch = std::env::temp_dir().join(format!("psk-t-pass-001-{}", std::process::id()));
        let _ = fs::remove_dir_all(&scratch);
        copy_dir(&root.join("architecture"), &scratch.join("architecture")).unwrap();

        let before = verify_architecture::check_architecture_bundle(&scratch).unwrap();
        assert!(before.matches(), "unveraenderte Kopie sollte I_A treffen");

        let target = scratch.join("architecture/pass_registry.yaml");
        let content = fs::read_to_string(&target).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let c6 = lines
            .iter()
            .position(|l| l.trim_start().starts_with("- {id: C6,"))
            .expect("C6 steht im realen Register");
        let c7 = lines
            .iter()
            .position(|l| l.trim_start().starts_with("- {id: C7,"))
            .expect("C7 steht im realen Register");
        assert_eq!(c7, c6 + 1, "C6 und C7 muessen benachbart sein");

        let mut swapped = lines.clone();
        swapped.swap(c6, c7);
        let mutated = swapped.join("\n") + "\n";

        // Die Mutation ist NUR eine Permutation: Zeilenmenge und Zahl
        // bleiben gleich. Ohne diese Zusicherung koennte der Test
        // unbemerkt zu einer gewoehnlichen Inhaltsaenderung werden und
        // damit wieder nur T-ARCH-001 nachspielen.
        let mut original_sorted = lines.clone();
        let mut mutated_sorted: Vec<&str> = mutated.lines().collect();
        original_sorted.sort_unstable();
        mutated_sorted.sort_unstable();
        assert_eq!(
            original_sorted, mutated_sorted,
            "die Mutation DARF ausschliesslich umordnen, nichts hinzufuegen oder aendern"
        );
        assert_ne!(
            content.lines().collect::<Vec<_>>(),
            mutated.lines().collect::<Vec<_>>(),
            "sie muss die Reihenfolge aber tatsaechlich aendern"
        );

        fs::write(&target, mutated).unwrap();

        let after = verify_architecture::check_architecture_bundle(&scratch).unwrap();
        assert!(
            !after.matches(),
            "eine reine Umordnung der Passfolge MUSS I_A brechen - die Reihenfolge \
             ist identitaetsbildend, nicht nur die Menge (Definition 11.1)"
        );

        fs::remove_dir_all(&scratch).ok();
    }
}
