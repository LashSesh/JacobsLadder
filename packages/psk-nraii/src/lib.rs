//! NRAII-RA, die innere aktive Maschine: Schichten L0 bis L7.
//!
//! ## Warum dieses Paket kein PSK-RA-Modul besitzt
//!
//! QPM Regel 9.2 (Eigenständig in der Architektur, nicht in den Grundlagen):
//! "NRAII-RA bindet an keine PSK-RA-Module und fuehrt eigene Schichten,
//! Gates und Konformanzstufen. Diese Eigenstaendigkeit betrifft
//! Architektur - Module, Ports, Autoritaet - und DARF NICHT die
//! Grundlagen." Deshalb steht hier kein M00-M27-Eintrag: das Paket ist
//! kein Pipelinemitglied, und `verify-dependencies` nimmt es aus der
//! Portdeckungspruefung aus, WEIL es kein Modul besitzt - dieselbe
//! Ausnahme, die schon psk-conformance und die Werkzeuge tragen. Die
//! Regel ist damit im Werkzeug abgebildet, nicht bloss zugesagt.
//!
//! ## Was uebernommen wird, und wann es faellig wurde
//!
//! Dieselbe Regel verlangt in der Gegenrichtung, dass Kanonisierung,
//! Digestbildung, Identitaetsprojektion, append-only Trace und
//! Residuenbuchfuehrung UEBERNOMMEN werden: "Eine zweite Kanonisierung
//! waere eine zweite Antwort auf dieselbe Frage."
//!
//! L0 uebernahm davon nichts, als erklaerter Nullstand nach
//! Regel 7.51 (Erklärter Nullstand) mit benannter Bedingung: sobald
//! eine Struktur dieses Pakets einen Payload traegt, ist eine
//! Kanonisierung faellig, und sie MUSS die geteilte sein. Die
//! Ersatzfuellung, die dieselbe Regel verbietet, waere gewesen,
//! `psk-canon` schon damals ungenutzt aufzunehmen, um die Uebernahme zu
//! BEHAUPTEN.
//!
//! **Mit L1 ist die Bedingung eingetreten.** Der kanonische Zustand
//! traegt einen Payload, also bezieht dieses Paket seit L1
//! `psk_canon::can` und `psk_canon::CanonicalBytes::digest` - siehe
//! [`CanonicalState`], wo QPM Axiom 10.3 (Kanonisierungsidempotenz)
//! die Kanonisierung ausdruecklich als "identisch zu PSK-RAs eigener
//! Kanonisierungsinvariante" bindet. Der Nullstand ist damit nicht
//! stillschweigend verschwunden, sondern eingeloest.
//!
//! ## Schichten und Stufen laufen nicht parallel
//!
//! QPM Struktur 9.1 (Normative Schichten L0–L9) traegt die
//! Abhaengigkeiten (L2 setzt L1 setzt L0 voraus),
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB)
//! ist das Messwerk. Die beiden Leitern decken sich NICHT: die
//! Nullanker-Statelessness aus L0 ist Mindestanforderung von
//! NRAII-**1**, zusammen mit kanonischem Zustand, Signatur und
//! Quotient - alles L1-Material. Gebaut wird schichtweise, gemessen
//! stufenweise; dieselbe Trennung wie I0-I8 gegen FC0-FC8 auf der
//! PSK-RA-Seite.
//!
//! Seit v1.0.11 sagen Kapiteltabelle und Registerlisting dasselbe: bis
//! v1.0.10 trug Listing C.3 noch die gekuerzte Leiter, waehrend
//! QPM Struktur 18.3 (Konformitätsstufen NRAII-0 bis NRAII-LAB)
//! bereits die vollstaendige fuehrte. Die Zuordnung oben braucht
//! deshalb keinen Vorbehalt mehr.

mod null_anchor;
pub use null_anchor::{
    apparent_connection, AnchoredRelation, ApparentConnection, NullAnchor, Step, Traversable, N0,
};

mod canonical_state;
pub use canonical_state::CanonicalState;

mod signature;
pub use signature::{
    diamond_equivalent, lift, CompatibilityBreach, DiamondClass, QuotientOperator, Signed,
};

mod domain_contract;
pub use domain_contract::{ClaimStatus, ContractBreach, ContractComponent, DomainContract};

mod boundary;
pub use boundary::{
    decompose, residue_for_residual_part, witness_seam, BoundarySplit, Involution,
    InvolutionBreach, ResidualPart, SeamWitness,
};

mod closure_mode;
pub use closure_mode::{chi, seal_mode, ClosureMode, ModeBreach, ReciprocityWitness};

mod arms;
pub use arms::{
    accept_arm, seam_witness_id, witness_cycle, ArmBreach, ArmType, Contraction, CycleWitness,
    OrbitStage, PrivateJustification, RadialArm, WingMesh,
};

mod diagnostic_field;
pub use diagnostic_field::{
    claim_is_complete, missing_counter_horizon_reason, AttractorMap, FalsificationCheck,
    HorizonPair, Marker, ObligationStanding, ProofHorizon, ProofObligation, Response,
    ResponseOrigin,
};

mod wish;
pub use wish::{
    dependent_pairs, lift_channel, narrow_class, reobserve, shared_dependencies, ClosureBreach,
    Facet, LoopClosure, LoopStage, Materialization, SharedDependency, Wish, WishBreach,
    WishDistance, WishOutcome, WishPerspective,
};

mod peristalsis;
pub use peristalsis::{
    assimilate, closure_degree, excalibrate, pass_gate, renew, sediment, ClosureDegree,
    CycleBreach, CycleGate, Excalibrated, Gated, Kernel, MassStage, MonodromyRatchet,
    PreservedStructure, Qsna, RatchetBreach, RawMass, RenewedBoundary, Sediment,
};

mod stack_closure;
pub use stack_closure::{
    reach_fixpoint, run_harness, AttractorStack, CheckOutcome, EmbeddingCertificate,
    FixpointBreach, FoldBundle, HarnessReport, Probe, Reproducer, StackBreach, StackFixpoint,
    StackLevel,
};
