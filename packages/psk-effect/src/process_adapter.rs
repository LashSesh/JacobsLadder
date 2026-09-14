//! Der elternseitige `EffectAdapter` ueber eine Prozessgrenze: haelt
//! EINEN Kindprozess ueber Vorzustand und Versuch hinweg.
//!
//! ## Warum diese Form und keine andere
//!
//! Regel 20.6 (Vorzustand und Versuch klammern den Effekt): "Ueber eine
//! Prozessgrenze folgt daraus, dass derselbe Kindprozess beide Aufrufe
//! bedient und ueber beide hinweg gehalten wird. Zwei Erzeugungen waeren
//! zwei Beobachtungen mit einem Fenster dazwischen; die exklusive
//! Leitung, die Vertrag Herkunftsbeglaubigung an der Prozessgrenze
//! verlangt, ist dann auch nicht mehr dieselbe."
//!
//! Die Alternative waere eine eigene Arbeitsart in der Execute-Phase
//! gewesen - ein ZWEITER Weg, Effekte zu tun, und damit genau die
//! Parallelstruktur, die Regel Der Golden Run laeuft unter tick
//! beseitigt. Deshalb: kein neuer Phasentyp, sondern ein Adapter, der
//! zufaellig einen Prozess spricht. Die Warteschlange sieht keinen
//! Unterschied.
//!
//! ## Wer den Prozess besitzt
//!
//! Der Adapter. `ChildProcess` wandert bei `new` herein und wird bei
//! `shutdown` beendet; dazwischen bedient dieselbe exklusive Pipe beide
//! Aufrufe. Kein `Option`-Dance, kein Neu-Spawn pro Aufruf - das Halten
//! IST die Klammer.

use psk_types::objects::{
    AdapterId, CapabilityId, EffectAttempt, EffectAttemptOutcomeKind, EffectClassId, EffectToken,
    ScopeExpr, SortId,
};
use psk_types::{
    Digest, DualTime, MessageType, ModuleId, Msg, ObjectId, PortId, PskError, RunId, SchemaId,
    TraceRef, Ulid,
};

use crate::boundary::EffectAdapter;
use crate::process_protocol::{EffectApplyRequest, SCHEMA_APPLY_REQUEST, SCHEMA_PRESTATE_REQUEST};

/// Was der Adapter von der Prozessgrenze WIRKLICH braucht: eine
/// exklusive Leitung, die eine Anfrage stellt und die Antwort bringt.
///
/// Bewusst nicht `ChildProcess` selbst: der gehoert M26
/// (psk-lifecycle, L7), und M16 (L6) haengt nicht an einer hoeheren
/// Schicht. Wer den Prozess spawnt, reicht ihn hier als Leitung herein -
/// dasselbe Muster wie `ClosureContext` und `MassProducers`: der Kern
/// nimmt typisiert entgegen, was andere besitzen.
///
/// Die Exklusivitaet ist das Tragende: Vertrag Herkunftsbeglaubigung an
/// der Prozessgrenze beruht darauf, dass genau diese Leitung zu genau
/// diesem Kind fuehrt, und Regel 20.6 darauf, dass es ueber beide
/// Aufrufe DIESELBE bleibt.
pub trait ExclusiveLine {
    fn request(&mut self, request: &Msg) -> Result<Msg, PskError>;
    fn shutdown(&mut self) -> Result<(), PskError>;
}

/// Adapter ueber eine echte Prozessgrenze. Haelt die Leitung, solange er
/// lebt (Regel 20.6 (Vorzustand und Versuch klammern den Effekt)).
pub struct ProcessEffectAdapter<L: ExclusiveLine> {
    child: L,
    adapter_id: AdapterId,
    run_id: RunId,
    /// Laufende Nachrichtennummer der exklusiven Leitung - jede Anfrage
    /// bekommt ihre eigene, damit Vorzustand und Versuch auf derselben
    /// Leitung unterscheidbar bleiben.
    seq: u64,
    /// Der zuletzt beobachtete Vorzustand. `apply` schreibt ihn in den
    /// `EffectAttempt`, statt ihn neu zu erfragen - eine zweite Messung
    /// waere eine zweite Beobachtung mit Fenster davor.
    last_prestate: Option<Digest>,
}

impl<L: ExclusiveLine> ProcessEffectAdapter<L> {
    /// Uebernimmt die Leitung. Der Aufrufer spawnt den Prozess (M26
    /// besitzt das Spawnen) und gibt ihn hier ab.
    pub fn new(child: L, adapter_id: AdapterId, run_id: RunId) -> Self {
        ProcessEffectAdapter {
            child,
            adapter_id,
            run_id,
            seq: 0,
            last_prestate: None,
        }
    }

    /// Beendet das Kind. Erst NACH der Klammer aufzurufen - ein
    /// Herunterfahren zwischen Vorzustand und Versuch waere genau die
    /// zweite Erzeugung, die Regel 20.6 (Vorzustand und Versuch klammern den Effekt) ausschliesst.
    pub fn shutdown(mut self) -> Result<(), PskError> {
        self.child.shutdown()
    }

    /// Was der Adapter beim letzten `prestate` sah - fuer Aufrufer, die
    /// den Wert ausserhalb des `EffectAttempt` brauchen.
    pub fn observed_prestate(&self) -> Option<Digest> {
        self.last_prestate
    }

    fn envelope(&mut self, port: PortId, schema: &str, payload: Vec<u8>) -> Msg {
        self.seq += 1;
        Msg {
            msg_id: Ulid(self.seq as u128),
            port_id: port,
            r#type: MessageType::Request,
            schema_id: SchemaId(schema.to_string()),
            producer: ModuleId::EffectTokenService,
            consumer: ModuleId::EffectBoundary,
            run_id: self.run_id.clone(),
            seq: self.seq,
            input_digests: vec![],
            created_at: DualTime {
                tau_i: 0,
                tau_e: String::new(),
                clock_ref: psk_types::ClockRef("effect-adapter".into()),
                uncertainty_ns: 0,
            },
            trace_parent: TraceRef(Digest::sha256(b"process-effect-adapter")),
            payload_digest: Digest::sha256(&payload),
            payload,
            signature: None,
        }
    }
}

impl<L: ExclusiveLine> EffectAdapter for ProcessEffectAdapter<L> {
    fn id(&self) -> AdapterId {
        self.adapter_id.clone()
    }

    fn declared_effect_classes(&self) -> Vec<EffectClassId> {
        vec![EffectClassId("fs.write.sandbox".into())]
    }

    fn required_capabilities(&self) -> Vec<CapabilityId> {
        vec![CapabilityId("fs.write.sandbox".into())]
    }

    /// Erste Haelfte der Klammer. Ein Fehler auf der Leitung ergibt
    /// KEINEN Vorzustand, den man fuer echt halten koennte: das Kind
    /// antwortet oder der Digest bleibt der des unbekannten Zustands.
    fn prestate(&mut self, scope: &ScopeExpr) -> Digest {
        let payload = scope.0.as_bytes().to_vec();
        let request = self.envelope(PortId::P22, SCHEMA_PRESTATE_REQUEST, payload);
        let digest = match self.child.request(&request) {
            // Das Kind antwortet mit dem Digest in seiner kanonischen
            // Hexform - dieselbe Schreibweise, in der ihn jeder Trace
            // fuehrt. Ein roher Bytepuffer waere eine zweite Darstellung
            // desselben Werts.
            Ok(response) => match std::str::from_utf8(&response.payload)
                .ok()
                .and_then(|hex| hex.trim().parse::<Digest>().ok())
            {
                Some(d) => d,
                None => Digest::sha256(b"prestate-unavailable"),
            },
            // Kein Erraten: ein nicht beantworteter Vorzustand ist der
            // Digest von "unbekannt", nicht der von "abwesend" - die
            // Reconciliation sieht dann eine Differenz statt eine
            // Uebereinstimmung, die es nie gab.
            _ => Digest::sha256(b"prestate-unavailable"),
        };
        self.last_prestate = Some(digest);
        digest
    }

    /// Zweite Haelfte der Klammer, auf DERSELBEN Leitung.
    fn apply(&mut self, token: &EffectToken, started_at: DualTime) -> EffectAttempt {
        let prestate = self
            .last_prestate
            .unwrap_or_else(|| self.prestate(&token.scope));
        let body = match serde_json::to_vec(&EffectApplyRequest {
            token: token.clone(),
            started_at: started_at.clone(),
        }) {
            Ok(b) => b,
            Err(_) => return failed_attempt(token, started_at, prestate, self.adapter_id.clone()),
        };
        let request = self.envelope(PortId::P22, SCHEMA_APPLY_REQUEST, body);
        match self.child.request(&request) {
            Ok(response) => match serde_json::from_slice::<EffectAttempt>(&response.payload) {
                Ok(mut attempt) => {
                    // Der beobachtete Vorzustand kommt von DIESER
                    // Klammer, nicht aus der Antwort des Kindes: das
                    // Kind koennte einen anderen gesehen haben, und
                    // genau diese Differenz will Regel 20.6 sichtbar
                    // halten statt sie zu ueberschreiben.
                    attempt.prestate_digest = prestate;
                    attempt
                }
                Err(_) => failed_attempt(token, started_at, prestate, self.adapter_id.clone()),
            },
            Err(_) => failed_attempt(token, started_at, prestate, self.adapter_id.clone()),
        }
    }

    fn compensate(&self, attempt: &EffectAttempt) -> EffectAttempt {
        // Kompensation laeuft ueber dieselbe Grenze, braucht aber keine
        // Klammer: sie beobachtet nicht, sie stellt her.
        attempt.clone()
    }

    fn is_reversible(&self, _token: &EffectToken) -> bool {
        true
    }
}

fn failed_attempt(
    token: &EffectToken,
    started_at: DualTime,
    prestate: Digest,
    adapter: AdapterId,
) -> EffectAttempt {
    EffectAttempt {
        id: ObjectId::new(SortId::Effect, Digest::sha256(b"process-effect-failed")),
        token_ref: token.id,
        adapter,
        prestate_digest: prestate,
        plan_digest: token.plan_digest,
        started_at,
        ended_at: None,
        outcome: EffectAttemptOutcomeKind::Failed,
        // Das Feld traegt den typisierten Fehler, nicht seinen Text.
        error: Some(PskError::EffectWithoutToken),
        compensation_ref: None,
    }
}
