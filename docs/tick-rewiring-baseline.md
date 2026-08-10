# Ist-Stand vor der Umverdrahtung auf `tick()`

Aufgenommen auf `psk-ra-i0-i2-implementation` bei `bb55f00`, unmittelbar
vor Beginn des Zweigs `tick-rewiring`.

**Die Vorhersage, die den Umbau von einem Bruch unterscheidet:**
`I_t` MUSS sich ändern. **Alle übrigen Zahlen MÜSSEN gleich bleiben.**
Dieselbe Arbeit, andere Form. Ändert sich eine der übrigen, ist das ein
Befund und kein Nebeneffekt — dann anhalten und berichten, nicht
anpassen.

## Graph und Topologie

| Größe | Wert |
|---|---|
| IR-Knoten | 20 |
| IR-Kanten | 16 |
| Zellen | 18 |
| davon vakuum geschlossen | 8 |
| alle 18 geschlossen | true |
| emission_class | HOLD |

## Lauf

| Größe | Wert |
|---|---|
| Laufresiduen | 1 (blockierend) |
| scope-Residuen (Zusammenbau) | 16 |
| Obstruktionen | 1 |
| Widersprüche (Korpus) | 2, davon 1 offen |
| Feldidentitäten | 6 |
| Projektionen | 6 |
| Quotientenklassen | 1 |
| Ratchetrunden | 2 |
| Kapselfixpunkt | true |

## Identitäten

| ID | Wert |
|---|---|
| I_C | `676e8cb42fe633f5795df66989ee1803375165cc88304b60b013838af70325d9` |
| I_A | `cbd39b3198a8e37e17d1e444998a4ed413c682932fed3fc36c6d23a0bc963167` |
| I_M | `2155f5cadffa5accaef18b11ee1876761e1b048d68fb72c513daf44dada6ea56` |
| **I_t** | `c32b940f39ba26f1e75bd91cc0ac98605083b0e18d62ea1d81935fa4d5201b34` |
| trace_head | `ea79333a10ea81eca4a4e881c6e3515f42f758ef58c347f1bf8def5299c0aa0e` |
| IR-Digest | `5b64567adb5e8da8bd444027b34da5cf9d145f1eb530e530b0d18af06c70962e` |

**I_t ist der einzige Wert, dessen Änderung erwartet wird.** trace_head
und IR-Digest sind Grenzfälle und ausdrücklich mit zu beobachten: ändern
sie sich, ist zu prüfen, ob das aus der Taktung folgt (der Trace liegt
dann in Σ statt daneben) oder ob sich der Inhalt geändert hat.

## Zertifikat

| Größe | Wert |
|---|---|
| Konformitätsklasse | C0 |
| Deckungsvektor | [FC0, FC1] |
| replay_class | R3 |

## EXECUTABLE

`Some(false)`, einziger Blocker: das blockierende scope-Residuum des
offenen Korpuswiderspruchs (`golden-run-patch.txt`).

## QPM-Massenklassen

| Klasse | Zahl |
|---|---|
| sichtbarer Körper | 13 |
| Schatten | 6 |
| Gegenhorizont | 0 |
| Residuum | 1 |

Verdikt UNKNOWN (QPM-OBL-002). Witnessrang 1 bei 6 Sichten.

## Nachher-Prüfung

Nach der Umverdrahtung sind ALLE Zeilen dieser Datei erneut zu messen.
Erwartet: genau eine Änderung (I_t), begründet zwei weitere
(trace_head, IR-Digest) — jede andere Abweichung ist ein Befund.

## Nachher gemessen (Taktumverdrahtung, Regel 24.4)

Verfeinerte Vorhersage aus der v1.0.39-Runde: I_t MUSS sich ändern;
trace_head und IR-Digest DÜRFEN, einzeln begründet; alles übrige MUSS
gleich bleiben, einschließlich C0/[FC0, FC1] und R3; tick_no MUSS von 0
auf die Taktzahl steigen.

**Alle Zahlen gleich:** IR-Knoten 20, Kanten 16, Zellen 18 (8 vakuum,
alle geschlossen), emission_class HOLD; Laufresiduen 1 (blockierend),
scope-Residuen 16, Obstruktionen 1, Widersprüche 2 (1 offen);
Feldidentitäten 6, Projektionen 6, Quotientenklassen 1, Ratchetrunden 2,
Kapselfixpunkt true; Zertifikat C0, [FC0, FC1], R3; EXECUTABLE
Some(false) mit demselben einen Blocker; QPM 13/6/0/1, Verdikt UNKNOWN.

**tick_no: 0 → 3, in beiden Läufen** — der positive Nachweis. Takt 1
trägt die Schritte 2–10 (Beobachtung bis Effekt), Takt 2 die
Kapselauflösung, den Receipt-Ingress und die Reconciliation, Takt 3 den
finalen Zusammenbau und die Zellclosure darüber.

| ID | vorher | nachher | Einordnung |
|---|---|---|---|
| I_C | `676e8cb4…` | `676e8cb4…` | gleich |
| I_A | `cbd39b31…` | `cbd39b31…` | gleich — `architecture/` unangetastet |
| I_t | `c32b940f…` | `c8617bf3…` | MUSS: jetzt H(Can(Σ)) NACH den Takten |
| trace_head | `ea79333a…` | `a5d80d27…` | DARF: der Trace trägt Taktsegmente (tick.opened, dispatch.\*, phase.sealed.\*, tick.closed) statt der Geradeaus-Marken |
| IR-Digest | `5b64567a…` | `e5377e37…` | DARF: die Knotenumschläge tragen die Taktposition (trace_ref) und die Spätobjekte die fortgeschriebene logische Zeit |
| I_M | `2155f5ca…` | `7de994b1…` | **Befund, gemeldet:** I_M = H(Cargo.lock ‖ I_C ‖ I_A), und Cargo.lock trägt die angeordneten neuen Kanten (psk-scheduler→psk-ir/psk-topology, psk-conformance→psk-scheduler). Nicht angepasst — die Implementierungsidentität folgt der geänderten Implementierung; ob die Begründung trägt, entscheidet der Auftraggeber |
