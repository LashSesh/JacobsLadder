# Versionierung

Regel 26.7 (PSK-RA v1.0.1, Kapitel 26.3): Alle Pakete verwenden semantische
Versionierung (SemVer).

- Eine Aenderung, die die Konstitutions-ID `I_C` oder die Architektur-ID
  `I_A` veraendert, erzwingt eine **Major-Version** der Implementierung.
- Eine Aenderung, die nur die Implementierungs-ID `I_M` veraendert und
  alle Golden Runs und Negativtests unveraendert bestehen laesst, ist
  **Patch** oder **Minor**.

`I_C`, `I_A`, `I_M` sind in `PSK.lock` gebunden (Struktur 26.1); ihre
Berechnung setzt die Kanonisierungsfunktion `Can()` (Algorithmus 6.1)
voraus, die erst mit WP01 (Phase I1) realisiert wird. Bis dahin traegt der
Workspace die Platzhalterversion `0.0.0` (`Cargo.toml`,
`[workspace.package].version`): keine Konformitaetsklasse ist erreicht
(Kapitel 32.1, Phase I0 hat keine zugeordnete Klasse), ein
Versionssprung waere ohne Bezugsgroesse.

Sobald Can() existiert und `I_C`/`I_A` erstmals berechnet sind, beginnt
die Versionszaehlung reell — der erste dann vergebene Stand bindet sich
an den zu diesem Zeitpunkt gueltigen `PSK.lock`-Inhalt.
