# Referenzkorpus

Die versiegelte Menge aus Schritt 1 des Referenzauftrags: Spezifikations-
und Quelltextdateien, die vor dem Versiegeln des Ankers in das beobachtete
Verzeichnis kopiert werden.

- `requirements.yaml` - die Anforderungen, in der Form von
  `constitution/requirement_matrix.yaml` plus `precedence`.
- `src/patch_target.txt` - die Quelltextdatei, auf die sich die
  Anforderungen beziehen und die der Patch spaeter aendert. Genau diese
  Aenderung ist die Beobachtung, unter der das Frischepraedikat des
  Ankers faellt (Regel "Ein Frischepraedikat muss verletzbar sein").

Das Korpus liegt ausserhalb von `architecture/`: es ist Domaeneninhalt,
kein Architekturkoerper, und darf deshalb nicht in I_A eingehen.
