# Updates

**Kurzfassung:** Du musst nichts einrichten. RF-NetGuard holt sich neue Versionen selbst aus dem GitHub-Repository
`friedlro/RF-Netguard`, prüft sie, sichert die alte Version und startet neu – bei Problemen automatisch zurück zur alten Version.

## Wie es funktioniert
* Alle 6 Stunden (`update.check_hours`) liest RF-NetGuard die Versionsnummer in `package.json` auf GitHub (Zweig `main`).
* Ist sie höher als die installierte, wird das Programm per HTTPS von GitHub geladen und – bei aktivierter Automatik (Standard) – installiert.
* Davor: Archiv auf unsichere Pfade/Links prüfen, Syntax und Start mit deiner vorhandenen Konfiguration testen. Danach: Sicherung (die letzten 3 bleiben in `/opt/netguard-backups`), austauschen, Dienst neu starten, Funktion prüfen. Startet die neue Version nicht, wird die alte wiederhergestellt.
* Nicht bei aktiver Netztrennung; schlägt eine Version fehl, wird sie nicht endlos wiederholt.
* Konfiguration, Passwort, Listen, Sperren und Protokolle bleiben erhalten; Firewall-Regeln bleiben während des Neustarts aktiv.

## Bedienung
| Was | Wie |
|---|---|
| Automatik an/aus | *Einstellungen → Updates → Updates automatisch installieren* |
| Jetzt suchen / installieren | *Nach Updates suchen* und *Jetzt aktualisieren* in der Oberfläche, oder `sudo rf-netguard update` |
| Nur prüfen | `sudo rf-netguard update --check` |
| Zurück zur vorherigen Version | Knopf *Vorherige Version wiederherstellen* oder `sudo rf-netguard rollback` |

## Neue Version veröffentlichen (Entwickler)
Version in `package.json` erhöhen und nach `main` bringen (per Pull Request mit Auto-Merge oder direkt). Das war's – alle Installationen ziehen die Version beim nächsten Check.

## Vertrauen und Sicherheit
Die Quelle ist dein GitHub-Repository über HTTPS; wer dort schreiben darf, kann Code verteilen. Schütze deshalb dein GitHub-Konto mit
Zwei-Faktor-Anmeldung. Wer zusätzlich Signaturen möchte, kann **optional** den signierten Weg nutzen:

* `update.url` auf eine eigene `latest.json` setzen (Pakete mit `node tools/release.js build` erzeugen) und optional `update.public_key` eintragen.
  Dann werden nur noch mit dem passenden Schlüssel signierte `.ngupdate`-Pakete installiert.
* Auch eine einzelne Datei lässt sich einspielen: `sudo rf-netguard update datei.ngupdate` bzw. in der Oberfläche unter *Erweitert*.
* Der GitHub-Workflow `release.yml` baut solche signierten Pakete automatisch, wenn das Secret `RELEASE_SIGNING_KEY` gesetzt ist (siehe `docs/ENTWICKLUNG.md`); ohne Secret läuft er übersprungen durch.

## Eigener Fork
`update.repo` (z. B. `meinname/mein-fork`) und `update.branch` in der Konfiguration anpassen.
