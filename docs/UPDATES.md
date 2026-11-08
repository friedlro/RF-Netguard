# Updates

RF-NetGuard aktualisiert sich **direkt von GitHub** (Releases von `friedlro/RF-Netguard`), ohne Neuinstallation.

## Automatisch von GitHub
* Standard-Update-Adresse: `https://github.com/friedlro/RF-Netguard/releases/latest/download/latest.json`
* RF-NetGuard prüft täglich (`update.check_hours`) und zeigt in der Oberfläche ein Banner; installiert wird nach Bestätigung
  (*Einstellungen → Updates*) oder per `sudo rf-netguard update https://github.com/friedlro/RF-Netguard/releases/latest/download/latest.json`.
* Jede Release-Datei ist mit Ed25519 signiert. Der öffentliche Schlüssel ist im Programm eingebaut (`src/update-key.js`);
  nicht passend signierte Dateien werden nie installiert.

## Ablauf und Sicherheit
Konfiguration, Passwort, Listen, Sperren und Protokolle liegen in `/etc/netguard`, `/var/lib/netguard` und `/var/log/netguard` –
ein Update tauscht nur das Programm in `/opt/netguard`. Die Firewall-Regeln bleiben während des kurzen Neustarts im Kernel aktiv.

**Ablauf jedes Updates:** Signatur und Prüfsumme prüfen → Archiv auf unsichere Pfade/Links prüfen → Syntax und Start mit deiner
vorhandenen Konfiguration testen → Sicherung der alten Version (die letzten 3 bleiben in `/opt/netguard-backups`) → austauschen →
Dienst neu starten → Funktion prüfen. **Startet die neue Version nicht, wird automatisch die alte wiederhergestellt.**


## Weitere Wege
| Weg | Befehl / Bedienung |
|---|---|
| Datei | `sudo rf-netguard update rf-rf-netguard-1.2.0.ngupdate` |
| Adresse | `sudo rf-netguard update https://server/rf-rf-netguard-1.2.0.ngupdate` |
| Oberfläche | *Einstellungen → Updates → Update-Datei installieren* (nur signierte Updates) |
| Zurück | `sudo rf-netguard rollback` oder Knopf *Vorherige Version wiederherstellen* |

## Eigener Fork / eigener Schlüssel
`node tools/release.js keygen ~/keys` erzeugt ein Schlüsselpaar. Öffentlichen Schlüssel unter `update.public_key` eintragen
(`sudo rf-netguard update-key release-key.pub`), mit `update.builtin_key: false` den eingebauten Schlüssel abschalten und
`update.url` auf den eigenen Fork setzen. Siehe `docs/ENTWICKLUNG.md`.
