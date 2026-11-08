# Änderungsprotokoll

## 1.2.2 – Sicherheits-Update
- **Log-Injection behoben:** Ein Angreifer konnte über einen SSH-Benutzernamen eine fremde IP-Adresse in die Logzeile schmuggeln und so unbeteiligte Adressen sperren lassen. SSH-Zeilen werden jetzt am Zeilenende verankert, Firewall-Meldungen nur noch als echte Kernel-Meldungen akzeptiert.
- **Quarantäne-Wiederherstellung:** folgt keinem Symlink mehr (Root-Schreibzugriff auf fremde Dateien nicht mehr möglich).
- **Web-Oberfläche:** Schutz vor CSRF und DNS-Rebinding (Origin-/Host-Prüfung, Option `web.allowed_hosts` für eigene Rechnernamen), kleine Größenlimits vor der Anmeldung, Server-Timeouts gegen Slowloris, strengere Prüfung der Konfiguration.
- **Downloads:** Weiterleitungen von HTTPS auf HTTP werden abgelehnt.
- **Dienst:** zusätzliche systemd-Härtung, restriktive Dateirechte (UMask 0077).

## 1.2.1
- Neues Logo (Schild mit R-Monogramm und Netzwerkknoten) in Oberfläche, Browser-Icon und README.

## 1.2.0
- **Auto-Updater:** neue signierte Versionen von GitHub werden automatisch installiert (Prüfung alle 6 h, abschaltbar unter *Einstellungen → Updates*, Schlüssel `update.auto_install`). Nicht bei aktiver Netztrennung; jede Version wird höchstens einmal automatisch versucht; Sicherung und Rollback wie gewohnt.

## 1.1.1
- Umbenennung in **RF-NetGuard**, Veröffentlichung unter der MIT-Lizenz auf GitHub (friedlro/RF-Netguard).
- Updates direkt von GitHub-Releases (signiert, mit automatischem Rollback); eingebauter Release-Schlüssel.
- Automatisches Zusammenführen (Auto-Merge) und automatische Releases per GitHub Actions.
- Dokumentation (`docs/`) und README.

## 1.1.0 und früher
- Firewall (nftables) mit Sicherheitsstufen, DNS-Filter/Werbeblocker (AdGuard-Syntax), Angriffserkennung,
  automatische Netztrennung mit LAN-Zugriff, ClamAV-Virenschutz, Benachrichtigungen, Web-Oberfläche,
  niedrige Latenz (Cache, Prefetch, Upstream-Ranking), Update-Mechanismus, Spenden-Button.
