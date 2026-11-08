# Änderungsprotokoll

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
