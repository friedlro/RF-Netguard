<p align="center"><img src="docs/logo.svg" alt="RF-NetGuard Logo" width="120"></p>

# RF-NetGuard

[![CI](https://github.com/friedlro/RF-Netguard/actions/workflows/ci.yml/badge.svg)](https://github.com/friedlro/RF-Netguard/actions/workflows/ci.yml)
[![Lizenz: MIT](https://img.shields.io/badge/Lizenz-MIT-green.svg)](LICENSE)

Firewall, WireGuard-VPN, DNS-Filter mit Werbeblocker (AdGuard-Syntax), Angriffserkennung und Virenschutz für einen Linux-Rechner (Ubuntu/Debian).
Läuft als Systemdienst, hat eine deutsche Web-Oberfläche und trennt den Rechner bei schwerem Verdacht automatisch vom Netz –
das interne Netz behält dabei Zugriff, damit du Fehlalarme sofort freigeben kannst.

## Funktionen

| Bereich | Was passiert |
|---|---|
| **Firewall** (nftables) | Alles Eingehende ist gesperrt, außer explizit freigegebene Ports. Vier Sicherheitsstufen (niedrig / normal / hoch / paranoid). Schutz vor SYN-Flut, Portscans, Brute-Force; automatische Sperrlisten; Bedrohungs-IP-Listen (Feodo, Spamhaus DROP, Emerging Threats). |
| **DNS-Filter** | Eigener DNS-Server (UDP+TCP) mit AdGuard-Regelsyntax, Werbeblocker (AdGuard, HaGeZi, OISD), Filterlisten, eigene Regeln/Ausnahmen, lokale DNS-Namen, SafeSearch, Cache, DNS-over-HTTPS zu Quad9/Cloudflare, Abfrageprotokoll und Statistik. |
| **Angriffserkennung** | Portscan, SSH-Einbruchsversuche, Verbindungen zu Botnet-Servern, Krypto-Miner, Reverse-Shells, neue offene Ports, Änderungen an Systemdateien (z. B. `/etc/passwd`, `ld.so.preload`), Traffic-Ausreißer, ARP-Spoofing, DNS-Tunneling/DGA. |
| **Virenschutz** | ClamAV: Echtzeitüberwachung neuer Dateien, täglicher Vollscan, Quarantäne, Schadprozesse werden beendet. |
| **Benachrichtigung** | Telegram, ntfy (Push), E-Mail, Webhook – ab einstellbarem Schweregrad. Nachrichten, die wegen Netztrennung nicht rausgehen, werden nach der Freigabe nachgeholt. |
| **Netztrennung** | Summe der „Kompromittierungs-Punkte" im Zeitfenster ≥ Schwellwert → erst Benachrichtigung, dann Trennung. Admin-Adressen bleiben optional erreichbar. |

## Installation

Einzeiler (Debian/Ubuntu, als root):
```bash
curl -fsSL https://raw.githubusercontent.com/friedlro/RF-Netguard/main/deploy/get.sh | sudo bash
```
oder manuell:
```bash
git clone https://github.com/friedlro/RF-Netguard.git
cd RF-Netguard && sudo ./deploy/install.sh
```
Danach die Oberfläche öffnen: `http://<IP-des-Rechners>:8088`. Details: [docs/INSTALLATION.md](docs/INSTALLATION.md)

> **Gegen Aussperren:** Trage deinen Admin-PC in `admin_ips` ein. Notfall: `sudo rf-netguard firewall-off`.

## Updates direkt von GitHub

RF-NetGuard prüft alle 6 Stunden das GitHub-Repository und installiert neuere Versionen automatisch (abschaltbar), mit Sicherung und automatischem Rollback.
Nichts einzurichten – von Hand: `sudo rf-netguard update` oder Knopf in den Einstellungen.
Mehr in [docs/UPDATES.md](docs/UPDATES.md); Entwickler-Hinweise in [docs/ENTWICKLUNG.md](docs/ENTWICKLUNG.md).

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Voraussetzungen, Installation, Deinstallation, Betriebsarten |
| [docs/BEDIENUNG.md](docs/BEDIENUNG.md) | Oberfläche, Fehlalarm, Netztrennung, Befehle, Benachrichtigungen |
| [docs/KONFIGURATION.md](docs/KONFIGURATION.md) | Wichtige Einstellungen und Dateipfade |
| [docs/VPN.md](docs/VPN.md) | WireGuard-VPN einrichten und verwalten |
| [docs/DNS-FILTER.md](docs/DNS-FILTER.md) | DNS-Regeln, Werbeblocker, Grenzen |
| [docs/SICHERHEIT.md](docs/SICHERHEIT.md) | Sicherheitsstufen, Konzept, Grenzen |
| [docs/UPDATES.md](docs/UPDATES.md) | Update-Mechanismus |
| [docs/ENTWICKLUNG.md](docs/ENTWICKLUNG.md) | Tests, Releases, GitHub-Automatik |

## Unterstützen

Gefällt dir RF-NetGuard? Spenden per PayPal: <https://paypal.me/RolandFriedl> (auch in den Einstellungen der Oberfläche).

## Lizenz

[MIT](LICENSE) © 2026 Roland Friedl – frei nutzbar, veränderbar und weitergebbar, ohne Gewähr.
