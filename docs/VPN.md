# WireGuard-VPN

RF-NetGuard enthält einen WireGuard-Server mit Teilnehmerverwaltung: Handy oder Laptop verbinden sich von unterwegs sicher mit deinem Netz,
nutzen dort den DNS-Filter/Werbeblocker und (optional) deinen Internetanschluss.

## Voraussetzungen
* Paket `wireguard-tools` (der Installer versucht es zu installieren; sonst `sudo apt install wireguard-tools`) und ein Kernel mit WireGuard (Ubuntu/Debian: Standard).
* Am Router: **UDP-Port 51820 (oder dein gewählter Port) an diesen Rechner weiterleiten**. Ohne öffentliche IPv4 (CGNAT) geht das nicht – dann ein VPS als Gegenstelle oder Tailscale verwenden.
* Optional ein DynDNS-Name, falls sich deine öffentliche IP ändert.

## Einrichten
1. *VPN* → **VPN-Server einschalten**, unter *Öffentliche Adresse für Clients* deinen DynDNS-Namen oder die öffentliche IP eintragen, *Speichern & anwenden*.
   Der Server-Schlüssel wird dabei automatisch erzeugt.
2. Unter *Teilnehmer* einen Namen eingeben (z. B. „Handy Roland“) → **Teilnehmer hinzufügen** → **Konfiguration** anzeigen.
3. Auf dem Gerät in der WireGuard-App „Tunnel aus Datei importieren“ (Datei herunterladen) oder den Text einfügen – fertig.

## Einstellungen
| Einstellung | Bedeutung |
|---|---|
| VPN-Netz | Adressbereich des VPN, Standard `10.66.0.1/24` (darf sich nicht mit deinem LAN überschneiden) |
| Clients dürfen ins LAN | Zugriff auf die unter *Erreichbare LAN-Netze* genannten Netze (leer = automatisch LAN-Netze ab /20; trage dein LAN ein, z. B. `192.168.1.0/24`) |
| Full-Tunnel | Der gesamte Internetverkehr der Clients läuft über diesen Rechner (inkl. DNS-Filter); IPv6 wird im Tunnel blockiert, damit nichts daran vorbeiläuft |
| Clients untereinander trennen | VPN-Geräte können sich nicht gegenseitig erreichen (empfohlen) |
| Dienste dieses Rechners | Zugriff auf Oberfläche, SSH und DNS-Filter über das VPN |
| DNS für Clients | leer = DNS-Filter dieses Rechners |

## Sicherheit
* Jeder Teilnehmer hat ein eigenes Schlüsselpaar plus Preshared Key (zusätzlicher Schutz). Der Server speichert die Client-Schlüssel in `/etc/netguard/config.json` (nur root lesbar), damit du Konfigurationen erneut anzeigen kannst. Die Oberfläche/API gibt Schlüssel nur in der Client-Konfiguration an angemeldete Nutzer heraus.
* **Teilnehmer sperren/löschen** wirkt sofort. Ist ein Gerät verloren, löschst du den Teilnehmer.
* Der UDP-Port ist in der Firewall für alle offen – WireGuard antwortet Unbekannten nicht (kein Portscan-Hinweis); Zugang haben nur bekannte Schlüssel.
* Bei Netztrennung bleibt der Zugriff aus dem VPN auf diesen Rechner erhalten (wie beim LAN), Weiterleitung ins Internet/LAN ist dann unterbrochen.

## Fehlersuche
* *Status*: „nicht aktiv“ + Meldung (fehlendes `wg`, Kernelmodul …) steht in der Oberfläche und im Log.
* Client verbindet nicht: Port-Weiterleitung am Router, richtige öffentliche Adresse, Zeit auf beiden Geräten.
* Kein Internet im Full-Tunnel: *Full-Tunnel* eingeschaltet? Rechner hat `net.ipv4.ip_forward=1` (wird automatisch gesetzt).
