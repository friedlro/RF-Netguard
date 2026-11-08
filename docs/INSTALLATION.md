# Installation

## Voraussetzungen
Debian/Ubuntu mit systemd, root-Rechte, Internetzugang für die Installation. Der Installer holt `nftables`, `iproute2`, `ClamAV`
und prüft Node.js ≥ 18.

## Installieren
```bash
curl -fsSL https://raw.githubusercontent.com/friedlro/RF-Netguard/main/deploy/get.sh | sudo bash
# oder
git clone https://github.com/friedlro/RF-Netguard.git && cd RF-Netguard && sudo ./deploy/install.sh
```
Der Einrichtungsassistent erkennt dein Netz, behält deine SSH-Verbindung und aktuell offene Ports bei, gibt Port 53 frei
(deaktiviert den systemd-resolved-Stub) und startet den Dienst `netguard`. Danach: `http://<IP>:8088`, Passwort setzen mit `sudo rf-netguard passwd`.

Der Befehl heißt `rf-netguard` (der alte Name `netguard` bleibt als Alias). Dienstname, Pfade (`/opt/netguard`, `/etc/netguard`, `/var/lib/netguard`,
`/var/log/netguard`) und nftables-Tabellen behalten ihre Namen, damit bestehende Installationen beim Update unverändert weiterlaufen.

> **Wichtig gegen Aussperren:** `admin_ips` setzen (der Assistent schlägt die aktuelle SSH-Adresse vor). Notfall: `sudo rf-netguard firewall-off`.
> Auch ohne laufenden Dienst bleiben die Regeln im Kernel aktiv (fail-closed) – bis zum Neustart oder `firewall-off`.

## Betriebsarten
* **host** – schützt diesen Rechner; der DNS-Filter bedient zusätzlich das LAN.
* **gateway** – der Rechner ist Router des Netzes: Forward-Filter, optional NAT, Zwang aller DNS-Anfragen auf den Filter (`net.ipv4.ip_forward=1` nötig).

Um das ganze Netz mit dem DNS-Filter zu schützen, trage die IP des Rechners im Router (DHCP) als DNS-Server ein oder nutze den Gateway-Modus.

## Deinstallieren
`sudo /opt/netguard/deploy/uninstall.sh`
