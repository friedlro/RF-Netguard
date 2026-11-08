# Bedienung

## Fehlalarm – freigeben oder abschalten
Aus dem internen Netz: Oberfläche öffnen (`http://<IP>:8088`), anmelden und

* **„Fehlalarm – Netz freigeben"**: hebt die Trennung auf und pausiert die automatische Trennung wahlweise 30 min bis 24 h,
  damit dieselbe Ursache nicht sofort wieder trennt (Ereignisse werden weiter protokolliert und gemeldet).
* **„Schutz ganz ausschalten"**: entfernt Firewall-Regeln und Auto-Trennung, bis du wieder einschaltest
  (bleibt auch nach Neustart aus). Erkennung und Protokoll laufen weiter.

Am Rechner: `sudo rf-netguard release --pause 60`, `sudo rf-netguard pause-isolation 60`, `sudo rf-netguard protection off|on`.
Ohne Passwort ist die Oberfläche nur lokal erreichbar – setze deshalb das Passwort (`sudo rf-netguard passwd`),
sonst kommst du im Alarmfall aus dem LAN nicht an die Freigabe.

## Wann wird getrennt?
Jedes Ereignis der Art „Kompromittierung" hat Punkte, z. B. Reverse-Shell 100, Krypto-Miner 80, Kontakt zu Botnet-Server 60,
SSH-Einbruch nach Fehlversuchen 70, Rootkit-Hinweis in `ld.so.preload` 70, Virenfund in Echtzeit 40 (mit laufendem Prozess 100).
Erreicht die Summe innerhalb von 15 Minuten **100**, wird der Rechner getrennt (Schwellwert/Zeitfenster einstellbar).
Reine Angriffe von außen (Portscans, Brute-Force) führen zu **Sperren der Angreifer**, nicht zur Trennung des Rechners.

Trennung = alle Verbindungen ins Internet werden verworfen (auch die Weiterleitung im Gateway-Modus).
**Das interne Netz (`lan_cidrs`) behält während der Trennung Zugriff auf diesen Rechner** (`isolation.keep_lan_access`, Standard an):
Web-Oberfläche, SSH und alle anderen für das LAN freigegebenen Ports bleiben erreichbar, sodass du von jedem Gerät im Netz
freigeben oder abschalten kannst. Zusätzlich bleiben `admin_ips` erreichbar. Mit `hard_disconnect` werden weitere Schnittstellen
abgeschaltet – die des internen Netzes bleiben dabei oben. Der DNS-Filter bedient das LAN weiter, kann aber wegen der
gesperrten Internetverbindung nur gecachte Namen auflösen.

## Befehle
```
sudo rf-netguard status            sudo rf-netguard events [n] [stufe]
sudo rf-netguard isolate [Grund]   sudo rf-netguard release [--pause min]
sudo rf-netguard pause-isolation <min>   sudo rf-netguard protection on|off
sudo rf-netguard bans | ban <ip> [min] | unban <ip>
sudo rf-netguard scan [pfad…]      sudo rf-netguard selftest        (Virenscanner mit EICAR-Testmuster)
sudo rf-netguard test-notify       sudo rf-netguard accept-listeners
sudo rf-netguard update <datei|url>      sudo rf-netguard rollback      sudo rf-netguard update-key <pub>
sudo rf-netguard passwd            sudo rf-netguard setup
sudo rf-netguard reload            sudo rf-netguard restart [--reboot]
sudo rf-netguard firewall-off    (NOTFALL)
```
Konfiguration: `/etc/netguard/config.json` (siehe `config.example.json`), Logs: `/var/log/netguard/`
(`events.jsonl` = Ereignisse, `netguard.log`), Daten: `/var/lib/netguard/`.

## Benachrichtigungen einrichten
* **Telegram:** Bot bei @BotFather anlegen → Token; Chat-ID via @userinfobot.
* **ntfy:** App installieren, schwer erratbares Topic abonnieren.
* **E-Mail:** SMTP-Daten (STARTTLS/TLS).

Danach „Testnachricht senden" in den Einstellungen. Ohne Passwort ist die Oberfläche nur lokal (127.0.0.1) erreichbar.
