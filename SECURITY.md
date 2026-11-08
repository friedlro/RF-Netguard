# Sicherheitshinweise

## Schwachstellen melden
Bitte **keine** öffentlichen Issues für Sicherheitslücken. Nutze stattdessen auf GitHub
*Security → Report a vulnerability* im Repository friedlro/RF-Netguard.

## Grundsätze
- Aufruf der Oberfläche über die IP-Adresse oder den Rechnernamen; weitere Namen trägst du unter `web.allowed_hosts` ein (Schutz vor DNS-Rebinding).
- Updates werden nur installiert, wenn ihre Ed25519-Signatur zu einem vertrauenswürdigen Schlüssel passt.
- Die Web-Oberfläche ist passwortgeschützt (scrypt) und standardmäßig nur aus dem LAN erreichbar.
- Standard-Updates kommen per HTTPS aus dem GitHub-Repository (Zwei-Faktor-Anmeldung für das GitHub-Konto empfohlen). Optional gibt es signierte Pakete (Ed25519); der private Schlüssel liegt nur als GitHub-Secret `RELEASE_SIGNING_KEY`, nie im Repository.
- Die Software wird ohne Gewähr bereitgestellt (siehe LICENSE). Teste Firewall-Änderungen nie nur über eine einzige Fernverbindung.
