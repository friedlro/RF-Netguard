# Sicherheitshinweise

## Schwachstellen melden
Bitte **keine** öffentlichen Issues für Sicherheitslücken. Nutze stattdessen auf GitHub
*Security → Report a vulnerability* im Repository friedlro/RF-Netguard.

## Grundsätze
- Updates werden nur installiert, wenn ihre Ed25519-Signatur zu einem vertrauenswürdigen Schlüssel passt.
- Die Web-Oberfläche ist passwortgeschützt (scrypt) und standardmäßig nur aus dem LAN erreichbar.
- Der private Release-Schlüssel liegt ausschließlich als GitHub-Secret `RELEASE_SIGNING_KEY` und nie im Repository.
- Die Software wird ohne Gewähr bereitgestellt (siehe LICENSE). Teste Firewall-Änderungen nie nur über eine einzige Fernverbindung.
