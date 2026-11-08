# Entwicklung und Veröffentlichung

## Repository
* `src/` Dienst (Node.js ≥ 18, keine Abhängigkeiten) · `ui/` Web-Oberfläche · `deploy/` Installer/systemd · `tools/` Release-Werkzeug · `test/` Tests.

## Tests
```bash
node test/run.js                         # Regeln, DNS-Server, Updates, Bedrohungslogik, Web-API (ohne Root)
sudo unshare -n node test/nft-live.js    # echte nftables-Regeln in isoliertem Netzwerk-Namespace
sudo bash test/netns-live.sh             # echter Verkehr in drei Namespaces (iproute2, python3)
```

## Automatik auf GitHub (Actions)
| Workflow | Aufgabe |
|---|---|
| `ci.yml` | Syntax- und Funktionstests bei jedem Push/PR |
| `auto-merge.yml` | Pull Requests werden nach bestandenem Test automatisch (Squash) gemergt – ohne Rückfrage |
| `release.yml` | *Optional:* baut bei neuer Version signierte Pakete (`.ngupdate` + `latest.json`) für eigene Update-Server. Ohne Secret `RELEASE_SIGNING_KEY` wird es übersprungen. Für die normalen Updates nicht nötig. |

Einmalige Einrichtung im Repository (Settings):
1. *General → Pull Requests*: **Allow auto-merge** und **Automatically delete head branches** aktivieren.
2. *Branches*: Regel für `main` mit erforderlichem Status-Check **test** (damit Auto-Merge erst nach grünem Test greift).
3. *Secrets and variables → Actions*: Secret **`RELEASE_SIGNING_KEY`** anlegen – Inhalt der privaten Schlüsseldatei `release-key.pem`
   (zum eingebauten öffentlichen Schlüssel in `src/update-key.js` passend).
4. *Actions → General → Workflow permissions*: **Read and write permissions**.

## Neue Version veröffentlichen
1. `version` in `package.json` erhöhen, `CHANGELOG.md` ergänzen, per Pull Request nach `main` bringen (wird automatisch gemergt).
2. `release.yml` erzeugt `rf-netguard-<version>.ngupdate` und `latest.json`; installierte Systeme melden das Update.

## Eigenen Schlüssel erzeugen
```bash
node tools/release.js keygen ~/rf-netguard-keys        # release-key.pem GEHEIM halten
```
Den öffentlichen Teil in `src/update-key.js` eintragen, den privaten als Secret `RELEASE_SIGNING_KEY` hinterlegen.
Lokal bauen: `node tools/release.js build --key release-key.pem --notes "Was ist neu"` → `dist/`.
