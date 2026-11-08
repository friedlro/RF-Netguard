#!/usr/bin/env bash
# Einzeiler-Installation bzw. Update: lädt das neueste signierte Release von GitHub und installiert es.
#   curl -fsSL https://raw.githubusercontent.com/friedlro/RF-Netguard/main/deploy/get.sh | sudo bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Bitte als root ausführen (sudo)."; exit 1; }
command -v curl >/dev/null || { apt-get update -qq && apt-get install -y -qq curl; }
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
curl -fsSL https://github.com/friedlro/RF-Netguard/archive/refs/heads/main.tar.gz | tar -xz -C "$T" --strip-components=1
bash "$T/deploy/install.sh"
