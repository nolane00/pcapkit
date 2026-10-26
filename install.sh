#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_USER="${SUDO_USER:-$(id -un)}"
UNINSTALL=0
NO_BIN=0

usage() {
  cat <<EOF
Usage : $0 [options]

Options :
  --user UTILISATEUR   installer pour cet utilisateur (défaut : utilisateur courant)
  --no-bin             ne pas créer le lien ~/.local/bin/pcapkit
  --uninstall          retirer le profil et le plugin
  -h, --help           afficher cette aide

Exemples :
  ./install.sh
  sudo ./install.sh --user <utilisateur>
  ./install.sh --uninstall
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --user)
      [ $# -ge 2 ] || { echo "Erreur : --user attend un nom." >&2; exit 1; }
      TARGET_USER="$2"
      shift 2
      ;;
    --uninstall) UNINSTALL=1; shift ;;
    --no-bin) NO_BIN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Option inconnue : $1" >&2; usage; exit 1 ;;
  esac
done

HOME_DIR="$(getent passwd "$TARGET_USER" | cut -d: -f6 || true)"
if [ -z "${HOME_DIR:-}" ]; then
  echo "Erreur : utilisateur inconnu : $TARGET_USER" >&2
  exit 1
fi

CONFIG_DIR="$HOME_DIR/.config/wireshark"
PLUGIN_DIR="$HOME_DIR/.local/lib/wireshark/plugins"

# Demande à tshark les chemins exacts (utile si XDG_CONFIG_HOME est personnalisé).
if command -v tshark >/dev/null 2>&1; then
  FOLDERS=""
  if [ "$(id -un)" = "$TARGET_USER" ]; then
    FOLDERS="$(tshark -G folders 2>/dev/null || true)"
  elif command -v runuser >/dev/null 2>&1; then
    FOLDERS="$(runuser -u "$TARGET_USER" -- tshark -G folders 2>/dev/null || true)"
  fi
  if [ -n "$FOLDERS" ]; then
    C="$(printf '%s\n' "$FOLDERS" | awk -F'\t' '/^Personal configuration:/ {print $2; exit}')"
    P="$(printf '%s\n' "$FOLDERS" | awk -F'\t' '/^Personal Lua Plugins:/ {print $2; exit}')"
    [ -n "${C:-}" ] && CONFIG_DIR="$C"
    [ -n "${P:-}" ] && PLUGIN_DIR="$P"
  fi
fi

PROFILE_DIR="$CONFIG_DIR/profiles/PcapKit"
LUA_DEST="$PLUGIN_DIR/pcapkit.lua"
BIN_DIR="$HOME_DIR/.local/bin"
BIN_LINK="$BIN_DIR/pcapkit"

if [ "$UNINSTALL" -eq 1 ]; then
  rm -rf "$PROFILE_DIR"
  rm -f "$LUA_DEST"
  rm -f "$BIN_LINK"
  echo "PcapKit désinstallé pour $TARGET_USER."
  echo "  Profil retiré : $PROFILE_DIR"
  echo "  Plugin retiré : $LUA_DEST"
  exit 0
fi

if ! command -v tshark >/dev/null 2>&1; then
  echo "Attention : tshark est introuvable. Installez Wireshark/tshark." >&2
fi

install -d -m 755 "$PROFILE_DIR" "$PLUGIN_DIR"
install -m 644 "$HERE/profile/preferences" "$PROFILE_DIR/preferences"
install -m 644 "$HERE/profile/colorfilters" "$PROFILE_DIR/colorfilters"
install -m 644 "$HERE/profile/dfilters" "$PROFILE_DIR/dfilters"
install -m 644 "$HERE/lua/pcapkit.lua" "$LUA_DEST"
chmod +x "$HERE/pcapkit.py"

if [ "$NO_BIN" -eq 0 ]; then
  install -d -m 755 "$BIN_DIR"
  ln -sf "$HERE/pcapkit.py" "$BIN_LINK"
fi

if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
  chown -R "$TARGET_USER":"$TARGET_USER" "$PROFILE_DIR"
  chown "$TARGET_USER":"$TARGET_USER" "$LUA_DEST"
fi

echo "PcapKit installé pour $TARGET_USER."
echo "  Profil Wireshark : $PROFILE_DIR"
echo "  Plugin Lua       : $LUA_DEST"
if [ "$NO_BIN" -eq 0 ]; then
  echo "  Commande         : $BIN_LINK"
fi
echo
echo "Prochaines étapes :"
echo "  1. Redémarrez Wireshark."
echo "  2. En bas à droite, choisissez le profil « PcapKit »."
echo "  3. Clic droit sur un paquet > PcapKit > Expliquer ce paquet."
echo "  4. Rapport HTML : pcapkit ma-capture.pcap --open"
echo
if [ "$NO_BIN" -eq 0 ] && ! printf '%s' ":$PATH:" | grep -q ":$BIN_DIR:"; then
  echo "Note : $BIN_DIR n'est pas dans votre PATH."
  echo "       Utilisez : python3 $HERE/pcapkit.py ma-capture.pcap"
fi
