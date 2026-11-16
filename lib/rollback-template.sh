#!/usr/bin/env bash
# =============================================================================
# rollback.sh — Revierte una ejecución de harden.sh a partir de su MANIFEST.
# Es AUTÓNOMO: se copia en cada directorio de backup para poder usarse aunque
# el repositorio de hardening se haya borrado.
#
# Uso:  sudo bash rollback.sh [--dry-run] [/var/backups/hardening/<ts>-<nivel>]
# Procesa el manifiesto en orden INVERSO (deshace lo último primero).
# =============================================================================
set -Euo pipefail

DRY=0
if [[ "${1:-}" == "--dry-run" ]]; then DRY=1; shift; fi
DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
MANIFEST="$DIR/MANIFEST"
[[ -f "$MANIFEST" ]] || { echo "ERROR: no existe $MANIFEST" >&2; exit 1; }
[[ $EUID -eq 0 || $DRY -eq 1 ]] || { echo "ERROR: ejecutar como root" >&2; exit 1; }

FAILS=0
act() { # ejecuta o muestra
  if (( DRY )); then echo "[DRY] $*"; return 0; fi
  echo "+ $*"
  "$@" || { echo "  ! falló: $*" >&2; FAILS=$((FAILS+1)); }
}

echo "== Rollback de $DIR =="
mapfile -t LINES < <(grep -v '^#' "$MANIFEST" | grep -v '^[[:space:]]*$')
for (( i=${#LINES[@]}-1; i>=0; i-- )); do
  IFS='|' read -r type a b c <<<"${LINES[$i]}"
  case "$type" in
    FILE)
      if [[ -d "$DIR/files$a" && ! -L "$DIR/files$a" ]]; then
        act rm -rf "$a"; act cp -a "$DIR/files$a" "$a"      # directorio completo
      elif [[ -e "$DIR/files$a" || -L "$DIR/files$a" ]]; then
        act cp -a "$DIR/files$a" "$a"
      else
        echo "  ! sin copia para $a (¿--no-backup?)" >&2
      fi ;;
    NEW)          [[ -e "$a" || -L "$a" ]] && act rm -f "$a" ;;
    NEWDIR)       [[ -d "$a" ]] && act rmdir --ignore-fail-on-non-empty "$a" ;;
    SVC_DISABLED) act systemctl enable "$a" ;;
    SVC_STOPPED)  act systemctl start "$a" ;;
    SVC_MASKED)   act systemctl unmask "$a" ;;
    SVC_ENABLED)  act systemctl disable --now "$a" ;;
    USER_LOCKED)  act usermod -U -e '' "$a" ;;
    USER_SHELL)   act usermod -s "$b" "$a" ;;
    NFT_TABLE)    # shellcheck disable=SC2086
                  if nft list table $a >/dev/null 2>&1; then act nft delete table $a; else echo "  (tabla $a ya no existe)"; fi ;;
    FW_STATE)
      case "$a" in
        ufw)       if [[ "$b" == 0 ]]; then act ufw --force disable; else act ufw reload; fi ;;
        firewalld) if [[ "$b" == 0 ]]; then act systemctl stop firewalld; else act firewall-cmd --reload; fi
                   [[ "${c:-1}" == 0 ]] && act systemctl disable firewalld ;;
      esac ;;
    GROUP_ADDED)  getent group "$a" >/dev/null && act groupdel "$a" ;;
    CRYPTO_POLICY) act update-crypto-policies --set "$a" ;;
    PKG_INSTALLED) echo "  i paquete instalado por el hardening (no se desinstala): $a" ;;
    PKG_REMOVED)   echo "  i paquete eliminado por el hardening (reinstalar si se necesita): $a" ;;
    *) echo "  ? acción desconocida: ${LINES[$i]}" ;;
  esac
done

# Recargas para que los archivos restaurados surtan efecto.
if (( ! DRY )); then
  command -v systemctl >/dev/null && systemctl daemon-reload 2>/dev/null || true
  command -v sysctl >/dev/null && sysctl --system >/dev/null 2>&1 || true
  if command -v sshd >/dev/null && sshd -t 2>/dev/null; then
    systemctl try-reload-or-restart ssh sshd 2>/dev/null || true
  fi
  command -v augenrules >/dev/null && augenrules --load >/dev/null 2>&1 || true
  systemctl try-restart systemd-journald 2>/dev/null || true
  command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q 'Status: active' && ufw reload >/dev/null 2>&1 || true
fi
echo "== Rollback terminado (${FAILS} fallos). Revise: sshd -t, firewall, servicios. Algunos cambios (fstab, GRUB, SELinux) requieren reinicio. =="
exit $(( FAILS > 0 ))
