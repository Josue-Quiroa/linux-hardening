# shellcheck shell=bash
# =============================================================================
# 00-evidence — Captura de evidencias forenses (SÓLO modo pánico, se ejecuta PRIMERO)
#
# POR QUÉ: si se sospecha un compromiso, cualquier cambio (parar servicios,
# matar sesiones, bloquear cuentas) destruye información volátil: procesos,
# conexiones, sesiones, binarios borrados en ejecución... Guía NIST SP 800-61 /
# RFC 3227 ("orden de volatilidad"): primero lo más volátil.
# AVISO: esto NO sustituye a una adquisición forense real (volcado de RAM con
# LiME/AVML, imagen de disco). Si el caso puede acabar en juicio, haz eso antes.
# =============================================================================
# shellcheck disable=SC2016  # los bash -c '...' se expanden en el subshell a propósito
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 00 evidence 4 "Captura de evidencias forenses antes de cualquier cambio"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta EVD-01 4 cambio bajo ninguno "Captura forense previa: procesos, sockets, sesiones, cron, claves, SUID, verificación de paquetes, hashes" \
  "<backup>/evidence/ (sólo lectura del sistema)" "Nada; tarda 1-5 min y usa CPU/disco (verificación de paquetes)"


EVIDENCE_DIR=""

_ev() { # _ev <archivo> <comando...> : guarda la salida de un comando
  local out="$EVIDENCE_DIR/$1"; shift
  if (( DRY_RUN || AUDIT )); then log_dry "evidencia: $* > $out"; return 0; fi
  { echo "# $(date -Is) :: $*"; "$@" 2>&1 || true; } >"$out" 2>&1
}

ev_check() { [[ -s "${RUN_DIR}/evidence/SHA256SUMS" ]]; } # se captura una vez por ejecución

ev_apply() {
  EVIDENCE_DIR="${RUN_DIR}/evidence"
  if (( ! DRY_RUN && ! AUDIT )); then mkdir -p "$EVIDENCE_DIR"; chmod 700 "$EVIDENCE_DIR"; fi
  note "directorio $EVIDENCE_DIR"
  # 1) Lo más volátil: procesos, red, sesiones
  _ev 01-date.txt date -Is
  _ev 02-ps.txt ps auxwwf
  have ss && _ev 03-ss-sockets.txt ss -tupanwe
  have ss && _ev 04-ss-established.txt ss -tanpo state established
  _ev 05-who.txt who -a
  _ev 06-w.txt w
  have loginctl && _ev 07-sessions.txt loginctl list-sessions --no-pager
  _ev 08-deleted-exe.txt bash -c 'ls -l /proc/[0-9]*/exe 2>/dev/null | grep -E "\(deleted\)|/tmp/|/dev/shm/|/var/tmp/"'
  _ev 09-proc-cmdline.txt bash -c 'for p in /proc/[0-9]*; do printf "%s\t%s\n" "${p#/proc/}" "$(tr "\0" " " <"$p/cmdline" 2>/dev/null)"; done'
  have lsof && _ev 10-lsof-net.txt lsof -nP -i
  _ev 11-ip-addr.txt ip -d addr
  _ev 12-ip-route.txt ip route show table all
  _ev 13-ip-neigh.txt ip neigh
  have nft && _ev 14-nft-ruleset.txt nft list ruleset
  have iptables-save && _ev 15-iptables.txt iptables-save
  _ev 16-lsmod.txt lsmod
  _ev 17-mounts.txt findmnt -l
  _ev 18-uname.txt uname -a
  # 2) Persistencia típica de atacantes: cron, systemd, claves SSH, sudoers, ld.so.preload
  _ev 20-last.txt last -Faiwx -n 500
  _ev 21-lastb.txt lastb -Faiw -n 200
  _ev 22-lastlog.txt bash -c 'command -v lastlog >/dev/null && lastlog || command -v lastlog2 >/dev/null && lastlog2'
  if (( HAS_SYSTEMD )); then
    _ev 23-units-running.txt systemctl list-units --all --no-pager
    _ev 24-timers.txt systemctl list-timers --all --no-pager
    _ev 25-unit-files.txt systemctl list-unit-files --no-pager
  fi
  _ev 26-crontabs.txt bash -c 'for f in /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/anacrontab; do [ -f "$f" ] && { echo "=== $f"; cat "$f"; }; done'
  _ev 27-authorized-keys.txt bash -c 'getent passwd | cut -d: -f1,6 | while IFS=: read -r u h; do for k in "$h"/.ssh/authorized_keys*; do [ -f "$k" ] && { echo "=== $u $k"; stat -c "%y %U %a" "$k"; cat "$k"; }; done; done'
  _ev 28-sudoers.txt bash -c 'cat /etc/sudoers /etc/sudoers.d/* 2>/dev/null'
  _ev 29-ld-preload.txt bash -c 'cat /etc/ld.so.preload 2>/dev/null; env | grep -i LD_ || true'
  _ev 30-passwd.txt getent passwd
  _ev 31-group.txt getent group
  _ev 32-uid0.txt awk -F: '$3==0' /etc/passwd
  _ev 33-recent-etc-bin.txt bash -c 'find /etc /usr/bin /usr/sbin /usr/lib/systemd /lib/systemd /root /tmp /var/tmp /dev/shm -xdev -mtime -7 -type f -printf "%TY-%Tm-%Td %TH:%TM %u %m %p\n" 2>/dev/null | sort -r | head -n 3000'
  _ev 34-tmp-listing.txt ls -laR /tmp /var/tmp /dev/shm
  _ev 35-suid.txt bash -c 'find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -printf "%m %u %p\n" 2>/dev/null'
  _ev 36-shell-history.txt bash -c 'getent passwd | cut -d: -f1,6 | while IFS=: read -r u h; do for f in "$h"/.bash_history "$h"/.zsh_history "$h"/.ash_history; do [ -f "$f" ] && { echo "=== $u $f"; tail -n 500 "$f"; }; done; done'
  _ev 37-journal-ssh.txt bash -c 'journalctl -u ssh -u sshd --since "-7 days" --no-pager 2>/dev/null | tail -n 5000'
  # 3) Integridad de paquetes (detecta binarios del sistema modificados)
  if is_debian && have dpkg; then _ev 40-dpkg-verify.txt dpkg --verify
  elif have rpm; then _ev 40-rpm-verify.txt rpm -Va --nomtime
  fi
  # 4) Cadena de custodia: hash de todo lo recogido
  if (( ! DRY_RUN && ! AUDIT )); then
    (cd "$EVIDENCE_DIR" && sha256sum -- * >SHA256SUMS 2>/dev/null) || true
    chmod -R go-rwx "$EVIDENCE_DIR"
    log_ok "Evidencia guardada en $EVIDENCE_DIR (SHA256SUMS incluido). Cópiala FUERA del host."
  fi
}

module_evidence() {
  control EVD-01 4 "Capturar evidencia volátil y de persistencia (antes de cambios)" ev_check ev_apply
}
