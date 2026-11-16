# shellcheck shell=bash
# =============================================================================
# lib/fwsafety.sh — "Red de seguridad" para cambios de firewall
#
# POR QUÉ: cambiar el firewall de un servidor remoto puede dejarte fuera. Igual
# que hacen los routers (Junos "commit confirmed", "iptables-apply"), ANTES de
# aplicar se programa una reversión automática (systemd-run, at o un sleep en
# segundo plano). Si no confirmas en FW_CONFIRM_TIMEOUT segundos (porque has
# perdido la conexión), el firewall vuelve a su estado anterior.
# Confirmar: responder "si" en el prompt o ejecutar `harden.sh --confirm-firewall`.
# =============================================================================

FW_ROLLBACK_UNIT=hardening-fw-rollback
FW_ROLLBACK_STATE=/run/hardening-fw-rollback

fw_arm_rollback() { # fw_arm_rollback <script_de_reversión>
  local script=$1 t=$FW_CONFIRM_TIMEOUT
  if (( t == 0 )); then log_warn "Rollback automático de firewall DESACTIVADO (--fw-timeout 0)."; return 0; fi
  if (( DRY_RUN )); then log_dry "programar reversión del firewall en ${t}s con $script"; return 0; fi
  mkdir -p "$FW_ROLLBACK_STATE"
  echo "$script" >"$FW_ROLLBACK_STATE/script"
  if (( HAS_SYSTEMD )) && have systemd-run; then
    systemctl stop "$FW_ROLLBACK_UNIT.timer" "$FW_ROLLBACK_UNIT.service" >/dev/null 2>&1 || true
    systemctl reset-failed "$FW_ROLLBACK_UNIT.service" >/dev/null 2>&1 || true
    systemd-run --quiet --unit="$FW_ROLLBACK_UNIT" --on-active="${t}s" \
      --timer-property=AccuracySec=1s /bin/bash "$script"
    echo systemd >"$FW_ROLLBACK_STATE/method"
  elif have at && { svc_active atd || pgrep -x atd >/dev/null; }; then
    local mins=$(( (t + 59) / 60 ))
    echo "/bin/bash '$script'" | at now + "$mins" minutes 2>&1 | awk '/job/{print $2}' >"$FW_ROLLBACK_STATE/atjob"
    echo at >"$FW_ROLLBACK_STATE/method"
  else
    nohup bash -c "sleep $t; /bin/bash '$script'" >/dev/null 2>&1 &
    echo $! >"$FW_ROLLBACK_STATE/pid"
    echo sleep >"$FW_ROLLBACK_STATE/method"
  fi
  log_warn "Reversión automática del firewall programada en ${t}s (si pierdes el acceso, espera)."
}

fw_disarm_rollback() {
  local m
  m=$(cat "$FW_ROLLBACK_STATE/method" 2>/dev/null || echo none)
  case "$m" in
    systemd) systemctl stop "$FW_ROLLBACK_UNIT.timer" >/dev/null 2>&1 || true ;;
    at)      atrm "$(cat "$FW_ROLLBACK_STATE/atjob")" 2>/dev/null || true ;;
    sleep)   kill "$(cat "$FW_ROLLBACK_STATE/pid")" 2>/dev/null || true ;;
    none)    log_info "No hay ninguna reversión de firewall pendiente."; return 0 ;;
  esac
  rm -rf "$FW_ROLLBACK_STATE"
  log_ok "Firewall confirmado: reversión automática cancelada."
}

fw_wait_confirm() {
  local t=$FW_CONFIRM_TIMEOUT ans=""
  (( t > 0 && ! DRY_RUN )) || return 0
  if (( ASSUME_YES )) || [[ ! -t 0 ]]; then
    log_warn "Modo no interactivo: el firewall se REVERTIRÁ en ${t}s salvo que ejecutes: $BASE_DIR/harden.sh --confirm-firewall"
    return 0
  fi
  printf '\n%sComprueba AHORA desde otra terminal que puedes abrir una NUEVA sesión SSH.%s\n' "$C_BLD$C_YLW" "$C_RST" >&2
  if read -r -t "$t" -p "¿Mantener el nuevo firewall? escribe 'si' (${t}s): " ans && [[ "${ans,,}" =~ ^(si|sí|s|yes|y)$ ]]; then
    fw_disarm_rollback
  elif [[ -n "$ans" ]]; then
    log_warn "No confirmado: revirtiendo el firewall ahora."
    bash "$(cat "$FW_ROLLBACK_STATE/script" 2>/dev/null || echo /dev/null)" || true
    fw_disarm_rollback
    return 1
  else
    log_warn "Sin respuesta: el firewall se revertirá automáticamente."
  fi
}
