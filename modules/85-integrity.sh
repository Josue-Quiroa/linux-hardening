# shellcheck shell=bash
# =============================================================================
# 85-integrity — Integridad de archivos con AIDE (nivel máximo y pánico)
#
# POR QUÉ: detectar binarios o configuraciones modificadas por un atacante
# (rootkits de espacio de usuario, backdoors en PAM/SSH). CIS 6.1.x lo exige.
# La creación de la base inicial puede tardar MUCHO (minutos a >1 h según el
# disco): se lanza en segundo plano con prioridad baja (nice/ionice).
# En pánico, si ya existe una base AIDE, se ejecuta una comparación y se guarda
# como evidencia.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 85 integrity 3 "Integridad de archivos (AIDE)"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta INT-01 3 cambio bajo "inmediato;base inicial en segundo plano" "AIDE instalado con base de datos inicial" "paquete aide, /var/lib/aide/aide.db*" "CPU/IO durante la generación inicial (puede tardar >1 h)"
ctl_meta INT-02 3 cambio bajo inmediato "Comprobación AIDE diaria" "/etc/cron.daily/aide o aidecheck.timer" "IO diario; avisos tras cada actualización de paquetes"
ctl_meta INT-03 4 cambio bajo ninguno "PÁNICO: aide --check contra la base previa (evidencia)" "<backup>/evidence/" "Nada (sólo lectura)"


aide_db() { local f; for f in /var/lib/aide/aide.db /var/lib/aide/aide.db.gz; do [[ -f "$f" ]] && { echo "$f"; return 0; }; done; return 1; }
aide_conf() { local f; for f in /etc/aide/aide.conf /etc/aide.conf; do [[ -f "$f" ]] && { echo "$f"; return 0; }; done; echo /etc/aide.conf; }

aide_check() {
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  pkg_installed aide || { note "AIDE no instalado"; return 1; }
  aide_db >/dev/null || { note "base de datos AIDE no inicializada"; return 1; }
}
aide_apply() {
  pkg_install aide
  is_debian && pkg_install aide-common
  (( AIDE_INIT )) || { note "AIDE_INIT=0: inicializa manualmente"; return 3; }
  local cmd
  if is_debian && have aideinit; then
    cmd="aideinit -y -f"
  else
    cmd="aide --init -c $(aide_conf) && mv -f /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz"
  fi
  if (( HAS_SYSTEMD )) && have systemd-run; then
    run_cmd systemd-run --unit=hardening-aide-init --nice=19 -p IOSchedulingClass=idle /bin/sh -c "$cmd"
  else
    run_sh "nohup nice -n 19 sh -c '$cmd' >/var/log/hardening-aide-init.log 2>&1 &"
  fi
  note "base AIDE generándose en segundo plano (journalctl -u hardening-aide-init)"
  return 4
}

aide_timer_check() {
  (( IN_CONTAINER )) && return 2
  (( HAS_SYSTEMD )) || return 2
  svc_enabled dailyaidecheck.timer || svc_enabled aidecheck.timer || [[ -e /etc/cron.daily/aide ]] || grep -qs aide /etc/crontab
}
aide_timer_apply() {
  if svc_exists dailyaidecheck.timer; then svc_enable_now dailyaidecheck.timer; return 0; fi
  write_file /etc/systemd/system/aidecheck.service 644 <<UNIT
# Generado por harden.sh (CIS 6.1.2)
[Unit]
Description=Comprobación de integridad de archivos con AIDE

[Service]
Type=simple
Nice=19
IOSchedulingClass=idle
ExecStart=$(command -v aide || echo /usr/sbin/aide) --check
UNIT
  write_file /etc/systemd/system/aidecheck.timer 644 <<'UNIT'
# Generado por harden.sh
[Unit]
Description=Comprobación diaria de AIDE

[Timer]
OnCalendar=*-*-* 05:00:00
RandomizedDelaySec=30m
Persistent=true
Unit=aidecheck.service

[Install]
WantedBy=timers.target
UNIT
  run_cmd systemctl daemon-reload
  svc_enable_now aidecheck.timer
}

aide_panic_check() { [[ -s "${RUN_DIR}/evidence/aide-check.txt" ]]; }
aide_panic_apply() {
  aide_db >/dev/null || { note "no hay base AIDE previa con la que comparar"; return 3; }
  if (( DRY_RUN )); then log_dry "aide --check > ${RUN_DIR}/evidence/aide-check.txt"; return 0; fi
  mkdir -p "${RUN_DIR}/evidence"
  aide --check -c "$(aide_conf)" >"${RUN_DIR}/evidence/aide-check.txt" 2>&1 || true
  note "resultado en ${RUN_DIR}/evidence/aide-check.txt"
}

module_integrity() {
  control INT-01 3 "AIDE instalado con base de datos inicial" aide_check aide_apply
  control INT-02 3 "Comprobación AIDE diaria programada" aide_timer_check aide_timer_apply
  if (( LEVEL_NUM >= 4 )); then
    control INT-03 4 "PÁNICO: comparar el sistema con la base AIDE previa (evidencia)" aide_panic_check aide_panic_apply
  fi
}
