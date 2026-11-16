# shellcheck shell=bash
# =============================================================================
# 99-lockdown — Medidas finales del modo PÁNICO y guía de respuesta a incidentes
#
# POR QUÉ: tras contener (red cerrada, servicios mínimos, cuentas bloqueadas),
# hay medidas extremas opcionales y pasos que NO deben automatizarse.
#  * kernel.modules_disabled=1: impide cargar CUALQUIER módulo (rootkits LKM)
#    hasta reiniciar. Es IRREVERSIBLE en caliente: opt-in con
#    PANIC_DISABLE_MODULE_LOADING=1. Se aplica al final, cuando el firewall ya
#    cargó sus módulos.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 99 lockdown 4 "Medidas finales de lockdown y guía de respuesta"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta PNC-01 4 cambio alto "inmediato;irreversible hasta reiniciar" "kernel.modules_disabled=1 (opt-in PANIC_DISABLE_MODULE_LOADING=1)" "sysctl en caliente" \
  "Cualquier carga de módulo: USB, VPN, CNI de contenedores, drivers"
ctl_meta PNC-02 4 aviso bajo ninguno "Siguientes pasos de respuesta a incidentes" "-" "Nada"


modload_check() {
  (( IN_CONTAINER )) && return 2
  [[ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)" == 1 ]] && return 0
  (( PANIC_DISABLE_MODULE_LOADING )) || { note "opt-in: PANIC_DISABLE_MODULE_LOADING=1 (irreversible hasta reiniciar)"; return 2; }
  return 1
}
modload_apply() { run_cmd sysctl -q -w kernel.modules_disabled=1; note "hasta el próximo reinicio no se pueden cargar módulos"; }

ir_steps() {
  note "1) Copia ${RUN_DIR}/evidence FUERA del host; 2) si es posible, captura RAM (AVML/LiME) e imagen de disco ANTES de reiniciar; 3) rota credenciales, claves SSH y tokens usados en este host; 4) revisa authorized_keys, cron, systemd y sudoers (ver evidencia); 5) busca movimiento lateral desde esta IP en el resto de la red; 6) lo más seguro es reinstalar desde una imagen limpia y restaurar datos verificados"
  return 1
}

module_lockdown() {
  control PNC-01 4 "Bloquear la carga de módulos del kernel (opt-in)" modload_check modload_apply
  advise  PNC-02 4 "Siguientes pasos de respuesta a incidentes" ir_steps
}
