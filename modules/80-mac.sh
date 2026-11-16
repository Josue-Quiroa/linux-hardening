# shellcheck shell=bash
# =============================================================================
# 80-mac — Control de acceso obligatorio: AppArmor (Debian/Ubuntu) / SELinux (RHEL)
#
# POR QUÉ: el MAC limita lo que puede hacer un proceso comprometido aunque
# corra como root (CIS 1.3.x / 1.6.x, STIG). La regla de oro es NO pasar de
# golpe de "disabled" a "enforcing" en SELinux: el sistema de archivos no está
# etiquetado y el arranque puede fallar. Se hace por etapas:
#   disabled -> permissive + /.autorelabel (reinicio) -> enforcing (siguiente ejecución)
#   permissive -> enforcing SOLO si no hay denegaciones AVC recientes
# AppArmor: medio = servicio activo con perfiles cargados; máximo = perfiles
# en "complain" pasan a "enforce" (los marcados "unconfined" no se tocan).
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 80 mac 1 "AppArmor / SELinux"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta MAC-01 1 aviso bajo ninguno "Hay un MAC (AppArmor/SELinux) activo" "-" "Nada"
ctl_meta MAC-02 1 aviso bajo ninguno "El MAC no está desactivado en la línea de arranque" "-" "Nada"
ctl_meta MAC-03 2 cambio alto "reinicio;SELinux disabled->permissive requiere reinicio y relabel" "AppArmor activo (Debian/Ubuntu) / SELinux permissive->enforcing por etapas (RHEL)" \
  "paquetes apparmor(-utils) | /etc/selinux/config, /.autorelabel" "Aplicaciones con rutas no estándar sin contexto/perfil (denegaciones AVC/AppArmor)"
ctl_meta MAC-04 3 cambio medio inmediato "Perfiles AppArmor en enforce / política SELinux targeted" "/etc/apparmor.d/* (aa-enforce) | /etc/selinux/config" "Aplicaciones cuyo perfil estaba en complain por un motivo"
ctl_meta MAC-05 3 aviso bajo ninguno "Servicios sin confinar (unconfined_service_t)" "-" "Nada"


mac_status_check() {
  if have getenforce; then
    local m; m=$(getenforce 2>/dev/null); note "SELinux: $m"; [[ "$m" == Enforcing ]]
  elif [[ -r /sys/module/apparmor/parameters/enabled ]]; then
    [[ "$(cat /sys/module/apparmor/parameters/enabled)" == Y ]] || { note "AppArmor desactivado en el kernel"; return 1; }
    note "AppArmor activo"
  else
    note "ningún MAC activo"; return 1
  fi
}

bootparam_check() {
  if grep -Eqw 'selinux=0|enforcing=0|apparmor=0' /proc/cmdline; then
    note "el MAC está desactivado en la línea del kernel: $(grep -Eow 'selinux=0|enforcing=0|apparmor=0' /proc/cmdline | tr '\n' ' ')"
    return 1
  fi
}

# --- AppArmor ------------------------------------------------------------------
aa_check() {
  is_debian || return 2
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  pkg_installed apparmor || { note "apparmor no instalado"; return 1; }
  (( HAS_SYSTEMD )) || return 0
  svc_enabled apparmor || { note "servicio apparmor deshabilitado"; return 1; }
  [[ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" == Y ]] || { note "desactivado en el kernel (revisar GRUB)"; return 1; }
}
aa_apply() {
  pkg_install apparmor
  (( LEVEL_NUM >= 3 )) && pkg_install apparmor-utils
  (( HAS_SYSTEMD )) && svc_enable_now apparmor
  return 0
}

aa_complain_profiles() {
  have aa-status || return 0
  aa-status 2>/dev/null | awk '/profiles are in complain mode/{f=1; next} /profiles are|processes/{f=0} f{gsub(/^[ \t]+/,""); print}'
}
aa_enforce_check() {
  is_debian || return 2
  have aa-status || { note "apparmor-utils no instalado"; return 1; }
  is_root || { note "requiere root"; return 2; }
  local l; l=$(aa_complain_profiles | tr '\n' ' ')
  [[ -z "$l" ]] || { note "en complain: ${l:0:200}"; return 1; }
}
aa_enforce_apply() {
  pkg_install apparmor-utils
  local p f
  for p in $(aa_complain_profiles); do
    if [[ "$p" == /* && -x "$p" ]]; then f=$p
    else f=$(grep -lE "^[[:space:]]*profile[[:space:]]+${p//\//\\/}[[:space:]{]" /etc/apparmor.d/* 2>/dev/null | head -n1); fi
    [[ -n "$f" ]] || continue
    if [[ -f "$f" ]] && grep -q 'flags=(.*unconfined' "$f" 2>/dev/null; then continue; fi
    run_cmd aa-enforce "$f" || note "no se pudo forzar $p"
  done
}

# --- SELinux ---------------------------------------------------------------------
selinux_cfg() { get_config_value /etc/selinux/config SELINUX '=' 2>/dev/null || echo "?"; }
se_check() {
  is_rhel || return 2
  (( IN_CONTAINER )) && { note "contenedor"; return 2; }
  have getenforce || { note "herramientas SELinux no instaladas"; return 1; }
  local rt cfg; rt=$(getenforce 2>/dev/null); cfg=$(selinux_cfg)
  note "runtime=$rt config=$cfg"
  [[ "$rt" == Enforcing && "${cfg,,}" == enforcing ]]
}
se_apply() {
  local rt; rt=$(getenforce 2>/dev/null || echo Disabled)
  case "$rt" in
    Disabled)
      set_config_value /etc/selinux/config SELINUX permissive "="
      if (( ! DRY_RUN )); then : >/.autorelabel; record_action NEW /.autorelabel; else log_dry "touch /.autorelabel"; fi
      note "SELinux estaba DESACTIVADO: se deja en permissive con reetiquetado al reiniciar. Tras el reinicio vuelve a ejecutar este nivel para pasar a enforcing."
      return 4 ;;
    Permissive)
      if have ausearch && ausearch -m AVC,USER_AVC -ts today --just-one >/dev/null 2>&1; then
        note "hay denegaciones AVC hoy: revisa 'ausearch -m AVC -ts today | audit2why' antes de pasar a enforcing"
        return 3
      fi
      set_config_value /etc/selinux/config SELINUX enforcing "="
      run_cmd setenforce 1 ;;
    Enforcing)
      set_config_value /etc/selinux/config SELINUX enforcing "=" ;;
  esac
}
setype_check() { is_rhel || return 2; [[ "$(get_config_value /etc/selinux/config SELINUXTYPE '=' 2>/dev/null)" =~ ^(targeted|mls)$ ]]; }
setype_apply() { set_config_value /etc/selinux/config SELINUXTYPE targeted "="; return 4; }
unconfined_check() {
  is_rhel && have ps || return 2
  local l; l=$(ps -eZ 2>/dev/null | awk '/unconfined_service_t/{print $NF}' | sort -u | tr '\n' ' ')
  [[ -z "$l" ]] || { note "procesos sin confinar: $l"; return 1; }
}

module_mac() {
  advise MAC-01 1 "Hay un MAC (AppArmor/SELinux) activo" mac_status_check
  advise MAC-02 1 "El MAC no está desactivado desde el gestor de arranque" bootparam_check
  if is_debian; then
    control MAC-03 2 "AppArmor instalado y activo" aa_check aa_apply
    control MAC-04 3 "Perfiles AppArmor en modo enforce (no complain)" aa_enforce_check aa_enforce_apply
  elif is_rhel; then
    control MAC-03 2 "SELinux en enforcing (por etapas, sin romper el arranque)" se_check se_apply
    control MAC-04 3 "Política SELinux targeted" setype_check setype_apply
    advise  MAC-05 3 "Servicios sin confinar (unconfined_service_t)" unconfined_check
  fi
}
