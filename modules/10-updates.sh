# shellcheck shell=bash
# =============================================================================
# 10-updates — Repositorios firmados y actualizaciones de seguridad
#
# POR QUÉ: la mayoría de compromisos explotan vulnerabilidades ya parcheadas.
# CIS (sección 1.2) exige verificación GPG de paquetes y parches al día; DISA
# STIG exige parches de seguridad. Las actualizaciones automáticas de SOLO
# seguridad reducen la ventana de exposición con riesgo bajo.
#   basico : comprobar firmas GPG y reportar actualizaciones pendientes
#   medio  : actualizaciones automáticas de seguridad (sin reinicio automático)
#            + aplicar ahora los parches de seguridad pendientes
#   maximo : actualización completa del sistema
#   panico : por defecto NO actualiza (preserva el estado para el análisis);
#            PANIC_UPDATE=1 para forzarlo.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 10 updates 1 "Repositorios firmados y actualizaciones"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta UPD-01 1 cambio bajo inmediato "Verificación GPG activa en todos los repositorios" \
  "/etc/dnf/dnf.conf, /etc/yum.repos.d/*.repo (RHEL); en Debian sólo informa de repos trusted=yes" "Repos internos sin firmar dejarán de instalarse (RHEL)"
ctl_meta UPD-02 1-1 aviso bajo ninguno "Informe de parches pendientes" "-" "Nada"
ctl_meta UPD-03 2 cambio medio inmediato "Actualizaciones automáticas sólo de seguridad, sin reinicio automático" \
  "paquete unattended-upgrades + /etc/apt/apt.conf.d/20auto-upgrades, 52hardening-unattended | dnf-automatic + /etc/dnf/automatic.conf, dnf-automatic.timer" \
  "Una actualización nocturna puede reiniciar servicios (needrestart) o cambiar versiones de BD/runtime"
ctl_meta UPD-04 2 cambio medio "inmediato;algunos parches (kernel, glibc) requieren reinicio" "Aplicar ya los parches pendientes (medio: seguridad; máximo: todos; pánico: sólo con PANIC_UPDATE=1)" \
  "paquetes del sistema (apt-get/dnf)" "Reinicio de servicios durante la actualización; cambios de versión; kernel nuevo hasta reiniciar"


# --- UPD-01: verificación GPG ------------------------------------------------
upd_gpg_check() {
  if is_rhel; then
    local f bad=0
    [[ "$(get_config_value /etc/dnf/dnf.conf gpgcheck '[[:space:]]*=[[:space:]]*' 2>/dev/null || echo 1)" =~ ^(1|True|true|yes)$ ]] || bad=1
    for f in /etc/yum.repos.d/*.repo; do
      [[ -f "$f" ]] || continue
      if grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' "$f"; then note "gpgcheck=0 en $f"; bad=1; fi
    done
    return "$bad"
  else
    local hits
    hits=$(grep -RlsE '\[[^]]*trusted=yes|AllowUnauthenticated[[:space:]]+"?(true|1)' /etc/apt/sources.list /etc/apt/sources.list.d /etc/apt/apt.conf.d 2>/dev/null || true)
    [[ -z "$hits" ]] || { note "repos sin firma: $(echo "$hits" | tr '\n' ' ')"; return 1; }
  fi
}
upd_gpg_apply() {
  if is_rhel; then
    set_config_value /etc/dnf/dnf.conf gpgcheck 1 "="
    local f
    for f in /etc/yum.repos.d/*.repo; do
      [[ -f "$f" ]] || continue
      if grep -Eq '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*0' "$f"; then
        sed -E 's/^([[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*)0/\11/' "$f" | write_file "$f" 644
      fi
    done
  else
    # En Debian/Ubuntu no lo corregimos automáticamente: un repo "trusted=yes"
    # suele ser interno y quitarlo rompería apt. Se reporta para revisión.
    note "revisar y firmar los repositorios marcados (no se modifican automáticamente)"
    return 3
  fi
}

# --- UPD-02: parches pendientes (informativo en básico) ---------------------
upd_pending_count() {
  case $PKG_MGR in
    apt) apt-get -s -o Debug::NoLocking=1 upgrade 2>/dev/null | grep -c '^Inst' || true ;;
    dnf|yum) "$PKG_MGR" -q check-update --security 2>/dev/null | awk 'NF==3' | wc -l ;;
    *) echo 0 ;;
  esac
}
upd_pending_check() {
  local n; n=$(upd_pending_count)
  note "$n paquetes con actualización pendiente (según caché local)"
  [[ "$n" == 0 ]]
}

# --- UPD-03: actualizaciones automáticas de seguridad ------------------------
upd_auto_check() {
  if is_debian; then
    pkg_installed unattended-upgrades || return 1
    [[ "$(get_config_value /etc/apt/apt.conf.d/20auto-upgrades 'APT::Periodic::Unattended-Upgrade' '[[:space:]]+' 2>/dev/null)" == '"1";' ]]
  else
    pkg_installed dnf-automatic || return 1
    if (( HAS_SYSTEMD )); then svc_enabled dnf-automatic.timer || return 1; fi
    [[ "$(get_config_value /etc/dnf/automatic.conf upgrade_type '[[:space:]]*=[[:space:]]*' 2>/dev/null)" == security ]]
  fi
}
upd_auto_apply() {
  if is_debian; then
    pkg_install unattended-upgrades
    write_file /etc/apt/apt.conf.d/20auto-upgrades 644 <<'CONF'
// Gestionado por harden.sh: actualizaciones automáticas diarias.
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
CONF
    # Sólo el origen -security, sin reinicio automático (decisión del administrador).
    write_file /etc/apt/apt.conf.d/52hardening-unattended 644 <<'CONF'
// Gestionado por harden.sh. Las reglas de 50unattended-upgrades se mantienen;
// aquí sólo forzamos que NUNCA se reinicie automáticamente y que se limpien
// dependencias obsoletas.
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
CONF
  else
    pkg_install dnf-automatic
    set_config_value /etc/dnf/automatic.conf upgrade_type security " = "
    set_config_value /etc/dnf/automatic.conf apply_updates yes " = "
    if (( HAS_SYSTEMD )); then svc_enable_now dnf-automatic.timer; fi
  fi
}

# --- UPD-04: aplicar parches ahora --------------------------------------------
upd_now_check() { upd_pending_check; }
upd_now_apply() {
  if (( LEVEL_NUM == 4 && ! PANIC_UPDATE )); then
    note "pánico: no se actualiza para preservar evidencias (PANIC_UPDATE=1 para forzar)"; return 3
  fi
  case $PKG_MGR in
    apt)
      run_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -qq
      if (( LEVEL_NUM >= 3 )); then
        run_cmd env DEBIAN_FRONTEND=noninteractive apt-get -y -q -o Dpkg::Options::=--force-confold dist-upgrade
      elif have unattended-upgrade; then
        run_cmd unattended-upgrade -v      # sólo orígenes de seguridad configurados
      else
        run_cmd env DEBIAN_FRONTEND=noninteractive apt-get -y -q -o Dpkg::Options::=--force-confold upgrade
      fi ;;
    dnf|yum)
      if (( LEVEL_NUM >= 3 )); then run_cmd "$PKG_MGR" -y -q upgrade
      else run_cmd "$PKG_MGR" -y -q upgrade --security; fi ;;
  esac
  if [[ -f /var/run/reboot-required ]] || { have needs-restarting && ! needs-restarting -r >/dev/null 2>&1; }; then
    note "el sistema requiere reinicio para cargar el nuevo kernel/librerías"; return 4
  fi
}

module_updates() {
  control UPD-01 1 "Verificación GPG de paquetes activada en todos los repositorios" upd_gpg_check upd_gpg_apply
  advise  UPD-02 1-1 "Parches pendientes (sólo informe en nivel básico)" upd_pending_check
  control UPD-03 2 "Actualizaciones automáticas de seguridad (sin reinicio automático)" upd_auto_check upd_auto_apply
  control UPD-04 2 "Aplicar parches pendientes ($( ((LEVEL_NUM>=3)) && echo 'todos' || echo 'sólo seguridad'))" upd_now_check upd_now_apply
}
