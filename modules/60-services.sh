# shellcheck shell=bash
# =============================================================================
# 60-services — Servicios innecesarios (denylist por nivel + allowlist en pánico)
#
# POR QUÉ: cada servicio en ejecución es superficie de ataque (CIS 2.1.x/2.2.x
# "Ensure X is not installed/in use"). Pero desactivar a ciegas un servicio que
# usas provoca caídas. Por eso:
#   basico : sólo informe de servicios legacy en texto claro y puertos abiertos
#   medio  : fuera telnet/rsh/rlogin/tftp/xinetd/talk/NIS, avahi, cups-browsed
#   maximo : + cups, bluetooth, ModemManager, rpcbind (si no hay NFS), autofs,
#            snmpd, rsyncd, servidores (ftp, samba, nfs, dns, http-proxy...)
#            SALVO que estén en SERVICES_KEEP; clientes legacy desinstalados
#   panico : ALLOWLIST: se paran todos los servicios en ejecución que no sean
#            esenciales (systemd, red, ssh, logs, auditd, firewall, cron...) o
#            estén en PANIC_KEEP_SERVICES. Todo queda en el MANIFEST.
#   (los servicios de "rol" — FTP, Samba, NFS, DNS... — sólo se reportan en máximo)
# Se usa "disable --now" (reversible) en lugar de desinstalar, salvo clientes legacy.
# =============================================================================
# shellcheck source=../lib/all.sh
[[ -n "${_HARDENING_LIBS:-}" ]] || source "$(dirname "${BASH_SOURCE[0]}")/../lib/all.sh"

register_module 60 services 1 "Servicios innecesarios"

# --- Metadatos (--list-controls, pre-check, resumen de reinicio) ---
ctl_meta SVC-00 1 aviso bajo ninguno "Inventario de puertos en escucha" "-" "Nada"
ctl_meta SVC-01 1 cambio bajo inmediato "Servicios legacy en texto claro (básico: informe; medio+: deshabilitar)" "telnet, rsh/rlogin/rexec, tftp, xinetd, NIS, talk" "Clientes que usan esos protocolos"
ctl_meta SVC-02 2 cambio bajo inmediato "Deshabilitar avahi (mDNS) y cups-browsed" "avahi-daemon, cups-browsed" "Descubrimiento de impresoras/equipos .local"
ctl_meta SVC-03 3 cambio medio inmediato "Deshabilitar cups, bluetooth, ModemManager, autofs, snmpd, rsync, rpcbind" "esas unidades systemd (SERVICES_KEEP para conservar)" \
  "Impresión, Bluetooth, automontaje, monitorización SNMP, NFSv3 (rpcbind)"
ctl_meta SVC-06 3 aviso bajo ninguno "Servicios de rol activos (FTP/Samba/NFS/DNS/proxy...)" "-" "Nada"
ctl_meta SVC-04 3 cambio bajo inmediato "Desinstalar clientes legacy (telnet, rsh, talk, nis, tftp)" "paquetes telnet, rsh-client, talk, nis, tftp..." "Scripts que usan telnet/tftp para pruebas o equipos de red"
ctl_meta SVC-05 4 cambio alto inmediato "PÁNICO: parar todo servicio no esencial (allowlist)" "todas las unidades no esenciales (PANIC_KEEP_SERVICES)" "Web, bases de datos, Docker, colas... todo lo que no esté en la allowlist"


SVC_LEGACY="telnet.socket inetd.service xinetd.service rsh.socket rlogin.socket rexec.socket tftp.socket tftpd-hpa.service ypserv.service ypbind.service talk.socket ntalk.service"
SVC_MEDIO="avahi-daemon.service avahi-daemon.socket cups-browsed.service"
SVC_MAXIMO="cups.service cups.socket cups.path bluetooth.service ModemManager.service autofs.service snmpd.service rsync.service rsyncd.service rpcbind.service rpcbind.socket"
# Servicios de "rol" (FTP, Samba, NFS, DNS, proxy, IMAP, LDAP, DHCP): NO se desactivan
# automáticamente en máximo (podrían ser la función del servidor); se reportan.
SVC_ROLES="vsftpd.service proftpd.service smbd.service nmbd.service smb.service nmb.service nfs-server.service named.service bind9.service squid.service dovecot.service slapd.service isc-dhcp-server.service dhcpd.service"
PKG_CLIENTS_LEGACY="telnet rsh-client rsh talk ntalk nis ypbind yp-tools tftp inetutils-telnet"

# Expresión de servicios esenciales para el modo pánico (allowlist)
PANIC_ESSENTIAL_RE='^(systemd-.*|dbus.*|ssh|sshd|auditd|rsyslog|syslog|chrony|chronyd|ntp|ntpd|ntpsec|cron|crond|atd|getty@.*|serial-getty@.*|console-getty|user@.*|user-runtime-dir@.*|polkit|NetworkManager|networking|network|wpa_supplicant|firewalld|ufw|nftables|hardening-.*|lvm2-.*|multipathd|iscsid|irqbalance|tuned|qemu-guest-agent|vmtoolsd|open-vm-tools|hv-.*|google-guest-agent|amazon-ssm-agent|walinuxagent|waagent|udisks2|unattended-upgrades|apparmor|snapd.*|accounts-daemon|rtkit-daemon|kmod-static-nodes|dm-event|mdmonitor|smartd|dnf-makecache|packagekit|fwupd)\.service$'

svc_list_existing() { local u; for u in $1; do svc_exists "$u" && echo "$u"; done; return 0; }
svc_list_on() { local u; for u in $1; do { svc_enabled "$u" || svc_active "$u"; } && echo "$u"; done; return 0; }

_SVCS=""
svcs_check() {
  (( HAS_SYSTEMD )) || { note "sin systemd"; return 2; }
  local on="" u
  for u in $(svc_list_on "$_SVCS"); do
    in_list "${u%.*}" "$SERVICES_KEEP" || in_list "$u" "$SERVICES_KEEP" || on+="$u "
  done
  [[ -z "$on" ]] || { note "activos: $on"; return 1; }
}
svcs_apply() {
  local u
  for u in $(svc_list_on "$_SVCS"); do
    if in_list "${u%.*}" "$SERVICES_KEEP" || in_list "$u" "$SERVICES_KEEP"; then continue; fi
    # rpcbind se mantiene si hay montajes NFS
    if [[ "$u" == rpcbind* ]] && findmnt -t nfs,nfs4 >/dev/null 2>&1; then note "rpcbind en uso por NFS"; continue; fi
    svc_disable_now "$u"
  done
}

open_ports_report() {
  have ss || { note "ss no disponible"; return 2; }
  local l
  l=$(ss -H -tuln 2>/dev/null | awk '$5!~/^(127\.|\[::1\]|::1)/{print $1" "$5}' | sort -u | tr '\n' ';')
  note "en escucha: ${l:-ninguno}"
  [[ -z "$l" ]]
}

legacy_pkgs_check() {
  local p bad=""
  for p in $PKG_CLIENTS_LEGACY; do pkg_installed "$p" && bad+="$p "; done
  [[ -z "$bad" ]] || { note "$bad"; return 1; }
}
legacy_pkgs_apply() { local p; for p in $PKG_CLIENTS_LEGACY; do pkg_remove "$p"; done; }

# --- Pánico: allowlist --------------------------------------------------------------
panic_targets() {
  local u
  while read -r u _; do
    [[ -n "$u" ]] || continue
    [[ "$u" =~ $PANIC_ESSENTIAL_RE ]] && continue
    in_list "${u%.service}" "$PANIC_KEEP_SERVICES" && continue
    in_list "$u" "$PANIC_KEEP_SERVICES" && continue
    echo "$u"
  done < <(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null)
}
panic_svc_check() {
  (( HAS_SYSTEMD )) || { note "sin systemd"; return 2; }
  local l; l=$(panic_targets | tr '\n' ' ')
  [[ -z "$l" ]] || { note "no esenciales en ejecución: $l"; return 1; }
}
panic_svc_apply() {
  local u l
  l=$(panic_targets | tr '\n' ' ')
  log_warn "Se pararán y deshabilitarán: $l"
  for u in $l; do svc_disable_now "$u"; done
  note "parados: $l (PANIC_KEEP_SERVICES para conservar alguno)"
}

module_services() {
  advise  SVC-00 1 "Puertos en escucha accesibles desde la red (inventario)" open_ports_report
  _SVCS="$SVC_LEGACY"
  if (( LEVEL_NUM == 1 )); then advise SVC-01 1 "Servicios legacy en texto claro (telnet, rsh, tftp, xinetd, NIS)" svcs_check
  else control SVC-01 2 "Deshabilitar servicios legacy en texto claro" svcs_check svcs_apply; fi
  _SVCS="$SVC_MEDIO";  control SVC-02 2 "Deshabilitar avahi (mDNS) y cups-browsed" svcs_check svcs_apply
  _SVCS="$SVC_MAXIMO"; control SVC-03 3 "Deshabilitar servicios no esenciales (cups, bluetooth, autofs, snmp, rpcbind...)" svcs_check svcs_apply
  _SVCS="$SVC_ROLES";  advise  SVC-06 3 "Servicios de rol activos (FTP/Samba/NFS/DNS/proxy...): confirmar necesidad o SERVICES_KEEP" svcs_check
  control SVC-04 3 "Desinstalar clientes legacy (telnet, rsh, talk, nis, tftp)" legacy_pkgs_check legacy_pkgs_apply
  control SVC-05 4 "PÁNICO: parar todo servicio no esencial (allowlist)" panic_svc_check panic_svc_apply
}
